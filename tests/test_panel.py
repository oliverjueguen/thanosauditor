"""Web panel tests (RF-18, RF-19, RF-20)."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from thanos.panel.store import PanelStore  # noqa: E402


@pytest.fixture()
def store(tmp_path):
    return PanelStore(tmp_path / "bundles")


@pytest.fixture()
def client(store, monkeypatch):
    # Inject an isolated store into the app without seeding fixtures.
    import thanos.panel.app as appmod

    monkeypatch.setattr(appmod, "store", store)
    return TestClient(appmod.app)


def test_store_dedup_by_person(store, real_bundle):
    """RF-18: re-uploading the same person's bundle replaces the previous one."""
    store.add_bundle(real_bundle)
    store.add_bundle(real_bundle)
    cycles = store.cycles()
    assert len(cycles) == 1
    assert cycles[0]["kpis"]["bundles"] == 1


def test_store_aggregates_two_people(store, real_bundle, synth_bundle):
    store.add_bundle(real_bundle)
    store.add_bundle(synth_bundle)
    cycle = store.cycles()[0]
    assert cycle["kpis"]["bundles"] == 2
    assert cycle["kpis"]["artifacts"] == 88


def test_home_lists_cycles(client, store, real_bundle):
    """RF-19: the home page lists the cycles."""
    store.add_bundle(real_bundle)
    r = client.get("/")
    assert r.status_code == 200
    assert "2026-04 Patch Tuesday FULL" in r.text
    assert "Thanos Panel" in r.text


def test_upload_and_view_cycle(client, real_path, synth_path):
    """RF-18/RF-20: upload bundles and see the cycle view with score and filtered noise."""
    files = [
        ("files", (p.name, p.read_bytes(), "application/json"))
        for p in (real_path, synth_path)
    ]
    r = client.post("/upload", files=files, follow_redirects=False)
    assert r.status_code == 303

    cycles = client.get("/api/cycles").json()
    assert len(cycles) == 1
    cid = cycles[0]["id"]

    html = client.get(f"/cycle/{cid}")
    assert html.status_code == 200
    assert "upnphost.dll" in html.text
    assert "Ghidra noise filtered" in html.text
    assert "show names" in html.text          # collapsible real names

    api = client.get(f"/api/cycle/{cid}").json()
    assert api["artifacts"][0]["logical_name"] == "upnphost.dll"
    assert api["artifacts"][0]["priority"] == "P1"


def test_upload_rejects_non_bundle(client):
    """RNF-06: a file that is not a bundle is skipped without bringing the panel down."""
    files = [("files", ("x.json", b'{"hello": 1}', "application/json")),
             ("files", ("y.json", b"no-json", "application/json"))]
    r = client.post("/upload", files=files, follow_redirects=False)
    assert r.status_code == 303
    assert "Skipped" in r.headers["location"]
    assert client.get("/api/cycles").json() == []


def test_cycle_not_found(client):
    assert client.get("/cycle/doesnotexist").status_code == 404
    assert client.get("/api/cycle/doesnotexist").status_code == 404


def test_health(client, store, real_bundle):
    store.add_bundle(real_bundle)
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "cycles": 1}


# --- Integration: auditor report and MSRC CVEs in the panel (FID-06, CLA-06) --- #

def test_panel_shows_analyst_report_and_cves(client, store, tmp_path, monkeypatch, real_bundle):
    import json

    from thanos.auditor import build_heuristic_report

    report = tmp_path / "report.json"
    report.write_text(json.dumps(build_heuristic_report([real_bundle])), encoding="utf-8")
    monkeypatch.setenv("THANOS_PANEL_REPORT", str(report))
    store.add_bundle(real_bundle)
    cid = client.get("/api/cycles").json()[0]["id"]

    api = client.get(f"/api/cycle/{cid}").json()
    top = api["artifacts"][0]
    assert top["logical_name"] == "upnphost.dll"
    assert top["analysis"]["priority"] == "P1"
    assert len(top["cve_candidates"]) == 8
    assert api["analysis_source"] == "heuristic"
    assert api["kpis"]["cves_cycle"] == 114          # WS2022 CVEs fixed by KB5082142

    page = client.get(f"/cycle/{cid}").text
    assert "Thanos Auditor report" in page and "CVE-2026-32156" in page
    assert "Hypothesis based on the component name" in page


def test_panel_without_report_says_so(client, store, monkeypatch, tmp_path, real_bundle):
    monkeypatch.setenv("THANOS_PANEL_REPORT", str(tmp_path / "does-not-exist.json"))
    store.add_bundle(real_bundle)
    cid = client.get("/api/cycles").json()[0]["id"]
    assert "No Thanos Auditor report" in client.get(f"/cycle/{cid}").text


def test_invalid_report_is_ignored(client, store, monkeypatch, tmp_path, real_bundle):
    bad = tmp_path / "bad.json"
    bad.write_text('{"review_targets": 5}', encoding="utf-8")
    monkeypatch.setenv("THANOS_PANEL_REPORT", str(bad))
    store.add_bundle(real_bundle)
    assert client.get("/health").status_code == 200
    cid = client.get("/api/cycles").json()[0]["id"]
    assert client.get(f"/cycle/{cid}").status_code == 200


def test_priority_filter(client, store, real_bundle):
    store.add_bundle(real_bundle)
    cid = client.get("/api/cycles").json()[0]["id"]
    page = client.get(f"/cycle/{cid}", params={"prio": "P1"}).text
    assert "upnphost.dll" in page and "clipboardserver.dll" not in page   # clipboardserver is P2
