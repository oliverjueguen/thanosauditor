"""Tests for the panel security controls (RNF-05, RNF-06).

Each test demonstrates a control declared in docs/03_security.md: input validation,
resilience to malformed bundles, size limits, HTML escaping, upload token, CSRF
protection via Origin, Host filtering and headers.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from thanos.panel.store import PanelStore  # noqa: E402

GOOD = {
    "patch_cycle": "2026-04 Patch Tuesday", "target_build": "20348.5020",
    "kb_ids": ["KB5078766", "KB5082142"], "person": "p",
    "artifacts": [{"logical_name": "a.dll", "sha256_before": "aa", "sha256_after": "bb"}],
}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    import thanos.panel.app as appmod

    monkeypatch.setattr(appmod, "store", PanelStore(tmp_path / "bundles"))
    monkeypatch.delenv("THANOS_PANEL_TOKEN", raising=False)
    return TestClient(appmod.app)


def _upload(client, *payloads, **kwargs):
    files = [("files", (f"f{i}.json", p, "application/json")) for i, p in enumerate(payloads)]
    return client.post("/upload", files=files, follow_redirects=False, **kwargs)


def _still_healthy(client):
    assert client.get("/").status_code == 200
    assert client.get("/health").status_code == 200
    assert client.get("/api/cycles").status_code == 200


MALFORMED = [
    b"5", b"null", b'"text"', b"[]", b"no-json",
    "\xff\xfe\x00no-utf8".encode("latin-1"),
    json.dumps({**GOOD, "artifacts": "abc"}).encode(),
    json.dumps({**GOOD, "artifacts": [1]}).encode(),
    json.dumps({**GOOD, "patch_cycle": None}).encode(),
    json.dumps({**GOOD, "patch_cycle": 12345}).encode(),
    json.dumps({**GOOD, "patch_cycle": "x" * 500}).encode(),
    json.dumps({**GOOD, "kb_ids": "KB1"}).encode(),
    json.dumps({**GOOD, "artifacts": [{**GOOD["artifacts"][0], "summary_before": "x"}]}).encode(),
    json.dumps({**GOOD, "changes": [{"diff": {"functions_added": [1]}}]}).encode(),
    b"[" * 100_000,
]


@pytest.mark.parametrize("payload", MALFORMED, ids=range(len(MALFORMED)))
def test_malformed_bundle_is_rejected_and_panel_survives(client, payload):
    """RNF-06: a malformed bundle is skipped with a reason and the panel stays up."""
    r = _upload(client, payload)
    assert r.status_code == 303
    assert "Skipped" in r.headers["location"]
    assert client.get("/api/cycles").json() == []
    _still_healthy(client)


def test_corrupt_file_on_disk_does_not_break_panel(client, tmp_path):
    """A corrupt file in the store is skipped (and logged) without bringing the panel down."""
    import thanos.panel.app as appmod

    _upload(client, json.dumps(GOOD).encode())
    (appmod.store.directory / "broken.json").write_text("{not json", encoding="utf-8")
    (appmod.store.directory / "invalid.json").write_text(json.dumps({"artifacts": 5}), encoding="utf-8")
    _still_healthy(client)
    assert len(client.get("/api/cycles").json()) == 1


def test_size_limit(client, monkeypatch):
    """SEC-05: a file above THANOS_PANEL_MAX_UPLOAD_MB is rejected."""
    monkeypatch.setenv("THANOS_PANEL_MAX_UPLOAD_MB", "0.001")   # ~1 KB
    big = json.dumps({**GOOD, "analysis_goal": "x" * 5000}).encode()
    r = _upload(client, big)
    assert "exceeds" in r.headers["location"]
    assert client.get("/api/cycles").json() == []


def test_xss_is_escaped(client):
    """Uploaded text is escaped when rendering (no active HTML)."""
    evil = "<script>alert(1)</script>"
    bundle = {**GOOD, "patch_cycle": evil, "person": evil,
              "artifacts": [{**GOOD["artifacts"][0], "logical_name": evil + ".dll"}]}
    _upload(client, json.dumps(bundle).encode())
    home = client.get("/").text
    assert evil not in home and "&lt;script&gt;" in home
    cid = client.get("/api/cycles").json()[0]["id"]
    page = client.get(f"/cycle/{cid}").text
    assert evil not in page and "&lt;script&gt;" in page
    msg = client.get("/", params={"message": evil}).text
    assert evil not in msg


def test_path_traversal_is_contained(client, tmp_path):
    """The saved file name comes from a slug: '../' does not escape the store."""
    import thanos.panel.app as appmod

    _upload(client, json.dumps({**GOOD, "person": "../../../etc/passwd"}).encode())
    files = list(appmod.store.directory.iterdir())
    assert len(files) == 1
    assert files[0].resolve().parent == appmod.store.directory.resolve()


def test_upload_token_required_when_configured(client, monkeypatch):
    """SEC-04: with THANOS_PANEL_TOKEN set, uploading without a token returns 401."""
    monkeypatch.setenv("THANOS_PANEL_TOKEN", "test-secret")
    assert _upload(client, json.dumps(GOOD).encode()).status_code == 401
    bad = client.post("/upload", files=[("files", ("a.json", json.dumps(GOOD).encode(), "application/json"))],
                      data={"token": "other"}, follow_redirects=False)
    assert bad.status_code == 401
    ok = client.post("/upload", files=[("files", ("a.json", json.dumps(GOOD).encode(), "application/json"))],
                     data={"token": "test-secret"}, follow_redirects=False)
    assert ok.status_code == 303
    assert len(client.get("/api/cycles").json()) == 1


def test_cross_origin_post_is_rejected(client):
    """SEC-04: an external website cannot upload bundles (CSRF): foreign Origin → 403."""
    r = _upload(client, json.dumps(GOOD).encode(), headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    assert client.get("/api/cycles").json() == []
    same = _upload(client, json.dumps(GOOD).encode(), headers={"Origin": "http://127.0.0.1:8000"})
    assert same.status_code == 303


def test_foreign_host_header_is_rejected(client):
    """Defense against DNS rebinding: non-local Host → 400."""
    assert client.get("/", headers={"Host": "evil.example"}).status_code == 400


def test_security_headers_present(client):
    r = client.get("/")
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"


def test_errors_have_no_traceback(client):
    """404 and 405 return a custom page, without internal tracebacks."""
    r = client.get("/does-not-exist")
    assert r.status_code == 404 and "Traceback" not in r.text and "Page not found" in r.text
    assert client.get("/upload").status_code == 405
    assert client.get("/api/does-not-exist").headers["content-type"].startswith("application/json")


def test_replacement_keeps_backup(client):
    """RF-18: re-uploading the same person's bundle replaces it and keeps a .bak copy."""
    import thanos.panel.app as appmod

    _upload(client, json.dumps(GOOD).encode())
    r = _upload(client, json.dumps(GOOD).encode())
    assert "replaced" in r.headers["location"]
    assert len(list(appmod.store.directory.glob("*.json.bak"))) == 1
    assert client.get("/api/cycles").json()[0]["kpis"]["bundles"] == 1
