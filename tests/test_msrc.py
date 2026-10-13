"""RF-01 tests with real data: MSRC CVEs (CVRF 2026-Apr) in the ontology.

They use the offline extract fixtures/msrc/2026-Apr.ws2022.json, generated with
thanos.ontology.msrc.extract_cves from the public MSRC CVRF document.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from thanos.ontology import ThanosOntology
from thanos.ontology.msrc import component, extract_cves, load_cves, match_cves

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "msrc" / "2026-Apr.ws2022.json"


@pytest.fixture(scope="module")
def cves():
    return load_cves(FIXTURE)


def test_fixture_provenance():
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert data["document"] == "2026-Apr"
    assert data["source"] == "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Apr"
    assert data["count"] == len(data["cves"]) == 115


def test_ws2022_cves_and_kb_chain(cves):
    """RF-01/RF-02: 114 of the 115 WS2022 CVEs are fixed by KB5082142, which supersedes KB5078766."""
    fixed_by_after = [c for c in cves if "KB5082142" in c["kbs"]]
    assert len(fixed_by_after) == 114
    assert all("KB5078766" in c["supersedes"] for c in fixed_by_after)
    assert {c["fixed_build"] for c in fixed_by_after} == {"10.0.20348.5020"}   # the canonical build
    assert sum(c["severity"] == "Critical" for c in cves) == 4
    assert [c["cve"] for c in cves if c["exploited"]] == ["CVE-2026-32202"]


def test_extract_filters_by_product():
    cvrf = {
        "ProductTree": {"FullProductName": [
            {"ProductID": "1", "Value": "Windows Server 2022"},
            {"ProductID": "2", "Value": "Windows 11"},
        ]},
        "Vulnerability": [
            {"CVE": "CVE-1", "Title": {"Value": "Windows X Elevation of Privilege Vulnerability"},
             "Threats": [{"Type": 0, "ProductID": ["1"], "Description": {"Value": "Elevation of Privilege"}},
                         {"Type": 3, "ProductID": ["1"], "Description": {"Value": "Important"}}],
             "Remediations": [{"Type": 2, "ProductID": ["1"], "Description": {"Value": "5082142"},
                               "Supercedence": "5078766", "FixedBuild": "10.0.20348.5020"}]},
            {"CVE": "CVE-2", "Title": {"Value": "Windows 11 only"},
             "Threats": [{"Type": 0, "ProductID": ["2"], "Description": {"Value": "Spoofing"}}]},
        ],
    }
    out = extract_cves(cvrf)
    assert [c["cve"] for c in out] == ["CVE-1"]
    assert out[0]["kbs"] == ["KB5082142"] and out[0]["supersedes"] == ["KB5078766"]


def test_component_name():
    assert component("Windows UPnP Device Host Remote Code Execution Vulnerability") == "Windows UPnP Device Host"


def test_upnphost_candidates_are_hypotheses(cves):
    """upnphost.dll (triage P1) <-> 8 "Windows UPnP Device Host" CVEs, never with high confidence."""
    cands = match_cves("upnphost.dll", "amd64_microsoft-windows-upnpdevicehost-server_31bf3856ad364e35_none", cves)
    assert len(cands) == 8
    assert all(c["title"].startswith("Windows UPnP Device Host") for c in cands)
    assert {c["confidence"] for c in cands} == {"medium"}
    assert all("Hypothesis" in c["reason"] for c in cands)


def test_generic_words_do_not_match(cves):
    """'desktop' or 'access' are not enough to link a CVE (avoids false positives)."""
    assert match_cves("windows.cortana.desktop.dll", "", cves) == []
    assert match_cves("userdataaccountapis.dll", "microsoft-windows-u..access-userdataapis", cves) == []


def test_never_high_confidence(cves, real_bundle):
    from thanos.core import artifact_diffs

    for d in artifact_diffs(real_bundle):
        assert all(c["confidence"] in ("medium", "low") for c in match_cves(d.logical_name, d.package_key, cves))


def test_ingest_cvrf_into_ontology(cves, real_path):
    onto = ThanosOntology()
    onto.ingest_bundle_file(real_path)
    result = onto.ingest_cvrf(cves)
    assert result["cves"] == 115 and result["candidates"] >= 8
    stats = onto.stats()
    assert stats["CVE"] == 115 and stats["Vulnerability"] == result["candidates"]
    up = onto.cves_for_binary("upnphost.dll")
    assert len(up) == 8 and up[0]["cvss"] >= up[-1]["cvss"]
    # addressedBy only to the fixing KB (MSR-04): no CVE points to BEFORE.
    rows = onto.query("SELECT ?c WHERE { ?c thanos:addressedBy ?kb . ?kb thanos:kbId 'KB5078766' }")
    assert rows == []
    assert onto.cve_stats()["by_severity"]["Critical"] == 4


def test_ingest_cvrf_is_idempotent(cves, real_path):
    onto = ThanosOntology()
    onto.ingest_bundle_file(real_path)
    onto.ingest_cvrf(cves)
    first = onto.stats()
    onto.ingest_cvrf(cves)
    assert onto.stats() == first


def test_report_takes_cve_candidates_from_the_ontology(tmp_path, monkeypatch, real_path, real_bundle, cves):
    """COR-08: Thanos Auditor queries the catalog (ontology); the MSRC extract is only a fallback."""
    from thanos.auditor import build_heuristic_report

    onto = ThanosOntology()
    onto.ingest_bundle_file(real_path)
    onto.ingest_cvrf(cves)
    catalog = tmp_path / "catalog.ttl"
    onto.save(catalog)
    monkeypatch.setenv("THANOS_ONTOLOGY_CATALOG", str(catalog))
    monkeypatch.setenv("THANOS_MSRC_CVES", str(tmp_path / "missing.json"))   # no fallback
    report = build_heuristic_report([real_bundle])
    assert report["cve_source"].startswith("ontology")
    top = report["review_targets"][0]
    assert top["logical_name"] == "upnphost.dll" and len(top["cve_candidates"]) == 8
    assert isinstance(top["cve_candidates"][0]["cvss"], float)


def test_report_falls_back_to_msrc_extract_without_catalog(tmp_path, monkeypatch, real_bundle):
    from thanos.auditor import build_heuristic_report

    monkeypatch.setenv("THANOS_ONTOLOGY_CATALOG", str(tmp_path / "missing.ttl"))
    report = build_heuristic_report([real_bundle])
    assert report["cve_source"].startswith("MSRC extract")
    assert len(report["review_targets"][0]["cve_candidates"]) == 8
