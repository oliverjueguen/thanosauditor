"""Coordinator tests (RF-02, RF-06, RF-07)."""

from __future__ import annotations

from thanos.coordinator import diff_manifests, split_round_robin
from thanos.coordinator.catalog import (
    download_dialog_payload,
    is_server_2022_cumulative,
    parse_msu_url,
    search_url,
)
from thanos.coordinator.split_workload import balance_report

# --- RF-07: Round-Robin split ---------------------------------------------- #

def test_round_robin_is_balanced():
    changed = [{"key": f"pkg{i}"} for i in range(10)]
    people = ["executor1", "executor2", "executor3", "executor4"]
    assignments = split_round_robin(changed, people)
    counts = sorted(balance_report(assignments).values())
    assert counts == [2, 2, 3, 3]          # 10 across 4, balanced
    assert sum(counts) == 10               # nothing is lost


def test_round_robin_is_deterministic():
    changed = [{"key": "b"}, {"key": "a"}, {"key": "c"}]
    a1 = split_round_robin(changed, ["x", "y"])
    a2 = split_round_robin(list(reversed(changed)), ["y", "x"])
    assert a1 == a2                        # independent of input order


def test_round_robin_needs_people():
    import pytest
    with pytest.raises(ValueError):
        split_round_robin([{"key": "a"}], [])


# --- RF-06: manifest diff by normalized key ------------------------------- #

def test_diff_manifests_matches_by_normalized_key():
    before = [{"logical_name": "x.dll",
               "package_id": "amd64_x_31bf_10.0.20348.4647_none_abc", "sha256": "AAA"}]
    after = [{"logical_name": "x.dll",
              "package_id": "amd64_x_31bf_10.0.20348.5020_none_abc", "sha256": "BBB"}]
    result = diff_manifests(before, after)
    assert len(result["changed"]) == 1     # same key (no version), different SHA
    assert result["changed"][0]["logical_name"] == "x.dll"


def test_diff_manifests_skips_unchanged():
    before = [{"package_id": "p_10.0.1.1_none_a", "sha256": "SAME"}]
    after = [{"package_id": "p_10.0.2.2_none_a", "sha256": "SAME"}]
    result = diff_manifests(before, after)
    assert result["changed"] == []
    assert result["unchanged"] == 1


# --- RF-02/RF-03: catalog ------------------------------------------------- #

def test_search_url():
    assert "KB5082142" in search_url("KB5082142")


def test_parse_msu_url():
    body = 'downloadInformation[0].files[0].url = "https://catalog.s.download.windowsupdate.com/d/msdownload/x.msu";'
    assert parse_msu_url(body).endswith(".msu")


def test_is_server_2022_cumulative():
    """The REAL title of the WS2022 cumulative update in the catalog is the "21H2" one."""
    real = ("2026-04 Cumulative Update for Microsoft server operating system version 21H2 "
            "for x64-based Systems (KB5082142)")
    assert is_server_2022_cumulative(real)
    assert not is_server_2022_cumulative(real.replace("21H2", "23H2"))
    assert not is_server_2022_cumulative(
        "2026-04 Cumulative Update for .NET Framework 3.5 and 4.8.1 for Microsoft server "
        "operating system version 21H2 for x64 (KB5082000)")
    assert not is_server_2022_cumulative("Update for Windows 10")


def test_download_dialog_payload():
    payload = download_dialog_payload(["guid-1", "guid-2"])
    assert len(payload["updateIDs"]) == 2
    assert payload["updateIDs"][0]["updateID"] == "guid-1"


# --- RF-05: reconstruction (reproducible part: CRC32 prefix) -------------- #

def test_strip_crc32_prefix():
    import pytest

    from thanos.coordinator.reconstruct import ReconstructionError, strip_crc32_prefix

    # With a 4-byte CRC32 prefix before PA30.
    delta = b"\x01\x02\x03\x04PA30restofdelta"
    assert strip_crc32_prefix(delta) == b"PA30restofdelta"
    # Already without prefix.
    assert strip_crc32_prefix(b"PA30xyz") == b"PA30xyz"
    # No PA30 after stripping the prefix → clear error.
    with pytest.raises(ReconstructionError):
        strip_crc32_prefix(b"\x00\x00\x00\x00NOPA")


# --- Catalog with the saved REAL HTML (RF-02, RF-03) ------------------------ #

from pathlib import Path  # noqa: E402

import pytest  # noqa: E402

from thanos.coordinator.catalog import (  # noqa: E402
    CatalogError,
    download_dialog_body,
    download_msu,
    parse_rows,
    select_cumulative,
)

CATALOG = Path(__file__).resolve().parents[1] / "fixtures" / "catalog"
REAL_GUID = "fd522b7b-4adf-4335-a6fe-2ae3327e54cb"   # complete; the P1 report truncated it


def _html(name):
    return (CATALOG / name).read_text(encoding="utf-8", errors="replace")


def test_real_search_resolves_documented_guid():
    """RF-02: KB5082142 → the GUID verified in P1 (complete)."""
    row = select_cumulative(parse_rows(_html("catalog-search-KB5082142.html")), "KB5082142")
    assert row["guid"] == REAL_GUID
    assert "21H2 for x64" in row["title"] and row["classification"] == "Security Updates"


def test_broad_search_filters_the_right_row():
    """RF-03: among 12 rows (.NET, 23H2, 24H2, Updates…) the WS2022 cumulative update is picked."""
    rows = parse_rows(_html("catalog-search-broad.html"))
    assert len(rows) == 12
    assert select_cumulative(rows, "KB5082142")["guid"] == REAL_GUID
    # Without a KB there are two 21H2 cumulative updates; the security update wins.
    assert select_cumulative(rows)["guid"] == REAL_GUID


def test_select_cumulative_errors():
    with pytest.raises(CatalogError, match="no Windows Server 2022 x64 cumulative update"):
        select_cumulative(parse_rows(_html("catalog-search-KB5082142.html")), "KB0000000")
    with pytest.raises(CatalogError):
        select_cumulative([])


def test_real_download_dialog_msu_url():
    url = parse_msu_url(_html("downloaddialog-KB5082142.html"))
    assert url.startswith("https://catalog.s.download.windowsupdate.com/")
    assert url.endswith(".msu") and "kb5082142-x64" in url


def test_download_dialog_body_is_form_encoded():
    body = download_dialog_body([REAL_GUID]).decode()
    assert body.startswith("updateIDs=") and "%22updateID%22" in body


def test_download_msu_rejects_foreign_domains(tmp_path):
    for url in ("http://catalog.s.download.windowsupdate.com/x.msu",      # no https
                "https://evil.example/windows10.0-kb5082142-x64.msu",
                "https://windowsupdate.com.evil.example/x.msu"):
        with pytest.raises(CatalogError, match="not allowed"):
            download_msu(url, tmp_path)


def test_download_msu_streams_and_hashes(tmp_path):
    import hashlib
    import io

    payload = b"MSU" * 1000

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

    url = "https://catalog.s.download.windowsupdate.com/d/x/windows10.0-kb5082142-x64_abc.msu"
    result = download_msu(url, tmp_path, opener=lambda u, timeout: _Resp(payload))
    assert result["bytes"] == len(payload)
    assert result["sha256"] == hashlib.sha256(payload).hexdigest()
    assert Path(result["path"]).read_bytes() == payload


# --- RF-06 with the REAL binaries (it used to return 2 of 7) -------------- #

def test_diff_real_split_bundle_keeps_all_seven(split_bundle):
    from thanos.coordinator.diff_index import manifests_from_bundle

    before, after = manifests_from_bundle(split_bundle)
    result = diff_manifests(before, after)
    assert len(result["changed"]) == 7          # 6 share an SXS package: not collapsed
    assert result["only_before"] == result["only_after"] == []


def test_diff_distinguishes_arch_and_trailing_hash():
    before = [
        {"logical_name": "p.dll", "package_id": "amd64_x_31bf_10.0.1.1_none_aaaaaaaaaaaaaaaa", "sha256": "1"},
        {"logical_name": "p.dll", "package_id": "wow64_x_31bf_10.0.1.1_none_bbbbbbbbbbbbbbbb", "sha256": "2"},
    ]
    after = [
        {"logical_name": "p.dll", "package_id": "amd64_x_31bf_10.0.2.2_none_cccccccccccccccc", "sha256": "1b"},
        {"logical_name": "p.dll", "package_id": "wow64_x_31bf_10.0.2.2_none_dddddddddddddddd", "sha256": "2"},
    ]
    result = diff_manifests(before, after)
    assert [c["package_after"][:5] for c in result["changed"]] == ["amd64"]   # trailing hash ignored
    assert result["unchanged"] == 1


def test_diff_rejects_duplicate_keys():
    from thanos.coordinator.diff_index import ManifestError

    dup = [{"logical_name": "a.dll", "package_id": "p_10.0.1.1_none", "sha256": "1"}] * 2
    with pytest.raises(ManifestError, match="duplicate"):
        diff_manifests(dup, [])


# --- RF-07 exact ------------------------------------------------------------ #

def test_round_robin_exact_assignment():
    """RF-07/RNF-02: alphabetical order of keys and people, i % n, no losses or overlaps."""
    items = [{"key": k} for k in ("d", "a", "c", "b", "e")]
    result = split_round_robin(items, ["zoe", "ana"])
    assert [i["key"] for i in result["ana"]] == ["a", "c", "e"]
    assert [i["key"] for i in result["zoe"]] == ["b", "d"]
    flat = [i["key"] for v in result.values() for i in v]
    assert sorted(flat) == ["a", "b", "c", "d", "e"]


# --- Coordinator CLI end to end (RF-06…RF-08) ------------------------------ #

def test_coordinator_cli_end_to_end(tmp_path, real_path, capsys):
    import json
    import zipfile

    import yaml

    from thanos.coordinator.__main__ import main

    man, changed, asg, zips = tmp_path / "man", tmp_path / "changed.json", tmp_path / "asg", tmp_path / "zips"
    assert main(["manifest", str(real_path), "--out-dir", str(man)]) == 0
    assert main(["diff", str(man / "before.json"), str(man / "after.json"), "-o", str(changed)]) == 0
    assert len(json.loads(changed.read_text())["changed"]) == 85
    assert main(["split", str(changed), "--people", "e1", "e2", "e3", "e4", "--out-dir", str(asg)]) == 0
    sizes = sorted(len(json.loads(f.read_text())) for f in asg.glob("*.json"))
    assert sizes == [21, 21, 21, 22]
    assert main(["package", "--assignments", str(asg), "--from-bundle", str(real_path), "--out-dir", str(zips)]) == 0
    with zipfile.ZipFile(zips / "thanos-e1.zip") as z:
        names = z.namelist()
        cfg = yaml.safe_load(z.read("config.yaml"))
    assert {"run_diff.py", "bootstrap.ps1", "config.yaml", "assignment.json"} <= set(names)
    assert any(n.startswith("thanos/executor/") for n in names)
    assert cfg["executor_id"] == "e1" and cfg["target_build"] == "20348.5020"   # text, not float


def test_coordinator_cli_errors(tmp_path, capsys):
    from thanos.coordinator.__main__ import main

    assert main(["diff", str(tmp_path / "no.json"), str(tmp_path / "no2.json")]) == 2
    assert main(["package", "--assignments", str(tmp_path)]) == 2
    err = capsys.readouterr().err
    assert "file not found" in err and "Traceback" not in err
