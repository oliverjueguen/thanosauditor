"""Executor tests (RF-12, RF-15)."""

from __future__ import annotations

from thanos.core.bundles import validate_bundle
from thanos.executor import build_artifact, build_bundle, changed_pairs, pair_binaries

# --- RF-12: pairing and discarding by SHA -------------------------------- #

def test_pair_and_skip_identical(tmp_path):
    before = tmp_path / "before"
    after = tmp_path / "after"
    before.mkdir()
    after.mkdir()

    # a.dll changes; b.dll is identical.
    (before / "a.dll").write_bytes(b"old-content")
    (after / "a.dll").write_bytes(b"new-content-different")
    (before / "b.dll").write_bytes(b"same")
    (after / "b.dll").write_bytes(b"same")

    pairs = pair_binaries(before, after)
    assert len(pairs) == 2
    changed = changed_pairs(pairs)
    assert [p.name for p in changed] == ["a.dll"]   # b.dll discarded (same SHA)


def test_pair_only_common_files(tmp_path):
    before = tmp_path / "before"
    after = tmp_path / "after"
    before.mkdir()
    after.mkdir()
    (before / "only_before.dll").write_bytes(b"x")
    (after / "only_after.dll").write_bytes(b"y")
    assert pair_binaries(before, after) == []       # no common pairs


# --- RF-15: bundle construction ------------------------------------------ #

def test_build_bundle_is_valid():
    artifact = build_artifact(
        "x.dll", "amd64_x_31bf_10.0.20348.5020_none_abc",
        before_facts={"function_count": 100, "export_count": 5},
        after_facts={"function_count": 110, "export_count": 6},
        sha256_before="aaa", sha256_after="bbb",
        version_before="10.0.20348.4647", version_after="10.0.20348.5020",
        size_before=1000, size_after=1024,
    )
    bundle = build_bundle(
        run_id="2026-04-executor1", patch_cycle="2026-04 Patch Tuesday FULL",
        target_build="20348.5020", kb_ids=["KB1", "KB2"],
        artifacts=[artifact], person="executor1",
    )
    # The generated bundle must pass core validation (RF-15).
    assert validate_bundle(bundle) == []
    assert bundle["artifacts"][0]["summary_after"]["function_count"] == 110


def test_build_artifact_fills_summary_keys():
    art = build_artifact(
        "y.dll", "pkg", before_facts={}, after_facts={},
        sha256_before="a", sha256_after="b",
    )
    for key in ("library_count", "total_imports", "export_count", "function_count", "string_count"):
        assert key in art["summary_before"]
        assert art["summary_before"][key] == 0


# --- RF-14: full name-based diff (P1 schema) ------------------------------- #

def test_compute_changes_p1_schema():
    from thanos.executor import compute_changes

    before = {"functions": ["main", "parse", "Unwind@1000"], "exports": ["Start"]}
    after = {"functions": ["main", "parse_v2", "Unwind@2000"], "exports": ["Start", "Stop"]}
    ch = compute_changes("x.dll", before, after, change_id="chg_001", evidence_id="ev_bin_001")
    assert ch["binary"] == "x.dll" and ch["evidence_ids"] == ["ev_bin_001"]
    assert ch["diff"]["functions_added"] == ["Unwind@2000", "parse_v2"]
    assert ch["diff"]["functions_removed"] == ["Unwind@1000", "parse"]
    assert ch["diff"]["exports_added"] == ["Stop"]
    assert ch["diff"]["before_function_count"] == 3     # full list, not truncated


def test_pairing_is_case_insensitive(tmp_path):
    """WIN-07: on Windows 'Foo.DLL' and 'foo.dll' are the same file."""
    (tmp_path / "before").mkdir()
    (tmp_path / "after").mkdir()
    (tmp_path / "before" / "Foo.DLL").write_bytes(b"a")
    (tmp_path / "after" / "foo.dll").write_bytes(b"b")
    (tmp_path / "after" / ".keep").write_bytes(b"")
    pairs = pair_binaries(tmp_path / "before", tmp_path / "after")
    assert [p.name for p in pairs] == ["foo.dll"] and pairs[0].changed


# --- Executor runner (executor/run_diff.py) with simulated facts ---------- #

import importlib.util  # noqa: E402
import json  # noqa: E402
from pathlib import Path  # noqa: E402

import pytest  # noqa: E402

RUN_DIFF = Path(__file__).resolve().parents[1] / "executor" / "run_diff.py"


def _run_diff_module():
    spec = importlib.util.spec_from_file_location("run_diff", RUN_DIFF)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _workdir(tmp_path, files):
    for side, name, content in files:
        d = tmp_path / "input" / side
        d.mkdir(parents=True, exist_ok=True)
        (d / name).write_bytes(content)
    (tmp_path / "config.yaml").write_text(
        'executor_id: executor1\npatch_cycle: "2026-04 Patch Tuesday"\ntarget_build: "20348.5020"\n'
        "kb_ids: [KB5078766, KB5082142]\nghidra_support_dir: 'C:\\\\ghidra\\\\support'\n", encoding="utf-8")
    return tmp_path


def _fake_facts(support, binary, java_home=None):
    data = Path(binary).read_bytes()
    names = ["main", "old_fn"] if b"old" in data else ["main", "new_fn", "DelayLoad_WinHttpOpen"]
    return {"function_count": len(names), "functions": names, "exports": ["Start"],
            "export_count": 1, "library_count": 2, "total_imports": 10, "string_count": 5}


def test_run_diff_produces_valid_p1_bundle(tmp_path):
    """RF-12…RF-15: pairs → Ghidra (simulated) → bundle with changes, valid for the core."""
    from thanos.core import aggregate, validate_bundle

    rd = _run_diff_module()
    base = _workdir(tmp_path, [("before", "a.dll", b"old"), ("after", "a.dll", b"new"),
                               ("before", "same.dll", b"x"), ("after", "same.dll", b"x")])
    out = rd.run(rd.load_config(base / "config.yaml"), base, facts=_fake_facts)
    bundle = json.loads(out.read_text(encoding="utf-8"))
    assert out.name == "2026-04-patch-tuesday-executor1.bundle.json"
    assert validate_bundle(bundle) == []
    assert [a["logical_name"] for a in bundle["artifacts"]] == ["a.dll"]        # same.dll discarded
    assert bundle["changes"][0]["diff"]["functions_added"] == ["DelayLoad_WinHttpOpen", "new_fn"]
    assert bundle["target_build"] == "20348.5020"
    row = aggregate([bundle])[0]["artifacts"][0]
    assert row["delay_loads_added"] == ["DelayLoad_WinHttpOpen"] and not row["name_diff_truncated"]


def test_run_diff_errors(tmp_path):
    rd = _run_diff_module()
    with pytest.raises(rd.RunError, match="does not exist"):
        rd.load_config(tmp_path / "config.yaml")
    base = _workdir(tmp_path, [("before", "a.dll", b"x")])
    with pytest.raises(rd.RunError, match="Found 0 pairs"):
        rd.run(rd.load_config(base / "config.yaml"), base, facts=_fake_facts)
    (base / "config.yaml").write_text("executor_id: e\npatch_cycle: c\ntarget_build: 20348.5020\n"
                                      "kb_ids: [KB1]\nghidra_support_dir: x\n", encoding="utf-8")
    with pytest.raises(rd.RunError, match="must be quoted"):
        rd.load_config(base / "config.yaml")


def test_run_diff_missing_ghidra_fails_early(tmp_path, capsys):
    rd = _run_diff_module()
    base = _workdir(tmp_path, [("before", "a.dll", b"old"), ("after", "a.dll", b"new")])
    assert rd.main(["--config", str(base / "config.yaml")]) == 2
    assert "analyzeHeadless not found" in capsys.readouterr().err


def test_config_example_quotes_target_build():
    """TST-15: the template quotes target_build (the P1 YAML bug)."""
    import yaml

    cfg = yaml.safe_load((RUN_DIFF.parent / "config.example.yaml").read_text(encoding="utf-8"))
    assert isinstance(cfg["target_build"], str) and cfg["target_build"] == "20348.5020"
