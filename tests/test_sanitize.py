"""Tests for bundle sanitization before publishing (RNF-05)."""

from __future__ import annotations

import json

from thanos.core.sanitize import PLACEHOLDER, main, sanitize_bundle


def test_sanitize_replaces_user_paths():
    bundle = {"artifacts": [{
        "before_artifact": "C:\\Users\\User\\Desktop\\thanos-executor1\\pipeline\\facts\\a.json",
        "after_artifact": "D:\\Users\\bob\\Documents\\x.json",
        "logical_name": "a.dll",
    }]}
    clean, n = sanitize_bundle(bundle)
    assert n == 2
    art = clean["artifacts"][0]
    assert art["before_artifact"] == PLACEHOLDER + "thanos-executor1\\pipeline\\facts\\a.json"
    assert "Users" not in art["after_artifact"]
    assert art["logical_name"] == "a.dll"          # the rest is untouched


def test_real_fixtures_have_no_local_paths(real_paths):
    """No published real fixture contains user profile paths."""
    assert len(real_paths) >= 2
    for path in real_paths:
        text = path.read_text(encoding="utf-8")
        assert "\\Users\\" not in text and "\\\\Users\\\\" not in text, path.name


def test_sanitize_cli(tmp_path):
    src, dst = tmp_path / "in.json", tmp_path / "out.json"
    src.write_text(json.dumps({"p": "C:\\Users\\X\\Desktop\\f.json"}), encoding="utf-8")
    assert main([str(src), str(dst)]) == 0
    assert json.loads(dst.read_text(encoding="utf-8")) == {"p": PLACEHOLDER + "f.json"}
