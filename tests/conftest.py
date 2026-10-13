"""Shared test fixtures.

- ``real_*``: REAL Practice 1 (P1) bundle, full run (2026-04 cycle, 85 binaries), sanitized.
- ``split_*``: REAL P1 bundle, split run (same month, 7 binaries), sanitized.
- ``synth_*``: SYNTHETIC bundle, only for testing aggregation of several people in one cycle.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REAL_DIR = ROOT / "fixtures" / "bundles"
REAL_PATH = REAL_DIR / "2026-04-patch-tuesday-full.bundle.json"
SPLIT_PATH = REAL_DIR / "2026-04-patch-tuesday-reparto.bundle.json"
SYNTH_PATH = ROOT / "fixtures" / "synthetic" / "2026-04-patch-tuesday.SYNTHETIC.bundle.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path, monkeypatch):
    """Tests do not touch the real data/panel nor depend on a local .env or token."""
    monkeypatch.setenv("THANOS_PANEL_DATA", str(tmp_path / "panel-data"))
    monkeypatch.setenv("THANOS_PANEL_SEED", "0")
    for name in ("THANOS_PANEL_TOKEN", "THANOS_PANEL_MAX_UPLOAD_MB", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture()
def real_path() -> Path:
    return REAL_PATH


@pytest.fixture()
def synth_path() -> Path:
    return SYNTH_PATH


@pytest.fixture()
def real_bundle() -> dict:
    return _load(REAL_PATH)


@pytest.fixture()
def synth_bundle() -> dict:
    return _load(SYNTH_PATH)


@pytest.fixture()
def split_path() -> Path:
    return SPLIT_PATH


@pytest.fixture()
def split_bundle() -> dict:
    """REAL bundle from the split run ("2026-04 Patch Tuesday", 7 binaries)."""
    return _load(SPLIT_PATH)


@pytest.fixture()
def real_paths() -> list[Path]:
    return sorted(REAL_DIR.glob("*.bundle.json"))
