"""Thanos Executor tier (runs on each team member's machine).

  - :mod:`.pair`     : before/after pairing and discarding of identical SHAs (RF-12)
  - :mod:`.ghidra`   : Ghidra headless + ExportFacts.java → binary facts (RF-13)
  - :mod:`.changes`  : diff by function/export names, P1 schema (RF-14)
  - :mod:`.bundle`   : bundle.json construction (RF-15)

The runner shipped in the ZIP is ``executor/run_diff.py``.
"""

from .bundle import build_artifact, build_bundle
from .changes import compute_changes
from .pair import changed_pairs, pair_binaries, sha256_file

__all__ = ["build_artifact", "build_bundle", "changed_pairs", "compute_changes", "pair_binaries", "sha256_file"]
