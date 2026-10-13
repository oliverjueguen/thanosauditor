"""Thanos Coordinator tier.

Entry point: ``python -m thanos.coordinator <resolve|manifest|diff|split|package>``.

Modules:
  - :mod:`.catalog`         : KB → GUID → MSU URL in the catalog, plus optional download (RF-02, RF-03)
  - :mod:`.reconstruct`     : DLL reconstruction from PA30 deltas with msdelta.dll (RF-05, Windows only)
  - :mod:`.diff_index`      : manifest diff by (normalized package, DLL) (RF-06)
  - :mod:`.split_workload`  : Round-Robin split among team members (RF-07)
  - :mod:`.package`         : per-person ZIP with the executor and its assignment (RF-08)

Extracting the baseline from the ISO/WIM (RF-04) requires Windows Server 2022 and is
documented in docs/02_coordinator_executor.md.

Imports are lazy so that importing ``thanos.coordinator.reconstruct`` on the
Windows machine does not require the ontology dependencies.
"""

from __future__ import annotations

__all__ = ["diff_manifests", "load_manifest", "split_round_robin"]


def __getattr__(name: str):
    if name in ("diff_manifests", "load_manifest"):
        from . import diff_index
        return getattr(diff_index, name)
    if name == "split_round_robin":
        from .split_workload import split_round_robin
        return split_round_robin
    raise AttributeError(name)
