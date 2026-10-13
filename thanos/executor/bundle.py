"""Construction of bundle.json, the runner's only deliverable (RF-15).

From the *facts* that Ghidra headless (RF-13) produces for each side of the pair
(functions, strings, imports, exports), it builds the per-binary artifact and the
complete bundle with its metadata.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

BUNDLE_VERSION = "1.0"

# Keys expected in the facts that Ghidra produces per binary.
_SUMMARY_KEYS = ("library_count", "total_imports", "export_count", "function_count", "string_count")


def _summary(facts: dict[str, Any]) -> dict[str, int]:
    return {k: int(facts.get(k, 0) or 0) for k in _SUMMARY_KEYS}


def build_artifact(
    logical_name: str,
    package_id: str,
    before_facts: dict[str, Any],
    after_facts: dict[str, Any],
    *,
    sha256_before: str,
    sha256_after: str,
    version_before: str = "",
    version_after: str = "",
    size_before: int = 0,
    size_after: int = 0,
    evidence_id: str | None = None,
    notes: str = "Reconstructed via msdelta apply on baseline; analyzed by Ghidra headless.",
) -> dict[str, Any]:
    """Build a bundle artifact (binary entry)."""
    return {
        "evidence_id": evidence_id or f"ev_{logical_name.replace('.', '_')}",
        "kind": "binary_metadata",
        "logical_name": logical_name,
        "package_id": package_id,
        "version_before": version_before,
        "version_after": version_after,
        "sha256_before": sha256_before,
        "sha256_after": sha256_after,
        "size_before": int(size_before),
        "size_after": int(size_after),
        "summary_before": _summary(before_facts),
        "summary_after": _summary(after_facts),
        "notes": notes,
    }


def build_bundle(
    *,
    run_id: str,
    patch_cycle: str,
    target_build: str,
    kb_ids: list[str],
    artifacts: list[dict[str, Any]],
    person: str,
    target_product: str = "Windows Server 2022",
    cve_ids: list[str] | None = None,
    analysis_goal: str = "Triage security-relevant changes in DLLs reconstructed from Patch Tuesday MSU deltas.",
    changes: list[dict[str, Any]] | None = None,
    analyst_notes: list[str] | None = None,
    questions: list[str] | None = None,
) -> dict[str, Any]:
    """Build the runner's complete bundle (RF-15), with the P1 schema."""
    bundle = {
        "bundle_version": BUNDLE_VERSION,
        "run_id": run_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "target_product": target_product,
        "target_build": target_build,
        "patch_cycle": patch_cycle,
        "analysis_goal": analysis_goal,
        "kb_ids": list(kb_ids),
        "cve_ids": list(cve_ids or []),
        "person": person,
        "artifacts": artifacts,
    }
    if changes is not None:
        bundle["changes"] = changes
    if analyst_notes is not None:
        bundle["analyst_notes"] = analyst_notes
    if questions is not None:
        bundle["questions"] = questions
    return bundle
