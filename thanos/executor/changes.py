"""Diff by function and export names between BEFORE and AFTER (RF-14).

Generates the bundle's ``changes`` section with the same schema the Practice 1
executor produced (``change_id``, ``binary``, ``diff.functions_added``…), but from
the COMPLETE list of names exported by Ghidra: in the P1 bundles the list was cut
at 512 functions and the diff was incomplete.
"""

from __future__ import annotations

from typing import Any


def _names(facts: dict[str, Any], key: str) -> set[str]:
    return {n for n in facts.get(key, []) or [] if isinstance(n, str) and n}


def compute_changes(
    logical_name: str,
    before_facts: dict[str, Any],
    after_facts: dict[str, Any],
    *,
    change_id: str,
    evidence_id: str,
) -> dict[str, Any]:
    """``changes`` entry for one binary (P1 schema)."""
    fb, fa = _names(before_facts, "functions"), _names(after_facts, "functions")
    eb, ea = _names(before_facts, "exports"), _names(after_facts, "exports")
    diff = {
        "functions_added": sorted(fa - fb),
        "functions_removed": sorted(fb - fa),
        "exports_added": sorted(ea - eb),
        "exports_removed": sorted(eb - ea),
        # Counts of the full list (names may repeat, e.g. thunks): this way they
        # match function_count and the diff is not flagged as truncated.
        "before_function_count": len(before_facts.get("functions", []) or []),
        "after_function_count": len(after_facts.get("functions", []) or []),
        "before_export_count": len(before_facts.get("exports", []) or []),
        "after_export_count": len(after_facts.get("exports", []) or []),
    }
    return {
        "change_id": change_id,
        "binary": logical_name,
        "function_name": "*",
        "change_type_guess": "unclassified",
        "evidence_ids": [evidence_id],
        "snippet_ids": [],
        "diff": diff,
        "notes": (
            f"{len(diff['functions_added'])} fn added, {len(diff['functions_removed'])} fn removed, "
            f"{len(diff['exports_added'])} exp added, {len(diff['exports_removed'])} exp removed"
        ),
    }
