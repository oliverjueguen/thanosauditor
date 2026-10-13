"""Criticality scoring of a changed binary (feeds the dashboard and Thanos Auditor).

The score is a deterministic heuristic over the diff (functions, exports,
imports, strings, size). It serves two purposes:

1. Rank binaries in the dashboard by relevance (SCORE column of the P1 dashboard).
2. Give Thanos Auditor (Claude) an objective pre-triage to start from, so that
   the pipeline and the dashboard **also work without an LLM** (heuristic mode, RNF-04).

Exports weigh more than internal functions because they are attack surface
(public entry points of the binary).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # avoids a circular import at runtime
    from .bundles import ArtifactDiff

# Weight of each component. Calibrated so that a large function change
# (e.g. +132) yields a high score comparable to the P1 dashboard.
WEIGHTS = {
    "fn": 2,     # internal function added/removed
    "exp": 10,   # export (public attack surface)
    "imp": 3,    # new import (new dependency/call)
    "str": 1,    # string (weak signal: messages, paths)
}


def score_components(diff: "ArtifactDiff") -> dict[str, int]:
    """Score breakdown by component (useful to explain the score).

    - With a name diff (bundles with a `changes` section): added/removed functions
      with a real name (without Ghidra noise) are the main signal; the raw change in
      the function count remains a secondary signal (weight 1), because it includes
      unnamed functions and varies with the analysis.
    - Without a name diff: the count change is used (P1 behavior).
    - Added or removed delay-load imports (DelayLoad_*) score as imports: they are
      changes to the binary's dependencies (e.g. network capability).
    """
    if diff.has_name_diff:
        delay = len(diff.delay_loads_added) + len(diff.delay_loads_removed)
        own_fn = diff.fn_changes - delay
        comp = {
            "fn": own_fn * WEIGHTS["fn"],
            "fn_count": abs(diff.fn_delta),
            "delay_load": delay * WEIGHTS["imp"],
        }
    else:
        comp = {"fn": abs(diff.fn_delta) * WEIGHTS["fn"]}
    comp.update(
        {
            "exp": diff.exp_changes * WEIGHTS["exp"],
            "imp": abs(diff.imp_delta) * WEIGHTS["imp"],
            "str": abs(diff.str_delta) * WEIGHTS["str"],
        }
    )
    # A SHA change without an observable code diff still deserves a minimal signal
    # (the binary changed, even if Ghidra sees no new functions/exports).
    if diff.changed and sum(comp.values()) == 0:
        comp["size"] = 1 if diff.size_delta else 0
    return comp


def score_for(diff: "ArtifactDiff") -> int:
    """Total criticality score of the binary."""
    return sum(score_components(diff).values())


def priority_for(score: int) -> str:
    """Map the score to a review priority, P1 (most urgent) to P4."""
    if score >= 200:
        return "P1"
    if score >= 80:
        return "P2"
    if score >= 20:
        return "P3"
    return "P4"


def severity_for(diff: "ArtifactDiff") -> str:
    """Estimated vulnerability level (critical | high | medium | low).

    Heuristic: export changes (public surface) raise the severity; a SHA change
    without a code diff is considered low (possible noise).
    """
    s = score_for(diff)
    exports_changed = diff.exp_changes > 0
    if exports_changed and s >= 80:
        return "critical"
    if s >= 200 or (exports_changed and s >= 20):
        return "high"
    if s >= 20 or diff.has_code_diff:
        return "medium"
    return "low"


def assess(diff: "ArtifactDiff") -> dict[str, Any]:
    """Full assessment of a binary: score, components, priority, severity."""
    s = score_for(diff)
    return {
        "logical_name": diff.logical_name,
        "arch": diff.arch,
        "person": diff.person,
        "score": s,
        "components": score_components(diff),
        "priority": priority_for(s),
        "severity": severity_for(diff),
        "fn_delta": diff.fn_delta,
        "exp_delta": diff.exp_delta,
        "size_delta": diff.size_delta,
        "changed": diff.changed,
        "has_code_diff": diff.has_code_diff,
        "has_name_diff": diff.has_name_diff,
        "fn_added": diff.fn_added,
        "fn_removed": diff.fn_removed,
        "exp_added": diff.exp_added,
        "exp_removed": diff.exp_removed,
        "delay_loads_added": diff.delay_loads_added,
        "delay_loads_removed": diff.delay_loads_removed,
        "noise_filtered": diff.noise_filtered,
        "name_diff_truncated": diff.name_diff_truncated,
        "imp_delta": diff.imp_delta,
        "str_delta": diff.str_delta,
        "p1_score": p1_score(diff),
    }


def p1_score(diff: "ArtifactDiff") -> int:
    """Score using the P1 dashboard formula: |FN+| + |FN-|.

    P1 summed functions added and removed by name, Ghidra noise included
    (e.g. configmanager2.dll, +132/-132 -> 264). P3 uses per-change-type weights and
    discards auto-generated names; this figure is kept for comparison.
    """
    if diff.has_name_diff:
        return diff.fn_changes + diff.noise_filtered
    return abs(diff.fn_delta)
