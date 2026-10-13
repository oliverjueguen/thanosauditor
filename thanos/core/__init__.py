"""Thanos core: bundle loading, binary diffing, scoring and aggregation.

These pieces do not depend on the heavy environment (Windows/Ghidra): they work
on already generated `bundle.json` files, so the dashboard, Thanos Auditor and the
tests can run on any machine (RNF-04).
"""

from .aggregate import aggregate
from .bundles import ArtifactDiff, artifact_diffs, load_bundle, validate_bundle
from .scoring import priority_for, score_components, score_for, severity_for

__all__ = [
    "ArtifactDiff",
    "artifact_diffs",
    "load_bundle",
    "validate_bundle",
    "priority_for",
    "score_for",
    "score_components",
    "severity_for",
    "aggregate",
]
