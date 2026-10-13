"""Per-cycle bundle aggregation for the dashboard (RF-18, RF-19, RF-20).

Takes several bundles (one per team member), groups them by Patch Tuesday cycle
and produces the structure the dashboard consumes: KPIs, received bundles and
artifacts aggregated per binary with their criticality score.
"""

from __future__ import annotations

from typing import Any

from .bundles import artifact_diffs, target_build
from .scoring import assess


def _cycle_key(bundle: dict[str, Any]) -> str:
    return f"{bundle.get('patch_cycle', '?')} · {target_build(bundle) or '?'}"


def aggregate(bundles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group bundles by cycle and return a list of aggregated cycles.

    Each cycle includes:
      - metadata (patch_cycle, target_product, target_build, kb_ids)
      - bundles: list of {person, run_id, created_at, artifact_count}
      - artifacts: per-binary list with its assessment (score, priority, severity)
      - kpis: {bundles, artifacts, with_fn_diff, with_exp_diff}
    """
    cycles: dict[str, dict[str, Any]] = {}

    for bundle in bundles:
        key = _cycle_key(bundle)
        cycle = cycles.setdefault(
            key,
            {
                "patch_cycle": bundle.get("patch_cycle", "?"),
                "target_product": bundle.get("target_product", ""),
                "target_build": target_build(bundle),
                "kb_ids": list(bundle.get("kb_ids", []) or []),
                "cve_ids": list(bundle.get("cve_ids", []) or []),
                "bundles": [],
                "artifacts": [],
            },
        )

        diffs = artifact_diffs(bundle)
        cycle["bundles"].append(
            {
                "person": bundle.get("person") or bundle.get("run_id") or "unknown",
                "run_id": bundle.get("run_id", ""),
                "created_at": bundle.get("created_at", ""),
                "artifact_count": len(diffs),
            }
        )
        for kb in bundle.get("kb_ids", []) or []:
            if kb not in cycle["kb_ids"]:
                cycle["kb_ids"].append(kb)

        for diff in diffs:
            row = assess(diff)
            row["package_key"] = diff.package_key
            row["version_before"] = diff.version_before
            row["version_after"] = diff.version_after
            cycle["artifacts"].append(row)

    result = []
    for cycle in cycles.values():
        cycle["artifacts"].sort(key=lambda r: r["score"], reverse=True)
        arts = cycle["artifacts"]
        cycle["kpis"] = {
            "bundles": len(cycle["bundles"]),
            "artifacts": len(arts),
            "with_fn_diff": sum(1 for a in arts if a["fn_delta"] != 0 or a["fn_added"] or a["fn_removed"]),
            "with_exp_diff": sum(
                1 for a in arts if a["exp_delta"] != 0 or a["exp_added"] or a["exp_removed"]
            ),
            "noise_filtered": sum(a["noise_filtered"] for a in arts),
        }
        result.append(cycle)

    result.sort(key=lambda c: c["patch_cycle"], reverse=True)
    return result
