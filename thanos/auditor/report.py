"""Thanos Auditor report schema and heuristic generator (RF-17).

The report contains:
  - summary: executive summary of the cycle.
  - review_targets: prioritized binaries (P1-P4) with severity and confidence.
  - findings: concrete observations with inferences from public information.
  - open_questions: doubts that require manual review.
  - next_artifacts: next evidence to collect to strengthen the analysis.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from ..config import env, resolve_path
from ..core.aggregate import aggregate
from ..core.noise import is_runtime_helper
from ..log import get_logger

log = get_logger("auditor.report")


def msrc_cves() -> list[dict[str, Any]]:
    """MSRC CVEs from the offline extract (empty list if unavailable)."""
    try:
        from ..ontology.msrc import load_cves

        return load_cves()
    except (OSError, ValueError, KeyError):
        return []


_KEEP = ("cve", "title", "severity", "impact", "cvss", "confidence")


@lru_cache(maxsize=4)
def _catalog_index(path: str, _mtime_ns: int) -> tuple[frozenset[str], dict[str, list[dict[str, Any]]]] | None:
    """CVE candidates from the catalog (ontology); None if it has no CVEs. Cached by mtime."""
    from ..ontology.store import ThanosOntology

    onto = ThanosOntology()
    onto.load(path)
    if not onto.stats()["CVE"]:
        return None
    return frozenset(onto.binary_names()), onto.cve_candidates()


def catalog_candidates() -> tuple[frozenset[str], dict[str, list[dict[str, Any]]]] | None:
    """Candidate index from the ontology (THANOS_ONTOLOGY_CATALOG), or None if there is none."""
    path = resolve_path(env("THANOS_ONTOLOGY_CATALOG", "data/ontology/catalog.ttl"))
    if not path.is_file():
        return None
    try:
        return _catalog_index(str(path), path.stat().st_mtime_ns)
    except Exception as exc:  # corrupt catalog: the MSRC extract is used instead
        log.warning("catalog_unreadable", extra={"fields": {"file": str(path), "error": str(exc)[:200]}})
        return None


def candidates_for(art: dict[str, Any], cves: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """CVE candidates (summarized) for an aggregated binary.

    Main source: the ontology (the catalog that replaces Neo4j), queried with SPARQL.
    Fallback: the MSRC extract, if the catalog does not exist, has no CVEs or does not
    know the binary (e.g. a bundle just uploaded to the panel).
    """
    index = catalog_candidates()
    if index is not None and art["logical_name"] in index[0]:
        return [{k: c.get(k) for k in _KEEP} for c in index[1].get(art["logical_name"], [])]
    if not cves:
        return []
    from ..ontology.msrc import match_cves

    return [{k: c[k] for k in _KEEP} for c in match_cves(art["logical_name"], art.get("package_key", ""), cves)]


def cve_source() -> str:
    """Where the candidate CVEs come from (shown in the report and in the panel)."""
    if catalog_candidates() is not None:
        return "ontology (" + env("THANOS_ONTOLOGY_CATALOG", "data/ontology/catalog.ttl") + ")"
    return "MSRC extract (" + env("THANOS_MSRC_CVES", "fixtures/msrc/2026-Apr.ws2022.json") + ")"


def component_name(title: str) -> str:
    from ..ontology.msrc import component

    return component(title)

REPORT_SCHEMA_VERSION = "1.0"


def _confidence(row: dict[str, Any]) -> str:
    """Heuristic triage confidence for a binary.

    - high: the exports change, or there are changes with real names in a COMPLETE diff.
    - medium: named changes in a truncated diff (P1 only listed part of the functions,
      so a name can "enter" or "leave" the window without changing), or only the total
      function count varies.
    - low: the SHA-256 changes but there is no observable code diff.
    """
    named = row.get("fn_added") or row.get("fn_removed") or row.get("exp_added") or row.get("exp_removed")
    if row["exp_delta"] != 0 or (named and not row.get("name_diff_truncated")):
        return "high"
    if named:
        return "medium"
    if row["fn_delta"] != 0:
        return "medium"
    return "low"


def _names(names: list[str], limit: int = 4) -> str:
    shown = ", ".join(n.removeprefix("DelayLoad_") for n in names[:limit])
    return shown + (f" (+{len(names) - limit} more)" if len(names) > limit else "")


def _rationale(row: dict[str, Any]) -> str:
    parts = []
    exp_names = row.get("exp_added", []) + row.get("exp_removed", [])
    if exp_names or row["exp_delta"]:
        parts.append(f"{len(exp_names) or abs(row['exp_delta'])} exports changed (public surface)")
    dl_add, dl_rem = row.get("delay_loads_added", []), row.get("delay_loads_removed", [])
    if dl_add:
        parts.append(f"{len(dl_add)} new delay-load imports ({_names(dl_add)})")
    if dl_rem:
        parts.append(f"{len(dl_rem)} delay-load imports removed ({_names(dl_rem)})")
    own_add = [n for n in row.get("fn_added", []) if n not in dl_add]
    own_rem = [n for n in row.get("fn_removed", []) if n not in dl_rem]
    if own_add or own_rem:
        parts.append(f"named functions +{len(own_add)}/-{len(own_rem)}")
    if row["fn_delta"]:
        parts.append(f"total function count {row['fn_delta']:+d}")
    if row["size_delta"]:
        parts.append(f"{row['size_delta']:+d} bytes")
    if not parts:
        parts.append("SHA-256 change with no observable code diff (possible noise)")
    if row.get("imp_delta"):
        parts.append(f"{row['imp_delta']:+d} imports")
    if row.get("noise_filtered"):
        parts.append(f"{row['noise_filtered']} Ghidra auto-generated names discarded")
    if row.get("name_diff_truncated") and (row.get("fn_added") or row.get("fn_removed")):
        parts.append("name diff truncated in P1 (partial function list)")
    return "; ".join(parts) + f". Heuristic score {row['score']}."


def build_heuristic_report(bundles: list[dict[str, Any]]) -> dict[str, Any]:
    """Generate the report deterministically, without an LLM."""
    cycles = aggregate(bundles)
    reports = []
    for cycle in cycles:
        arts = cycle["artifacts"]
        review_targets = [
            {
                "logical_name": a["logical_name"],
                "arch": a.get("arch", ""),
                "person": a["person"],
                "priority": a["priority"],
                "severity": a["severity"],
                "confidence": _confidence(a),
                "score": a["score"],
                "rationale": _rationale(a),
            }
            for a in arts
            if a["changed"]
        ]

        findings = []
        for a in arts:
            exp_names = a.get("exp_added", []) + a.get("exp_removed", [])
            dl_add, dl_rem = a.get("delay_loads_added", []), a.get("delay_loads_removed", [])
            own_add = [n for n in a.get("fn_added", []) if n not in dl_add]
            if exp_names or a["exp_delta"] != 0:
                findings.append(
                    f"{a['logical_name']}: change in exports ({_names(exp_names) or a['exp_delta']}); "
                    "check whether it introduces or modifies public attack surface."
                )
            if dl_add:
                findings.append(
                    f"{a['logical_name']}: {len(dl_add)} new delay-load dependencies "
                    f"({_names(dl_add, 6)}); the binary gains capabilities it did not use before."
                )
            if dl_rem:
                findings.append(
                    f"{a['logical_name']}: removes {len(dl_rem)} delay-load dependencies "
                    f"({_names(dl_rem, 6)}); possible refactoring or removal of a code path."
                )
            runtime = [n for n in own_add if is_runtime_helper(n)]
            if own_add and len(runtime) >= 0.6 * len(own_add):
                findings.append(
                    f"{a['logical_name']}: the new functions are mostly C runtime helpers "
                    f"({_names(own_add)}); likely relinked against another CRT/toolchain rather than "
                    "new logic. Confirm before investing review time."
                )
            elif own_add:
                findings.append(
                    f"{a['logical_name']}: new named functions ({_names(own_add)}); "
                    "candidates to decompile and review."
                )
            elif not (exp_names or dl_add or dl_rem) and a["fn_delta"] != 0 and a["score"] >= 80:
                named = len(a.get("fn_added", [])) + len(a.get("fn_removed", []))
                findings.append(
                    f"{a['logical_name']}: the total function count varies by {a['fn_delta']:+d} with "
                    f"only {named} named change(s); substantial change in functions without symbols."
                )
        noise_total = sum(a.get("noise_filtered", 0) for a in arts)
        if noise_total:
            findings.append(
                f"{noise_total} Ghidra auto-generated names (Unwind@/Catch@…) were discarded; "
                "they only reflect address shifts, not code changes."
            )

        noisy = [a["logical_name"] for a in arts if a["changed"] and not a["has_code_diff"]]
        open_questions = []
        if noisy:
            sample = ", ".join(noisy[:6]) + (f" and {len(noisy) - 6} more" if len(noisy) > 6 else "")
            open_questions.append(
                f"Are the {len(noisy)} binaries with a different SHA but no code diff just "
                f"recompilation/signing changes? (e.g. {sample})"
            )
        # MSRC candidate CVEs for each binary (hypothesis based on the component name).
        cves = msrc_cves()
        for t in review_targets:
            art = next(a for a in arts if a["logical_name"] == t["logical_name"] and a.get("arch", "") == t["arch"])
            t["cve_candidates"] = candidates_for(art, cves)
        for t in review_targets:
            if t["cve_candidates"] and t["priority"] in ("P1", "P2", "P3"):
                cands = t["cve_candidates"]
                top = max(cands, key=lambda c: c.get("cvss") or 0)
                findings.append(
                    f"{t['logical_name']}: {len(cands)} MSRC candidate CVEs by component name "
                    f"('{component_name(top['title'])}', max CVSS {top.get('cvss')}, e.g. {top['cve']}). "
                    "This is a hypothesis: Microsoft does not publish the CVE→file mapping."
                )
        p1 = [t for t in review_targets if t["priority"] == "P1"]
        unmatched = [t["logical_name"] for t in p1 if not t["cve_candidates"]]
        if unmatched:
            open_questions.append(
                f"P1 priority with no MSRC candidate CVE for {', '.join(cycle['kb_ids'])}: "
                f"{', '.join(unmatched)}. Functional change without a CVE, silent fix, or "
                "component under a different name in the bulletin?"
            )

        next_artifacts = [
            f"Decompile the new functions of {t['logical_name']} with Ghidra"
            + (f" and compare them against {', '.join(c['cve'] for c in t['cve_candidates'][:3])}"
               if t["cve_candidates"] else "")
            for t in review_targets[:3]
            if t["priority"] in ("P1", "P2")
        ]

        n_p1 = sum(1 for a in review_targets if a["priority"] == "P1")
        n_p2 = sum(1 for a in review_targets if a["priority"] == "P2")
        summary = (
            f"Cycle {cycle['patch_cycle']} ({cycle['target_product']} "
            f"{cycle['target_build']}): {len(review_targets)} binaries changed out of "
            f"{cycle['kpis']['artifacts']} analyzed; {n_p1} in P1 and {n_p2} in P2. "
            f"KBs {', '.join(cycle['kb_ids'])}."
        )

        reports.append(
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "generated_by": "heuristic",
                "patch_cycle": cycle["patch_cycle"],
                "target_product": cycle["target_product"],
                "target_build": cycle["target_build"],
                "kb_ids": cycle["kb_ids"],
                "summary": summary,
                "review_targets": review_targets,
                "findings": findings,
                "open_questions": open_questions,
                "next_artifacts": next_artifacts,
                "cve_source": cve_source(),
            }
        )

    if len(reports) == 1:
        return reports[0]
    return {"schema_version": REPORT_SCHEMA_VERSION, "generated_by": "heuristic", "cycles": reports}


PRIORITIES = ("P1", "P2", "P3", "P4")
SEVERITIES = ("critical", "high", "medium", "low")
CONFIDENCES = ("high", "medium", "low")


def validate_report(report: Any, known_binaries: set[str] | None = None) -> list[str]:
    """Check the schema, types and allowed values of a report (RF-17).

    Accepts a single-cycle report or the multi-cycle format ``{"cycles": [...]}``. If
    ``known_binaries`` is given, every review_target must refer to an input binary
    (prevents the model from inventing binaries). Never raises.
    """
    if not isinstance(report, dict):
        return ["the report must be a JSON object"]
    if "cycles" in report:
        if not isinstance(report["cycles"], list) or not report["cycles"]:
            return ["'cycles' must be a non-empty list"]
        errors = []
        for i, sub in enumerate(report["cycles"]):
            errors += [f"cycles[{i}]: {e}" for e in validate_report(sub, known_binaries)]
        return errors

    errors = []
    if not isinstance(report.get("summary"), str) or not report.get("summary", "").strip():
        errors.append("'summary' must be a non-empty string")
    for key in ("findings", "open_questions", "next_artifacts"):
        value = report.get(key)
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            errors.append(f"'{key}' must be a list of strings")
    targets = report.get("review_targets")
    if not isinstance(targets, list):
        return errors + ["'review_targets' must be a list"]
    allowed = {"priority": PRIORITIES, "severity": SEVERITIES, "confidence": CONFIDENCES}
    for i, t in enumerate(targets):
        if not isinstance(t, dict):
            errors.append(f"review_targets[{i}] is not an object")
            continue
        name = t.get("logical_name")
        if not isinstance(name, str) or not name:
            errors.append(f"review_targets[{i}]: missing 'logical_name'")
        elif known_binaries is not None and name not in known_binaries:
            errors.append(f"review_targets[{i}]: unknown binary {name[:80]!r}")
        for key, values in allowed.items():
            if t.get(key) not in values:
                errors.append(f"review_targets[{i}]: '{key}' must be one of {'/'.join(values)}")
        if "rationale" in t and not isinstance(t["rationale"], str):
            errors.append(f"review_targets[{i}]: 'rationale' must be a string")
    return errors[:20]
