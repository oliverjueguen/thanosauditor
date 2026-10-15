"""Panel bundle store.

Persists the uploaded bundles in a directory, one per (cycle, person). Uploading the
same person's bundle for the same cycle again **replaces** the previous one (RF-18),
keeping a ``.bak`` copy. Only bundles that pass ``validate_bundle`` are saved; when
reading, a corrupt or invalid file is skipped and logged, so it never leaves the
panel unusable (RNF-06).
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from ..auditor.report import candidates_for, cve_source, msrc_cves, validate_report
from ..config import env, resolve_path
from ..core.aggregate import aggregate
from ..core.bundles import target_build, validate_bundle
from ..log import get_logger
from ..ontology.namespaces import slug

log = get_logger("panel.store")
_MAX_SLUG = 80


def default_directory() -> Path:
    """Panel data directory (THANOS_PANEL_DATA), read at call time."""
    return resolve_path(env("THANOS_PANEL_DATA", "data/panel/bundles"))


def cycle_id(bundle: dict[str, Any]) -> str:
    return slug(f"{bundle.get('patch_cycle', 'na')}-{target_build(bundle) or 'na'}")[:_MAX_SLUG]


def _person(bundle: dict[str, Any]) -> str:
    return bundle.get("person") or bundle.get("run_id") or "unknown"


def load_report() -> dict[str, Any] | None:
    """Thanos Auditor report (THANOS_PANEL_REPORT); None if missing or invalid."""
    path = resolve_path(env("THANOS_PANEL_REPORT", "output/report.json"))
    if not path.is_file():
        return None
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        log.warning("report_unreadable", extra={"fields": {"file": str(path), "error": str(exc)[:200]}})
        return None
    errors = validate_report(report)
    if errors:
        log.warning("report_invalid", extra={"fields": {"file": str(path), "error": errors[0]}})
        return None
    return report


def enrich(cycles: list[dict[str, Any]], bundles: list[dict[str, Any]],
           report: dict[str, Any] | None, cves: list[dict[str, Any]]) -> None:
    """Add the auditor assessment and the MSRC candidate CVEs to each binary."""
    by_cycle = {}
    if report:
        for sub in report.get("cycles", [report]):
            by_cycle[sub.get("patch_cycle")] = (sub, report.get("generated_by") or sub.get("generated_by", ""))
    synthetic = {b.get("patch_cycle") for b in bundles if b.get("synthetic")}
    for c in cycles:
        sub, source = by_cycle.get(c["patch_cycle"], (None, ""))
        targets = {}
        for t in (sub or {}).get("review_targets", []):
            targets.setdefault((t["logical_name"], t.get("arch", "")), t)
            targets.setdefault((t["logical_name"], None), t)
        for a in c["artifacts"]:
            t = targets.get((a["logical_name"], a.get("arch", ""))) or targets.get((a["logical_name"], None))
            if t:
                a["analysis"] = {k: t.get(k, "") for k in ("priority", "severity", "confidence", "rationale")}
            a["cve_candidates"] = candidates_for(a, cves)
        c["analysis_source"] = source if sub else ""
        c["analysis_summary"] = (sub or {}).get("summary", "")
        kbs = set(c.get("kb_ids", []))
        c["kpis"]["cves_cycle"] = sum(1 for cve in cves if kbs & set(cve.get("kbs", []))) if cves else "-"
        c["cve_source"] = cve_source()
        c["provenance"] = ("contains SYNTHETIC data (tests only)" if c["patch_cycle"] in synthetic
                           else "data from the uploaded bundles (by default, the real P1 ones)")


class InvalidBundle(ValueError):
    """The bundle does not pass schema and type validation."""


class PanelStore:
    """On-disk store of the bundles uploaded to the panel."""

    def __init__(self, directory: str | Path | None = None):
        self.directory = Path(directory) if directory else default_directory()
        self.directory.mkdir(parents=True, exist_ok=True)

    # ---- writing ---------------------------------------------------------- #

    def add_bundle(self, bundle: Any) -> tuple[str, bool]:
        """Validate and save/replace the bundle for (cycle, person).

        Returns (cycle id, replaced). Raises InvalidBundle if it is not valid.
        """
        errors = validate_bundle(bundle)
        if errors:
            raise InvalidBundle("; ".join(errors[:3]))
        cid = cycle_id(bundle)
        path = self.directory / f"{cid}__{slug(_person(bundle))[:_MAX_SLUG]}.json"
        replaced = path.exists()
        if replaced:
            shutil.copy2(path, path.with_suffix(".json.bak"))
        text = json.dumps(bundle, ensure_ascii=False, indent=2)
        path.write_text(text, encoding="utf-8")
        log.info(
            "bundle_saved",
            extra={"fields": {
                "cycle": cid, "person": _person(bundle), "replaced": replaced,
                "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            }},
        )
        return cid, replaced

    def seed_from(self, *paths: str | Path) -> int:
        """Load sample bundles (e.g. the real P1 fixtures)."""
        n = 0
        for p in paths:
            p = Path(p)
            for f in [p] if p.is_file() else sorted(p.glob("*.bundle.json")):
                self.add_bundle(json.loads(f.read_text(encoding="utf-8")))
                n += 1
        return n

    def _all_bundles(self) -> list[dict[str, Any]]:
        out = []
        for f in sorted(self.directory.glob("*.json")):
            try:
                bundle = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, ValueError, RecursionError) as exc:
                log.warning("bundle_unreadable", extra={"fields": {"file": f.name, "error": str(exc)[:200]}})
                continue
            errors = validate_bundle(bundle)
            if errors:
                log.warning("bundle_invalid_skipped", extra={"fields": {"file": f.name, "error": errors[0]}})
                continue
            out.append(bundle)
        return out

    def cycles(self) -> list[dict[str, Any]]:
        """Aggregated cycles with their id, the auditor report and the candidate CVEs (RF-19, RF-20)."""
        bundles = self._all_bundles()
        cycles = aggregate(bundles)
        enrich(cycles, bundles, load_report(), msrc_cves())
        for c in cycles:
            c["id"] = slug(f"{c['patch_cycle']}-{c['target_build']}")[:_MAX_SLUG]
        return cycles

    def get_cycle(self, cid: str) -> dict[str, Any] | None:
        """Aggregated cycle by its id, or None (RF-20)."""
        for c in self.cycles():
            if c["id"] == cid:
                return c
        return None

    def is_empty(self) -> bool:
        return not any(self.directory.glob("*.json"))
