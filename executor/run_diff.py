#!/usr/bin/env python3
"""run_diff.py: executor runner (RF-09, RF-11 … RF-15).

Runs on each team member's machine, from the folder of the ZIP delivered by the
coordinator (or from executor/ in the repository):

  1. Reads and validates config.yaml (RF-11).
  2. Checks that analyzeHeadless exists BEFORE starting.
  3. Pairs input/before ↔ input/after (case-insensitive) and discards pairs with
     identical SHA-256 (RF-12). Clear error if there are no pairs (RF-09).
  4. Analyzes each side with Ghidra headless + ExportFacts.java (RF-13).
  5. Computes the full name-based diff of functions and exports (RF-14).
  6. Writes output/<run_id>.bundle.json with the P1 schema and validates it (RF-15).

Usage:  python run_diff.py [--config config.yaml]
Exit codes: 0 success, 2 configuration or input error, 3 no binary analyzed.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Callable

# The thanos/ package ships next to this script in the ZIP; in the repo it is one level up.
HERE = Path(__file__).resolve().parent
for _root in (HERE, HERE.parent):
    if (_root / "thanos" / "__init__.py").is_file():
        sys.path.insert(0, str(_root))
        break

try:
    import yaml
except ImportError:
    sys.exit("pyyaml is missing. Run bootstrap.ps1 first (or: pip install pyyaml rdflib).")

from thanos.executor import build_artifact, build_bundle, changed_pairs, compute_changes, pair_binaries  # noqa: E402
from thanos.executor.ghidra import GhidraError, analyze_headless, ghidra_facts  # noqa: E402

REQUIRED = ("executor_id", "patch_cycle", "target_build", "kb_ids", "ghidra_support_dir")
P1_QUESTIONS = [
    "Which functions added/removed sit on externally reachable code paths?",
    "Are added exports backed by new validation or new attack surface?",
    "Do removed functions correlate with deprecated unsafe paths?",
]


class RunError(Exception):
    """Configuration or input error: printed on one line."""


def load_config(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise RunError(f"{path} does not exist (copy config.example.yaml to config.yaml and edit it)")
    try:
        cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise RunError(f"{path} is not valid YAML: {exc}") from None
    missing = [k for k in REQUIRED if k not in cfg or (k != "kb_ids" and not cfg[k])]
    if missing:
        raise RunError(f"missing keys in {path.name}: {', '.join(missing)}")
    if not isinstance(cfg["kb_ids"], list):
        raise RunError("kb_ids must be a list (e.g. [KB5078766, KB5082142])")
    if not isinstance(cfg["target_build"], str):
        raise RunError("target_build must be quoted in config.yaml (e.g. \"20348.5020\"); "
                       "unquoted, YAML turns it into a number and drops the trailing zero")
    return cfg


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _assignment(base: Path) -> dict[str, dict[str, Any]]:
    """Coordinator assignment.json: logical_name → entry (for the package_id)."""
    path = base / "assignment.json"
    if not path.is_file():
        return {}
    entries = json.loads(path.read_text(encoding="utf-8"))
    return {e.get("logical_name", "").casefold(): e for e in entries if isinstance(e, dict)}


def run(cfg: dict[str, Any], base: Path, facts: Callable[..., dict[str, Any]] = ghidra_facts) -> Path:
    if facts is ghidra_facts:
        analyze_headless(cfg["ghidra_support_dir"])      # fail fast if the path is wrong
    input_dir = base / cfg.get("input_dir", "input")
    pairs = pair_binaries(input_dir / "before", input_dir / "after")
    if not pairs:
        raise RunError(f"Found 0 pairs: {input_dir}/before and {input_dir}/after have no files in common "
                       "(was the ZIP extracted correctly?)")
    changed = changed_pairs(pairs)
    if not changed:
        raise RunError(f"{len(pairs)} pairs found, but all have the same SHA-256: nothing to analyze")

    assigned = _assignment(base)
    artifacts, changes, failed = [], [], []
    for i, pair in enumerate(changed, start=1):
        print(f"[{i}/{len(changed)}] Ghidra: {pair.name}", flush=True)
        try:
            fb = facts(cfg["ghidra_support_dir"], pair.before, java_home=cfg.get("java_home"))
            fa = facts(cfg["ghidra_support_dir"], pair.after, java_home=cfg.get("java_home"))
        except GhidraError as exc:
            print(f"  warning: skipping {pair.name}: {exc}", file=sys.stderr)
            failed.append(pair.name)
            continue
        evidence = f"ev_bin_{len(artifacts) + 1:03d}"
        entry = assigned.get(pair.name.casefold(), {})
        artifacts.append(build_artifact(
            pair.name, entry.get("package_after", ""), fb, fa,
            sha256_before=pair.sha_before, sha256_after=pair.sha_after,
            size_before=pair.before.stat().st_size, size_after=pair.after.stat().st_size,
            evidence_id=evidence,
            notes="Analyzed by Ghidra headless (thanos ExportFacts.java).",
        ))
        change_id = f"chg_{len(changes) + 1:03d}"
        changes.append(compute_changes(pair.name, fb, fa, change_id=change_id, evidence_id=evidence))

    if not artifacts:
        raise RunError(f"Ghidra could not analyze any binary ({len(failed)} failed)")
    notes = [
        f"Pair count discovered: {len(pairs)}; pairs with sha256 delta: {len(changed)}.",
        "Function/export deltas are name-set diffs over the full function list; not a control-flow diff.",
    ]
    if failed:
        notes.append(f"Ghidra failed on {len(failed)} binaries: {', '.join(failed)}")
    run_id = f"{_slug(cfg['patch_cycle'])}-{_slug(cfg['executor_id'])}"
    bundle = build_bundle(
        run_id=run_id, patch_cycle=cfg["patch_cycle"], target_build=cfg["target_build"],
        target_product=cfg.get("target_product", "Windows Server 2022"),
        kb_ids=cfg["kb_ids"], cve_ids=cfg.get("cve_ids") or [], person=cfg["executor_id"],
        artifacts=artifacts, changes=changes, analyst_notes=notes, questions=P1_QUESTIONS,
    )
    out_dir = base / cfg.get("output_dir", "output")
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{run_id}.bundle.json"
    out.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Thanos executor runner (Ghidra headless → bundle.json).")
    parser.add_argument("--config", default="config.yaml")
    args = parser.parse_args(argv)
    config_path = Path(args.config).resolve()
    try:
        out = run(load_config(config_path), config_path.parent)
    except (RunError, GhidraError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3 if "any binary" in str(exc) else 2
    print(f"Bundle written to {out}. Hand it to the coordinator or upload it to the panel.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
