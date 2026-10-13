"""Coordinator CLI: ``python -m thanos.coordinator <subcommand>`` (or ``thanos-coordinator``).

P1 flow (Phases 2-5), with default paths under ``staging/``:

    resolve KB5082142 [--download downloads/msu]     # RF-02/RF-03: MSU GUID and URL
    manifest fixtures/bundles/…full.bundle.json      # demo: BEFORE/AFTER manifests from a real bundle
    diff staging/manifests/before.json staging/manifests/after.json   # RF-06
    split staging/changed_manifest.json --people ana luis marta pablo  # RF-07
    package --cycle "2026-04 Patch Tuesday" --target-build 20348.5020 \
            --kb KB5078766 --kb KB5082142                              # RF-08

DLL reconstruction (RF-05) and the baseline (RF-04) run on the Windows Server 2022
coordinator (see thanos/coordinator/reconstruct.py and docs/02).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..cliutil import CliError, fail, load_json_file, utf8_stdout
from ..config import load_env, project_root, resolve_path
from ..core.bundles import target_build, validate_bundle
from ..log import get_logger, setup_logging

log = get_logger("coordinator")


def _staging(*parts: str) -> Path:
    return project_root() / "staging" / Path(*parts)


def _write_json(path: Path, data) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def cmd_resolve(args) -> int:
    from .catalog import CatalogError, download_msu, resolve_kb

    try:
        info = resolve_kb(args.kb)
        print(f"{info['kb']}: {info['title']}\n  GUID: {info['guid']}\n  MSU:  {info['msu_url']}")
        if args.download:
            result = download_msu(info["msu_url"], resolve_path(args.download))
            print(f"  downloaded: {result['path']} ({result['bytes']} bytes, sha256 {result['sha256']})")
            info.update(result)
    except CatalogError as exc:
        raise CliError(str(exc)) from None
    log.info("kb_resolved", extra={"fields": info})
    return 0


def cmd_manifest(args) -> int:
    from .diff_index import manifests_from_bundle

    bundle = load_json_file(args.bundle)
    errors = validate_bundle(bundle)
    if errors:
        raise CliError(f"'{args.bundle}' is not a valid bundle: {errors[0]}")
    before, after = manifests_from_bundle(bundle)
    out = resolve_path(args.out_dir) if args.out_dir else _staging("manifests")
    _write_json(out / "before.json", before)
    _write_json(out / "after.json", after)
    print(f"BEFORE/AFTER manifests ({len(after)} entries) in {out}")
    return 0


def cmd_diff(args) -> int:
    from .diff_index import ManifestError, diff_manifests, load_manifest

    try:
        result = diff_manifests(load_manifest(args.before), load_manifest(args.after))
    except ManifestError as exc:
        raise CliError(str(exc)) from None
    out = _write_json(resolve_path(args.output) if args.output else _staging("changed_manifest.json"), result)
    print(f"{len(result['changed'])} changed binaries, {result['unchanged']} unchanged, "
          f"{len(result['only_before'])} only BEFORE, {len(result['only_after'])} only AFTER → {out}")
    log.info("diff_done", extra={"fields": {"changed": len(result["changed"]), "output": str(out)}})
    return 0


def cmd_split(args) -> int:
    from .split_workload import balance_report, split_round_robin

    changed = load_json_file(args.changed)
    items = changed.get("changed") if isinstance(changed, dict) else changed
    if not isinstance(items, list):
        raise CliError(f"'{args.changed}' does not contain a 'changed' list")
    assignments = split_round_robin(items, args.people)
    out = resolve_path(args.out_dir) if args.out_dir else _staging("assignments")
    for person, slice_ in assignments.items():
        _write_json(out / f"{person}.json", slice_)
    print(f"Round-Robin split in {out}: {balance_report(assignments)}")
    return 0


def cmd_package(args) -> int:
    from .package import build_zip

    cycle = {"patch_cycle": args.cycle, "target_build": args.target_build, "kb_ids": args.kb or []}
    if args.from_bundle:
        bundle = load_json_file(args.from_bundle)
        cycle = {"patch_cycle": bundle["patch_cycle"], "target_build": target_build(bundle),
                 "target_product": bundle.get("target_product", ""), "kb_ids": bundle.get("kb_ids", [])}
    if not cycle["patch_cycle"] or not cycle["target_build"]:
        raise CliError("specify --cycle and --target-build (or --from-bundle)")
    assignments_dir = resolve_path(args.assignments) if args.assignments else _staging("assignments")
    files = sorted(assignments_dir.glob("*.json"))
    if not files:
        raise CliError(f"no assignments in '{assignments_dir}' (run 'split' first)")
    out = resolve_path(args.out_dir) if args.out_dir else _staging("zips")
    for f in files:
        zip_path = build_zip(f.stem, load_json_file(f), cycle, out)
        print(f"  {zip_path}")
        log.info("zip_built", extra={"fields": {"person": f.stem, "zip": str(zip_path)}})
    print(f"{len(files)} ZIPs generated in {out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    utf8_stdout()
    load_env()
    setup_logging()
    parser = argparse.ArgumentParser(prog="thanos-coordinator", description="Thanos Coordinator (RF-02…RF-08).")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("resolve", help="Resolve a KB in the Microsoft Update catalog (network).")
    p.add_argument("kb")
    p.add_argument("--download", metavar="DIR", help="Also download the MSU into DIR (hundreds of MB).")
    p.set_defaults(func=cmd_resolve)

    p = sub.add_parser("manifest", help="BEFORE/AFTER manifests from a bundle (reproducible demo).")
    p.add_argument("bundle")
    p.add_argument("--out-dir")
    p.set_defaults(func=cmd_manifest)

    p = sub.add_parser("diff", help="Manifest diff → changed_manifest.json (RF-06).")
    p.add_argument("before")
    p.add_argument("after")
    p.add_argument("-o", "--output")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("split", help="Alphabetical Round-Robin split (RF-07).")
    p.add_argument("changed")
    p.add_argument("--people", nargs="+", required=True)
    p.add_argument("--out-dir")
    p.set_defaults(func=cmd_split)

    p = sub.add_parser("package", help="Per-person ZIP with the executor and its assignment (RF-08).")
    p.add_argument("--assignments", help="Assignments directory (default: staging/assignments).")
    p.add_argument("--cycle", default="")
    p.add_argument("--target-build", default="")
    p.add_argument("--kb", action="append")
    p.add_argument("--from-bundle", help="Take cycle, build and KBs from a bundle.")
    p.add_argument("--out-dir")
    p.set_defaults(func=cmd_package)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except CliError as exc:
        return fail(str(exc))


if __name__ == "__main__":
    sys.exit(main())
