"""Thanos ontology CLI (catalog that replaces Neo4j).

Examples::

    python -m thanos.ontology.cli ingest "fixtures/bundles/*.bundle.json" --fresh
    python -m thanos.ontology.cli ingest-cvrf --from-file fixtures/msrc/2026-Apr.ws2022.json
    python -m thanos.ontology.cli stats
    python -m thanos.ontology.cli changed --cycle "2026-04 Patch Tuesday FULL"
    python -m thanos.ontology.cli cves --binary upnphost.dll
    python -m thanos.ontology.cli query "SELECT ?name WHERE { ?b thanos:logicalName ?name }"

The default catalog is THANOS_ONTOLOGY_CATALOG (data/ontology/catalog.ttl),
resolved from the project root. Invalid input -> message and exit code 2.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from ..cliutil import CliError, expand_files, fail, load_json_file, utf8_stdout
from ..config import env, load_env, resolve_path
from ..core.bundles import validate_bundle
from ..log import get_logger, setup_logging
from .store import ThanosOntology

log = get_logger("ontology")


def _catalog_path(value: str | None) -> Path:
    return resolve_path(value or env("THANOS_ONTOLOGY_CATALOG", "data/ontology/catalog.ttl"))


def _load(catalog: Path, *, required: bool = True) -> ThanosOntology:
    onto = ThanosOntology()
    if catalog.exists():
        onto.load(catalog)
    elif required:
        raise CliError(f"catalog '{catalog}' does not exist; create it with 'ingest' (and 'ingest-cvrf')")
    return onto


def _table(rows: list[dict], columns: list[str]) -> None:
    if not rows:
        print("(no results)")
        return
    def cell(r: dict, c: str) -> str:
        return "-" if r.get(c) is None else str(r[c])

    widths = {c: min(48, max(len(c), *(len(cell(r, c)) for r in rows))) for c in columns}
    print("  ".join(c.upper().ljust(widths[c]) for c in columns))
    for r in rows:
        print("  ".join(cell(r, c)[: widths[c]].ljust(widths[c]) for c in columns))


def main(argv: list[str] | None = None) -> int:
    utf8_stdout()
    load_env()
    setup_logging()
    parser = argparse.ArgumentParser(prog="thanos-ontology", description="Thanos ontology (catalog).")
    parser.add_argument("--catalog", help="Turtle catalog (default THANOS_ONTOLOGY_CATALOG).")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("schema-check", help="Check that the schema (TBox) loads correctly.")
    sub.add_parser("stats", help="Per-class counts and CVE summary of the catalog.")

    p = sub.add_parser("ingest", help="Populate the ontology from .json bundles (re-ingesting replaces).")
    p.add_argument("bundles", nargs="+", help="bundle.json files (wildcards allowed).")
    p.add_argument("-o", "--output", help="Where to save the catalog (default: the same one).")
    p.add_argument("--fresh", action="store_true", help="Start from scratch (do not load the previous catalog).")

    p = sub.add_parser("ingest-cvrf", help="Ingest the Windows Server 2022 CVEs from MSRC (RF-01).")
    p.add_argument("--from-file", help="Offline extract (default THANOS_MSRC_CVES).")
    p.add_argument("--live", metavar="DOC", help="Download the MSRC CVRF (e.g. 2026-Apr) and save the extract.")
    p.add_argument("-o", "--output", help="Where to save the catalog (default: the same one).")

    p = sub.add_parser("changed", help="Changed binaries sorted by score.")
    p.add_argument("--cycle", help="Filter by cycle label.")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("cves", help="Candidate CVEs (hypotheses) for a binary.")
    p.add_argument("--binary", required=True)
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("query", help="Run a SPARQL query (thanos: prefix already bound).")
    p.add_argument("sparql")
    p.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    catalog = _catalog_path(args.catalog)
    try:
        return _dispatch(args, catalog)
    except CliError as exc:
        return fail(str(exc))


def _dispatch(args: argparse.Namespace, catalog: Path) -> int:
    if args.cmd == "schema-check":
        onto = ThanosOntology()
        print(f"Schema OK: {len(onto.graph)} triples in the TBox (thanos/ontology/thanos-schema.ttl).")
        return 0

    if args.cmd == "ingest":
        onto = ThanosOntology() if args.fresh else _load(catalog, required=False)
        for path in expand_files(args.bundles):
            bundle = load_json_file(path)
            errors = validate_bundle(bundle)
            if errors:
                raise CliError(f"'{path}' is not a valid bundle: {errors[0]}")
            counts = onto.ingest_bundle(bundle)
            print(f"  ingested {path.name}: {counts['binaries']} binaries, {counts['kbs']} KB")
        out = onto.save(resolve_path(args.output) if args.output else catalog)
        log.info("ingest", extra={"fields": {"catalog": str(out), **onto.stats()}})
        print(f"Catalog saved to {out}: {onto.stats()}")
        return 0

    if args.cmd == "ingest-cvrf":
        from .msrc import build_fixture, fetch_cvrf, load_cves

        if args.live:
            try:
                fixture = build_fixture(fetch_cvrf(args.live), args.live, date.today().isoformat())
            except RuntimeError as exc:
                raise CliError(str(exc)) from None
            target = resolve_path(args.from_file or f"fixtures/msrc/{args.live}.ws2022.json")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(fixture, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
            print(f"MSRC extract saved to {target} ({fixture['count']} CVEs).")
            cves = fixture["cves"]
        else:
            source = resolve_path(args.from_file or env("THANOS_MSRC_CVES", "fixtures/msrc/2026-Apr.ws2022.json"))
            if not source.exists():
                raise CliError(f"MSRC extract '{source}' does not exist (use --live 2026-Apr to download it)")
            cves = load_cves(source)
        onto = _load(catalog, required=False)
        result = onto.ingest_cvrf(cves)
        out = onto.save(resolve_path(args.output) if args.output else catalog)
        log.info("ingest_cvrf", extra={"fields": {"catalog": str(out), **result}})
        print(f"{result['cves']} Windows Server 2022 CVEs and {result['candidates']} candidate "
              f"CVE-to-binary links (hypotheses) in {out}")
        return 0

    onto = _load(catalog)
    if args.cmd == "stats":
        print(json.dumps({**onto.stats(), "cves": onto.cve_stats()}, indent=2, ensure_ascii=False))
        return 0
    if args.cmd == "changed":
        rows = onto.changed_binaries(args.cycle)
        print(json.dumps(rows, ensure_ascii=False, indent=2)) if args.json else _table(
            rows, ["name", "arch", "person", "prio", "score", "fn", "exp", "size"])
        return 0
    if args.cmd == "cves":
        rows = onto.cves_for_binary(args.binary)
        print(json.dumps(rows, ensure_ascii=False, indent=2)) if args.json else _table(
            rows, ["cve", "severity", "cvss", "confidence", "title"])
        return 0
    if args.cmd == "query":
        try:
            rows = onto.query(args.sparql)
        except Exception as exc:  # rdflib SPARQL syntax errors
            raise CliError(f"invalid SPARQL query: {str(exc).splitlines()[0][:200]}") from None
        if args.json or not rows:
            print(json.dumps(rows, indent=2, ensure_ascii=False, default=str))
        else:
            _table(rows, list(rows[0].keys()))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
