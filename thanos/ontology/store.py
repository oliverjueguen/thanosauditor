"""Thanos ontology store: construction, ingestion, querying and persistence.

The graph is queried with SPARQL and saved as Turtle. It replaces the Neo4j graph
from Practice 1 (P1) without needing a server or external service.
"""

from __future__ import annotations

import json
from decimal import Decimal
from importlib import resources
from pathlib import Path
from typing import Any

from rdflib import RDF, RDFS, Graph, Literal, URIRef
from rdflib.namespace import XSD

from ..core.bundles import artifact_diffs, target_build
from ..core.scoring import assess
from .namespaces import THANOS, slug

# The schema (TBox) ships inside the package (package data), so the ontology
# also works with a non-editable install (`pip install .`).
_SCHEMA_RESOURCE = "thanos-schema.ttl"


def default_schema_text() -> str:
    return resources.files(__package__).joinpath(_SCHEMA_RESOURCE).read_text(encoding="utf-8")


class ThanosOntology:
    """RDF/OWL graph of the patch triage catalog.

    Typical usage::

        onto = ThanosOntology()                 # loads the schema (TBox)
        onto.ingest_bundle(bundle_dict)          # populates from a bundle.json
        for row in onto.changed_binaries():      # query
            ...
        onto.save("data/ontology/catalog.ttl")   # persists as Turtle
    """

    def __init__(self, schema_path: str | Path | None = None, *, load_schema: bool = True):
        self.graph = Graph()
        self.graph.bind("thanos", THANOS)
        self.schema_path = Path(schema_path) if schema_path else None
        if load_schema:
            if self.schema_path is None:
                self.graph.parse(data=default_schema_text(), format="turtle")
            elif self.schema_path.exists():
                self.graph.parse(self.schema_path, format="turtle")
            else:
                raise FileNotFoundError(f"Ontology schema not found: {self.schema_path}")

    # ------------------------------------------------------------------ #
    # Construction helpers (minting individuals and asserting triples)
    # ------------------------------------------------------------------ #

    def _add(self, subject: URIRef, cls: URIRef, label: str | None = None) -> URIRef:
        self.graph.add((subject, RDF.type, cls))
        if label:
            self.graph.add((subject, RDFS.label, Literal(label)))
        return subject

    def _lit(self, subject: URIRef, prop: URIRef, value: Any, datatype=None) -> None:
        if value is None or value == "":
            return
        self.graph.add((subject, prop, Literal(value, datatype=datatype)))

    def cycle_uri(self, label: str) -> URIRef:
        return THANOS[f"cycle-{slug(label)}"]

    def kb_uri(self, kb_id: str) -> URIRef:
        return THANOS[f"kb-{slug(kb_id)}"]

    def cve_uri(self, cve_id: str) -> URIRef:
        return THANOS[f"cve-{slug(cve_id)}"]

    def binary_uri(
        self, cycle_label: str, logical_name: str, person: str, arch: str = ""
    ) -> URIRef:
        # Includes person and architecture: in P1 playready.dll appeared twice in the
        # same cycle (wow64 package for one executor and another package for another).
        # Each observation is its own node and deltas are not mixed.
        arch_part = f"{slug(arch)}-" if arch else ""
        return THANOS[f"bin-{slug(cycle_label)}-{slug(person)}-{arch_part}{slug(logical_name)}"]

    def package_uri(self, package_key: str) -> URIRef:
        return THANOS[f"pkg-{slug(package_key)}"]

    # ------------------------------------------------------------------ #
    # Ingestion from a bundle.json (executor deliverable, RF-15)
    # ------------------------------------------------------------------ #

    def _replace(self, subject: URIRef) -> None:
        """Delete an individual's triples before rewriting it (re-ingestion without accumulating)."""
        self.graph.remove((subject, None, None))

    def ingest_bundle(self, bundle: dict[str, Any]) -> dict[str, int]:
        """Populate the ontology from an executor bundle (re-ingesting replaces it).

        The score and priority of each binary are computed with the core
        (thanos.core.scoring), same as in the dashboard.
        """
        cycle_label = bundle.get("patch_cycle") or "unknown-cycle"
        person = bundle.get("person") or bundle.get("run_id") or "unknown"
        kb_ids: list[str] = bundle.get("kb_ids", []) or []
        cve_ids: list[str] = bundle.get("cve_ids", []) or []

        cycle = self.cycle_uri(cycle_label)
        self._replace(cycle)
        self._add(cycle, THANOS.PatchCycle, cycle_label)
        self._lit(cycle, THANOS.cycleLabel, cycle_label)
        self._lit(cycle, THANOS.targetProduct, bundle.get("target_product"))
        self._lit(cycle, THANOS.targetBuild, target_build(bundle))

        # Cycle KBs: the first is BEFORE (vulnerable) and the last is AFTER, which
        # supersedes BEFORE and is the one that fixes the CVEs (addressedBy only to AFTER).
        kb_uris = []
        for kb_id in kb_ids:
            kb = self._add(self.kb_uri(kb_id), THANOS.KB, kb_id)
            self._lit(kb, THANOS.kbId, kb_id)
            self.graph.add((kb, THANOS.partOfCycle, cycle))
            kb_uris.append(kb)
        if len(kb_uris) >= 2:
            self.graph.add((kb_uris[-1], THANOS.supersedes, kb_uris[0]))
        for cve_id in cve_ids:
            cve = self._add(self.cve_uri(cve_id), THANOS.CVE, cve_id)
            self._lit(cve, THANOS.cveId, cve_id)
            if kb_uris:
                self.graph.add((cve, THANOS.addressedBy, kb_uris[-1]))

        counts = {"cycles": 1, "kbs": len(kb_uris), "cves": len(cve_ids), "binaries": 0}
        for diff in artifact_diffs(bundle):
            counts["binaries"] += 1
            row = assess(diff)
            binary = self.binary_uri(cycle_label, diff.logical_name, person, diff.arch)
            self._replace(binary)
            self._add(binary, THANOS.Binary, diff.logical_name)
            self._lit(binary, THANOS.logicalName, diff.logical_name)
            self._lit(binary, THANOS.arch, diff.arch)
            self._lit(binary, THANOS.versionBefore, diff.version_before)
            self._lit(binary, THANOS.versionAfter, diff.version_after)
            self._lit(binary, THANOS.sha256Before, diff.sha256_before)
            self._lit(binary, THANOS.sha256After, diff.sha256_after)
            self._lit(binary, THANOS.analyzedBy, person)
            self.graph.add((binary, THANOS.changedInCycle, cycle))
            self._lit(binary, THANOS.sizeDelta, diff.size_delta, XSD.integer)
            self._lit(binary, THANOS.functionDelta, diff.fn_delta, XSD.integer)
            self._lit(binary, THANOS.exportDelta, diff.exp_delta, XSD.integer)
            self._lit(binary, THANOS.score, row["score"], XSD.integer)
            self._lit(binary, THANOS.priorityLabel, row["priority"])
            if diff.package_key:
                pkg = self._add(self.package_uri(diff.package_key), THANOS.Package)
                self._lit(pkg, THANOS.packageKey, diff.package_key)
                self.graph.add((pkg, THANOS.hasBinary, binary))
        return counts

    def ingest_bundle_file(self, path: str | Path) -> dict[str, int]:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return self.ingest_bundle(data)

    def ingest_cvrf(self, cves: list[dict[str, Any]]) -> dict[str, int]:
        """Populate real MSRC CVEs and CVE-to-binary candidates (RF-01).

        - CVE with title, severity, impact, CVSS, CWE, exploitation and fixed build.
        - addressedBy to the KB that fixes it; supersedes between KBs per MSRC.
        - For each already ingested binary, one Vulnerability individual per candidate
          CVE (confidence medium/low and its rationale: it is a hypothesis, not a
          mapping published by Microsoft).
        """
        from .msrc import match_cves

        for cve in cves:
            node = self.cve_uri(cve["cve"])
            self._replace(node)
            self._add(node, THANOS.CVE, cve["cve"])
            self._lit(node, THANOS.cveId, cve["cve"])
            self._lit(node, THANOS.title, cve.get("title"))
            self._lit(node, THANOS.msrcSeverity, cve.get("severity"))
            self._lit(node, THANOS.impact, cve.get("impact"))
            if cve.get("cvss") is not None:
                self._lit(node, THANOS.cvssBaseScore, cve["cvss"], XSD.decimal)
            self._lit(node, THANOS.cvssVector, cve.get("vector"))
            for cwe in cve.get("cwe", []):
                self._lit(node, THANOS.cwe, cwe)
            self._lit(node, THANOS.exploited, bool(cve.get("exploited")), XSD.boolean)
            self._lit(node, THANOS.fixedBuild, cve.get("fixed_build"))
            for kb_id in cve.get("kbs", []):
                kb = self._add(self.kb_uri(kb_id), THANOS.KB, kb_id)
                self._lit(kb, THANOS.kbId, kb_id)
                self.graph.add((node, THANOS.addressedBy, kb))
                for old in cve.get("supersedes", []):
                    prev = self._add(self.kb_uri(old), THANOS.KB, old)
                    self._lit(prev, THANOS.kbId, old)
                    self.graph.add((kb, THANOS.supersedes, prev))

        candidates = 0
        for binary in list(self.graph.subjects(RDF.type, THANOS.Binary)):
            name = str(self.graph.value(binary, THANOS.logicalName) or "")
            package = next((str(self.graph.value(pkg, THANOS.packageKey) or "")
                            for pkg in self.graph.subjects(THANOS.hasBinary, binary)), "")
            for vuln in list(self.graph.objects(binary, THANOS.hasVulnerability)):
                self._replace(vuln)
            self.graph.remove((binary, THANOS.hasVulnerability, None))
            for cand in match_cves(name, package, cves):
                vuln = THANOS[f"vuln-{binary.split('#')[-1]}-{slug(cand['cve'])}"]
                self._add(vuln, THANOS.Vulnerability)
                self.graph.add((vuln, THANOS.concernsCVE, self.cve_uri(cand["cve"])))
                self._lit(vuln, THANOS.confidence, cand["confidence"])
                self._lit(vuln, THANOS.rationale, cand["reason"])
                self.graph.add((binary, THANOS.hasVulnerability, vuln))
                candidates += 1
        return {"cves": len(cves), "candidates": candidates}

    # ------------------------------------------------------------------ #
    # Queries
    # ------------------------------------------------------------------ #

    def query(self, sparql: str) -> list[dict[str, Any]]:
        """Run SPARQL and return a list of dicts {variable: value}."""
        results = self.graph.query(sparql, initNs={"thanos": THANOS})
        rows: list[dict[str, Any]] = []
        for row in results:
            rows.append({str(var): _py(row[var]) for var in results.vars})
        return rows

    def changed_binaries(self, cycle_label: str | None = None) -> list[dict[str, Any]]:
        """Binaries that changed, sorted by the core score (like the dashboard)."""
        cycle_filter = ""
        if cycle_label:
            cycle_uri = self.cycle_uri(cycle_label).n3()
            cycle_filter = f"?bin thanos:changedInCycle {cycle_uri} ."
        sparql = f"""
        SELECT ?name ?arch ?person ?score ?prio ?fn ?exp ?size WHERE {{
            ?bin a thanos:Binary ;
                 thanos:logicalName ?name .
            {cycle_filter}
            OPTIONAL {{ ?bin thanos:arch          ?arch }}
            OPTIONAL {{ ?bin thanos:analyzedBy    ?person }}
            OPTIONAL {{ ?bin thanos:score         ?score }}
            OPTIONAL {{ ?bin thanos:priorityLabel ?prio }}
            OPTIONAL {{ ?bin thanos:functionDelta ?fn }}
            OPTIONAL {{ ?bin thanos:exportDelta   ?exp }}
            OPTIONAL {{ ?bin thanos:sizeDelta     ?size }}
        }}
        """
        rows = self.query(sparql)
        rows.sort(key=lambda r: (-(r.get("score") or 0), r.get("name") or ""))
        return rows

    _CANDIDATES_SPARQL = """
        SELECT DISTINCT ?name ?cve ?title ?severity ?impact ?cvss ?confidence ?reason WHERE {{
            ?bin thanos:logicalName ?name ; thanos:hasVulnerability ?v .
            {filter}
            ?v thanos:concernsCVE ?c ; thanos:confidence ?confidence ; thanos:rationale ?reason .
            ?c thanos:cveId ?cve .
            OPTIONAL {{ ?c thanos:title ?title }}
            OPTIONAL {{ ?c thanos:msrcSeverity ?severity }}
            OPTIONAL {{ ?c thanos:impact ?impact }}
            OPTIONAL {{ ?c thanos:cvssBaseScore ?cvss }}
        }}"""

    def cves_for_binary(self, logical_name: str) -> list[dict[str, Any]]:
        """Candidate CVEs (hypotheses) for a binary, with confidence and rationale."""
        name = Literal(logical_name).n3()
        rows = self.query(self._CANDIDATES_SPARQL.format(filter=f"FILTER(?name = {name})"))
        return sorted(rows, key=lambda r: (-(r.get("cvss") or 0), r["cve"]))

    def cve_candidates(self) -> dict[str, list[dict[str, Any]]]:
        """All CVE-to-binary candidates in the catalog, keyed by binary name (single query)."""
        index: dict[str, list[dict[str, Any]]] = {}
        for row in self.query(self._CANDIDATES_SPARQL.format(filter="")):
            index.setdefault(row.pop("name"), []).append(row)
        for rows in index.values():
            rows.sort(key=lambda r: (-(r.get("cvss") or 0), r["cve"]))
        return index

    def binary_names(self) -> set[str]:
        return {str(o) for o in self.graph.objects(None, THANOS.logicalName)}

    def cve_stats(self) -> dict[str, Any]:
        """Summary of the catalog CVEs by severity and impact."""
        rows = self.query("""
            SELECT ?severity ?impact (COUNT(?c) AS ?n) WHERE {
                ?c a thanos:CVE .
                OPTIONAL { ?c thanos:msrcSeverity ?severity }
                OPTIONAL { ?c thanos:impact ?impact }
            } GROUP BY ?severity ?impact""")
        by_sev: dict[str, int] = {}
        by_imp: dict[str, int] = {}
        for r in rows:
            by_sev[r.get("severity") or "?"] = by_sev.get(r.get("severity") or "?", 0) + r["n"]
            by_imp[r.get("impact") or "?"] = by_imp.get(r.get("impact") or "?", 0) + r["n"]
        return {"total": sum(by_sev.values()), "by_severity": by_sev, "by_impact": by_imp}

    def cycles(self) -> list[dict[str, Any]]:
        return self.query(
            """
            SELECT ?label ?product ?build (COUNT(?bin) AS ?binaries) WHERE {
                ?c a thanos:PatchCycle ; thanos:cycleLabel ?label .
                OPTIONAL { ?c thanos:targetProduct ?product }
                OPTIONAL { ?c thanos:targetBuild   ?build }
                OPTIONAL { ?bin thanos:changedInCycle ?c }
            } GROUP BY ?label ?product ?build
            """
        )

    def stats(self) -> dict[str, int]:
        """Individual count per class (useful for tests and the dashboard)."""
        out = {}
        for name in ("PatchCycle", "KB", "MSU", "Package", "Binary", "CVE", "Vulnerability"):
            n = len(list(self.graph.subjects(RDF.type, THANOS[name])))
            out[name] = n
        out["triples"] = len(self.graph)
        return out

    # ------------------------------------------------------------------ #
    # Persistence
    # ------------------------------------------------------------------ #

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.graph.serialize(destination=str(path), format="turtle")
        return path

    def load(self, path: str | Path) -> None:
        self.graph.parse(str(path), format="turtle")




def _py(value: Any) -> Any:
    """Convert an RDF term to a plain Python value."""
    if value is None:
        return None
    if isinstance(value, Literal):
        py = value.toPython()
        return float(py) if isinstance(py, Decimal) else py
    if isinstance(value, URIRef):
        return str(value)
    return str(value)

