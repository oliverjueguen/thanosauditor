"""Tests for the Thanos ontology (replaces Neo4j).

They cover RF-01 (queryable catalog), RF-06 (package key normalization)
and RNF-03 (lightweight, versionable ontology instead of Neo4j).
"""

from __future__ import annotations

from thanos.ontology import ThanosOntology
from thanos.ontology.namespaces import normalize_package_key


def test_schema_loads():
    """RNF-03: the schema (TBox) loads without a server, using only rdflib."""
    onto = ThanosOntology()
    assert len(onto.graph) > 0


def test_normalize_package_key_removes_version():
    """RF-06: the package key matches across months by removing the version."""
    before = "amd64_microsoft-onecore-bluetooth-service_31bf3856ad364e35_10.0.20348.4647_none_abc"
    after = "amd64_microsoft-onecore-bluetooth-service_31bf3856ad364e35_10.0.20348.5020_none_abc"
    assert normalize_package_key(before) == normalize_package_key(after)
    assert "20348" not in normalize_package_key(after)


def test_ingest_real_bundle(real_path):
    """RF-01: the real bundle (85 binaries) is loaded into the ontology."""
    onto = ThanosOntology()
    counts = onto.ingest_bundle_file(real_path)
    assert counts["binaries"] == 85
    stats = onto.stats()
    assert stats["PatchCycle"] == 1
    assert stats["KB"] == 2
    assert stats["Binary"] == 85


def test_ingest_two_people_dedups_cycle_and_kbs(real_path, synth_path):
    """RF-01: two bundles from the same cycle share the cycle and KBs, but each
    binary observation belongs to its person (deltas are not mixed)."""
    onto = ThanosOntology()
    onto.ingest_bundle_file(real_path)
    onto.ingest_bundle_file(synth_path)
    stats = onto.stats()
    assert stats["PatchCycle"] == 1
    assert stats["KB"] == 2
    assert stats["Binary"] == 85 + 3   # configmanager2.dll appears in both and is not merged


def test_ingest_all_real_bundles(real_paths):
    """RF-01: the two real bundles are two different runs (cycles) that share
    the same KB pair."""
    onto = ThanosOntology()
    for p in real_paths:
        onto.ingest_bundle_file(p)
    stats = onto.stats()
    assert stats["PatchCycle"] == 2      # "2026-04 Patch Tuesday" and "... FULL"
    assert stats["KB"] == 2              # same KB5078766 / KB5082142
    assert stats["Binary"] == 85 + 7
    rows = onto.query(
        "SELECT ?name WHERE { ?b thanos:logicalName ?name ; thanos:arch \"wow64\" }"
    )
    assert {r["name"] for r in rows} >= {"windows.media.protection.playready.dll"}


def test_changed_binaries_ranked_like_the_panel(real_path, real_bundle):
    """COR-08: the ontology ranking uses the same score as the dashboard."""
    from thanos.core import aggregate

    onto = ThanosOntology()
    onto.ingest_bundle_file(real_path)
    rows = onto.changed_binaries()
    assert len(rows) == 85
    panel_top = aggregate([real_bundle])[0]["artifacts"][0]
    assert rows[0]["name"] == panel_top["logical_name"] == "upnphost.dll"
    assert rows[0]["score"] == panel_top["score"] and rows[0]["prio"] == "P1"


def test_reingest_replaces_instead_of_accumulating(real_path):
    """COR-13: ingesting the same bundle twice does not duplicate values."""
    once = ThanosOntology()
    once.ingest_bundle_file(real_path)
    twice = ThanosOntology()
    twice.ingest_bundle_file(real_path)
    twice.ingest_bundle_file(real_path)
    assert twice.stats() == once.stats()


def test_supersedes_relation(real_path):
    """RF-02: the AFTER KB supersedes the BEFORE KB of the pair."""
    onto = ThanosOntology()
    onto.ingest_bundle_file(real_path)
    rows = onto.query("SELECT ?after ?before WHERE { ?after thanos:supersedes ?before }")
    assert len(rows) == 1
    assert rows[0]["after"].endswith("kb-kb5082142")
    assert rows[0]["before"].endswith("kb-kb5078766")


def test_save_and_reload(tmp_path, real_path):
    """RNF-03: the catalog is persisted as Turtle and reloads identically."""
    onto = ThanosOntology()
    onto.ingest_bundle_file(real_path)
    out = tmp_path / "catalog.ttl"
    onto.save(out)
    assert out.exists()

    reloaded = ThanosOntology()
    reloaded.load(out)
    assert reloaded.stats() == onto.stats()


def test_sparql_person_counts(real_path, synth_path, real_bundle, synth_bundle):
    """RF-01: the catalog can be queried with arbitrary SPARQL."""
    onto = ThanosOntology()
    onto.ingest_bundle_file(real_path)
    onto.ingest_bundle_file(synth_path)
    rows = onto.query(
        "SELECT ?person (COUNT(?b) AS ?n) WHERE "
        "{ ?b a thanos:Binary ; thanos:analyzedBy ?person } GROUP BY ?person"
    )
    counts = {r["person"]: r["n"] for r in rows}
    assert counts == {real_bundle["person"]: 85, synth_bundle["person"]: 3}
