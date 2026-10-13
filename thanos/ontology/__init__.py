"""Thanos ontology: patch triage catalog (replaces Neo4j).

Exposes :class:`ThanosOntology`, an RDF/OWL graph that can be queried with SPARQL
and persisted as Turtle; the namespaces in :mod:`.namespaces`; and the ingestion of
real MSRC CVEs in :mod:`.msrc` (RF-01).

Imports are lazy: ``thanos.core`` uses :mod:`.namespaces` and the store uses
``thanos.core``, so importing the package must not load the store.
"""

from __future__ import annotations

__all__ = ["THANOS", "ThanosOntology"]


def __getattr__(name: str):
    if name == "THANOS":
        from .namespaces import THANOS
        return THANOS
    if name == "ThanosOntology":
        from .store import ThanosOntology
        return ThanosOntology
    raise AttributeError(name)
