"""Thanos Auditor: triage of the changed binaries (RF-16, RF-17).

Two backends:

- ``heuristic``: deterministic, no LLM. Uses the core scoring. Lets the pipeline
  and the panel run and be tested without Claude credentials (RNF-04).
- ``claude``: uses Claude via the Claude Agent SDK, with the Claude credentials the
  user has configured locally (subscription login or API key).

Both produce the same report schema (see :mod:`.report`).
"""

from .backends import analyze
from .report import REPORT_SCHEMA_VERSION, build_heuristic_report

__all__ = ["analyze", "build_heuristic_report", "REPORT_SCHEMA_VERSION"]
