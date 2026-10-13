"""Thanos web panel (FastAPI).

Uploads the team's bundles, infers the Patch Tuesday cycle and shows the aggregated
changed binaries with their criticality (RF-18, RF-19, RF-20). A locally installable
rebuild of the "Thanos Panel" from Practice 1 (P1).
"""

from .store import PanelStore

__all__ = ["PanelStore"]
