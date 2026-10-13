"""Structured logging for Thanos (RNF-08).

Each event is one JSON line on stderr (``{"ts", "level", "logger", "event", ...fields}``),
easy to filter with ``jq`` and enough to trace the pipeline: panel uploads, auditor
backend and fallback, ontology ingests, coordinator steps.

Usage::

    from thanos.log import get_logger, setup_logging
    setup_logging()                      # in every CLI / panel main()
    log = get_logger("panel")
    log.info("upload_accepted", extra={"fields": {"person": p, "sha256": h}})

The level comes from ``THANOS_LOG_LEVEL`` (default WARNING for the CLIs, so their output
stays clean; the panel uses INFO).
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone

_ROOT_LOGGER = "thanos"
_configured = False


class _JsonLinesFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="seconds"),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload.update(fields)
        if record.exc_info:
            payload["error"] = self.formatException(record.exc_info).splitlines()[-1]
        return json.dumps(payload, ensure_ascii=False, default=str)


def setup_logging(default_level: str = "WARNING") -> None:
    """Configure the ``thanos`` logger once, with JSON-lines output on stderr."""
    global _configured
    if _configured:
        return
    _configured = True
    level = os.environ.get("THANOS_LOG_LEVEL", default_level).upper()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_JsonLinesFormatter())
    root = logging.getLogger(_ROOT_LOGGER)
    root.addHandler(handler)
    root.setLevel(getattr(logging, level, logging.WARNING))
    root.propagate = False


def get_logger(name: str) -> logging.Logger:
    """Child of the ``thanos`` logger (e.g. ``get_logger("panel")`` -> ``thanos.panel``)."""
    return logging.getLogger(f"{_ROOT_LOGGER}.{name}")
