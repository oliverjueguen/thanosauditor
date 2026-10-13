"""Namespaces and URI minting utilities for the Thanos ontology."""

from __future__ import annotations

import re

from rdflib import Namespace

# Thanos ontology namespace (must match the `thanos:` prefix of the schema
# in thanos/ontology/thanos-schema.ttl).
THANOS = Namespace("https://thanos.evolve/ontology#")

_SLUG_RE = re.compile(r"[^a-z0-9]+")
# Version segment such as 10.0.20348.5020 inside an SXS package_id.
_VERSION_RE = re.compile(r"_\d+\.\d+\.\d+\.\d+_")
# Trailing hash of the SXS folder (16 hex), which also changes between releases.
_TRAILING_HASH_RE = re.compile(r"_[0-9a-f]{16}$", re.IGNORECASE)


def slug(value: str) -> str:
    """Normalize text into a safe URI fragment (lowercase, hyphens)."""
    value = (value or "").strip().lower()
    value = _SLUG_RE.sub("-", value)
    return value.strip("-") or "na"


_ARCHES = ("amd64", "wow64", "x86", "arm64", "arm", "msil")


def package_arch(package_id: str) -> str:
    """Architecture of the SXS package (package_id prefix): amd64, wow64, x86...

    The same DLL may ship in several packages (e.g. playready.dll in amd64 and in
    wow64); they are different binaries and must not be confused.
    """
    prefix = (package_id or "").split("_", 1)[0].lower()
    return prefix if prefix in _ARCHES else ""


def normalize_package_key(package_id: str) -> str:
    """Stable key of an SXS package_id across releases (RF-06).

    The SXS folder name includes the version (``..._10.0.20348.5020_...``) and a
    trailing hash (``..._none_94e481d2ef38b09b``), both different from month to month.
    Both are removed to match the same package across releases.
    """
    return _TRAILING_HASH_RE.sub("", _VERSION_RE.sub("_", package_id or ""))
