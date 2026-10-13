"""Manifest diff by normalized package key (RF-06, Phase 4).

Joins two manifests (BEFORE/AFTER) on the key (SXS package without version or
trailing hash, DLL name), so the same binary is paired across months even when
the folders are named differently, and returns the pairs whose key exists in
both but with a different SHA-256. The result is the ``changed_manifest.json``
that feeds the split.

The key includes the DLL name because an SXS package often contains several
binaries (in the real split bundle, 6 DLLs share a package): indexing by package
alone collapsed them into one.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..cliutil import load_json_file
from ..ontology.namespaces import normalize_package_key

# A manifest is a list of entries:
#   {"logical_name": "...", "package_id": "...", "sha256": "..."}


class ManifestError(ValueError):
    """Manifest with duplicate or malformed entries."""


def load_manifest(path: str | Path) -> list[dict[str, Any]]:
    data = load_json_file(path)
    if isinstance(data, dict) and "entries" in data:
        data = data["entries"]
    if not isinstance(data, list) or not all(isinstance(e, dict) for e in data):
        raise ManifestError(f"'{path}' is not a manifest (list of entries)")
    return data


def entry_key(entry: dict[str, Any]) -> str:
    """Key that is stable across releases: normalized package + DLL name (lowercase)."""
    package = normalize_package_key(entry.get("package_id", ""))
    name = (entry.get("logical_name") or "").lower()
    return f"{package}/{name}" if package else name


def _index_by_key(manifest: list[dict[str, Any]], side: str) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for entry in manifest:
        key = entry_key(entry)
        if not key:
            raise ManifestError(f"entry without package_id or logical_name in the {side} manifest")
        if key in index:
            raise ManifestError(f"duplicate key in the {side} manifest: {key}")
        index[key] = entry
    return index


def diff_manifests(
    before: list[dict[str, Any]], after: list[dict[str, Any]]
) -> dict[str, Any]:
    """Return the changed_manifest: pairs present in both with a different SHA-256.

    Output structure::

        {
          "changed": [{"key","logical_name","package_before","package_after",
                       "sha256_before","sha256_after"}],
          "only_before": [key, ...],
          "only_after":  [key, ...],
          "unchanged":   n,
        }
    """
    bi, ai = _index_by_key(before, "BEFORE"), _index_by_key(after, "AFTER")
    bkeys, akeys = set(bi), set(ai)

    changed = []
    unchanged = 0
    for key in sorted(bkeys & akeys):
        be, ae = bi[key], ai[key]
        if be.get("sha256") != ae.get("sha256"):
            changed.append(
                {
                    "key": key,
                    "logical_name": ae.get("logical_name") or be.get("logical_name", ""),
                    "package_before": be.get("package_id", ""),
                    "package_after": ae.get("package_id", ""),
                    "sha256_before": be.get("sha256", ""),
                    "sha256_after": ae.get("sha256", ""),
                }
            )
        else:
            unchanged += 1

    return {
        "changed": changed,
        "only_before": sorted(bkeys - akeys),
        "only_after": sorted(akeys - bkeys),
        "unchanged": unchanged,
    }


def manifests_from_bundle(bundle: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """BEFORE/AFTER manifests derived from a real bundle (for the reproducible demo).

    The BEFORE package carries the previous version in its name, as in the SXS store.
    """
    before, after = [], []
    for art in bundle.get("artifacts", []):
        package = art.get("package_id", "")
        version_before = (art.get("version_before") or "").split(" ")[0]
        version_after = (art.get("version_after") or "").split(" ")[0]
        package_before = package.replace(version_after, version_before) if version_after and version_before else package
        before.append({"logical_name": art["logical_name"], "package_id": package_before,
                       "sha256": art["sha256_before"]})
        after.append({"logical_name": art["logical_name"], "package_id": package, "sha256": art["sha256_after"]})
    return before, after
