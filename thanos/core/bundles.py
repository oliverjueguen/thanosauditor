"""Loading, validation and diffing of executor bundles (RF-12, RF-14, RF-15).

The bundle is the runner's only deliverable. This module defines its minimal
schema, validates it and computes the per-binary diff from the before/after
summaries Ghidra produced on each side of the pair.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..ontology.namespaces import normalize_package_key, package_arch
from .noise import filter_names, is_delay_load

# Required bundle-level fields (RF-15).
_REQUIRED_BUNDLE = ("patch_cycle", "target_build", "kb_ids", "artifacts")
# Required fields per artifact.
_REQUIRED_ARTIFACT = ("logical_name", "sha256_before", "sha256_after")


@dataclass
class ArtifactDiff:
    """Computed difference of a binary between BEFORE and AFTER."""

    logical_name: str
    person: str
    package_key: str = ""
    arch: str = ""
    version_before: str = ""
    version_after: str = ""
    sha256_before: str = ""
    sha256_after: str = ""
    size_delta: int = 0
    fn_delta: int = 0
    exp_delta: int = 0
    imp_delta: int = 0
    str_delta: int = 0
    notes: str = ""
    # Name diff (bundle `changes` section), already without Ghidra noise.
    has_name_diff: bool = False
    fn_added: list[str] = field(default_factory=list)
    fn_removed: list[str] = field(default_factory=list)
    exp_added: list[str] = field(default_factory=list)
    exp_removed: list[str] = field(default_factory=list)
    noise_filtered: int = 0
    # In P1 the executor only listed the names of part of the functions
    # (e.g. 512 of 14,749): the name diff is incomplete (70 of 85 binaries).
    name_diff_truncated: bool = False

    @property
    def changed(self) -> bool:
        """RF-12: the pair changed if the SHA-256 hashes differ."""
        return bool(self.sha256_before) and self.sha256_before != self.sha256_after

    @property
    def fn_changes(self) -> int:
        """Functions with a real name added + removed."""
        return len(self.fn_added) + len(self.fn_removed)

    @property
    def exp_changes(self) -> int:
        """Exports added + removed (by name, or by count if there are no names)."""
        return max(len(self.exp_added) + len(self.exp_removed), abs(self.exp_delta))

    @property
    def delay_loads_added(self) -> list[str]:
        return [n for n in self.fn_added if is_delay_load(n)]

    @property
    def delay_loads_removed(self) -> list[str]:
        return [n for n in self.fn_removed if is_delay_load(n)]

    @property
    def has_code_diff(self) -> bool:
        """There is an observable change in functions or exports (strong signal)."""
        return self.fn_changes > 0 or self.exp_changes > 0 or self.fn_delta != 0

def load_bundle(path: str | Path) -> dict[str, Any]:
    """Load a bundle.json from disk."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


_MAX_ERRORS = 20
_MAX_ARTIFACTS = 5000


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _str_ok(value: Any, max_len: int, *, required: bool = False) -> bool:
    if value is None:
        return not required
    return isinstance(value, str) and (not required or value.strip() != "") and len(value) <= max_len


def validate_bundle(bundle: Any) -> list[str]:
    """Return schema and type errors (empty list if the bundle is valid).

    Accepts any JSON value and never raises: the dashboard uses it to reject
    malformed uploads before storing them (RNF-05, RNF-06).
    """
    if not isinstance(bundle, dict):
        return ["the bundle must be a JSON object"]
    errors: list[str] = []
    for key in _REQUIRED_BUNDLE:
        if key not in bundle:
            errors.append(f"missing required field '{key}'")

    if "patch_cycle" in bundle and not _str_ok(bundle["patch_cycle"], 128, required=True):
        errors.append("'patch_cycle' must be a string of 1 to 128 characters")
    build = bundle.get("target_build")
    if "target_build" in bundle and not (_is_number(build) or _str_ok(build, 64, required=True)):
        errors.append("'target_build' must be a string or a number")
    for key in ("person", "run_id", "target_product"):
        if not _str_ok(bundle.get(key), 128):
            errors.append(f"'{key}' must be a string of at most 128 characters")
    for key in ("kb_ids", "cve_ids"):
        value = bundle.get(key, [])
        if not isinstance(value, list) or not all(_str_ok(v, 32, required=True) for v in value):
            errors.append(f"'{key}' must be a list of string identifiers")

    artifacts = bundle.get("artifacts", [])
    if not isinstance(artifacts, list):
        errors.append("'artifacts' must be a list")
        artifacts = []
    elif len(artifacts) > _MAX_ARTIFACTS:
        errors.append(f"'artifacts' has more than {_MAX_ARTIFACTS} items")
        artifacts = []
    for i, art in enumerate(artifacts):
        errors += _artifact_errors(i, art)
        if len(errors) >= _MAX_ERRORS:
            break

    changes = bundle.get("changes", [])
    if not isinstance(changes, list) or not all(isinstance(c, dict) for c in changes):
        errors.append("'changes' must be a list of objects")
    else:
        for i, ch in enumerate(changes):
            diff = ch.get("diff")
            if diff is not None and not isinstance(diff, dict):
                errors.append(f"changes[{i}].diff must be an object")
                continue
            for key in ("functions_added", "functions_removed", "exports_added", "exports_removed"):
                names = (diff or {}).get(key, [])
                if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
                    errors.append(f"changes[{i}].diff.{key} must be a list of strings")
    return errors[:_MAX_ERRORS]


def _artifact_errors(i: int, art: Any) -> list[str]:
    if not isinstance(art, dict):
        return [f"artifact[{i}] is not an object"]
    name = art.get("logical_name")
    label = name if isinstance(name, str) else "?"
    errors = []
    if not _str_ok(name, 260, required=True):
        errors.append(f"artifact[{i}]: 'logical_name' must be a string of 1 to 260 characters")
    for key in _REQUIRED_ARTIFACT[1:]:
        if not _str_ok(art.get(key), 128, required=True):
            errors.append(f"artifact[{i}] ('{label}'): '{key}' is missing or not a string")
    for key in ("kind", "package_id", "version_before", "version_after", "notes", "evidence_id"):
        if not _str_ok(art.get(key), 1024):
            errors.append(f"artifact[{i}] ('{label}'): '{key}' must be a string")
    for key in ("size_before", "size_after"):
        if key in art and art[key] is not None and not _is_number(art[key]):
            errors.append(f"artifact[{i}] ('{label}'): '{key}' must be a number")
    for key in ("summary_before", "summary_after"):
        summary = art.get(key, {})
        if summary is None:
            continue
        if not isinstance(summary, dict) or not all(_is_number(v) for v in summary.values()):
            errors.append(f"artifact[{i}] ('{label}'): '{key}' must be an object of numeric counters")
    return errors


_BUILD_RE = re.compile(r"^\d+\.\d+\.(\d+\.\d+)")


def target_build(bundle: dict[str, Any]) -> str:
    """Canonical target_build, always as a string.

    P1 bundles store it as a number (``20348.502``) because config.yaml had
    ``target_build: 20348.5020`` unquoted and YAML read it as a float, dropping the
    trailing zero. In that case it is derived from the most frequent AFTER version
    of the binaries (``10.0.20348.5020`` -> ``20348.5020``), which is what MSRC
    confirms for KB5082142. An explicit string is kept as is.
    """
    value = bundle.get("target_build", "")
    if isinstance(value, str) and value:
        return value
    builds = Counter(
        m.group(1)
        for art in bundle.get("artifacts", []) or []
        if isinstance(art, dict) and isinstance(art.get("version_after"), str)
        for m in [_BUILD_RE.match(art["version_after"])]
        if m
    )
    if builds:
        return builds.most_common(1)[0][0]
    return "" if value is None else str(value)


def lint_bundle(bundle: dict[str, Any]) -> list[str]:
    """Non-blocking warnings about a bundle (quality issues, not schema issues)."""
    warnings: list[str] = []
    raw = bundle.get("target_build")
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        warnings.append(
            f"numeric target_build ({raw!r}, unquoted YAML); using {target_build(bundle)!r} "
            "derived from version_after"
        )
    return warnings


def _delta(after: Any, before: Any) -> int:
    try:
        return int(after) - int(before)
    except (TypeError, ValueError):
        return 0


def _is_truncated(named: dict[str, Any], sb: dict[str, Any], sa: dict[str, Any]) -> bool:
    """The name diff covers fewer functions than Ghidra's total count."""
    for side, summary in (("before", sb), ("after", sa)):
        listed, total = named.get(f"{side}_function_count"), summary.get("function_count")
        if _is_number(listed) and _is_number(total) and listed < total:
            return True
    return False


def _changes_by_evidence(bundle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Index the `changes` section (name diff) by evidence_id and by binary."""
    index: dict[str, dict[str, Any]] = {}
    for ch in bundle.get("changes", []) or []:
        diff = ch.get("diff")
        if not isinstance(diff, dict):
            continue
        for ev in ch.get("evidence_ids", []) or []:
            index[f"ev:{ev}"] = diff
        if ch.get("binary"):
            index[f"bin:{ch['binary']}"] = diff
    return index


def artifact_diffs(bundle: dict[str, Any]) -> list[ArtifactDiff]:
    """Compute the diff of each artifact in the bundle (RF-14).

    If the bundle includes the `changes` section (function/export name diff), it
    is used as the main signal after filtering Ghidra's auto-generated names.
    """
    person = bundle.get("person") or bundle.get("run_id") or "unknown"
    changes = _changes_by_evidence(bundle)
    diffs: list[ArtifactDiff] = []
    for art in bundle.get("artifacts", []) or []:
        if art.get("kind") not in (None, "binary_metadata"):
            continue
        name = art.get("logical_name")
        if not name:
            continue
        sb = art.get("summary_before") or {}
        sa = art.get("summary_after") or {}

        named = changes.get(f"ev:{art.get('evidence_id')}") or changes.get(f"bin:{name}")
        name_fields: dict[str, Any] = {}
        if named is not None:
            noise = 0
            for key in ("functions_added", "functions_removed", "exports_added", "exports_removed"):
                real, dropped = filter_names(named.get(key, []))
                name_fields[key] = real
                noise += dropped
            name_fields = {
                "has_name_diff": True,
                "fn_added": name_fields["functions_added"],
                "fn_removed": name_fields["functions_removed"],
                "exp_added": name_fields["exports_added"],
                "exp_removed": name_fields["exports_removed"],
                "noise_filtered": noise,
                "name_diff_truncated": _is_truncated(named, sb, sa),
            }

        diffs.append(
            ArtifactDiff(
                **name_fields,
                logical_name=name,
                person=person,
                package_key=normalize_package_key(art.get("package_id", "")),
                arch=package_arch(art.get("package_id", "")),
                version_before=art.get("version_before", ""),
                version_after=art.get("version_after", ""),
                sha256_before=art.get("sha256_before", ""),
                sha256_after=art.get("sha256_after", ""),
                size_delta=_delta(art.get("size_after"), art.get("size_before")),
                fn_delta=_delta(sa.get("function_count"), sb.get("function_count")),
                exp_delta=_delta(sa.get("export_count"), sb.get("export_count")),
                imp_delta=_delta(sa.get("total_imports"), sb.get("total_imports")),
                str_delta=_delta(sa.get("string_count"), sb.get("string_count")),
                notes=art.get("notes", ""),
            )
        )
    return diffs
