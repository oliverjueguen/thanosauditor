"""Before/after binary pairing and discarding of identical pairs (RF-12).

Walks `input/before` and `input/after` pairing by file name, computes the SHA-256
of each side and discards the pairs whose content has not changed (same hash),
since they add nothing to the analysis.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Pair:
    name: str
    before: Path
    after: Path
    sha_before: str
    sha_after: str

    @property
    def changed(self) -> bool:
        return self.sha_before != self.sha_after


def sha256_file(path: str | Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def pair_binaries(before_dir: str | Path, after_dir: str | Path) -> list[Pair]:
    """Pair the files present in both directories by name (case-insensitive, like the
    Windows file system); hidden files (.keep) are ignored."""
    before_dir, after_dir = Path(before_dir), Path(after_dir)

    def _index(folder: Path) -> dict[str, Path]:
        return {p.name.casefold(): p for p in folder.glob("*") if p.is_file() and not p.name.startswith(".")}

    before, after = _index(before_dir), _index(after_dir)
    pairs: list[Pair] = []
    for key in sorted(set(before) & set(after)):
        name = after[key].name
        pairs.append(
            Pair(
                name=name,
                before=before[key],
                after=after[key],
                sha_before=sha256_file(before[key]),
                sha_after=sha256_file(after[key]),
            )
        )
    return pairs


def changed_pairs(pairs: list[Pair]) -> list[Pair]:
    """Keep only the pairs whose SHA-256 differs (RF-12)."""
    return [p for p in pairs if p.changed]
