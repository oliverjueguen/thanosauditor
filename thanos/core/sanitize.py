"""Bundle sanitization before publishing them to the repository (RNF-05).

Bundles produced by the runner store absolute local paths to the facts
(e.g. ``C:\\Users\\<user>\\Desktop\\thanos-<person>\\pipeline\\output\\...``),
which expose the Windows user name and the machine layout. This utility
replaces them with a neutral placeholder without touching any analysis data.

Usage::

    python -m thanos.core.sanitize input.bundle.json output.bundle.json
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

# Windows user profile prefix: C:\Users\<user>\[Desktop|Documents|Downloads\]
_USER_PATH_RE = re.compile(
    r"[A-Za-z]:\\+Users\\+[^\\]+\\+(?:(?:Desktop|Documents|Downloads|OneDrive)\\+)?",
    re.IGNORECASE,
)
PLACEHOLDER = "<runner>\\"


def sanitize_value(value: Any) -> tuple[Any, int]:
    """Sanitize recursively; return (sanitized value, number of substitutions)."""
    if isinstance(value, str):
        new, n = _USER_PATH_RE.subn(lambda _m: PLACEHOLDER, value)
        return new, n
    if isinstance(value, list):
        total, out = 0, []
        for v in value:
            nv, n = sanitize_value(v)
            out.append(nv)
            total += n
        return out, total
    if isinstance(value, dict):
        total, out = 0, {}
        for k, v in value.items():
            nv, n = sanitize_value(v)
            out[k] = nv
            total += n
        return out, total
    return value, 0


def sanitize_bundle(bundle: dict[str, Any]) -> tuple[dict[str, Any], int]:
    return sanitize_value(bundle)


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 2:
        print("usage: python -m thanos.core.sanitize <input.json> <output.json>", file=sys.stderr)
        return 2
    src, dst = Path(args[0]), Path(args[1])
    bundle = json.loads(src.read_text(encoding="utf-8"))
    clean, n = sanitize_bundle(bundle)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(clean, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"{n} local paths replaced with '{PLACEHOLDER}'. Saved to {dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
