"""Shared CLI helpers: one-line errors, glob expansion and UTF-8 output.

On bad input (missing file, glob with no matches, corrupt JSON) the CLIs print a clear
message to stderr and exit with code 2, never a traceback (RNF-06).
"""

from __future__ import annotations

import glob
import json
import sys
from pathlib import Path
from typing import Any

from .config import resolve_path


class CliError(Exception):
    """Usage or input error: printed on one line, the CLI exits with code 2."""


def utf8_stdout() -> None:
    """Avoid UnicodeEncodeError when output is piped on Windows consoles (cp1252)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            reconfigure(encoding="utf-8", errors="replace")


def expand_files(patterns: list[str]) -> list[Path]:
    """Expand globs; clear error when a pattern matches no file."""
    files: list[Path] = []
    for pattern in patterns:
        matched = sorted(glob.glob(pattern)) or sorted(glob.glob(str(resolve_path(pattern))))
        if not matched:
            raise CliError(f"no file matches '{pattern}'")
        files.extend(Path(m) for m in matched)
    return files


def load_json_file(path: str | Path) -> Any:
    """Load JSON with one-line errors (missing, unreadable or corrupt file)."""
    path = Path(path)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise CliError(f"file not found: '{path}'") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise CliError(f"cannot read '{path}': {exc}") from None
    except (ValueError, RecursionError) as exc:
        raise CliError(f"'{path}' is not valid JSON: {exc}") from None


def fail(message: str, code: int = 2) -> int:
    print(f"error: {message}", file=sys.stderr)
    return code
