"""Shared configuration: `.env` loading and project paths.

- :func:`load_env` loads ``.env`` (current directory first, then the project root)
  without overriding variables already exported. Every CLI and the panel call it, so
  what ``.env.example`` documents really reaches the code.
- :func:`project_root` and :func:`resolve_path` resolve relative paths against the
  project root, so commands work from any directory.
- :func:`env` reads a variable at call time (not at import time).
"""

from __future__ import annotations

import os
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_loaded = False


def project_root() -> Path:
    """Project root: the repository checkout (where ``pyproject.toml`` lives) or, when the
    package is installed without its sources (e.g. in the container), the current directory."""
    return _ROOT if (_ROOT / "pyproject.toml").is_file() else Path.cwd()


def load_env() -> None:
    """Load ``.env`` once; never overrides variables already set in the environment."""
    global _loaded
    if _loaded:
        return
    _loaded = True
    try:
        from dotenv import load_dotenv
    except ImportError:  # python-dotenv is a declared dependency; without it, skip
        return
    for candidate in (Path.cwd() / ".env", project_root() / ".env"):
        if candidate.is_file():
            load_dotenv(candidate, override=False)
            break


def env(name: str, default: str = "") -> str:
    """Value of an environment variable, read at call time."""
    return os.environ.get(name, default)


def resolve_path(value: str | os.PathLike[str]) -> Path:
    """Absolute path: if relative and missing from the cwd, resolve it from the project root."""
    path = Path(value)
    if path.is_absolute() or path.exists():
        return path
    return project_root() / path
