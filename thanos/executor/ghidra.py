"""Runs Ghidra headless on a binary and reads its facts (RF-13).

Launches ``analyzeHeadless`` (``analyzeHeadless.bat`` on Windows) with a temporary
project, imports the binary, runs the ``ExportFacts.java`` post-script (in
``thanos/executor/ghidra_scripts``) and returns the facts JSON:

    library_count, total_imports, export_count, function_count, string_count,
    functions [names], exports [names]

In P1 this phase was driven by Claude Code through a Ghidra MCP; in P3
analyzeHeadless is invoked directly from Python (no intermediaries), which makes it
reproducible and testable.
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404 - only used to launch analyzeHeadless
import tempfile
from importlib import resources
from pathlib import Path
from typing import Any

DEFAULT_TIMEOUT = 1800   # seconds per binary (large DLLs take several minutes)


class GhidraError(RuntimeError):
    """Failure locating or running Ghidra headless."""


def analyze_headless(support_dir: str | Path) -> Path:
    """Path to analyzeHeadless inside Ghidra's ``support`` folder."""
    exe = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    path = Path(support_dir) / exe
    if not path.is_file():
        raise GhidraError(
            f"analyzeHeadless not found in '{support_dir}'. Check ghidra_support_dir in config.yaml "
            "(it must be the 'support' folder of the Ghidra installation)."
        )
    return path


def scripts_dir() -> Path:
    return Path(str(resources.files(__package__).joinpath("ghidra_scripts")))


def ghidra_facts(
    support_dir: str | Path,
    binary: str | Path,
    *,
    java_home: str | Path | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Analyze ``binary`` with Ghidra headless and return its facts.

    Ghidra needs a JDK (a JRE is not enough): taken from ``java_home`` or JAVA_HOME.
    """
    exe = analyze_headless(support_dir)
    binary = Path(binary)
    env = dict(os.environ)
    if java_home:
        # The Ghidra launcher finds the JDK from the `java` on PATH: prepend the JDK's one.
        env["JAVA_HOME"] = str(java_home)
        env["PATH"] = str(Path(java_home) / "bin") + os.pathsep + env.get("PATH", "")
    with tempfile.TemporaryDirectory(prefix="thanos-ghidra-") as tmp:
        out = Path(tmp) / "facts.json"
        cmd = [
            str(exe), tmp, "thanos",
            "-import", str(binary),
            # Only the binary matters: do not import its dependent DLLs (with System32 in the
            # same folder, Ghidra would load dozens of libraries and take forever).
            "-loader", "PeLoader",
            "-loader-loadLocalLibraries", "false",
            "-loader-loadSystemLibraries", "false",
            "-scriptPath", str(scripts_dir()),
            "-postScript", "ExportFacts.java", str(out),
            "-deleteProject",
            "-analysisTimeoutPerFile", str(timeout),
        ]
        try:
            # Argument list without a shell; the executable is analyzeHeadless from the configured path.
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 300, env=env)  # nosec B603
        except subprocess.TimeoutExpired as exc:
            raise GhidraError(f"Ghidra timed out on {binary.name}") from exc
        except OSError as exc:
            raise GhidraError(f"could not launch analyzeHeadless: {exc}") from exc
        if not out.is_file():
            log = (proc.stdout + proc.stderr).strip()
            if "JDK" in log and "JAVA_HOME" not in env:
                raise GhidraError("Ghidra cannot find a JDK 17+: set JAVA_HOME or java_home in config.yaml")
            tail = "\n".join(log.splitlines()[-5:])
            raise GhidraError(f"Ghidra produced no facts for {binary.name} (rc={proc.returncode}): {tail}")
        try:
            return json.loads(out.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise GhidraError(f"unreadable facts for {binary.name}: {exc}") from exc
