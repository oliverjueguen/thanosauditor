"""Thanos Auditor backends: ``heuristic`` (offline) and ``claude`` (Agent SDK).

The ``claude`` backend uses the user's own Claude session (subscription or, if set,
ANTHROPIC_API_KEY) through the Claude Agent SDK, isolated:

- ``tools=[]``: the model has NO tools at all (no shell, no files, no network); it
  can only return text. This is the main defense against prompt injection from the
  names extracted from binaries.
- ``strict_mcp_config=True`` and ``setting_sources=[]``: no MCP servers and no user or
  project settings are loaded.
- ``permission_mode="dontAsk"``: any tool request is denied (bypassPermissions is not
  used; it also fails when running as root).
- ``max_turns=1``: a single response.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any

from ..config import env
from ..core.aggregate import aggregate
from ..log import get_logger
from .prompts import SYSTEM_PROMPT, build_cycle_prompt
from .report import (
    REPORT_SCHEMA_VERSION,
    build_heuristic_report,
    candidates_for,
    cve_source,
    msrc_cves,
    validate_report,
)

log = get_logger("auditor")

# Extra defense: although tools=[] already leaves the model without tools, the Claude
# Code tools are explicitly denied in case a future version changes the default.
_DENIED_TOOLS = [
    "Bash", "Monitor", "Write", "Edit", "MultiEdit", "Read", "Glob", "Grep", "LS",
    "WebSearch", "WebFetch", "NotebookEdit", "TodoWrite", "Task", "Agent", "Skill",
]


def default_model() -> str:
    return env("THANOS_AUDITOR_MODEL", "claude-opus-5-5")


class AnalystError(RuntimeError):
    """Auditor error (missing SDK, no session, invalid response...)."""


def agent_options(model: str):
    """Agent SDK options with the auditor isolated (no tools)."""
    from claude_agent_sdk import ClaudeAgentOptions

    return ClaudeAgentOptions(
        model=model,
        system_prompt=SYSTEM_PROMPT,
        tools=[],
        disallowed_tools=_DENIED_TOOLS,
        permission_mode="dontAsk",
        strict_mcp_config=True,
        setting_sources=[],
        max_turns=1,
    )


def analyze(
    bundles: list[dict[str, Any]],
    *,
    backend: str = "heuristic",
    model: str | None = None,
    fallback: bool = True,
) -> dict[str, Any]:
    """Analyze the bundles and return the triage report (RF-16, RF-17).

    - ``backend="heuristic"``: deterministic, no LLM.
    - ``backend="claude"``: Claude via the Agent SDK, ONE query per cycle. If it fails
      and ``fallback=True``, it falls back to the heuristic and the warning includes
      the cause.
    """
    if backend == "heuristic":
        log.info("analysis", extra={"fields": {"backend": "heuristic"}})
        return build_heuristic_report(bundles)

    if backend == "claude":
        try:
            report = _analyze_with_claude(bundles, model or default_model())
            log.info("analysis", extra={"fields": {"backend": "claude"}})
            return report
        except AnalystError as exc:
            log.warning("claude_failed", extra={"fields": {"error": str(exc)[:300], "fallback": fallback}})
            if not fallback:
                raise
            report = build_heuristic_report(bundles)
            report["generated_by"] = "heuristic (fallback)"
            report["warning"] = (
                f"Could not use Claude: {exc}. Returning the heuristic triage. "
                "Check the session with `python -m thanos.auditor.cli status` "
                "(or log in with `... login`)."
            )
            return report

    raise ValueError(f"unknown backend: {backend!r} (use 'heuristic' or 'claude')")


def _analyze_with_claude(bundles: list[dict[str, Any]], model: str) -> dict[str, Any]:
    cycles = aggregate(bundles)
    if not cycles:
        raise AnalystError("no cycles to analyze")
    cves = msrc_cves()
    reports = []
    for cycle in cycles:
        print(
            f"Analyzing cycle '{cycle['patch_cycle']}' with Claude (~1 min)…",
            file=sys.stderr, flush=True,
        )
        candidates = {a["logical_name"]: candidates_for(a, cves) for a in cycle["artifacts"]}
        text = _query_claude(build_cycle_prompt(cycle, candidates), model)
        reports.append(_cycle_report(cycle, _parse_json(text), cves))
    if len(reports) == 1:
        return reports[0]
    return {"schema_version": REPORT_SCHEMA_VERSION, "generated_by": "claude", "cycles": reports}


def _query_claude(prompt: str, model: str) -> str:
    import asyncio

    try:
        from claude_agent_sdk import ResultMessage, query
    except ImportError as exc:
        raise AnalystError(
            "claude-agent-sdk is not installed; install it with: pip install -e \".[auditor]\""
        ) from exc

    async def _run() -> str:
        final, error = None, None
        async for message in query(prompt=prompt, options=agent_options(model)):
            if isinstance(message, ResultMessage):
                if getattr(message, "subtype", None) == "success":
                    final = message.result
                else:
                    error = getattr(message, "subtype", "error")
        if final is None:
            raise AnalystError(f"Claude did not return a valid response ({error or 'no result'})")
        return final

    try:
        return asyncio.run(_run())
    except AnalystError:
        raise
    except Exception as exc:  # credentials, network or CLI process
        raise AnalystError(f"failed to invoke Claude via the Agent SDK: {str(exc)[:300]}") from exc


def _cycle_report(cycle: dict[str, Any], report: Any, cves: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Validate the model response and add the trusted cycle metadata to it."""
    known = {a["logical_name"] for a in cycle["artifacts"]}
    errors = validate_report(report, known_binaries=known)
    if errors:
        raise AnalystError(f"Claude's response does not match the schema: {errors[:3]}")
    # The person is not sent to the model: it is reattached here by (binary, architecture).
    owners = {(a["logical_name"], a.get("arch", "")): a["person"] for a in cycle["artifacts"]}
    by_name = {a["logical_name"]: a["person"] for a in cycle["artifacts"]}
    arts = {(a["logical_name"], a.get("arch", "")): a for a in cycle["artifacts"]}
    for t in report["review_targets"]:
        key = (t["logical_name"], t.get("arch", ""))
        t["person"] = owners.get(key, by_name.get(t["logical_name"], ""))
        art = arts.get(key) or next(a for a in cycle["artifacts"] if a["logical_name"] == t["logical_name"])
        t["cve_candidates"] = candidates_for(art, cves or [])
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_by": "claude",
        "patch_cycle": cycle["patch_cycle"],
        "target_product": cycle.get("target_product", ""),
        "target_build": cycle.get("target_build", ""),
        "kb_ids": cycle.get("kb_ids", []),
        "cve_source": cve_source(),
        **{k: report[k] for k in ("summary", "review_targets", "findings", "open_questions", "next_artifacts")},
    }


def _parse_json(text: str) -> Any:
    """Extract a JSON value from the model response, tolerantly."""
    if not text or not text.strip():
        raise AnalystError("empty response from the model")
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
    candidate = fenced.group(1) if fenced else text
    if not candidate.lstrip().startswith("{"):
        start, end = candidate.find("{"), candidate.rfind("}")
        if start != -1 and end != -1:
            candidate = candidate[start : end + 1]
    try:
        return json.loads(candidate)
    except (ValueError, RecursionError) as exc:
        raise AnalystError(f"could not parse JSON from the response: {exc}") from exc
