"""Operational tests: structured logging (RNF-08) and Claude session (RNF-09)."""

from __future__ import annotations

import json
import logging


def test_log_lines_are_json(capsys):
    """RNF-08: each event is emitted as one JSON line with its fields."""
    from thanos.log import _JsonLinesFormatter

    record = logging.LogRecord("thanos.panel", logging.INFO, __file__, 1, "upload", None, None)
    record.fields = {"added": 2, "skipped": 1}
    line = json.loads(_JsonLinesFormatter().format(record))
    assert line["event"] == "upload" and line["logger"] == "thanos.panel"
    assert line["added"] == 2 and line["level"] == "INFO" and "ts" in line


def test_login_and_status_use_the_claude_cli(monkeypatch, tmp_path):
    """RNF-09: 'login' opens the subscription login and 'status' shows the session."""
    import thanos.auditor.cli as cli

    fake = tmp_path / "claude"
    fake.write_text("")
    calls = []
    monkeypatch.setattr(cli, "claude_cli", lambda: fake)
    monkeypatch.setattr(cli.subprocess, "call", lambda args: calls.append(args) or 0)
    assert cli.main(["login"]) == 0
    assert cli.main(["status"]) == 0
    assert calls == [[str(fake), "auth", "login", "--claudeai"], [str(fake), "auth", "status", "--text"]]


def test_status_warns_when_api_key_overrides_subscription(monkeypatch, tmp_path, capsys):
    import thanos.auditor.cli as cli

    monkeypatch.setattr(cli, "claude_cli", lambda: tmp_path / "claude")
    monkeypatch.setattr(cli.subprocess, "call", lambda args: 0)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    cli.main(["status"])
    assert "takes precedence over the subscription" in capsys.readouterr().err


def test_login_without_cli_is_a_clear_error(monkeypatch, capsys):
    import thanos.auditor.cli as cli

    monkeypatch.setattr(cli, "claude_cli", lambda: None)
    assert cli.main(["login"]) == 2
    assert "pip install" in capsys.readouterr().err
