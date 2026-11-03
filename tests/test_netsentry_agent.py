import json
from pathlib import Path

import pytest

from scripts import netsentry_agent


def test_agent_prompts_for_access_log_and_keeps_token_out_of_command(tmp_path: Path, monkeypatch, capsys):
    log_path = tmp_path / "access.log"
    log_path.write_text("", encoding="utf-8")
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({
        "site_id": 42,
        "api_url": "https://api.example.test",
        "log_format": "jsonl",
    }), encoding="utf-8")
    collector_path = tmp_path / "generic_traffic_collector.py"
    collector_path.write_text("# collector", encoding="utf-8")
    captured = {}
    token = "test-only-one-time-key"

    monkeypatch.setattr(netsentry_agent, "CONFIG", config_path)
    monkeypatch.setattr(netsentry_agent, "COLLECTOR", collector_path)
    monkeypatch.setattr("builtins.input", lambda _prompt: str(log_path))
    monkeypatch.setattr(netsentry_agent.getpass, "getpass", lambda _prompt: token)
    monkeypatch.setattr(netsentry_agent.sys.stdin, "isatty", lambda: True)

    def fake_call(command, **kwargs):
        captured["command"] = command
        captured["environment"] = kwargs["env"].copy()
        return 0

    monkeypatch.setattr(netsentry_agent.subprocess, "call", fake_call)

    assert netsentry_agent.main() == 0
    assert token not in captured["command"]
    assert captured["environment"]["NETSENTRY_INGEST_TOKEN"] == token
    assert captured["command"][-2:] == ["--format", "jsonl"]
    assert token not in capsys.readouterr().out


def test_agent_refuses_to_prompt_for_token_without_interactive_terminal(tmp_path: Path, monkeypatch, capsys):
    log_path = tmp_path / "access.log"
    log_path.write_text("", encoding="utf-8")
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({
        "site_id": 42,
        "api_url": "https://api.example.test",
        "log_format": "jsonl",
    }), encoding="utf-8")
    monkeypatch.setattr(netsentry_agent, "CONFIG", config_path)
    monkeypatch.setattr("builtins.input", lambda _prompt: str(log_path))
    monkeypatch.setattr(netsentry_agent.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(
        netsentry_agent.getpass,
        "getpass",
        lambda _prompt: pytest.fail("The token prompt must not run without a terminal"),
    )

    with pytest.raises(SystemExit) as exit_error:
        netsentry_agent.main()

    assert exit_error.value.code == 2
    assert "interactive terminal" in capsys.readouterr().err


@pytest.mark.parametrize("api_url", [
    "http://collector.example.test",
    "https://user:password@api.example.test",
])
def test_agent_rejects_noncanonical_api_origins(tmp_path: Path, monkeypatch, capsys, api_url):
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({
        "site_id": 42,
        "api_url": api_url,
        "log_format": "jsonl",
    }), encoding="utf-8")
    monkeypatch.setattr(netsentry_agent, "CONFIG", config_path)

    with pytest.raises(SystemExit) as exit_error:
        netsentry_agent.main()

    assert exit_error.value.code == 2
    assert "api origin" in capsys.readouterr().err.lower()
