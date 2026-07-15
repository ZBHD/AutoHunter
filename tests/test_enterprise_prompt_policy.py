from __future__ import annotations

import pytest

from app.agents import escalate as escalate_module
from app.agents import killsweep as killsweep_module
from app.agents.prompts import killsweep_system_prompt, worker_system_prompt
from app.tools.guard import (
    ENTERPRISE_ALLOWED_PARSERS,
    CommandBlocked,
    check_command,
    check_enterprise_command,
)
from app.tools.executor import ToolExecutor
from app.tools.local_parsers import parse_local_value
from app.tools.schemas import escalate_tool_schemas, worker_tool_schemas


def _tool_names(schemas: list[dict]) -> set[str]:
    return {item["function"]["name"] for item in schemas}


def test_enterprise_worker_has_a_distinct_precise_policy() -> None:
    enterprise = worker_system_prompt("enterprise", "current")
    education = worker_system_prompt("edusrc", "current")

    assert enterprise != education
    assert "禁止任何自动化漏洞扫描器" in enterprise
    assert "单请求" in enterprise
    assert "任务资产边界" in enterprise
    assert "扫描器只能" not in enterprise


def test_enterprise_killsweep_prompt_disallows_automated_scanners() -> None:
    prompt = killsweep_system_prompt("enterprise")

    assert "禁止任何自动化漏洞扫描器" in prompt
    assert "单请求" in prompt


def test_enterprise_tool_schemas_hide_automated_vulnerability_scanners() -> None:
    blocked = {"scan_nuclei", "verify_xss"}

    assert blocked.isdisjoint(_tool_names(worker_tool_schemas(enterprise=True)))
    assert blocked.isdisjoint(_tool_names(escalate_tool_schemas(enterprise=True)))
    assert blocked <= _tool_names(worker_tool_schemas(enterprise=False))


@pytest.mark.parametrize(
    "command",
    [
        "nuclei -u https://example.test",
        "sqlmap -u https://example.test/item?id=1 --batch",
        "dalfox url https://example.test/?q=x",
        "nikto -h https://example.test",
        "xray webscan --url https://example.test",
        "/opt/tools/pocsuite3 -u https://example.test",
        "nmap --script vuln -p 443 example.test",
        "docker run --rm projectdiscovery/nuclei:latest -u https://example.test",
    ],
)
def test_enterprise_shell_blocks_automated_vulnerability_scanners(command: str) -> None:
    with pytest.raises(CommandBlocked, match="自动化漏洞扫描"):
        check_command(command, enterprise=True)


def test_enterprise_shell_keeps_single_request_verification() -> None:
    check_command("curl -i https://example.test/api/me", enterprise=True)


def test_enterprise_command_returns_bounded_curl_argv() -> None:
    argv = check_enterprise_command(
        'curl -sS -i -X POST -H "Content-Type: application/json" '
        '--data-raw "{\\"probe\\":true}" --max-time 20 '
        'https://example.test/api/check',
        scope_target="https://example.test",
        allowed_parsers=ENTERPRISE_ALLOWED_PARSERS,
    )

    assert argv[0] == "curl"
    assert argv[-1] == "https://example.test/api/check"


@pytest.mark.parametrize(
    "command",
    [
        "curl https://outside.test/api",
        "curl -L https://example.test/login",
        "curl -K config.txt https://example.test/",
        "curl -o response.txt https://example.test/",
        'curl -H "Host: outside.test" https://example.test/',
        "curl --proxy http://proxy.test https://example.test/",
        "curl --resolve example.test:443:127.0.0.1 https://example.test/",
        "curl --max-time nan https://example.test/",
        "curl --data @local.txt https://example.test/",
        "curl -H @headers.txt https://example.test/",
        "curl https://example.test/ ; whoami",
        "curl https://example.test/$(whoami)",
        "curl https://example.test/ | python -m json.tool",
    ],
)
def test_enterprise_command_rejects_unregistered_or_scope_bypassing_curl(
    command: str,
) -> None:
    with pytest.raises(CommandBlocked):
        check_enterprise_command(
            command,
            scope_target="https://example.test",
            allowed_parsers=ENTERPRISE_ALLOWED_PARSERS,
        )


def test_enterprise_command_allows_only_fixed_local_parser_argv() -> None:
    assert check_enterprise_command(
        'python -m app.tools.local_parsers json --value "{\\"ok\\":true}"',
        scope_target="https://example.test",
        allowed_parsers=ENTERPRISE_ALLOWED_PARSERS,
    ) == (
        "python",
        "-m",
        "app.tools.local_parsers",
        "json",
        "--value",
        '{"ok":true}',
    )

    with pytest.raises(CommandBlocked):
        check_enterprise_command(
            "python -c print(1)",
            scope_target="https://example.test",
            allowed_parsers=ENTERPRISE_ALLOWED_PARSERS,
        )


def test_local_parser_modes_are_bounded_pure_transformations() -> None:
    assert parse_local_value("json", '{"b":2,"a":1}') == {"b": 2, "a": 1}
    assert parse_local_value("headers", "X-Test: yes\nContent-Type: text/plain") == {
        "x-test": "yes",
        "content-type": "text/plain",
    }
    assert parse_local_value("urlencode", "a/b c") == "a%2Fb%20c"

    with pytest.raises(ValueError, match="Header"):
        parse_local_value("headers", "missing-colon")


def test_enterprise_executor_runs_validated_argv_without_shell(tmp_path, monkeypatch) -> None:
    captured: dict = {}

    def fake_run_process(self, command, **kwargs):
        captured["command"] = command
        captured.update(kwargs)
        return {"ok": True, "output": "HTTP/1.1 200 OK"}

    monkeypatch.setattr(ToolExecutor, "_run_process", fake_run_process)
    executor = ToolExecutor(
        "https://example.test",
        work_dir=str(tmp_path),
        enterprise=True,
    )

    result = executor.run_shell("curl -i https://example.test/api/me")

    assert result["ok"] is True
    assert captured["command"] == ("curl", "-i", "https://example.test/api/me")
    assert captured["shell"] is False


def test_enterprise_local_parser_runs_from_worker_directory(tmp_path) -> None:
    result = ToolExecutor(
        "https://example.test",
        work_dir=str(tmp_path),
        enterprise=True,
    ).run_shell(
        'python -m app.tools.local_parsers urlencode --value "a/b c"'
    )

    assert result["ok"] is True
    assert '"value": "a%2Fb%20c"' in result["output"]


def test_enterprise_escalation_enables_executor_policy(monkeypatch) -> None:
    captured: dict = {}

    class FakeExecutor:
        def __init__(self, *_args, **kwargs) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(escalate_module, "ToolExecutor", FakeExecutor)
    escalate_module.EscalateHunter(
        {
            "severity": "高危",
            "title": "Example finding",
            "vuln_type": "idor",
            "target_url": "https://example.test",
        },
        llm=object(),
        src_type="enterprise",
    )

    assert captured["enterprise"] is True


def test_enterprise_killsweep_enables_executor_policy(monkeypatch) -> None:
    captured: dict = {}

    class FakeExecutor:
        def __init__(self, *_args, **kwargs) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(killsweep_module, "ToolExecutor", FakeExecutor)
    killsweep_module.KillsweepHunter(
        {
            "title": "Example finding",
            "target_url": "https://example.test",
            "raw_request": "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
        },
        fofa_key="",
        llm=object(),
        src_type="enterprise",
    )

    assert captured["enterprise"] is True


@pytest.mark.parametrize(
    "command",
    [
        "nuclei -u https://example.test",
        "dalfox url https://example.test/?q=x",
    ],
)
def test_enterprise_killsweep_enables_scanner_policy(monkeypatch, command: str) -> None:
    captured: dict = {}

    class FakeExecutor:
        def __init__(self, *_args, **kwargs) -> None:
            captured.update(kwargs)

        def run_shell(self, value: str, timeout=None) -> dict:
            try:
                check_command(value, enterprise=bool(captured.get("enterprise")))
            except CommandBlocked as exc:
                return {"ok": False, "blocked": True, "error": str(exc)}
            return {"ok": True, "blocked": False}

    monkeypatch.setattr(killsweep_module, "ToolExecutor", FakeExecutor)
    hunter = killsweep_module.KillsweepHunter(
        {"target_url": "https://example.test", "vuln_type": "idor"},
        fofa_key="",
        llm=object(),
        src_type="enterprise",
    )

    result = hunter._dispatch("run_shell", {"command": command})

    assert captured["enterprise"] is True
    shell_schema = next(
        schema for schema in hunter._tools
        if schema["function"]["name"] == "run_shell"
    )
    assert "扫描器" not in shell_schema["function"]["description"]
    assert result["blocked"] is True
    assert "自动化漏洞扫描" in result["error"]
