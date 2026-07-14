from __future__ import annotations

import pytest

from app.agents import escalate as escalate_module
from app.agents import killsweep as killsweep_module
from app.agents.prompts import killsweep_system_prompt, worker_system_prompt
from app.tools.guard import CommandBlocked, check_command
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
