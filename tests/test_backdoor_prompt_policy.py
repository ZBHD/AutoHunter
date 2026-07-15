from __future__ import annotations

import pytest

from app.agents.depth_policy import depth_policy_for
from app.agents.escalate import EscalateHunter
from app.agents.prompts import (
    collector_query_prompt,
    escalate_system_prompt,
    reviewer_system_prompt,
    worker_system_prompt,
)
from app.schemas import Finding
from app.tools.schemas import ESCALATE_TOOL_SCHEMAS, worker_tool_schemas


def _function_schema(schemas: list[dict], name: str) -> dict:
    return next(item["function"] for item in schemas if item["function"]["name"] == name)


@pytest.mark.parametrize(
    ("src_type", "version"),
    [
        ("edusrc", "current"),
        ("edusrc", "modern"),
        ("edusrc", "legacy"),
        ("enterprise", "current"),
    ],
)
def test_worker_profiles_share_backdoor_evidence_policy(src_type: str, version: str) -> None:
    prompt = worker_system_prompt(src_type, version)

    for marker in (
        "backdoor_compromised",
        "raw_request",
        "raw_response",
        "Cache-Control: no-cache",
        "redirect chain",
        "归属",
        "webshell",
        "可重复",
        "域名停放",
        "合法 SSO",
        "CDN/WAF",
        "历史缓存",
        "广告",
        "UGC",
        "iframe",
    ):
        assert marker in prompt


@pytest.mark.parametrize("src_type", ["edusrc", "enterprise"])
def test_reviewer_profiles_share_backdoor_decision_matrix(src_type: str) -> None:
    prompt = reviewer_system_prompt(src_type)

    for marker in (
        "backdoor_compromised",
        "当前复取",
        "响应来源",
        "高危 7~8",
        "严重 9~10",
        "初始入口",
        "accepted",
        "deepen",
        "ignored",
    ):
        assert marker in prompt
    assert "任何异常页面都 accepted" not in prompt


@pytest.mark.parametrize("src_type", ["edusrc", "enterprise"])
def test_collector_policy_is_gated_by_selected_type(src_type: str) -> None:
    backdoor_prompt = collector_query_prompt(src_type, ["backdoor_compromised"])
    ordinary_prompt = collector_query_prompt(src_type, ["idor"])

    assert "后门类型查询门槛" in backdoor_prompt
    assert "归属锚点" in backdoor_prompt
    assert "宽泛词" in backdoor_prompt
    assert "后门类型查询门槛" not in ordinary_prompt


@pytest.mark.parametrize("src_type", ["edusrc", "enterprise"])
def test_escalation_prompt_has_backdoor_root_cause_route(src_type: str) -> None:
    prompt = escalate_system_prompt(src_type)

    for marker in (
        "服务器被攻陷",
        "初始入口",
        "上传",
        "未授权管理面",
        "组件漏洞",
        "文件写入",
        "泄露凭证",
        "abandon_escalation",
    ):
        assert marker in prompt


def test_backdoor_escalation_brief_requests_new_root_cause_evidence() -> None:
    hunter = EscalateHunter.__new__(EscalateHunter)
    hunter.finding = {
        "severity": "高危",
        "title": "Example University - 首页被篡改",
        "vuln_type": "网页被篡改",
        "target_url": "https://example.test/",
        "raw_request": "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "raw_response": "HTTP/1.1 200 OK\r\n\r\nCasino page",
    }
    hunter.src_type = "edusrc"
    hunter.depth_policy = depth_policy_for("高危")
    hunter.max_rounds = hunter.depth_policy.escalation_rounds

    brief = hunter._brief()

    assert "后门/被攻陷专用目标" in brief
    assert "初始入口" in brief
    assert "新的 raw_request 和 raw_response" in brief
    assert "真正对应的漏洞类型" in brief
    assert "abandon_escalation" in brief


def test_non_backdoor_escalation_brief_keeps_generic_route() -> None:
    hunter = EscalateHunter.__new__(EscalateHunter)
    hunter.finding = {
        "severity": "高危",
        "title": "Example IDOR",
        "vuln_type": "idor",
        "target_url": "https://example.test/api/records/1",
    }
    hunter.src_type = "edusrc"
    hunter.depth_policy = depth_policy_for("高危")
    hunter.max_rounds = hunter.depth_policy.escalation_rounds

    assert "后门/被攻陷专用目标" not in hunter._brief()


def test_schema_examples_document_canonical_backdoor_type() -> None:
    finding_description = Finding.model_fields["vuln_type"].description or ""
    worker_schemas = worker_tool_schemas()
    duplicate_schema = _function_schema(worker_schemas, "check_duplicate_finding")
    submit_schema = _function_schema(worker_schemas, "submit_finding")
    escalation_schema = _function_schema(ESCALATE_TOOL_SCHEMAS, "submit_escalation")

    assert "backdoor_compromised" in finding_description
    assert "backdoor_compromised" in duplicate_schema["description"]
    assert "duplicate=true" in duplicate_schema["description"]
    assert "其它 endpoint/类型/证据链继续挖" in duplicate_schema["description"]
    assert "backdoor_compromised" in submit_schema["description"]
    assert "backdoor_compromised" in escalation_schema["description"]
