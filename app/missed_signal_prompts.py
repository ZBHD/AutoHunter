"""No-tool prompt and parser for missed-signal report drafts."""
from __future__ import annotations

import json
import re
from typing import Any, Mapping


DRAFT_SYSTEM_PROMPT = """你是 AutoHunter 的报告草稿整理器，只能整理系统已经持久化的证据。

硬性约束：
1. 不得调用任何工具、不得发起网络请求、不得建议后台替你继续探测。
2. 不得编造请求、响应、账号、数据样本、复现结果、归属单位或危害。
3. raw_request 与 raw_response 必须来自同一次现有证据；不能确认时填写“待补充”。
4. PoC 必须能由现有请求推导且可复现；证据不足时填写“待补充”。
5. owner 必填；无法从证据确认时写“待确认（现有证据无法确认归属）”。
6. 描述实际观察到的影响，不把“可能”写成已经发生的事实。
7. kill_chain 只记录真实的侦察、定位、利用、取证步骤。
8. 所有缺失事实都放入 missing_evidence，禁止用常识补齐。

只返回一个 JSON 对象，不要 Markdown 代码块。字段必须为：
{
  "title": "",
  "vuln_type": "",
  "severity": "严重|高危|中危|低危",
  "owner": "",
  "target_url": "",
  "description": "",
  "affected_scope": "",
  "steps": [""],
  "poc": "",
  "raw_request": "",
  "raw_response": "",
  "evidence": {"extracted_data_sample": "", "tool_output": "", "notes": ""},
  "kill_chain": [{"method": "", "detail": ""}],
  "missing_evidence": [""]
}
"""


def build_draft_messages(
    signal: Mapping[str, Any],
    evidence: list[Mapping[str, Any]],
) -> list[dict[str, str]]:
    payload = {
        "signal": dict(signal),
        "stored_evidence": [dict(item) for item in evidence],
        "instruction": "仅按上述已保存内容生成可人工编辑的报告草稿。",
    }
    return [
        {"role": "system", "content": DRAFT_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": json.dumps(payload, ensure_ascii=False, indent=2, default=str),
        },
    ]


def _extract_json(text: str) -> dict[str, Any]:
    value = str(text or "").strip()
    if value.startswith("```"):
        value = re.sub(r"^```(?:json)?\s*", "", value, flags=re.I)
        value = re.sub(r"\s*```$", "", value)
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        start = value.find("{")
        end = value.rfind("}")
        if start < 0 or end <= start:
            raise ValueError("LLM 未返回有效 JSON 草稿") from None
        try:
            parsed = json.loads(value[start : end + 1])
        except json.JSONDecodeError as exc:
            raise ValueError("LLM 未返回有效 JSON 草稿") from exc
    if not isinstance(parsed, dict):
        raise ValueError("LLM 草稿必须是 JSON 对象")
    nested = parsed.get("finding")
    if isinstance(nested, dict):
        merged = dict(nested)
        if "missing_evidence" not in merged:
            merged["missing_evidence"] = parsed.get("missing_evidence", [])
        return merged
    return parsed


_SEVERITY = {
    "critical": "严重",
    "严重": "严重",
    "high": "高危",
    "高危": "高危",
    "medium": "中危",
    "中危": "中危",
    "low": "低危",
    "低危": "低危",
}


def normalize_draft_content(
    value: Mapping[str, Any],
    *,
    defaults: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    source = dict(value)
    base = dict(defaults or {})
    if "severity" not in source and "severity_claimed" in source:
        source["severity"] = source.get("severity_claimed")

    scalar_fields = (
        "title",
        "vuln_type",
        "owner",
        "target_url",
        "description",
        "affected_scope",
        "poc",
        "raw_request",
        "raw_response",
    )
    content: dict[str, Any] = {}
    for field in scalar_fields:
        current = source.get(field, base.get(field, ""))
        content[field] = str(current or "").strip()

    severity = str(source.get("severity") or base.get("severity") or "中危").strip()
    content["severity"] = _SEVERITY.get(severity.lower(), _SEVERITY.get(severity, "中危"))

    steps = source.get("steps", base.get("steps", []))
    content["steps"] = [str(item).strip() for item in steps if str(item).strip()] if isinstance(steps, list) else []
    evidence = source.get("evidence", base.get("evidence", {}))
    content["evidence"] = dict(evidence) if isinstance(evidence, Mapping) else {}
    chain = source.get("kill_chain", base.get("kill_chain", []))
    content["kill_chain"] = [dict(item) for item in chain if isinstance(item, Mapping)] if isinstance(chain, list) else []

    missing = source.get("missing_evidence", [])
    missing_items = [str(item).strip() for item in missing if str(item).strip()] if isinstance(missing, list) else []
    required = {
        "title": "漏洞标题",
        "vuln_type": "漏洞类型",
        "owner": "归属单位",
        "target_url": "目标 URL",
        "description": "漏洞描述",
        "poc": "可复现 PoC",
        "raw_request": "同次原始请求",
        "raw_response": "同次原始响应",
    }
    for field, label in required.items():
        text = content[field]
        if not text or text == "待补充":
            missing_items.append(label)
    if not content["steps"]:
        missing_items.append("复现步骤")
    missing_items = list(dict.fromkeys(missing_items))
    return content, missing_items


def parse_draft_response(
    text: str,
    *,
    defaults: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    return normalize_draft_content(_extract_json(text), defaults=defaults)


__all__ = [
    "DRAFT_SYSTEM_PROMPT",
    "build_draft_messages",
    "normalize_draft_content",
    "parse_draft_response",
]
