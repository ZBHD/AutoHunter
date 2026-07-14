from __future__ import annotations

import json

from app.agents.reviewer import Reviewer
from app.llm.protocols import LLMResponse, ToolCall
from app.schemas import Finding


class RecordingReviewerBackend:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def chat(self, messages, **kwargs):
        self.calls.append({"messages": messages, **kwargs})
        return LLMResponse(tool_calls=[
            ToolCall(
                id="review-1",
                name="submit_review",
                arguments=json.dumps({
                    "verdict": "ignored",
                    "confidence": "uncertain",
                    "severity_final": None,
                    "score": 1,
                    "in_scope": True,
                    "is_duplicate": False,
                    "ignore_reasons": ["insufficient evidence"],
                    "downgrade_reasons": [],
                    "reproduced": False,
                    "reviewer_notes": "not enough evidence",
                    "deepen_directive": "",
                }),
            )
        ])


def test_reviewer_injects_task_rules_once_in_system_policy() -> None:
    backend = RecordingReviewerBackend()
    marker = "CUSTOM-PROGRAM-RULE-314159"
    reviewer = Reviewer(
        backend,
        enable_reproduce=False,
        src_type="enterprise",
        src_rules=marker,
    )
    finding = Finding(
        vuln_type="idor",
        title="Example finding",
        severity_claimed="中危",
        target_url="https://example.test/item/1",
        description="Evidence under review",
        steps=["Request the item"],
        poc="curl https://example.test/item/1",
    )

    assert reviewer._llm_review(finding) is not None

    messages = backend.calls[0]["messages"]
    system_text = messages[0]["content"]
    user_text = "\n".join(item["content"] for item in messages[1:])
    assert system_text.count(marker) == 1
    assert marker not in user_text


def test_reviewer_caps_task_rules_at_eight_thousand_characters() -> None:
    backend = RecordingReviewerBackend()
    reviewer = Reviewer(
        backend,
        enable_reproduce=False,
        src_rules="RULE-BEGIN\n" + ("z" * 9000) + "\nRULE-END",
    )
    finding = Finding(
        vuln_type="idor",
        title="Example finding",
        severity_claimed="中危",
        target_url="https://example.test/item/1",
        description="Evidence under review",
        steps=["Request the item"],
        poc="curl https://example.test/item/1",
    )

    assert reviewer._llm_review(finding) is not None

    system_text = backend.calls[0]["messages"][0]["content"]
    custom = system_text.split("# 当前任务 SRC 规则", 1)[1]
    assert len(custom.strip()) <= 8000
    assert "RULE-BEGIN" in custom
    assert "RULE-END" not in custom
