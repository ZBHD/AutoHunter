from __future__ import annotations

import json

from app.agents.collector import _with_edusrc_scope_filter
from app.agents.collector_llm import judge_edu_batch
from app.agents.prompts import collector_query_prompt, collector_scope_note
from app.llm.protocols import LLMResponse, ToolCall
from app.tools.schemas import COLLECTOR_EDU_SCHEMAS


class EduJudgeBackend:
    def chat(self, _messages, **_kwargs):
        return LLMResponse(tool_calls=[
            ToolCall(
                id="judge-1",
                name="judge_edu",
                arguments=json.dumps({
                    "results": [{
                        "index": 0,
                        "is_edu": True,
                        "school": "Example University",
                        "reason": "certificate and university title agree",
                    }]
                }),
            )
        ])


def test_edusrc_collector_uses_multiple_scope_anchors() -> None:
    text = collector_query_prompt("edusrc") + collector_scope_note("edusrc")

    assert "domain" in text
    assert "cert" in text
    assert "org" in text
    assert "title" in text
    assert '必须带 && org="China Education and Research Network Center"' not in text
    assert "至少一类教育归属锚点" in text


def test_judge_edu_schema_and_parser_preserve_reason() -> None:
    result_schema = COLLECTOR_EDU_SCHEMAS[0]["function"]["parameters"]["properties"]["results"]["items"]
    assert "reason" in result_schema["properties"]

    result = judge_edu_batch(EduJudgeBackend(), [{"host": "example.edu.cn"}])
    assert result[0] == {
        "is_edu": True,
        "school": "Example University",
        "reason": "certificate and university title agree",
    }


def test_runtime_edusrc_scope_fallback_uses_multiple_anchors() -> None:
    scoped = _with_edusrc_scope_filter('body="Swagger UI"')

    assert 'domain=".edu.cn"' in scoped
    assert 'cert="edu.cn"' in scoped
    assert 'org="China Education and Research Network Center"' in scoped
    assert "||" in scoped
