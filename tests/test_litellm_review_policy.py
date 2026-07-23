from __future__ import annotations

from app.agents.prompts import reviewer_system_prompt


def test_litellm_reviewer_requires_structured_evidence() -> None:
    prompt = reviewer_system_prompt("litellm")
    for phrase in (
        "鉴权对照",
        "Provider 验证",
        "公开健康检查",
        "无 Key 可完成模型推理",
        "请求/响应必须成对",
        "伪 200",
        "WAF",
        "SPA",
        "掩码值",
    ):
        assert phrase in prompt


def test_litellm_reviewer_separates_models_from_inference_and_requires_secret_evidence() -> None:
    prompt = reviewer_system_prompt("litellm")
    assert "匿名模型列表" in prompt
    assert "匿名推理" in prompt
    assert "真实 Evidence" in prompt
    assert "Validator" in prompt
    assert "健康接口本身不成漏洞" in prompt


def test_non_litellm_reviewer_prompt_does_not_receive_gateway_policy() -> None:
    assert "匿名模型列表" not in reviewer_system_prompt("edusrc")
