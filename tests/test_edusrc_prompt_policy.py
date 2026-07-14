from __future__ import annotations

from app.agents.prompts import reviewer_system_prompt, worker_system_prompt


def test_edusrc_worker_uses_business_model_and_single_variable_method() -> None:
    prompt = worker_system_prompt("edusrc", "current")

    assert "业务建模" in prompt
    assert "单变量" in prompt
    assert "双测试账号" in prompt
    assert "身份、对象、功能、状态、数量、输出" in prompt
    assert "最小证据" in prompt
    assert "敏感信息泄露只认四类" not in prompt
    assert "字段敏感性" in prompt
    assert "业务必要性" in prompt


def test_edusrc_reviewer_uses_official_impact_based_grading() -> None:
    prompt = reviewer_system_prompt("edusrc")

    assert "严重 9~10" in prompt
    assert "高危 7~9" in prompt
    assert "中危 4~7" in prompt
    assert "低危 0~4" in prompt
    assert "敏感信息泄露只认四类" not in prompt
    assert "字段敏感性" in prompt
    assert "数据量" in prompt
    assert "业务必要性" in prompt


def test_edusrc_reviewer_checks_authenticity_environment_and_test_boundaries() -> None:
    prompt = reviewer_system_prompt("edusrc")

    assert "蜜罐" in prompt
    assert "夸大" in prompt
    assert "测试行为边界" in prompt
    assert "证据不足" in prompt
    assert "扫描器" in prompt
