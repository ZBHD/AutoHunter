import pytest

from app.agents import worker as worker_module
from app.agents.prompt_releases import (
    CANDIDATE_RELEASE_ID,
    COMPILED_STABLE_RELEASE_ID,
    LEGACY_RELEASE_ID,
    get_prompt_release,
    render_candidate_route_block,
)


class _FakeExecutor:
    def __init__(self, *_args, **_kwargs) -> None:
        pass


@pytest.mark.parametrize(
    ("signal", "heading", "minimum_evidence"),
    [
        (
            "callback_url webhook proxy preview image_url",
            "SSRF",
            "服务端请求差异",
        ),
        (
            "SOAP XML Office 富文本导入",
            "XXE/解析",
            "解析行为差异",
        ),
        (
            "Shiro Fastjson ViewState Dubbo Java serialization",
            "反序列化",
            "可重复的解析或执行证据",
        ),
        (
            "JWT Authorization Bearer",
            "Token/身份边界",
            "实际获得不同身份或受限资源",
        ),
    ],
)
def test_candidate_injects_only_matching_short_route(
    signal: str,
    heading: str,
    minimum_evidence: str,
) -> None:
    block = render_candidate_route_block(
        get_prompt_release(CANDIDATE_RELEASE_ID),
        signal,
    )

    assert heading in block
    assert minimum_evidence in block
    assert len(block) < 1800


@pytest.mark.parametrize("release_id", [COMPILED_STABLE_RELEASE_ID, LEGACY_RELEASE_ID])
def test_non_candidate_release_never_adds_conditional_route(release_id: str) -> None:
    block = render_candidate_route_block(
        get_prompt_release(release_id),
        "webhook SOAP Fastjson JWT",
    )

    assert block == ""


def test_signal_free_candidate_adds_no_route() -> None:
    block = render_candidate_route_block(
        get_prompt_release(CANDIDATE_RELEASE_ID),
        "普通首页 static web home",
    )

    assert block == ""


def test_worker_uses_pinned_candidate_release_for_conditional_route(monkeypatch) -> None:
    monkeypatch.setattr(worker_module, "ToolExecutor", _FakeExecutor)
    worker = worker_module.Worker(
        "https://example.test/api?callback_url=[TARGET]",
        llm=object(),
        target_meta={"title": "Webhook preview"},
        prompt_release_id=CANDIDATE_RELEASE_ID,
        prompt_cohort="candidate",
    )

    assert "SSRF" in worker._playbook_block()
    assert worker.prompt_release_id == CANDIDATE_RELEASE_ID
    assert worker.prompt_cohort == "candidate"


def test_worker_stable_release_keeps_existing_playbook_unchanged(monkeypatch) -> None:
    monkeypatch.setattr(worker_module, "ToolExecutor", _FakeExecutor)
    worker = worker_module.Worker(
        "https://example.test/api?callback_url=[TARGET]",
        llm=object(),
        target_meta={"playbook_block": "# Existing route\n"},
        prompt_release_id=COMPILED_STABLE_RELEASE_ID,
        prompt_cohort="stable",
    )

    assert worker._playbook_block() == "# Existing route\n"
