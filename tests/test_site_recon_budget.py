import inspect
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.agents import site_collab
from app.agents import worker as worker_module
from app.agents.worker import Worker
from app.api.stream import _observer_event
from app.api.dto import FofaConfigDTO, PartialFofaConfigDTO


def _task(config):
    return SimpleNamespace(fofa_config=config)


def test_site_recon_mode_defaults_to_full() -> None:
    assert FofaConfigDTO().site_recon_mode == "full"


def test_site_recon_mode_accepts_light() -> None:
    assert FofaConfigDTO(site_recon_mode="light").site_recon_mode == "light"


def test_partial_site_recon_mode_preserves_explicit_full() -> None:
    assert PartialFofaConfigDTO(
        site_recon_mode="full"
    ).model_dump(exclude_unset=True) == {"site_recon_mode": "full"}


@pytest.mark.parametrize("dto", [FofaConfigDTO, PartialFofaConfigDTO])
def test_site_recon_mode_rejects_unknown_values(dto) -> None:
    with pytest.raises(ValidationError):
        dto(site_recon_mode="auto")


def test_recon_mode_defaults_to_full_without_config() -> None:
    assert site_collab.recon_mode_for(None) == "full"
    assert site_collab.recon_mode_for(_task({})) == "full"


def test_recon_mode_resolves_explicit_and_legacy_values() -> None:
    assert site_collab.recon_mode_for(_task({"site_recon_mode": "light"})) == "light"
    assert site_collab.recon_mode_for(_task({"skip_site_recon": True})) == "light"
    assert site_collab.recon_mode_for(
        _task({"site_recon_mode": "full", "skip_site_recon": True})
    ) == "full"
    assert site_collab.recon_mode_for(_task({"site_recon_mode": "unknown"})) == "full"


def test_light_mode_keeps_every_initial_route() -> None:
    assert [r.source for r in site_collab.INITIAL_ROUTES] == [
        "site_map",
        "site_js",
        "site_auth",
        "site_unauth",
        "site_file",
        "site_inject",
        "site_logic",
    ]


def test_runtime_route_meta_only_marks_site_map_as_light() -> None:
    task = _task({"site_recon_mode": "light"})
    site_map = site_collab.route_for_source("site_map")
    site_js = site_collab.route_for_source("site_js")
    assert site_map and site_js
    assert site_collab.runtime_route_meta(site_map, task)["recon_mode"] == "light"
    assert "recon_mode" not in site_collab.runtime_route_meta(site_js, task)


def test_runtime_route_meta_preserves_route_fields_for_every_initial_route() -> None:
    task = _task({"site_recon_mode": "light"})
    common_keys = {"source", "label", "focus", "js_first"}
    for route in site_collab.INITIAL_ROUTES:
        meta = site_collab.runtime_route_meta(route, task)
        assert {key: meta[key] for key in common_keys} == {
            "source": route.source,
            "label": route.label,
            "focus": route.focus,
            "js_first": route.js_first,
        }
        if route.source == "site_map":
            assert set(meta) == common_keys | {"recon_mode"}
            assert meta["recon_mode"] == "light"
        else:
            assert set(meta) == common_keys


def test_light_recon_prompt_declares_budget_and_minimum_coverage() -> None:
    route = site_collab.route_for_source("site_map")
    assert route
    prompt = site_collab.render_context(route, recon_mode="light")
    assert "最多 18 轮" in prompt
    assert "第 12 轮" in prompt
    assert "首页与跳转链" in prompt
    assert "robots.txt / sitemap.xml" in prompt
    assert "API 文档与前端主要路由" in prompt
    assert "存在可用登录态时至少完成一次内部菜单/API 盘点" in prompt
    assert "先调用 report_coverage，再 finish" in prompt


def test_theme_prompt_reports_light_site_map_without_skipping_it() -> None:
    route = site_collab.route_for_source("site_auth")
    assert route
    prompt = site_collab.render_context(route, recon_mode="light")
    assert "site_map（轻量）/site_js" in prompt
    assert "跳过" not in prompt


def test_orchestrator_wires_site_recon_runtime_snapshot() -> None:
    from app.orchestrator import TaskRunner

    source = inspect.getsource(TaskRunner._run_worker_inner)
    assert "runtime_route_meta" in source
    assert "recon_mode=site_collab.recon_mode_for(task_obj)" in source
    assert 'self._live[target_id]["site_route"]' in source
    assert 'self._live[target_id]["site_recon_mode"]' in source

    diagnostic_source = inspect.getsource(TaskRunner.diagnostic_snapshot)
    assert '"site_route": item.get("site_route")' in diagnostic_source
    assert '"site_recon_mode": item.get("site_recon_mode")' in diagnostic_source

    from app.api import tasks as task_api

    board_source = inspect.getsource(task_api.task_board)
    assert '"site_route": w.get("site_route", "")' in board_source
    assert '"site_recon_mode": w.get("site_recon_mode", "")' in board_source


def _worker_start_event(monkeypatch, site_route: dict | None) -> dict:
    class FakeExecutor:
        def __init__(self, *_args, **_kwargs):
            pass

    class FailingLLM:
        def chat(self, *_args, **_kwargs):
            raise RuntimeError("stop after startup")

    monkeypatch.setattr(worker_module, "ToolExecutor", FakeExecutor)
    events: list[tuple[str, dict]] = []
    worker = Worker(
        "https://example.test",
        llm=FailingLLM(),
        on_event=lambda kind, data: events.append((kind, dict(data))),
        target_meta={"site_collab_route": site_route} if site_route is not None else {},
    )
    worker.run()
    return next(data for kind, data in events if kind == "worker_start")


def test_worker_start_event_exposes_normalized_site_recon_snapshot(monkeypatch) -> None:
    light = _worker_start_event(
        monkeypatch, {"source": "site_map", "recon_mode": "light"}
    )
    assert light["site_route"] == "site_map"
    assert light["site_recon_mode"] == "light"

    full = _worker_start_event(monkeypatch, {"source": "site_map"})
    assert full["site_route"] == "site_map"
    assert full["site_recon_mode"] == "full"

    theme = _worker_start_event(
        monkeypatch, {"source": "site_auth", "recon_mode": "light"}
    )
    assert theme["site_route"] == "site_auth"
    assert "site_recon_mode" not in theme


def test_observer_stream_preserves_only_non_sensitive_site_mode_metadata() -> None:
    projected = _observer_event({
        "agent": "worker",
        "kind": "worker_start",
        "site_route": "site_map",
        "site_recon_mode": "light",
        "target": "https://secret.example",
        "token": "secret-token",
    })
    assert projected["site_route"] == "site_map"
    assert projected["site_recon_mode"] == "light"
    assert "target" not in projected
    assert "token" not in projected


def _worker_for_route(source: str, recon_mode: str = "light") -> Worker:
    worker = Worker.__new__(Worker)
    worker.target_meta = {
        "playbook_route": {},
        "site_collab_route": {"source": source, "recon_mode": recon_mode},
    }
    worker.deepen_context = None
    worker._enterprise = False
    return worker


def test_light_site_map_caps_hard_and_soft_rounds(monkeypatch) -> None:
    monkeypatch.setattr("app.agents.worker.worker_config.soft_round_budget_cap", 0)
    assert _worker_for_route("site_map")._route_rounds(90, 45) == (18, 12)


def test_light_site_map_cap_applies_after_deep_policy_calculation(monkeypatch) -> None:
    monkeypatch.setattr("app.agents.worker.worker_config.soft_round_budget_cap", 0)
    worker = _worker_for_route("site_map")
    worker.target_meta["playbook_route"] = {"intensity": "deep"}
    worker.deepen_context = {"depth_policy": {"soft_round_ratio": 1}}
    assert worker._route_rounds(90, 45) == (18, 12)


@pytest.mark.parametrize(
    ("source", "mode"),
    [("site_map", "full"), ("site_js", "light"), ("site_focus", "light")],
)
def test_recon_budget_does_not_cap_other_route_cases(
    monkeypatch, source: str, mode: str
) -> None:
    monkeypatch.setattr("app.agents.worker.worker_config.soft_round_budget_cap", 0)
    assert _worker_for_route(source, mode)._route_rounds(90, 45) == (90, 45)
