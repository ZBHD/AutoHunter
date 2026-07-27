from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Callable, Sequence

from app.agents.history import bounded_tool_content
from app.agents.prompt_releases import (
    CANDIDATE_RELEASE_ID,
    PromptRelease,
    render_worker_prompt,
)
from app.db.models import PromptExperimentSample
from app.llm.usage import pop_target_usage
from app.tools.schemas import worker_tool_schemas

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE_DIR = ROOT / "tests" / "fixtures" / "prompt_replay"

_SECRET_PATTERNS = (
    re.compile(r"(?i)authorization\s*:\s*bearer\s+(?!\[)[A-Za-z0-9._-]{8,}"),
    re.compile(r"(?i)cookie\s*:\s*[^\[\s][^\r\n]{3,}"),
    re.compile(r"(?i)(?:api[_-]?key|token|secret|password)\s*[=:]\s*(?!\[)[^\s\"']{4,}"),
    re.compile(r"sk-[A-Za-z0-9_-]{8,}"),
    re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"),
    re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)"),
    re.compile(r"(?<![\w[])\d{1,3}(?:\.\d{1,3}){3}(?![\w\]])"),
    re.compile(r"https?://(?!\[)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"),
)
_EXTERNAL_URL_RE = re.compile(r"https?://", re.IGNORECASE)


class ReplayFixtureError(ValueError):
    pass


@dataclass(frozen=True)
class ReplayFixture:
    schema_version: int
    case_id: str
    src_type: str
    route_id: str
    initial_context: dict[str, Any]
    scripted_tool_results: dict[str, tuple[dict[str, Any], ...]]
    allowed_tools: tuple[str, ...]
    forbidden_tools: tuple[str, ...]
    expected_terminal_verdicts: tuple[str, ...]
    required_evidence: tuple[str, ...]
    max_rounds: int
    max_total_tokens: int
    historical_human_outcome: str


@dataclass(frozen=True)
class ReplayScheduleItem:
    fixture: ReplayFixture
    release_id: str
    run_number: int


def _require_string(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ReplayFixtureError(f"fixture field must be a non-empty string: {key}")
    return value.strip()


def _string_tuple(payload: dict[str, Any], key: str) -> tuple[str, ...]:
    value = payload.get(key)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ReplayFixtureError(f"fixture field must be a string list: {key}")
    return tuple(item.strip() for item in value if item.strip())


def _ensure_sanitized(raw: str, source: Path) -> None:
    if any(pattern.search(raw) for pattern in _SECRET_PATTERNS):
        raise ReplayFixtureError(f"fixture must contain only sanitized placeholders: {source.name}")


def _parse_fixture(payload: Any, source: Path) -> ReplayFixture:
    if not isinstance(payload, dict):
        raise ReplayFixtureError(f"fixture must be an object: {source.name}")
    if payload.get("schema_version") != 1:
        raise ReplayFixtureError(f"unsupported fixture schema: {source.name}")
    initial_context = payload.get("initial_context")
    scripted = payload.get("scripted_tool_results")
    if not isinstance(initial_context, dict) or not isinstance(scripted, dict):
        raise ReplayFixtureError(f"fixture context/results must be objects: {source.name}")
    scripted_results: dict[str, tuple[dict[str, Any], ...]] = {}
    for tool, results in scripted.items():
        if not isinstance(tool, str) or not isinstance(results, list):
            raise ReplayFixtureError(f"invalid scripted tool results: {source.name}")
        if any(not isinstance(result, dict) for result in results):
            raise ReplayFixtureError(f"scripted tool results must be objects: {source.name}")
        scripted_results[tool] = tuple(dict(result) for result in results)
    max_rounds = int(payload.get("max_rounds") or 0)
    max_total_tokens = int(payload.get("max_total_tokens") or 0)
    if max_rounds < 1 or max_total_tokens < 1:
        raise ReplayFixtureError(f"fixture budgets must be positive: {source.name}")
    return ReplayFixture(
        schema_version=1,
        case_id=_require_string(payload, "case_id"),
        src_type=_require_string(payload, "src_type"),
        route_id=_require_string(payload, "route_id"),
        initial_context=dict(initial_context),
        scripted_tool_results=scripted_results,
        allowed_tools=_string_tuple(payload, "allowed_tools"),
        forbidden_tools=_string_tuple(payload, "forbidden_tools"),
        expected_terminal_verdicts=_string_tuple(payload, "expected_terminal_verdicts"),
        required_evidence=_string_tuple(payload, "required_evidence"),
        max_rounds=max_rounds,
        max_total_tokens=max_total_tokens,
        historical_human_outcome=_require_string(payload, "historical_human_outcome"),
    )


def load_replay_fixtures(path: str | Path | None = None) -> list[ReplayFixture]:
    source = Path(path) if path is not None else DEFAULT_FIXTURE_DIR
    files = [source] if source.is_file() else sorted(source.glob("*.json"))
    if not files:
        raise ReplayFixtureError(f"no replay fixtures found: {source}")
    fixtures: list[ReplayFixture] = []
    seen: set[str] = set()
    for file in files:
        raw = file.read_text(encoding="utf-8")
        _ensure_sanitized(raw, file)
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ReplayFixtureError(f"invalid fixture JSON: {file.name}: {exc}") from None
        fixture = _parse_fixture(payload, file)
        if fixture.case_id in seen:
            raise ReplayFixtureError(f"duplicate replay case id: {fixture.case_id}")
        seen.add(fixture.case_id)
        fixtures.append(fixture)
    return fixtures


def build_replay_schedule(
    fixtures: Sequence[ReplayFixture],
    *,
    stable_release_id: str,
    candidate_release_id: str,
    repeat: int = 3,
    seed: str,
) -> list[ReplayScheduleItem]:
    if repeat < 1:
        raise ValueError("repeat must be positive")
    schedule: list[ReplayScheduleItem] = []
    ordered = sorted(
        fixtures,
        key=lambda fixture: hashlib.sha256(
            f"{seed}:{fixture.case_id}".encode("utf-8")
        ).hexdigest(),
    )
    for fixture in ordered:
        for run_number in range(1, repeat + 1):
            parity = hashlib.sha256(
                f"{seed}:{fixture.case_id}:{run_number}".encode("utf-8")
            ).digest()[0] % 2
            pair = (
                (stable_release_id, candidate_release_id)
                if parity == 0
                else (candidate_release_id, stable_release_id)
            )
            schedule.extend(
                ReplayScheduleItem(fixture, release_id, run_number)
                for release_id in pair
            )
    return schedule


def _schema_name(schema: dict[str, Any]) -> str:
    return str((schema.get("function") or {}).get("name") or "")


def _contains_external_url(value: Any) -> bool:
    if isinstance(value, str):
        return bool(_EXTERNAL_URL_RE.search(value))
    if isinstance(value, dict):
        return any(_contains_external_url(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_external_url(item) for item in value)
    return False


class PromptReplayRunner:
    def __init__(self, router_factory: Callable[..., Any]) -> None:
        self.router_factory = router_factory

    def run_case(
        self,
        fixture: ReplayFixture,
        release: PromptRelease,
        *,
        experiment_id: str,
        run_number: int,
        cohort: str | None = None,
    ) -> PromptExperimentSample:
        target_key = f"offline:{experiment_id}:{fixture.case_id}:{release.release_id}:{run_number}"
        llm = self.router_factory(release, fixture, run_number, target_key=target_key)
        schemas = worker_tool_schemas(
            enterprise=fixture.src_type == "enterprise",
            route_id=fixture.route_id,
        )
        allowed = set(fixture.allowed_tools)
        tools = [schema for schema in schemas if _schema_name(schema) in allowed]
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": render_worker_prompt(release, fixture.src_type)},
            {
                "role": "user",
                "content": json.dumps(fixture.initial_context, ensure_ascii=False, sort_keys=True),
            },
        ]
        positions: dict[str, int] = {}
        observed: list[str] = []
        seen_call_ids: set[str] = set()
        tool_calls = 0
        tool_errors = 0
        forbidden = 0
        protocol_errors = 0
        verdict = "incomplete"
        started_at = datetime.now(timezone.utc).replace(tzinfo=None)
        rounds = 0

        for rounds in range(1, fixture.max_rounds + 1):
            response = llm.chat(messages, tools=tools, tool_choice="auto")
            calls = list(getattr(response, "tool_calls", None) or [])
            messages.append(response.as_history_message())
            if not calls:
                messages.append({"role": "user", "content": "继续执行声明路线或调用 finish。"})
                continue
            for call in calls:
                tool_calls += 1
                if not call.id or call.id in seen_call_ids:
                    protocol_errors += 1
                seen_call_ids.add(call.id)
                try:
                    arguments = json.loads(call.arguments or "{}")
                except json.JSONDecodeError:
                    arguments = {}
                    tool_errors += 1

                result: dict[str, Any]
                if (
                    call.name not in allowed
                    or call.name in fixture.forbidden_tools
                    or _contains_external_url(arguments)
                ):
                    forbidden += 1
                    result = {
                        "ok": False,
                        "error": {"kind": "forbidden_replay_action", "retryable": False},
                    }
                elif call.name == "finish":
                    verdict = str(arguments.get("verdict") or "no_vuln")
                    result = {"ok": True, "verdict": verdict}
                else:
                    position = positions.get(call.name, 0)
                    scripted = fixture.scripted_tool_results.get(call.name, ())
                    if position >= len(scripted):
                        forbidden += 1
                        result = {
                            "ok": False,
                            "error": {"kind": "scripted_result_exhausted", "retryable": False},
                        }
                    else:
                        result = dict(scripted[position])
                        positions[call.name] = position + 1
                        if result.get("ok") is False:
                            tool_errors += 1
                observed.append(json.dumps(result, ensure_ascii=False, sort_keys=True))
                messages.append({
                    "role": "tool",
                    "tool_call_id": call.id,
                    "content": bounded_tool_content(result, call.name),
                })
            if verdict != "incomplete":
                break

        usage = pop_target_usage(target_key)
        if int(usage.get("total_tokens") or 0) > fixture.max_total_tokens:
            forbidden += 1
        evidence_complete = all(
            marker in "\n".join(observed)
            for marker in fixture.required_evidence
        )
        expected = verdict in fixture.expected_terminal_verdicts
        return PromptExperimentSample(
            experiment_id=experiment_id,
            phase="offline",
            cohort=(
                cohort
                if cohort in {"stable", "candidate"}
                else (
                    "candidate"
                    if release.release_id == CANDIDATE_RELEASE_ID
                    else "stable"
                )
            ),
            release_id=release.release_id,
            case_id=fixture.case_id,
            run_number=run_number,
            src_type=fixture.src_type,
            route_id=fixture.route_id,
            terminal_verdict=verdict,
            rounds=rounds,
            tool_calls=tool_calls,
            tool_errors=tool_errors,
            prompt_tokens=max(0, int(usage.get("prompt_tokens") or 0)),
            completion_tokens=max(0, int(usage.get("completion_tokens") or 0)),
            total_tokens=max(0, int(usage.get("total_tokens") or 0)),
            usage_complete=int(usage.get("requests") or 0) > 0,
            evidence_complete=evidence_complete,
            forbidden_action_count=forbidden,
            metrics={
                "protocol_error_count": protocol_errors,
                "expected_terminal": expected,
                "historical_human_outcome": fixture.historical_human_outcome,
            },
            started_at=started_at,
            finished_at=datetime.now(timezone.utc).replace(tzinfo=None),
        )


__all__ = [
    "DEFAULT_FIXTURE_DIR",
    "PromptReplayRunner",
    "ReplayFixture",
    "ReplayFixtureError",
    "ReplayScheduleItem",
    "build_replay_schedule",
    "load_replay_fixtures",
]
