from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
import hashlib
import re
import secrets
from typing import Any, Sequence

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.prompt_releases import (
    COMPILED_STABLE_RELEASE_ID,
    get_prompt_release,
    require_promotable_release,
    resolve_prompt_release,
)
from app.db.models import (
    PromptExperiment,
    PromptExperimentSample,
    SystemSettings,
    Target,
    Task,
)
from app.settings_service import refresh_cache, resolve_stable_prompt_release_id
from app.prompt_replay import build_replay_schedule

_ACTIVE_ASSIGNMENT_STATUSES = ("live", "promoted")
_MANUAL_ALIASES = frozenset({
    "legacy",
    "old",
    "20260625",
    "2026-06-25",
    "modern",
    "full",
})
_HOLDBACK_DURATION = timedelta(hours=48)
_HOLDBACK_PERCENT = 10.0
_ROUTE_REASON_RE = re.compile(r"(?:^|\s|·)route:([^/\s]+)")


@dataclass(frozen=True)
class PromptAssignment:
    release_id: str
    experiment_id: str = ""
    cohort: str = "stable"


@dataclass(frozen=True)
class GateDecision:
    passed: bool
    reason: str
    metrics: dict[str, Any]
    insufficient: list[str]


class PromptExperimentConflictError(RuntimeError):
    pass


def cohort_bucket(seed: str, target_id: str) -> int:
    digest = hashlib.sha256(f"{seed}:{target_id}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % 10_000


def _utc_naive(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is not None:
        current = current.astimezone(timezone.utc).replace(tzinfo=None)
    return current


async def _stable_release_id(session: AsyncSession) -> str:
    settings = await session.get(SystemSettings, "global")
    if settings is None:
        return resolve_stable_prompt_release_id()
    return resolve_stable_prompt_release_id(dict(settings.defaults or {}))


async def _active_assignment_experiment(
    session: AsyncSession,
) -> PromptExperiment | None:
    return await session.scalar(
        select(PromptExperiment)
        .where(PromptExperiment.status.in_(_ACTIVE_ASSIGNMENT_STATUSES))
        .order_by(PromptExperiment.created_at.desc())
        .limit(1)
    )


async def assignment_for_target(
    session: AsyncSession,
    task: Task,
    target: Target,
    *,
    now: datetime | None = None,
) -> PromptAssignment:
    if target.prompt_release_id:
        return PromptAssignment(
            release_id=target.prompt_release_id,
            experiment_id=str(target.prompt_experiment_id or ""),
            cohort=str(target.prompt_cohort or "stable"),
        )

    stable_release_id = await _stable_release_id(session)
    model_config = dict(task.model_config_json or {})
    alias = str(model_config.get("prompt_version") or "current").strip().lower()
    if alias in _MANUAL_ALIASES:
        release = resolve_prompt_release(
            alias,
            stable_release_id=stable_release_id,
        )
        return PromptAssignment(release.release_id, cohort="manual")

    experiment = await _active_assignment_experiment(session)
    if experiment is None:
        return PromptAssignment(stable_release_id)

    bucket = cohort_bucket(experiment.seed, target.id)
    if experiment.status == "live":
        threshold = round(max(0.0, min(100.0, experiment.canary_percent)) * 100)
        if bucket < threshold:
            return PromptAssignment(
                experiment.candidate_release_id,
                experiment.id,
                "candidate",
            )
        return PromptAssignment(
            experiment.stable_release_id,
            experiment.id,
            "stable",
        )

    promoted_at = _utc_naive(experiment.promoted_at)
    current = _utc_naive(now)
    if current < promoted_at + _HOLDBACK_DURATION:
        holdback_threshold = round(_HOLDBACK_PERCENT * 100)
        if bucket < holdback_threshold:
            return PromptAssignment(
                experiment.previous_stable_id or experiment.stable_release_id,
                experiment.id,
                "holdback",
            )
        return PromptAssignment(
            experiment.candidate_release_id,
            experiment.id,
            "candidate",
        )

    return PromptAssignment(experiment.candidate_release_id)


def _sample_route_id(target: Target, result: dict) -> str:
    explicit = str(result.get("route_id") or "").strip()
    if explicit:
        return explicit[:80]
    match = _ROUTE_REASON_RE.search(str(target.priority_reason or ""))
    return match.group(1)[:80] if match else ""


def _evidence_complete(findings: list) -> bool:
    if not findings:
        return False
    for finding in findings:
        if not isinstance(finding, dict):
            return False
        evidence = finding.get("evidence")
        if not isinstance(evidence, dict) or not evidence:
            return False
    return True


async def finalize_live_sample(
    session: AsyncSession,
    target: Target,
    result: dict,
    usage: dict,
) -> PromptExperimentSample | None:
    experiment_id = str(target.prompt_experiment_id or "")
    if not experiment_id or not target.prompt_release_id:
        return None

    sample = await session.scalar(
        select(PromptExperimentSample).where(
            PromptExperimentSample.experiment_id == experiment_id,
            PromptExperimentSample.target_id == target.id,
        )
    )
    if sample is None:
        sample = PromptExperimentSample(
            experiment_id=experiment_id,
            phase="holdback" if target.prompt_cohort == "holdback" else "live",
            cohort=str(target.prompt_cohort or "stable"),
            release_id=target.prompt_release_id,
            task_id=target.task_id,
            target_id=target.id,
        )
        session.add(sample)

    metrics = result.get("metrics") if isinstance(result.get("metrics"), dict) else {}
    findings = result.get("findings") if isinstance(result.get("findings"), list) else []
    sample.release_id = target.prompt_release_id
    sample.cohort = str(target.prompt_cohort or "stable")
    sample.src_type = str(result.get("src_type") or "")[:20]
    sample.route_id = _sample_route_id(target, result)
    sample.terminal_verdict = str(result.get("verdict") or target.verdict or "")[:30]
    sample.rounds = max(0, int(result.get("rounds") or 0))
    sample.tool_calls = max(0, int(metrics.get("tool_calls") or 0))
    sample.tool_errors = max(0, int(metrics.get("tool_errors") or 0))
    sample.agent_terminated_by_tool = bool(
        result.get("failure_kind") == "tool_exception"
        or metrics.get("agent_terminated_by_tool")
    )
    sample.prompt_tokens = max(0, int(usage.get("prompt_tokens") or 0))
    sample.completion_tokens = max(0, int(usage.get("completion_tokens") or 0))
    sample.total_tokens = max(0, int(usage.get("total_tokens") or 0))
    sample.usage_complete = int(usage.get("requests") or 0) > 0
    sample.finding_count = len(findings)
    sample.evidence_complete = _evidence_complete(findings)
    sample.forbidden_action_count = max(
        0,
        int(metrics.get("forbidden_action_count") or 0),
    )
    sample.metrics = {
        "protocol_error_count": max(
            0,
            int(metrics.get("protocol_error_count") or 0),
        ),
        "evidence_crossing_count": max(
            0,
            int(metrics.get("evidence_crossing_count") or 0),
        ),
    }
    sample.finished_at = _utc_naive()
    return sample


def _rate(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return numerator / denominator


def aggregate_samples(
    samples: Sequence[PromptExperimentSample],
) -> dict[str, Any]:
    rows = list(samples)
    terminal_targets = len(rows)
    passed = sum(max(0, int(row.human_passed_count or 0)) for row in rows)
    rejected = sum(max(0, int(row.human_rejected_count or 0)) for row in rows)
    reviewed = passed + rejected
    evidence_complete = sum(bool(row.evidence_complete) for row in rows)
    terminated = sum(bool(row.agent_terminated_by_tool) for row in rows)
    no_vuln_rows = [row for row in rows if row.terminal_verdict == "no_vuln"]
    missed = sum(max(0, int(row.missed_signal_count or 0)) for row in no_vuln_rows)
    usage_rows = [row for row in rows if row.usage_complete]
    total_tokens = sum(max(0, int(row.total_tokens or 0)) for row in usage_rows)
    protocol_errors = sum(
        max(0, int((row.metrics or {}).get("protocol_error_count") or 0))
        for row in rows
    )
    evidence_crossing = sum(
        max(0, int((row.metrics or {}).get("evidence_crossing_count") or 0))
        for row in rows
    )
    return {
        "terminal_targets": terminal_targets,
        "task_count": len({row.task_id for row in rows if row.task_id}),
        "route_count": len({row.route_id for row in rows if row.route_id}),
        "human_passed_count": passed,
        "human_rejected_count": rejected,
        "human_reviewed_count": reviewed,
        "human_pass_rate": _rate(passed, reviewed),
        "human_reject_rate": _rate(rejected, reviewed),
        "evidence_complete_rate": _rate(evidence_complete, terminal_targets),
        "agent_termination_rate": _rate(terminated, terminal_targets),
        "missed_signal_rate": _rate(missed, len(no_vuln_rows)),
        "accepted_findings_per_100_targets": (
            _rate(passed * 100, terminal_targets)
        ),
        "usage_complete_targets": len(usage_rows),
        "avg_total_tokens": _rate(total_tokens, len(usage_rows)),
        "forbidden_action_count": sum(
            max(0, int(row.forbidden_action_count or 0)) for row in rows
        ),
        "protocol_error_count": protocol_errors,
        "evidence_crossing_count": evidence_crossing,
    }


def evaluate_offline_gate(
    stable: dict[str, Any],
    candidate: dict[str, Any],
) -> GateDecision:
    insufficient: list[str] = []
    for key in ("evidence_complete_rate", "avg_total_tokens"):
        if stable.get(key) is None:
            insufficient.append(f"stable_{key}")
        if candidate.get(key) is None:
            insufficient.append(f"candidate_{key}")
    checks = {
        "static_contract": candidate.get("static_contract_pass_rate") == 1.0,
        "forbidden_actions": int(candidate.get("forbidden_action_count") or 0) == 0,
        "critical_cases": bool(candidate.get("critical_cases_passed")),
        "tool_protocol": int(candidate.get("protocol_error_count") or 0) == 0,
        "agent_crashes": int(candidate.get("agent_crash_count") or 0) == 0,
    }
    if not insufficient:
        checks["evidence"] = (
            candidate["evidence_complete_rate"] >= stable["evidence_complete_rate"]
        )
        checks["tokens"] = candidate["avg_total_tokens"] <= stable["avg_total_tokens"] * 1.15
    failed = [name for name, passed in checks.items() if not passed]
    passed = not failed and not insufficient
    return GateDecision(
        passed=passed,
        reason="offline gate passed" if passed else ", ".join(failed or insufficient),
        metrics={"checks": checks, "stable": stable, "candidate": candidate},
        insufficient=insufficient,
    )


def evaluate_live_eligibility(
    experiment: PromptExperiment,
    samples: Sequence[PromptExperimentSample],
    *,
    now: datetime,
) -> GateDecision:
    current = _utc_naive(now)
    started = _utc_naive(experiment.live_started_at)
    stable_rows = [row for row in samples if row.cohort == "stable"]
    candidate_rows = [row for row in samples if row.cohort == "candidate"]
    stable = aggregate_samples(stable_rows)
    candidate = aggregate_samples(candidate_rows)
    values = {
        "live_days": (current - started).total_seconds() / 86_400,
        "stable_terminal_targets": stable["terminal_targets"],
        "candidate_terminal_targets": candidate["terminal_targets"],
        "candidate_tasks": candidate["task_count"],
        "candidate_routes": candidate["route_count"],
        "candidate_human_reviews": candidate["human_reviewed_count"],
    }
    minimums = {
        "live_days": 7,
        "stable_terminal_targets": 100,
        "candidate_terminal_targets": 100,
        "candidate_tasks": 5,
        "candidate_routes": 3,
        "candidate_human_reviews": 20,
    }
    insufficient = [key for key, minimum in minimums.items() if values[key] < minimum]
    return GateDecision(
        passed=not insufficient,
        reason="live sample minimums met" if not insufficient else ", ".join(insufficient),
        metrics={"values": values, "minimums": minimums},
        insufficient=insufficient,
    )


def evaluate_daily_window(
    stable: dict[str, Any],
    candidate: dict[str, Any],
) -> GateDecision:
    required_rates = (
        "evidence_complete_rate",
        "agent_termination_rate",
        "human_pass_rate",
        "missed_signal_rate",
        "accepted_findings_per_100_targets",
        "avg_total_tokens",
    )
    insufficient = [
        f"{cohort}_{key}"
        for cohort, metrics in (("stable", stable), ("candidate", candidate))
        for key in required_rates
        if metrics.get(key) is None
    ]
    immediate = (
        int(candidate.get("forbidden_action_count") or 0)
        + int(candidate.get("protocol_error_count") or 0)
        + int(candidate.get("evidence_crossing_count") or 0)
    )
    quality_checks: dict[str, bool] = {"immediate_failures": immediate == 0}
    effect_uplift: float | None = None
    token_reduction: float | None = None
    if not insufficient:
        quality_checks.update({
            "evidence": candidate["evidence_complete_rate"] >= stable["evidence_complete_rate"] - 0.02,
            "termination": candidate["agent_termination_rate"] <= stable["agent_termination_rate"],
            "human_pass": candidate["human_pass_rate"] >= stable["human_pass_rate"] - 0.02,
            "missed_signal": candidate["missed_signal_rate"] <= stable["missed_signal_rate"] + 0.03,
        })
        stable_effect = stable["accepted_findings_per_100_targets"]
        candidate_effect = candidate["accepted_findings_per_100_targets"]
        if stable_effect > 0:
            effect_uplift = (candidate_effect - stable_effect) / stable_effect
        stable_tokens = stable["avg_total_tokens"]
        if stable_tokens > 0:
            token_reduction = (stable_tokens - candidate["avg_total_tokens"]) / stable_tokens
        quality_checks["improvement"] = (
            effect_uplift is not None and effect_uplift >= 0.10
        ) or (
            candidate_effect >= stable_effect * 0.98
            and token_reduction is not None
            and token_reduction >= 0.15
        )
    failed = [key for key, passed in quality_checks.items() if not passed]
    passed = not insufficient and not failed
    return GateDecision(
        passed=passed,
        reason="daily window passed" if passed else ", ".join(failed or insufficient),
        metrics={
            "stable": stable,
            "candidate": candidate,
            "effect_uplift": effect_uplift,
            "token_reduction": token_reduction,
            "checks": quality_checks,
        },
        insufficient=insufficient,
    )


def has_consecutive_passing_windows(
    windows: Sequence[dict[str, Any]],
    *,
    required: int,
) -> bool:
    streak = 0
    previous: date | None = None
    for window in sorted(windows, key=lambda item: str(item.get("date") or "")):
        try:
            current = date.fromisoformat(str(window.get("date") or ""))
        except ValueError:
            streak = 0
            previous = None
            continue
        if not window.get("passed"):
            streak = 0
        elif previous is not None and current == previous + timedelta(days=1):
            streak += 1
        else:
            streak = 1
        previous = current
        if streak >= required:
            return True
    return False


def _daily_windows(
    samples: Sequence[PromptExperimentSample],
    *,
    now: datetime,
    promoted: bool = False,
) -> list[dict[str, Any]]:
    today = _utc_naive(now).date()
    days = sorted({
        row.finished_at.date()
        for row in samples
        if row.finished_at is not None and row.finished_at.date() < today
    })
    windows: list[dict[str, Any]] = []
    for day in days:
        rows = [row for row in samples if row.finished_at and row.finished_at.date() == day]
        stable_name = "holdback" if promoted else "stable"
        stable = aggregate_samples([row for row in rows if row.cohort == stable_name])
        candidate = aggregate_samples([row for row in rows if row.cohort == "candidate"])
        decision = evaluate_daily_window(stable, candidate)
        windows.append({
            "date": day.isoformat(),
            "passed": decision.passed,
            "reason": decision.reason,
            "metrics": decision.metrics,
        })
    return windows


def _rollback_regression(stable: dict[str, Any], candidate: dict[str, Any]) -> bool:
    comparisons = (
        ("agent_termination_rate", 0.02, "higher"),
        ("human_reject_rate", 0.05, "higher"),
        ("evidence_complete_rate", 0.02, "lower"),
    )
    for key, delta, direction in comparisons:
        left = stable.get(key)
        right = candidate.get(key)
        if left is None or right is None:
            continue
        if direction == "higher" and right >= left + delta:
            return True
        if direction == "lower" and right <= left - delta:
            return True
    return False


class PromptExperimentService:
    async def start(
        self,
        session: AsyncSession,
        *,
        candidate_release_id: str,
        canary_percent: float = 10.0,
        seed: str | None = None,
        now: datetime | None = None,
    ) -> PromptExperiment:
        candidate = require_promotable_release(candidate_release_id)
        percent = float(canary_percent)
        if not 0 < percent < 100:
            raise ValueError("canary_percent must be greater than 0 and less than 100")
        active = await session.scalar(
            select(PromptExperiment)
            .where(PromptExperiment.status.in_(("offline", "live", "promoted")))
            .limit(1)
        )
        if active is not None:
            raise PromptExperimentConflictError(
                f"an active prompt experiment already exists: {active.id} ({active.status})"
            )
        stable = await _stable_release_id(session)
        if stable == candidate.release_id:
            raise PromptExperimentConflictError(
                "candidate release is already the Stable release"
            )
        current = _utc_naive(now)
        experiment = PromptExperiment(
            status="offline",
            stable_release_id=stable,
            candidate_release_id=candidate.release_id,
            seed=str(seed or secrets.token_hex(24))[:64],
            canary_percent=percent,
            thresholds={
                "offline_repeat": 3,
                "minimum_live_days": 7,
                "minimum_targets_per_arm": 100,
                "minimum_candidate_tasks": 5,
                "minimum_candidate_routes": 3,
                "minimum_human_reviews": 20,
                "promotion_windows": 3,
                "holdback_hours": 48,
            },
            offline_started_at=current,
        )
        session.add(experiment)
        await session.commit()
        return experiment

    async def run_offline(
        self,
        session: AsyncSession,
        experiment: PromptExperiment,
        runner: Any,
        fixtures: Sequence[Any],
        *,
        static_contract_pass_rate: float,
        repeat: int = 3,
    ) -> GateDecision:
        if experiment.status != "offline":
            raise PromptExperimentConflictError(
                f"offline replay requires offline status, got {experiment.status}"
            )
        schedule = build_replay_schedule(
            fixtures,
            stable_release_id=experiment.stable_release_id,
            candidate_release_id=experiment.candidate_release_id,
            repeat=repeat,
            seed=experiment.seed,
        )
        stable_rows: list[PromptExperimentSample] = []
        candidate_rows: list[PromptExperimentSample] = []
        for item in schedule:
            cohort = (
                "candidate"
                if item.release_id == experiment.candidate_release_id
                else "stable"
            )
            sample = runner.run_case(
                item.fixture,
                get_prompt_release(item.release_id),
                experiment_id=experiment.id,
                run_number=item.run_number,
                cohort=cohort,
            )
            session.add(sample)
            if cohort == "candidate":
                candidate_rows.append(sample)
            else:
                stable_rows.append(sample)
        await session.flush()

        stable = aggregate_samples(stable_rows)
        candidate = aggregate_samples(candidate_rows)
        case_passes: dict[str, int] = {}
        for row in candidate_rows:
            if (row.metrics or {}).get("expected_terminal"):
                case_passes[row.case_id] = case_passes.get(row.case_id, 0) + 1
        candidate["static_contract_pass_rate"] = float(static_contract_pass_rate)
        candidate["critical_cases_passed"] = all(
            case_passes.get(fixture.case_id, 0) >= 2
            for fixture in fixtures
        )
        candidate["agent_crash_count"] = sum(
            row.terminal_verdict == "incomplete"
            or bool((row.metrics or {}).get("agent_crash"))
            for row in candidate_rows
        )
        decision = evaluate_offline_gate(stable, candidate)
        experiment.metrics = {"offline": decision.metrics}
        if decision.passed:
            experiment.status = "live"
            experiment.live_started_at = _utc_naive()
            experiment.failure_reason = ""
        else:
            experiment.status = "failed"
            experiment.failure_reason = decision.reason
        await session.commit()
        return decision

    async def cancel(
        self,
        session: AsyncSession,
        reason: str,
    ) -> PromptExperiment:
        experiment = await session.scalar(
            select(PromptExperiment)
            .where(PromptExperiment.status.in_(("offline", "live")))
            .order_by(PromptExperiment.created_at.desc())
            .limit(1)
        )
        if experiment is None:
            raise PromptExperimentConflictError("no cancellable prompt experiment")
        experiment.status = "cancelled"
        experiment.failure_reason = str(reason or "operator cancelled")
        await session.commit()
        return experiment

    async def latest(self, session: AsyncSession) -> PromptExperiment | None:
        return await session.scalar(
            select(PromptExperiment)
            .order_by(PromptExperiment.created_at.desc())
            .limit(1)
        )

    async def report(
        self,
        session: AsyncSession,
        experiment_id: str | None = None,
    ) -> dict[str, Any]:
        experiment = (
            await session.get(PromptExperiment, experiment_id)
            if experiment_id
            else await self.latest(session)
        )
        if experiment is None:
            raise PromptExperimentConflictError("no prompt experiment found")
        fixture_ids = sorted(set(await session.scalars(
            select(PromptExperimentSample.case_id).where(
                PromptExperimentSample.experiment_id == experiment.id,
                PromptExperimentSample.case_id != "",
            )
        )))
        return {
            "id": experiment.id,
            "status": experiment.status,
            "stable_release_id": experiment.stable_release_id,
            "candidate_release_id": experiment.candidate_release_id,
            "canary_percent": experiment.canary_percent,
            "metrics": dict(experiment.metrics or {}),
            "fixture_ids": fixture_ids,
            "failure_reason": experiment.failure_reason,
            "promotion_reason": experiment.promotion_reason,
            "rollback_reason": experiment.rollback_reason,
        }

    async def promote(
        self,
        session: AsyncSession,
        experiment: PromptExperiment,
        metrics: dict[str, Any],
        *,
        now: datetime | None = None,
    ) -> None:
        require_promotable_release(experiment.candidate_release_id)
        settings = await session.get(SystemSettings, "global")
        if settings is None:
            settings = SystemSettings(
                id="global",
                defaults={"stable_prompt_release_id": COMPILED_STABLE_RELEASE_ID},
            )
            session.add(settings)
            await session.flush()
        expected = dict(settings.defaults or {})
        current = resolve_stable_prompt_release_id(expected)
        if current != experiment.stable_release_id:
            experiment.status = "failed"
            experiment.failure_reason = (
                f"Stable 指针冲突：expected={experiment.stable_release_id}, actual={current}"
            )
            await session.commit()
            return
        updated = dict(expected)
        updated["worker_prompt_channel"] = "stable"
        updated["stable_prompt_release_id"] = experiment.candidate_release_id
        result = await session.execute(
            update(SystemSettings)
            .where(
                SystemSettings.id == settings.id,
                SystemSettings.defaults == expected,
            )
            .values(defaults=updated)
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            experiment.status = "failed"
            experiment.failure_reason = "Stable 指针冲突：compare-and-set 未命中"
            await session.commit()
            return
        experiment.previous_stable_id = experiment.stable_release_id
        experiment.status = "promoted"
        experiment.promoted_at = _utc_naive(now)
        experiment.metrics = dict(metrics)
        experiment.promotion_reason = "连续 3 个完整窗口满足自动晋升门槛"
        await session.commit()
        await session.refresh(settings)
        await refresh_cache(session)

    async def rollback(
        self,
        session: AsyncSession,
        experiment: PromptExperiment,
        reason: str,
        *,
        now: datetime | None = None,
    ) -> None:
        settings = await session.get(SystemSettings, "global")
        if settings is None:
            experiment.rollback_reason = "Stable 指针冲突：设置行不存在"
            await session.commit()
            return
        expected = dict(settings.defaults or {})
        current = resolve_stable_prompt_release_id(expected)
        if current != experiment.candidate_release_id:
            experiment.rollback_reason = (
                f"Stable 指针冲突：expected={experiment.candidate_release_id}, actual={current}"
            )
            await session.commit()
            return
        updated = dict(expected)
        updated["stable_prompt_release_id"] = (
            experiment.previous_stable_id or experiment.stable_release_id
        )
        result = await session.execute(
            update(SystemSettings)
            .where(
                SystemSettings.id == settings.id,
                SystemSettings.defaults == expected,
            )
            .values(defaults=updated)
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            experiment.rollback_reason = "Stable 指针冲突：compare-and-set 未命中"
            await session.commit()
            return
        experiment.status = "rolled_back"
        experiment.rollback_reason = str(reason or "自动回滚")
        experiment.rolled_back_at = _utc_naive(now)
        await session.commit()
        await session.refresh(settings)
        await refresh_cache(session)

    async def recompute(
        self,
        session: AsyncSession,
        *,
        now: datetime | None = None,
    ) -> PromptExperiment | None:
        experiment = await session.scalar(
            select(PromptExperiment)
            .where(PromptExperiment.status.in_(("offline", "live", "promoted")))
            .order_by(PromptExperiment.created_at.desc())
            .limit(1)
        )
        if experiment is None:
            return None
        samples = list(await session.scalars(
            select(PromptExperimentSample).where(
                PromptExperimentSample.experiment_id == experiment.id
            )
        ))
        forbidden = sum(row.forbidden_action_count or 0 for row in samples)
        protocol = sum(
            int((row.metrics or {}).get("protocol_error_count") or 0)
            for row in samples
        )
        crossing = sum(
            int((row.metrics or {}).get("evidence_crossing_count") or 0)
            for row in samples
        )
        if forbidden or protocol or crossing:
            reason = (
                f"立即门槛失败：禁止行为={forbidden}，协议错误={protocol}，证据串线={crossing}"
            )
            if experiment.status == "promoted":
                await self.rollback(session, experiment, reason, now=now)
            else:
                experiment.status = "failed"
                experiment.failure_reason = reason
                await session.commit()
            return experiment

        current = _utc_naive(now)
        if experiment.status == "live":
            eligibility = evaluate_live_eligibility(experiment, samples, now=current)
            windows = _daily_windows(samples, now=current)
            experiment.metrics = {
                "eligibility": eligibility.metrics,
                "windows": windows,
            }
            if eligibility.passed and has_consecutive_passing_windows(
                windows,
                required=3,
            ):
                await self.promote(
                    session,
                    experiment,
                    experiment.metrics,
                    now=current,
                )
            else:
                await session.commit()
            return experiment

        if experiment.status == "promoted":
            windows = _daily_windows(samples, now=current, promoted=True)
            regressions = []
            for window in windows:
                metrics = window["metrics"]
                regressions.append({
                    "date": window["date"],
                    "regressed": _rollback_regression(
                        metrics["stable"],
                        metrics["candidate"],
                    ),
                })
            if len(regressions) >= 2 and all(
                item["regressed"] for item in regressions[-2:]
            ):
                await self.rollback(
                    session,
                    experiment,
                    "连续两个完整窗口触发质量回滚门槛",
                    now=current,
                )
            elif experiment.promoted_at and current >= (
                _utc_naive(experiment.promoted_at) + _HOLDBACK_DURATION
            ):
                experiment.status = "completed"
                experiment.metrics = {**dict(experiment.metrics or {}), "holdback": regressions}
                await session.commit()
            return experiment

        return experiment


__all__ = [
    "PromptAssignment",
    "GateDecision",
    "PromptExperimentService",
    "PromptExperimentConflictError",
    "aggregate_samples",
    "assignment_for_target",
    "cohort_bucket",
    "evaluate_daily_window",
    "evaluate_live_eligibility",
    "evaluate_offline_gate",
    "finalize_live_sample",
    "has_consecutive_passing_windows",
]
