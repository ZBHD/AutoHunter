from datetime import datetime, timedelta

from app.agents.prompt_releases import CANDIDATE_RELEASE_ID, COMPILED_STABLE_RELEASE_ID
from app.db.models import PromptExperiment, PromptExperimentSample
from app.prompt_experiments import (
    aggregate_samples,
    evaluate_daily_window,
    evaluate_live_eligibility,
    has_consecutive_passing_windows,
)


def _sample(
    index: int,
    cohort: str,
    *,
    total_tokens: int = 100,
    usage_complete: bool = True,
    human_passed: int = 0,
    human_rejected: int = 0,
    evidence_complete: bool = True,
    terminated: bool = False,
    verdict: str = "no_vuln",
    missed_signal_count: int = 0,
) -> PromptExperimentSample:
    return PromptExperimentSample(
        experiment_id="experiment",
        phase="live",
        cohort=cohort,
        release_id=(
            CANDIDATE_RELEASE_ID
            if cohort == "candidate"
            else COMPILED_STABLE_RELEASE_ID
        ),
        task_id=f"task-{index % 5}",
        target_id=f"{cohort}-target-{index}",
        route_id=f"route-{index % 3}",
        terminal_verdict=verdict,
        total_tokens=total_tokens,
        usage_complete=usage_complete,
        finding_count=human_passed + human_rejected,
        human_passed_count=human_passed,
        human_rejected_count=human_rejected,
        evidence_complete=evidence_complete,
        agent_terminated_by_tool=terminated,
        missed_signal_count=missed_signal_count,
        metrics={"protocol_error_count": 0, "evidence_crossing_count": 0},
        finished_at=datetime(2026, 7, 20, 12),
    )


def test_aggregate_samples_excludes_incomplete_usage_from_cost_average() -> None:
    metrics = aggregate_samples([
        _sample(1, "candidate", total_tokens=100),
        _sample(2, "candidate", total_tokens=900, usage_complete=False),
    ])

    assert metrics["terminal_targets"] == 2
    assert metrics["usage_complete_targets"] == 1
    assert metrics["avg_total_tokens"] == 100


def test_live_eligibility_passes_exact_minimum_sample_boundaries() -> None:
    now = datetime(2026, 7, 27, 12)
    experiment = PromptExperiment(
        id="experiment",
        status="live",
        stable_release_id=COMPILED_STABLE_RELEASE_ID,
        candidate_release_id=CANDIDATE_RELEASE_ID,
        seed="seed",
        canary_percent=10,
        live_started_at=now - timedelta(days=7),
    )
    stable = [_sample(i, "stable") for i in range(100)]
    candidate = [
        _sample(i, "candidate", human_passed=1 if i < 20 else 0)
        for i in range(100)
    ]

    decision = evaluate_live_eligibility(experiment, stable + candidate, now=now)

    assert decision.passed is True
    assert decision.insufficient == []


def test_live_eligibility_reports_every_missing_boundary() -> None:
    now = datetime(2026, 7, 27, 12)
    experiment = PromptExperiment(
        id="experiment",
        status="live",
        stable_release_id=COMPILED_STABLE_RELEASE_ID,
        candidate_release_id=CANDIDATE_RELEASE_ID,
        seed="seed",
        canary_percent=10,
        live_started_at=now - timedelta(days=6),
    )

    decision = evaluate_live_eligibility(
        experiment,
        [_sample(1, "stable"), _sample(1, "candidate")],
        now=now,
    )

    assert decision.passed is False
    assert set(decision.insufficient) == {
        "live_days",
        "stable_terminal_targets",
        "candidate_terminal_targets",
        "candidate_tasks",
        "candidate_routes",
        "candidate_human_reviews",
    }


def test_daily_window_with_zero_denominator_is_insufficient() -> None:
    decision = evaluate_daily_window(
        {"terminal_targets": 0},
        {"terminal_targets": 0},
    )

    assert decision.passed is False
    assert decision.insufficient


def test_daily_window_passes_effect_uplift_with_noninferior_quality() -> None:
    stable = aggregate_samples([
        _sample(i, "stable", human_passed=1 if i < 20 else 0)
        for i in range(100)
    ])
    candidate = aggregate_samples([
        _sample(i, "candidate", human_passed=1 if i < 23 else 0)
        for i in range(100)
    ])

    decision = evaluate_daily_window(stable, candidate)

    assert decision.passed is True
    assert decision.metrics["effect_uplift"] >= 0.10


def test_three_passing_windows_must_be_consecutive_dates() -> None:
    windows = [
        {"date": "2026-07-20", "passed": True},
        {"date": "2026-07-22", "passed": True},
        {"date": "2026-07-23", "passed": True},
    ]

    assert has_consecutive_passing_windows(windows, required=3) is False

    windows[1]["date"] = "2026-07-21"
    windows[2]["date"] = "2026-07-22"
    assert has_consecutive_passing_windows(windows, required=3) is True
