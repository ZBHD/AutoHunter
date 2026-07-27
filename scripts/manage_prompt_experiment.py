from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import sys
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy.ext.asyncio import async_sessionmaker

from app.db.session import SessionLocal, init_db
from app.llm.usage import UsageContext
from app.prompt_experiments import PromptExperimentConflictError, PromptExperimentService
from app.prompt_replay import PromptReplayRunner, load_replay_fixtures
from app.settings_service import init_settings_cache, llm_router_for_task
from scripts.evaluate_prompts import evaluate_profiles


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="管理不可变 Prompt Release 灰度实验")
    commands = parser.add_subparsers(dest="command", required=True)

    start = commands.add_parser("start")
    start.add_argument("--candidate", required=True)
    start.add_argument("--canary-percent", type=float, default=10.0)
    start.add_argument("--seed")

    commands.add_parser("status")
    report = commands.add_parser("report")
    report.add_argument("--format", choices=("json",), default="json")
    report.add_argument("--out")
    cancel = commands.add_parser("cancel")
    cancel.add_argument("--reason", required=True)
    rollback = commands.add_parser("rollback")
    rollback.add_argument("--reason", required=True)
    return parser


def _replay_runner(experiment) -> PromptReplayRunner:
    def router_factory(release, _fixture, _run_number, *, target_key):
        cohort = (
            "candidate"
            if release.release_id == experiment.candidate_release_id
            else "stable"
        )
        context = UsageContext(
            task_id=f"prompt-replay:{experiment.id}",
            target_id=target_key,
            experiment_id=experiment.id,
            release_id=release.release_id,
            cohort=cohort,
        )
        return llm_router_for_task(None, usage_context=context)

    return PromptReplayRunner(router_factory)


async def async_main(
    argv: Sequence[str] | None = None,
    *,
    session_factory: async_sessionmaker | None = None,
    initialize: bool = True,
) -> int:
    args = _parser().parse_args(argv)
    if initialize:
        await init_db()
        await init_settings_cache()
    sessions = session_factory or SessionLocal
    service = PromptExperimentService()
    try:
        async with sessions() as session:
            if args.command == "start":
                experiment = await service.start(
                    session,
                    candidate_release_id=args.candidate,
                    canary_percent=args.canary_percent,
                    seed=args.seed,
                )
                static_report = evaluate_profiles(repeat=1)
                static_rate = static_report["profiles"]["current"]["aggregate"]["pass_rate"]
                await service.run_offline(
                    session,
                    experiment,
                    _replay_runner(experiment),
                    load_replay_fixtures(),
                    static_contract_pass_rate=static_rate,
                )
                payload = await service.report(session, experiment.id)
            elif args.command == "status":
                payload = await service.report(session)
            elif args.command == "report":
                payload = await service.report(session)
                if args.out:
                    output = Path(args.out)
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_text(
                        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8",
                    )
            elif args.command == "cancel":
                experiment = await service.cancel(session, args.reason)
                payload = await service.report(session, experiment.id)
            else:
                experiment = await service.latest(session)
                if experiment is None or experiment.status != "promoted":
                    raise PromptExperimentConflictError(
                        "rollback requires a promoted holdback experiment"
                    )
                await service.rollback(session, experiment, args.reason)
                payload = await service.report(session, experiment.id)
    except (PromptExperimentConflictError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    return asyncio.run(async_main(argv))


if __name__ == "__main__":
    raise SystemExit(main())
