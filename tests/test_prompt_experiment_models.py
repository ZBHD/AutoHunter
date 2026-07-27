import asyncio

from sqlalchemy.ext.asyncio import create_async_engine

from app.db.models import Base, PromptExperiment, PromptExperimentSample, Target


def test_prompt_experiment_models_define_expected_tables_and_target_columns() -> None:
    assert PromptExperiment.__tablename__ == "prompt_experiments"
    assert PromptExperimentSample.__tablename__ == "prompt_experiment_samples"
    assert {
        "prompt_release_id",
        "prompt_experiment_id",
        "prompt_cohort",
    }.issubset(Target.__table__.columns.keys())


def test_prompt_experiment_sample_indexes_enforce_live_and_offline_identity() -> None:
    indexes = {index.name: index for index in PromptExperimentSample.__table__.indexes}

    live = indexes["ux_prompt_samples_live_target"]
    assert live.unique is True
    assert tuple(column.name for column in live.columns) == (
        "experiment_id",
        "target_id",
    )

    offline = indexes["ux_prompt_samples_offline_run"]
    assert offline.unique is True
    assert tuple(column.name for column in offline.columns) == (
        "experiment_id",
        "case_id",
        "release_id",
        "run_number",
    )


def test_new_database_creates_prompt_experiment_tables() -> None:
    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
                rows = await conn.exec_driver_sql(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
                tables = {row[0] for row in rows.fetchall()}

            assert "prompt_experiments" in tables
            assert "prompt_experiment_samples" in tables
        finally:
            await engine.dispose()

    asyncio.run(scenario())
