from __future__ import annotations

import asyncio

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.models import Base, MissedSignal, RawEvidence, Target, Task
from app.db.session import _auto_migrate, _ensure_secondary_indexes, _ensure_unique_indexes


def test_old_system_settings_table_gains_provider_pool_column() -> None:
    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        try:
            async with engine.begin() as conn:
                other_tables = [
                    table for table in Base.metadata.sorted_tables
                    if table.name != "system_settings"
                ]
                await conn.run_sync(lambda sync_conn: Base.metadata.create_all(sync_conn, tables=other_tables))
                await conn.exec_driver_sql(
                    """
                    CREATE TABLE system_settings (
                        id VARCHAR(32) PRIMARY KEY,
                        llm JSON DEFAULT '{}',
                        fofa JSON DEFAULT '{}',
                        engines JSON DEFAULT '{}',
                        defaults JSON DEFAULT '{}',
                        updated_at DATETIME
                    )
                    """
                )

                await _auto_migrate(conn)

                columns = await conn.exec_driver_sql("PRAGMA table_info(system_settings)")
                names = {row[1] for row in columns.fetchall()}
                assert "llm_providers" in names

                await conn.exec_driver_sql("INSERT INTO system_settings (id) VALUES ('global')")
                value = await conn.exec_driver_sql(
                    "SELECT llm_providers FROM system_settings WHERE id='global'"
                )
                assert value.scalar_one() == "[]"
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_old_raw_evidence_table_gains_private_spool_registry_without_data_loss() -> None:
    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        try:
            async with engine.begin() as conn:
                other_tables = [
                    table for table in Base.metadata.sorted_tables
                    if table.name != "raw_evidence"
                ]
                await conn.run_sync(
                    lambda sync_conn: Base.metadata.create_all(sync_conn, tables=other_tables)
                )
                await conn.exec_driver_sql(
                    """
                    CREATE TABLE raw_evidence (
                        id VARCHAR(32) PRIMARY KEY,
                        task_id VARCHAR(32) NOT NULL,
                        missed_signal_id VARCHAR(32),
                        created_at DATETIME
                    )
                    """
                )
                await conn.exec_driver_sql(
                    "INSERT INTO raw_evidence (id, task_id) VALUES ('legacy-evidence', 'task')"
                )

                await _auto_migrate(conn)

                columns = await conn.exec_driver_sql("PRAGMA table_info(raw_evidence)")
                assert "spool_directory" in {row[1] for row in columns.fetchall()}
                row = await conn.exec_driver_sql(
                    "SELECT id, spool_directory FROM raw_evidence WHERE id='legacy-evidence'"
                )
                assert row.one() == ("legacy-evidence", None)
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_legacy_killsweeps_are_transformed_and_indexes_are_upgraded() -> None:
    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        try:
            async with engine.begin() as conn:
                await conn.exec_driver_sql(
                    """
                    CREATE TABLE killsweeps (
                        id VARCHAR(32) PRIMARY KEY,
                        task_id VARCHAR(32) NOT NULL,
                        origin_finding_id VARCHAR(32) DEFAULT '',
                        product_key VARCHAR(120) DEFAULT '',
                        is_killsweep BOOLEAN DEFAULT 0,
                        verified BOOLEAN DEFAULT 0,
                        status VARCHAR(20) DEFAULT 'analyzing'
                    )
                    """
                )
                await conn.exec_driver_sql(
                    "CREATE UNIQUE INDEX ux_killsweeps_task_product "
                    "ON killsweeps(task_id, product_key)"
                )
                await conn.exec_driver_sql(
                    """
                    INSERT INTO killsweeps (
                        id, task_id, origin_finding_id, product_key,
                        is_killsweep, verified, status
                    ) VALUES ('legacy', 'task', 'finding', 'product', 1, 1, 'done')
                    """
                )
                other_tables = [
                    table for table in Base.metadata.sorted_tables
                    if table.name != "killsweeps"
                ]
                await conn.run_sync(
                    lambda sync_conn: Base.metadata.create_all(sync_conn, tables=other_tables)
                )

                await _auto_migrate(conn)
                await _ensure_unique_indexes(conn)
                await _ensure_secondary_indexes(conn)

                columns = await conn.exec_driver_sql("PRAGMA table_info(killsweeps)")
                names = {row[1] for row in columns.fetchall()}
                assert {
                    "automatic_verdict", "manual_verdict", "manual_reason",
                    "manual_actor", "manual_reviewed_at", "failure_kind",
                    "failure_message", "attempt_count", "queued_at", "started_at",
                    "finished_at", "legacy_without_timeline", "current_attempt_id",
                    "latest_success_attempt_id",
                } <= names

                transformed = await conn.exec_driver_sql(
                    "SELECT status, automatic_verdict, legacy_without_timeline "
                    "FROM killsweeps WHERE id='legacy'"
                )
                assert transformed.one() == ("succeeded", "killsweep", 1)

                index_rows = await conn.exec_driver_sql(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='index' AND tbl_name='killsweeps'"
                )
                indexes = {row[0] for row in index_rows.fetchall()}
                assert "ux_killsweeps_task_product" not in indexes
                assert "ix_killsweeps_task_product" in indexes
                assert "ux_killsweeps_origin_finding" in indexes

                # Product is now a lookup key, not a case identity constraint.
                await conn.exec_driver_sql(
                    "INSERT INTO killsweeps "
                    "(id, task_id, origin_finding_id, product_key, legacy_without_timeline) "
                    "VALUES ('new', 'task', 'finding', 'product', 0)"
                )
                with pytest.raises(IntegrityError):
                    await conn.exec_driver_sql(
                        "INSERT INTO killsweeps "
                        "(id, task_id, origin_finding_id, product_key, legacy_without_timeline) "
                        "VALUES ('duplicate', 'task', 'finding', 'other', 0)"
                    )

                # Data migrations are recorded and safe to run repeatedly.
                await _auto_migrate(conn)
                migrations = await conn.exec_driver_sql(
                    "SELECT COUNT(*) FROM schema_migrations "
                    "WHERE name='20260714_killsweep_operations_v1'"
                )
                assert migrations.scalar_one() == 1
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_findings_index_shape_upgrade_does_not_depend_on_legacy_killsweep_index() -> None:
    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        try:
            async with engine.begin() as conn:
                await conn.exec_driver_sql(
                    "CREATE TABLE findings (task_id VARCHAR(32), dedup_key VARCHAR(128))"
                )
                await conn.exec_driver_sql(
                    "CREATE UNIQUE INDEX ux_findings_dedup_global "
                    "ON findings(task_id, dedup_key)"
                )

                await _ensure_unique_indexes(conn)

                row = await conn.exec_driver_sql(
                    "SELECT sql FROM sqlite_master "
                    "WHERE type='index' AND name='ux_findings_dedup_global'"
                )
                sql = (row.scalar_one() or "").replace("\n", " ").lower()
                assert "on findings(dedup_key)" in sql
                assert "task_id" not in sql
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_legacy_raw_evidence_links_are_backfilled_into_shared_signal_table() -> None:
    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
            async with sessions() as session:
                session.add(Task(id="task-link", name="Links"))
                session.add(Target(
                    id="target-link", task_id="task-link", url="https://link.test",
                    host="link.test",
                ))
                session.add(MissedSignal(
                    id="signal-link", task_id="task-link", target_id="target-link",
                    dedup_key="link-dedup", rule_key="exception_leak",
                    endpoint_key="GET https://link.test/error",
                ))
                session.add(RawEvidence(
                    id="evidence-link", task_id="task-link", target_id="target-link",
                    missed_signal_id="signal-link", source_kind="legacy",
                ))
                await session.commit()

            async with engine.begin() as conn:
                await _auto_migrate(conn)
                row = await conn.exec_driver_sql(
                    "SELECT missed_signal_id, evidence_id "
                    "FROM missed_signal_evidence"
                )
                assert row.first() == ("signal-link", "evidence-link")
        finally:
            await engine.dispose()

    asyncio.run(scenario())
