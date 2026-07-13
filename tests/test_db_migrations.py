from __future__ import annotations

import asyncio

from sqlalchemy.ext.asyncio import create_async_engine

from app.db.models import Base
from app.db.session import _auto_migrate


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
