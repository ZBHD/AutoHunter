"""异步数据库会话管理（SQLite + aiosqlite）。"""
from __future__ import annotations

import os
from pathlib import Path
from typing import AsyncGenerator

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.models import Base

DB_PATH = os.environ.get("DB_PATH", str(Path(__file__).resolve().parent.parent.parent / "data" / "autohunter.db"))
Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

DATABASE_URL = f"sqlite+aiosqlite:///{DB_PATH}"

engine = create_async_engine(DATABASE_URL, echo=False, future=True)
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

# 每条物理连接建立时统一设置 PRAGMA（init_db 的一次性 PRAGMA 只作用于建库那条连接，
# aiosqlite 连接池里后续每条新连接都需要重新设，否则 busy_timeout 默认为 0、
# 一遇写锁立刻 SQLITE_BUSY）。24x7 下 orchestrator 写事件 + N 个 heartbeat +
# API 读 + worker 落库高并发，这几项是缓解锁竞争性价比最高的优化。
_CONNECT_PRAGMAS = (
    "PRAGMA busy_timeout=5000;",          # 写锁最多等 5s 再报错，吸收瞬时竞争
    "PRAGMA synchronous=NORMAL;",         # WAL 下安全，显著降低写延迟
    "PRAGMA foreign_keys=ON;",
    "PRAGMA cache_size=-64000;",          # 约 64MB page cache，减少看板/列表热读扫盘
    "PRAGMA mmap_size=268435456;",        # 256MB mmap，SQLite 读多写少场景更稳
    "PRAGMA temp_store=MEMORY;",          # ORDER BY/GROUP BY 临时表走内存
    "PRAGMA wal_autocheckpoint=1000;",
)


@event.listens_for(engine.sync_engine, "connect")
def _set_sqlite_pragma(dbapi_connection, _connection_record):
    cursor = dbapi_connection.cursor()
    try:
        for pragma in _CONNECT_PRAGMAS:
            cursor.execute(pragma)
    finally:
        cursor.close()


# 轻量自动迁移：新增列时无需删库（demo 友好）
# (table, column, "TYPE DEFAULT ...")
_MIGRATIONS = [
    ("reviews", "user_status", "VARCHAR(20) DEFAULT 'pending'"),
    ("reviews", "user_severity", "VARCHAR(10)"),
    ("reviews", "user_notes", "TEXT DEFAULT ''"),
    ("reviews", "user_edits", "JSON DEFAULT '{}'"),
    ("reviews", "submitted", "BOOLEAN DEFAULT 0"),
    ("reviews", "user_reviewed_at", "DATETIME"),
    ("targets", "priority_score", "FLOAT DEFAULT 0"),
    ("targets", "priority_reason", "VARCHAR(300) DEFAULT ''"),
    ("targets", "queue_position", "INTEGER"),
    ("reviews", "deepen_directive", "TEXT DEFAULT ''"),
    ("targets", "deepen_context", "JSON"),
    ("targets", "deepen_count", "INTEGER DEFAULT 0"),
    ("targets", "leaked_creds", "JSON"),
    ("targets", "dead_reason", "VARCHAR(300) DEFAULT ''"),
    ("targets", "last_error", "VARCHAR(500) DEFAULT ''"),
    ("targets", "school", "VARCHAR(200) DEFAULT ''"),
    ("findings", "owner", "VARCHAR(300) DEFAULT ''"),
    ("findings", "kill_chain", "JSON"),
    ("findings", "assistant_messages", "JSON DEFAULT '[]'"),
    ("findings", "markdown_downloaded_at", "DATETIME"),
    ("killsweeps", "affected_table", "JSON DEFAULT '[]'"),
    ("system_settings", "engines", "JSON DEFAULT '{}'"),
    ("system_settings", "llm_providers", "JSON DEFAULT '[]'"),
    ("system_settings", "fofa_keys", "JSON DEFAULT '[]'"),
    ("tasks", "engine", "VARCHAR(20) DEFAULT ''"),
    ("tasks", "hunt_direction", "TEXT DEFAULT ''"),
    ("tasks", "mode_config", "JSON DEFAULT '{}'"),
    ("tasks", "search_enabled", "BOOLEAN DEFAULT 1"),
    ("targets", "killsweep_case_id", "VARCHAR(32)"),
    ("killsweeps", "automatic_verdict", "VARCHAR(20) DEFAULT 'pending_validation'"),
    ("killsweeps", "manual_verdict", "VARCHAR(20)"),
    ("killsweeps", "manual_reason", "TEXT DEFAULT ''"),
    ("killsweeps", "manual_actor", "VARCHAR(40) DEFAULT ''"),
    ("killsweeps", "manual_reviewed_at", "DATETIME"),
    ("killsweeps", "failure_kind", "VARCHAR(60) DEFAULT ''"),
    ("killsweeps", "failure_message", "TEXT DEFAULT ''"),
    ("killsweeps", "attempt_count", "INTEGER DEFAULT 0"),
    ("killsweeps", "queued_at", "DATETIME"),
    ("killsweeps", "started_at", "DATETIME"),
    ("killsweeps", "finished_at", "DATETIME"),
    ("killsweeps", "legacy_without_timeline", "BOOLEAN DEFAULT 0"),
    ("killsweeps", "current_attempt_id", "VARCHAR(32)"),
    ("killsweeps", "latest_success_attempt_id", "VARCHAR(32)"),
    ("raw_evidence", "spool_directory", "TEXT"),
]

# 唯一索引：目标库(host)/漏洞库(dedup_key)的 DB 级查重兜底。
# 名字与 models.__table_args__ 保持一致；老库表已存在不会被 create_all 补，靠这里建。
_UNIQUE_INDEXES = [
    ("ux_targets_id_task_id",
     "CREATE UNIQUE INDEX IF NOT EXISTS ux_targets_id_task_id "
     "ON targets(id, task_id)"),
    ("ux_gateway_assets_id_task_id",
     "CREATE UNIQUE INDEX IF NOT EXISTS ux_gateway_assets_id_task_id "
     "ON gateway_assets(id, task_id)"),
    ("ux_gateway_asset_task_origin",
     "CREATE UNIQUE INDEX IF NOT EXISTS ux_gateway_asset_task_origin "
     "ON gateway_assets(task_id, origin_key)"),
    ("ux_gateway_observation_probe",
     "CREATE UNIQUE INDEX IF NOT EXISTS ux_gateway_observation_probe "
     "ON gateway_observations(gateway_asset_id, scan_epoch, probe_id, auth_variant)"),
    ("ux_gateway_secret_asset_hash",
     "CREATE UNIQUE INDEX IF NOT EXISTS ux_gateway_secret_asset_hash "
     "ON gateway_secrets(gateway_asset_id, secret_sha256)"),
    ("ux_targets_task_host",
     "CREATE UNIQUE INDEX IF NOT EXISTS ux_targets_task_host ON targets(task_id, host, source)"),
    ("ux_findings_dedup_global",
     "CREATE UNIQUE INDEX IF NOT EXISTS ux_findings_dedup_global ON findings(dedup_key) "
     "WHERE dedup_key <> ''"),
    ("ux_missed_signals_dedup_key",
     "CREATE UNIQUE INDEX IF NOT EXISTS ux_missed_signals_dedup_key ON missed_signals(dedup_key)"),
    ("ux_missed_signal_drafts_signal",
     "CREATE UNIQUE INDEX IF NOT EXISTS ux_missed_signal_drafts_signal "
     "ON missed_signal_drafts(signal_id)"),
    ("ux_raw_evidence_chunks_channel_seq",
     "CREATE UNIQUE INDEX IF NOT EXISTS ux_raw_evidence_chunks_channel_seq "
     "ON raw_evidence_chunks(evidence_id, channel, seq)"),
    ("ux_killsweep_attempts_case_number",
     "CREATE UNIQUE INDEX IF NOT EXISTS ux_killsweep_attempts_case_number "
     "ON killsweep_attempts(case_id, attempt_no)"),
    ("ux_killsweep_attempts_active_case",
     "CREATE UNIQUE INDEX IF NOT EXISTS ux_killsweep_attempts_active_case "
     "ON killsweep_attempts(case_id) WHERE status IN ('queued', 'running')"),
    ("ux_killsweeps_origin_finding",
     "CREATE UNIQUE INDEX IF NOT EXISTS ux_killsweeps_origin_finding "
     "ON killsweeps(origin_finding_id) "
     "WHERE origin_finding_id <> '' AND legacy_without_timeline = 0"),
]

# 普通索引：跨 host 查重按归一化类型别名集合做 IN 预筛时走索引，避免全表扫。
# create_all 不会给已存在的老表补索引，这里显式建。
_SECONDARY_INDEXES = [
    ("ix_gateway_assets_task_id",
     "CREATE INDEX IF NOT EXISTS ix_gateway_assets_task_id ON gateway_assets(task_id)"),
    ("ix_gateway_assets_next_scan_at",
     "CREATE INDEX IF NOT EXISTS ix_gateway_assets_next_scan_at ON gateway_assets(next_scan_at)"),
    ("ix_gateway_secrets_task_id",
     "CREATE INDEX IF NOT EXISTS ix_gateway_secrets_task_id ON gateway_secrets(task_id)"),
    ("ix_gateway_secrets_gateway_asset_id",
     "CREATE INDEX IF NOT EXISTS ix_gateway_secrets_gateway_asset_id "
     "ON gateway_secrets(gateway_asset_id)"),
    ("ix_gateway_secrets_validation_status",
     "CREATE INDEX IF NOT EXISTS ix_gateway_secrets_validation_status "
     "ON gateway_secrets(validation_status)"),
    ("ix_gateway_observations_task_id",
     "CREATE INDEX IF NOT EXISTS ix_gateway_observations_task_id ON gateway_observations(task_id)"),
    ("ix_gateway_observations_gateway_asset_id",
     "CREATE INDEX IF NOT EXISTS ix_gateway_observations_gateway_asset_id "
     "ON gateway_observations(gateway_asset_id)"),
    ("ix_gateway_observations_observed_at",
     "CREATE INDEX IF NOT EXISTS ix_gateway_observations_observed_at "
     "ON gateway_observations(observed_at)"),
    ("ix_findings_vuln_type_status",
     "CREATE INDEX IF NOT EXISTS ix_findings_vuln_type_status ON findings(vuln_type, status)"),
    # 派发热点：_pop_queued 按 (task_id, status='queued') 过滤 + priority_score 排序。
    ("ix_targets_task_status_priority",
     "CREATE INDEX IF NOT EXISTS ix_targets_task_status_priority "
     "ON targets(task_id, status, priority_score)"),
    ("ix_targets_task_status_priority_created",
     "CREATE INDEX IF NOT EXISTS ix_targets_task_status_priority_created "
     "ON targets(task_id, status, priority_score, created_at)"),
    ("ix_targets_task_status_queue_position",
     "CREATE INDEX IF NOT EXISTS ix_targets_task_status_queue_position "
     "ON targets(task_id, status, queue_position, priority_score, created_at)"),
    # 审核派发：_dispatch_reviews 按 (task_id, status='pending_review') 取。
    ("ix_findings_task_status",
     "CREATE INDEX IF NOT EXISTS ix_findings_task_status ON findings(task_id, status)"),
    ("ix_findings_task_status_created",
     "CREATE INDEX IF NOT EXISTS ix_findings_task_status_created ON findings(task_id, status, created_at)"),
    # findings 列表/详情排序：按 (task_id, created_at DESC)。
    ("ix_findings_task_created",
     "CREATE INDEX IF NOT EXISTS ix_findings_task_created ON findings(task_id, created_at)"),
    # 看板统计 + results/submit-list/review-queue/rejected 联表过滤的核心复合索引。
    ("ix_reviews_task_verdict_user",
     "CREATE INDEX IF NOT EXISTS ix_reviews_task_verdict_user "
     "ON reviews(task_id, verdict, user_status, submitted)"),
    ("ix_reviews_task_verdict_score",
     "CREATE INDEX IF NOT EXISTS ix_reviews_task_verdict_score "
     "ON reviews(task_id, verdict, score)"),
    ("ix_reviews_task_verdict_user_score",
     "CREATE INDEX IF NOT EXISTS ix_reviews_task_verdict_user_score "
     "ON reviews(task_id, verdict, user_status, score)"),
    ("ix_reviews_task_user_submitted_score",
     "CREATE INDEX IF NOT EXISTS ix_reviews_task_user_submitted_score "
     "ON reviews(task_id, user_status, submitted, score)"),
    ("ix_reviews_task_user_reviewed_score",
     "CREATE INDEX IF NOT EXISTS ix_reviews_task_user_reviewed_score "
     "ON reviews(task_id, user_status, user_reviewed_at, score)"),
    # 全局漏洞库 /api/vulns：跨任务按 (user_status='passed', submitted) 过滤。
    ("ix_reviews_user_status_submitted",
     "CREATE INDEX IF NOT EXISTS ix_reviews_user_status_submitted "
     "ON reviews(user_status, submitted)"),
    # 全局硬骨头库：按 (status IN dead/skipped) 过滤 + updated_at DESC 排序。
    ("ix_targets_status_updated",
     "CREATE INDEX IF NOT EXISTS ix_targets_status_updated ON targets(status, updated_at)"),
    # 看板 killsweep 计数 + 列表：按 (task_id, is_killsweep)。
    ("ix_killsweeps_task_iskillsweep",
     "CREATE INDEX IF NOT EXISTS ix_killsweeps_task_iskillsweep "
     "ON killsweeps(task_id, is_killsweep)"),
    ("ix_killsweeps_task_hit_rank",
     "CREATE INDEX IF NOT EXISTS ix_killsweeps_task_hit_rank "
     "ON killsweeps(task_id, is_killsweep, verified, asset_count, created_at)"),
    ("ix_killsweeps_task_product",
     "CREATE INDEX IF NOT EXISTS ix_killsweeps_task_product "
     "ON killsweeps(task_id, product_key)"),
    ("ix_killsweeps_status_finished",
     "CREATE INDEX IF NOT EXISTS ix_killsweeps_status_finished "
     "ON killsweeps(status, finished_at)"),
    ("ix_missed_signals_status_risk_seen",
     "CREATE INDEX IF NOT EXISTS ix_missed_signals_status_risk_seen "
     "ON missed_signals(status, risk_score, last_seen_at)"),
    ("ix_missed_signals_task_status",
     "CREATE INDEX IF NOT EXISTS ix_missed_signals_task_status "
     "ON missed_signals(task_id, status)"),
    ("ix_missed_signal_evidence_evidence",
     "CREATE INDEX IF NOT EXISTS ix_missed_signal_evidence_evidence "
     "ON missed_signal_evidence(evidence_id)"),
    ("ix_killsweep_attempts_task_status",
     "CREATE INDEX IF NOT EXISTS ix_killsweep_attempts_task_status "
     "ON killsweep_attempts(task_id, status)"),
    # 运行异常日志：按 level/agent 过滤 + ts DESC 排序。
    ("ix_task_events_level_ts",
     "CREATE INDEX IF NOT EXISTS ix_task_events_level_ts ON task_events(level, ts)"),
    # 看板历史回放：WHERE task_id=? ORDER BY id DESC LIMIT N。
    ("ix_task_events_task_id_id",
     "CREATE INDEX IF NOT EXISTS ix_task_events_task_id_id ON task_events(task_id, id)"),
]

# 废弃的残留列：老 schema 里是 NOT NULL 无默认值，新代码不再写入会导致 INSERT 失败。
# SQLite 不支持 DROP COLUMN/ALTER COLUMN（旧版），用"给残留列补默认值"的方式重建表。
# (table, [废弃列名])
_DROP_COLUMNS = [
    ("reviews", ["user_decision"]),
]


async def init_db() -> None:
    async with engine.begin() as conn:
        # SQLite 并发：开启 WAL，提升 24x7 读写并发能力
        await conn.exec_driver_sql("PRAGMA journal_mode=WAL;")
        await conn.run_sync(Base.metadata.create_all)
        await _auto_migrate(conn)
        await _ensure_unique_indexes(conn)
        await _ensure_secondary_indexes(conn)


async def _ensure_unique_indexes(conn) -> None:
    """为老库补建唯一索引（查重 DB 级兜底）。
    若历史数据已有重复导致唯一索引建不上，降级为普通索引——保数据不丢，
    新数据仍由应用层 dedup 拦截。"""
    # targets 去重索引从「同任务 host 唯一」升级为「同任务 host+source 唯一」。
    # 单站协作需要同一真实 host 以不同 source(路线) 并行入队；普通 fofa/manual
    # 仍然 source 相同，继续由 DB 兜底去重。
    rows = await conn.exec_driver_sql(
        "SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name='targets'"
    )
    target_indexes = {r[0]: (r[1] or "") for r in rows.fetchall()}
    target_unique_sql = target_indexes.get("ux_targets_task_host", "")
    target_shape = target_unique_sql.replace("\n", " ").lower()
    if target_unique_sql and "source" not in target_shape:
        try:
            await conn.exec_driver_sql("DROP INDEX IF EXISTS ux_targets_task_host")
        except Exception:
            pass

    # findings 去重索引从「(task_id, dedup_key)」升级为「(dedup_key) 全局唯一」。
    # 老库若已有旧索引，先删后建，确保跨任务查重真正由 DB 兜底。
    rows = await conn.exec_driver_sql(
        "SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name='findings'"
    )
    indexes = {r[0]: (r[1] or "") for r in rows.fetchall()}
    old_sql = indexes.get("ux_findings_task_dedup", "")
    new_sql = indexes.get("ux_findings_dedup_global", "")
    wants_old_shape = "task_id, dedup_key" in old_sql.replace("\n", " ")
    wants_new_shape = "ON findings(dedup_key)" in new_sql.replace("\n", " ")
    if wants_old_shape or (new_sql and not wants_new_shape):
        try:
            await conn.exec_driver_sql("DROP INDEX IF EXISTS ux_findings_task_dedup")
        except Exception:
            pass
        try:
            await conn.exec_driver_sql("DROP INDEX IF EXISTS ux_findings_dedup_global")
        except Exception:
            pass

    # 旧版把 (task_id, product_key) 当作通杀案例身份。新版一条源 Finding
    # 对应一个案例，同产品允许产生多条独立案例，因此先移除旧唯一索引。
    rows = await conn.exec_driver_sql(
        "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='killsweeps'"
    )
    killsweep_indexes = {r[0] for r in rows.fetchall()}
    if "ux_killsweeps_task_product" in killsweep_indexes:
        try:
            await conn.exec_driver_sql("DROP INDEX IF EXISTS ux_killsweeps_task_product")
        except Exception:
            pass

    strict_index_shapes = {
        "ux_targets_id_task_id": ("targets", ("id", "task_id")),
        "ux_gateway_assets_id_task_id": ("gateway_assets", ("id", "task_id")),
        "ux_gateway_asset_task_origin": ("gateway_assets", ("task_id", "origin_key")),
        "ux_gateway_observation_probe": (
            "gateway_observations",
            ("gateway_asset_id", "scan_epoch", "probe_id", "auth_variant"),
        ),
        "ux_gateway_secret_asset_hash": (
            "gateway_secrets",
            ("gateway_asset_id", "secret_sha256"),
        ),
    }
    table_rows = await conn.exec_driver_sql(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )
    existing_tables = {row[0] for row in table_rows.fetchall()}

    async def strict_index_shape(
        table: str,
        index: str,
    ) -> tuple[bool, tuple[str, ...], bool] | None:
        index_rows = await conn.exec_driver_sql(f'PRAGMA index_list("{table}")')
        index_row = next((row for row in index_rows.fetchall() if row[1] == index), None)
        if index_row is None:
            return None
        column_rows = await conn.exec_driver_sql(f'PRAGMA index_info("{index}")')
        columns = tuple(row[2] for row in sorted(column_rows.fetchall(), key=lambda row: row[0]))
        return bool(index_row[2]), columns, bool(index_row[4])

    async def verify_strict_index(name: str, table: str, columns: tuple[str, ...]) -> bool:
        shape = await strict_index_shape(table, name)
        if shape is None:
            return False
        if shape != (True, columns, False):
            raise RuntimeError(
                f"数据库索引 {name} 形态错误：需要完整 UNIQUE{columns}，实际为 {shape}"
            )
        return True

    for name, sql in _UNIQUE_INDEXES:
        strict_shape = strict_index_shapes.get(name)
        if strict_shape is not None and strict_shape[0] not in existing_tables:
            continue
        if strict_shape is not None and await verify_strict_index(name, *strict_shape):
            continue
        try:
            await conn.exec_driver_sql(sql)
        except Exception:
            if strict_shape is not None:
                raise
            try:
                await conn.exec_driver_sql(sql.replace("UNIQUE INDEX", "INDEX"))
            except Exception:
                pass
        if strict_shape is not None:
            await verify_strict_index(name, *strict_shape)


async def _ensure_secondary_indexes(conn) -> None:
    """为老库补建普通查询索引（性能优化，失败不阻断启动）。"""
    for _name, sql in _SECONDARY_INDEXES:
        try:
            await conn.exec_driver_sql(sql)
        except Exception:
            pass


async def _auto_migrate(conn) -> None:
    for table, col, decl in _MIGRATIONS:
        rows = await conn.exec_driver_sql(f"PRAGMA table_info({table})")
        existing = {r[1] for r in rows.fetchall()}
        if col not in existing:
            await conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")

    # 清理废弃残留列（老 schema 的 NOT NULL 列会阻塞新代码 INSERT）
    for table, cols in _DROP_COLUMNS:
        rows = await conn.exec_driver_sql(f"PRAGMA table_info({table})")
        existing = {r[1] for r in rows.fetchall()}
        for col in cols:
            if col in existing:
                try:
                    await conn.exec_driver_sql(f"ALTER TABLE {table} DROP COLUMN {col}")
                except Exception:
                    # 旧 SQLite 不支持 DROP COLUMN 时不阻断启动；线上镜像用新版 SQLite 会正常清理。
                    pass

    await _run_schema_migrations(conn)
    await _backfill_missed_signal_evidence_links(conn)


async def _backfill_missed_signal_evidence_links(conn) -> None:
    """Promote the legacy one-signal foreign key into the shared link table."""
    await conn.exec_driver_sql(
        """
        INSERT OR IGNORE INTO missed_signal_evidence
            (missed_signal_id, evidence_id, created_at)
        SELECT missed_signal_id, id, COALESCE(created_at, CURRENT_TIMESTAMP)
        FROM raw_evidence
        WHERE missed_signal_id IS NOT NULL
        """
    )


async def _run_schema_migrations(conn) -> None:
    """执行需要改写历史数据的一次性、可重入迁移。"""
    await conn.exec_driver_sql(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            name VARCHAR(120) PRIMARY KEY,
            applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    migration = "20260714_killsweep_operations_v1"
    row = await conn.exec_driver_sql(
        "SELECT 1 FROM schema_migrations WHERE name = ?", (migration,)
    )
    if row.first() is not None:
        return

    # 此函数在列迁移之后运行。此刻表中的行全部来自旧 schema，标成历史记录
    # 后即可在不丢数据的前提下启用“一个源 Finding 一个新案例”的部分唯一索引。
    await conn.exec_driver_sql(
        """
        UPDATE killsweeps
        SET automatic_verdict = CASE
                WHEN is_killsweep = 1 AND verified = 1 THEN 'killsweep'
                WHEN is_killsweep = 1 THEN 'pending_validation'
                ELSE 'not_killsweep'
            END,
            manual_verdict = CASE
                WHEN status = 'invalid' THEN 'invalid'
                ELSE manual_verdict
            END,
            status = CASE
                WHEN status = 'done' THEN 'succeeded'
                WHEN status = 'analyzing' THEN 'running'
                WHEN status = 'invalid' THEN 'succeeded'
                ELSE status
            END,
            legacy_without_timeline = 1
        """
    )
    await conn.exec_driver_sql(
        "INSERT INTO schema_migrations (name) VALUES (?)", (migration,)
    )


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with SessionLocal() as session:
        yield session
