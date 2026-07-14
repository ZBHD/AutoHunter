from __future__ import annotations

import asyncio

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import app.db.models as models
from app.db.session import _auto_migrate, _ensure_secondary_indexes, _ensure_unique_indexes


async def _create_operations_schema():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)
        await _auto_migrate(conn)
        await _ensure_unique_indexes(conn)
        await _ensure_secondary_indexes(conn)
    return engine


def test_operations_tables_columns_and_indexes_exist() -> None:
    async def scenario() -> None:
        engine = await _create_operations_schema()
        try:
            async with engine.connect() as conn:
                table_rows = await conn.exec_driver_sql(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
                tables = {row[0] for row in table_rows.fetchall()}
                assert {
                    "missed_signals",
                    "missed_signal_events",
                    "missed_signal_drafts",
                    "raw_evidence",
                    "raw_evidence_chunks",
                    "killsweep_attempts",
                    "killsweep_events",
                    "killsweep_reanalysis_batches",
                    "schema_migrations",
                } <= tables

                required_columns = {
                    "missed_signals": {
                        "id", "task_id", "target_id", "source_finding_id",
                        "converted_finding_id", "dedup_key", "rule_key", "rule_label",
                        "method", "endpoint_key", "title", "summary", "risk_level",
                        "risk_score", "source_types", "status", "hit_count",
                        "evidence_count", "deepen_count", "deepen_phase",
                        "deepen_directive", "deepen_error", "last_rejection_reason",
                        "rejected_at", "converted_at", "first_seen_at", "last_seen_at",
                        "created_at", "updated_at",
                    },
                    "missed_signal_events": {
                        "id", "signal_id", "task_id", "kind", "actor_role",
                        "from_status", "to_status", "reason", "payload", "created_at",
                    },
                    "missed_signal_drafts": {
                        "id", "signal_id", "task_id", "status", "content",
                        "missing_evidence", "provider_trace", "last_error",
                        "generation_count", "revision", "created_at", "updated_at",
                        "confirmed_at",
                    },
                    "raw_evidence": {
                        "id", "task_id", "target_id", "missed_signal_id",
                        "killsweep_event_id", "source_kind", "capture_status",
                        "metadata_json", "preview", "content_hash", "spool_directory", "occurred_at",
                        "created_at",
                    },
                    "missed_signal_evidence": {
                        "missed_signal_id", "evidence_id", "created_at",
                    },
                    "raw_evidence_chunks": {
                        "id", "evidence_id", "channel", "seq", "data",
                    },
                    "killsweep_attempts": {
                        "id", "case_id", "task_id", "batch_id", "attempt_no",
                        "trigger", "status", "automatic_verdict", "result",
                        "provider_trace", "error_kind", "error_message", "created_at",
                        "started_at", "finished_at",
                    },
                    "killsweep_events": {
                        "id", "case_id", "attempt_id", "task_id", "sequence",
                        "kind", "level", "summary", "payload", "created_at",
                    },
                    "killsweep_reanalysis_batches": {
                        "id", "filters", "actor_role", "created_at",
                    },
                    "killsweeps": {
                        "automatic_verdict", "manual_verdict", "manual_reason",
                        "manual_actor", "manual_reviewed_at", "failure_kind",
                        "failure_message", "attempt_count", "queued_at", "started_at",
                        "finished_at", "legacy_without_timeline", "current_attempt_id",
                        "latest_success_attempt_id",
                    },
                    "targets": {"killsweep_case_id"},
                }
                for table, expected in required_columns.items():
                    rows = await conn.exec_driver_sql(f"PRAGMA table_info({table})")
                    actual = {row[1] for row in rows.fetchall()}
                    assert expected <= actual, f"{table} missing {sorted(expected - actual)}"

                index_rows = await conn.exec_driver_sql(
                    "SELECT name, sql FROM sqlite_master WHERE type='index'"
                )
                indexes = {row[0]: row[1] or "" for row in index_rows.fetchall()}
                assert "ux_killsweeps_task_product" not in indexes
                assert {
                    "ux_missed_signals_dedup_key",
                    "ux_missed_signal_drafts_signal",
                    "ux_raw_evidence_chunks_channel_seq",
                    "ix_missed_signal_evidence_evidence",
                    "ux_killsweeps_origin_finding",
                    "ux_killsweep_attempts_active_case",
                    "ux_killsweep_attempts_case_number",
                    "ix_killsweeps_task_product",
                } <= indexes.keys()
                assert "where" in indexes["ux_killsweeps_origin_finding"].lower()
                assert "where" in indexes["ux_killsweep_attempts_active_case"].lower()
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_operations_model_defaults_are_persisted() -> None:
    async def scenario() -> None:
        required_models = {
            "MissedSignal", "MissedSignalEvent", "MissedSignalDraft", "RawEvidence",
            "RawEvidenceChunk", "MissedSignalEvidence", "KillsweepAttempt", "KillsweepEvent",
            "KillsweepReanalysisBatch",
        }
        assert required_models <= set(vars(models))

        engine = await _create_operations_schema()
        session_factory = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with session_factory() as session:
                signal = models.MissedSignal(
                    id="signal", task_id="task", target_id="target", dedup_key="signal-key",
                    rule_key="sensitive_endpoint", endpoint_key="GET example.test/admin",
                )
                draft = models.MissedSignalDraft(
                    id="draft", signal_id=signal.id, task_id="task",
                )
                batch = models.KillsweepReanalysisBatch(
                    id="batch", filters={"status": "failed"},
                )
                case = models.Killsweep(
                    id="case", task_id="task", origin_finding_id="finding",
                )
                attempt = models.KillsweepAttempt(
                    id="attempt", case_id=case.id, task_id="task",
                    batch_id=batch.id, attempt_no=1,
                )
                event = models.KillsweepEvent(
                    id=1, case_id=case.id, attempt_id=attempt.id, task_id="task",
                    sequence=1, kind="queued",
                )
                evidence = models.RawEvidence(
                    id="evidence", task_id="task", target_id="target",
                    missed_signal_id=signal.id, killsweep_event_id=event.id,
                    source_kind="http",
                )
                chunk = models.RawEvidenceChunk(
                    evidence_id=evidence.id, channel="response", seq=0, data=b"body",
                )
                session.add_all([signal, draft, batch, case, attempt, event, evidence, chunk])
                await session.flush()

                assert signal.status == "pending"
                assert signal.source_types == []
                assert signal.hit_count == 1
                assert signal.evidence_count == 0
                assert signal.deepen_count == 0
                assert draft.status == "generating"
                assert draft.revision == 0
                assert evidence.capture_status == "writing"
                assert case.status == "queued"
                assert case.automatic_verdict == "pending_validation"
                assert case.manual_verdict is None
                assert case.attempt_count == 0
                assert case.legacy_without_timeline is False
                assert attempt.status == "queued"
                assert attempt.automatic_verdict == "pending_validation"
        finally:
            await engine.dispose()

    asyncio.run(scenario())
