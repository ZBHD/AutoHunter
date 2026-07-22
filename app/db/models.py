"""SQLAlchemy 数据库模型（对应设计文档 §5 + §8.5 状态机）。

设计为 24x7 不停歇：所有状态全部持久化，进程重启可从这些表完整恢复。
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import (
    JSON, Boolean, DateTime, Float, ForeignKey, ForeignKeyConstraint, Index,
    Integer, LargeBinary, String, Text, text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> datetime:
    return datetime.now(timezone.utc)


CST = timezone(timedelta(hours=8))  # 东八区（北京时间）


def to_cst_iso(dt: datetime | None) -> str | None:
    """数据库存 UTC naive 时间（列无时区信息），输出统一转东八区 ISO 字符串。

    前端用 slice(0,19) 截取时直接得到东八区时间值；用 new Date 解析时按
    +08:00 偏移正确换算本地时区。
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(CST).isoformat()


class Base(DeclarativeBase):
    pass


class Task(Base):
    """一个挖掘任务 = 一个资产范围（FOFA 语法 / 域名清单），running 时永不自停。"""
    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200))
    src_type: Mapped[str] = mapped_column(String(20), default="edusrc")
    vuln_types: Mapped[list] = mapped_column(JSON, default=list)        # 选定漏洞类型
    src_rules: Mapped[str] = mapped_column(Text, default="")            # SRC 规则全文（审核用）
    target_source: Mapped[str] = mapped_column(String(20), default="fofa")  # fofa / manual / both / site
    fofa_query: Mapped[str] = mapped_column(Text, default="")
    hunt_direction: Mapped[str] = mapped_column(Text, default="")
    manual_targets: Mapped[list] = mapped_column(JSON, default=list)
    model_config_json: Mapped[dict] = mapped_column("model_config", JSON, default=dict)
    # 专项任务模式配置；旧任务通过迁移补列并默认为空对象。
    mode_config_json: Mapped[dict] = mapped_column("mode_config", JSON, default=dict)
    fofa_config: Mapped[dict] = mapped_column(JSON, default=dict)       # keys/max_pages/page_size/cursor
    search_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    engine: Mapped[str] = mapped_column(String(20), default="")         # 搜索引擎：fofa/quake/hunter/zoomeye/shodan/censys
    concurrency: Mapped[int] = mapped_column(Integer, default=3)
    # created / running / paused / stopped / idle
    status: Mapped[str] = mapped_column(String(20), default="created")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)

    targets: Mapped[list["Target"]] = relationship(back_populates="task", cascade="all, delete-orphan")
    gateway_assets: Mapped[list["GatewayAsset"]] = relationship(
        back_populates="task",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class Target(Base):
    """单个待挖目标（host 级）。状态机贯穿 24x7 恢复逻辑。"""
    __tablename__ = "targets"
    # 目标库去重：普通搜集同一 source 下 host 唯一；单站协作可让同一 host 按不同路线并行。
    __table_args__ = (
        Index("ux_targets_task_host", "task_id", "host", "source", unique=True),
        # LiteLLM 扩展表通过 (target_id, task_id) 复合外键锁定任务归属。
        Index("ux_targets_id_task_id", "id", "task_id", unique=True),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), index=True)
    url: Mapped[str] = mapped_column(String(500))
    host: Mapped[str] = mapped_column(String(255), index=True)         # 去重键
    ip: Mapped[str] = mapped_column(String(64), default="")
    org: Mapped[str] = mapped_column(String(300), default="")
    title: Mapped[str] = mapped_column(String(500), default="")
    source: Mapped[str] = mapped_column(String(20), default="fofa")    # fofa / manual
    is_edu: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    school: Mapped[str] = mapped_column(String(200), default="")  # 搜集阶段判定的候选归属学校

    # EduSRC 目标优先级评分（决定 worker 先打谁，高分先派；只排序不过滤）
    priority_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    priority_reason: Mapped[str] = mapped_column(String(300), default="")
    # 人工队列顺序；NULL 表示仍使用 AI priority_score 自动排序。
    queue_position: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # queued / assigned / scanning / done / skipped / dead / removed
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    verdict: Mapped[str] = mapped_column(String(20), default="")       # found / no_vuln / error
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    # 硬骨头库：仅记录终态 dead/skipped 的原因，便于审计与回捞
    dead_reason: Mapped[str] = mapped_column(String(300), default="")
    # 非终态最近错误：临时 LLM/网络/恢复回队等，不再污染 dead_reason
    last_error: Mapped[str] = mapped_column(String(500), default="")
    # 审核打回深挖：本轮要定向打穿什么(指令+原 finding 摘要)，以及已深挖次数(防死循环)
    deepen_context: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    deepen_count: Mapped[int] = mapped_column(Integer, default=0)
    # 搜集阶段顺带查到的、过滤打分后的该域泄露凭证（喂给 worker 作额外攻击面）。
    leaked_creds: Mapped[list | None] = mapped_column(JSON, nullable=True)
    # 通杀派生目标所属案例；人工否定时只取消该案例尚未执行的目标。
    killsweep_case_id: Mapped[str | None] = mapped_column(
        ForeignKey("killsweeps.id", ondelete="SET NULL"), nullable=True, index=True,
    )
    assigned_worker: Mapped[str] = mapped_column(String(64), default="")
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)

    task: Mapped["Task"] = relationship(back_populates="targets")
    findings: Mapped[list["Finding"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    gateway_asset: Mapped["GatewayAsset | None"] = relationship(
        back_populates="target",
        primaryjoin="Target.id == GatewayAsset.target_id",
        foreign_keys="GatewayAsset.target_id",
        uselist=False,
        passive_deletes=True,
    )


class Finding(Base):
    """worker 产出的原始漏洞，对应 schemas.Finding。"""
    __tablename__ = "findings"
    # 漏洞库去重：全局 dedup_key 唯一（空 key 不约束；superseded 会改写 key 腾位）
    __table_args__ = (
        Index("ux_findings_dedup_global", "dedup_key", unique=True, sqlite_where=text("dedup_key != ''")),
        # 跨 host 查重按归一化类型的别名集合做 IN 预筛，复合索引覆盖 (vuln_type, status)
        # 让 `WHERE vuln_type IN (...) AND status != superseded` 走索引而非全表扫。
        Index("ix_findings_vuln_type_status", "vuln_type", "status"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), index=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), index=True)
    worker_id: Mapped[str] = mapped_column(String(64), default="")
    vuln_type: Mapped[str] = mapped_column(String(80))
    title: Mapped[str] = mapped_column(String(500))
    severity_claimed: Mapped[str] = mapped_column(String(10))
    target_url: Mapped[str] = mapped_column(String(500))
    owner: Mapped[str] = mapped_column(String(300), default="")  # 归属单位(学校)+确认依据
    description: Mapped[str] = mapped_column(Text, default="")
    steps: Mapped[list] = mapped_column(JSON, default=list)
    poc: Mapped[str] = mapped_column(Text, default="")
    raw_request: Mapped[str] = mapped_column(Text, default="")
    raw_response: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    affected_scope: Mapped[str] = mapped_column(Text, default="")
    kill_chain: Mapped[list] = mapped_column(JSON, default=list)  # 攻击链路：[{method, detail}, ...]
    # 报告助手对话历史：[{role:'user'|'assistant', content:'...'}]，按 finding 持久化
    assistant_messages: Mapped[list] = mapped_column(JSON, default=list)
    # Markdown 报告成功下载时间；为空表示尚未下载。
    markdown_downloaded_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    self_check: Mapped[dict] = mapped_column(JSON, default=dict)
    dedup_key: Mapped[str] = mapped_column(String(128), default="", index=True)  # 漏洞级去重
    # pending_review / reviewed
    status: Mapped[str] = mapped_column(String(20), default="pending_review", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    target: Mapped["Target"] = relationship(back_populates="findings")
    review: Mapped["Review | None"] = relationship(back_populates="finding", uselist=False, cascade="all, delete-orphan")


class Review(Base):
    """审核 agent 对 Finding 的结论，对应 schemas.Review。"""
    __tablename__ = "reviews"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True, unique=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), index=True)
    verdict: Mapped[str] = mapped_column(String(20))           # accepted / ignored
    confidence: Mapped[str] = mapped_column(String(20))        # confirmed / likely / uncertain
    severity_final: Mapped[str | None] = mapped_column(String(10), nullable=True)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    in_scope: Mapped[bool] = mapped_column(Boolean, default=True)
    is_duplicate: Mapped[bool] = mapped_column(Boolean, default=False)
    ignore_reasons: Mapped[list] = mapped_column(JSON, default=list)
    downgrade_reasons: Mapped[list] = mapped_column(JSON, default=list)
    reproduced: Mapped[bool] = mapped_column(Boolean, default=False)
    reviewer_notes: Mapped[str] = mapped_column(Text, default="")
    deepen_directive: Mapped[str] = mapped_column(Text, default="")  # verdict=deepen 时的深挖指令
    reviewed_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    # ===== 用户复审（人工二次审核，仅 AI accepted 进入）=====
    # pending=待复审 / passed=通过(进待提交) / rejected=不通过
    user_status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    user_severity: Mapped[str | None] = mapped_column(String(10), nullable=True)  # 用户调整后的等级
    user_notes: Mapped[str] = mapped_column(Text, default="")                     # 用户复审备注
    # 用户编辑后的报告内容（覆盖 finding 原值，None 表示用原值）
    user_edits: Mapped[dict] = mapped_column(JSON, default=dict)
    # 待提交后：是否已提交到 SRC
    submitted: Mapped[bool] = mapped_column(Boolean, default=False)
    user_reviewed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    finding: Mapped["Finding"] = relationship(back_populates="review")


class MissedSignal(Base):
    """尚未形成正式 Finding 的高价值信号及其人工处理状态。"""
    __tablename__ = "missed_signals"
    __table_args__ = (
        Index("ux_missed_signals_dedup_key", "dedup_key", unique=True),
        Index("ix_missed_signals_status_risk_seen", "status", "risk_score", "last_seen_at"),
        Index("ix_missed_signals_task_status", "task_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id", ondelete="CASCADE"), index=True)
    target_id: Mapped[str | None] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), nullable=True, index=True,
    )
    source_finding_id: Mapped[str | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True,
    )
    converted_finding_id: Mapped[str | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True,
    )
    dedup_key: Mapped[str] = mapped_column(String(128))
    rule_key: Mapped[str] = mapped_column(String(80), default="")
    rule_label: Mapped[str] = mapped_column(String(200), default="")
    method: Mapped[str] = mapped_column(String(16), default="")
    endpoint_key: Mapped[str] = mapped_column(String(1000), default="")
    title: Mapped[str] = mapped_column(String(500), default="")
    summary: Mapped[str] = mapped_column(Text, default="")
    risk_level: Mapped[str] = mapped_column(String(20), default="medium")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    source_types: Mapped[list] = mapped_column(JSON, default=list)
    # pending / deepening / converted / rejected
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    hit_count: Mapped[int] = mapped_column(Integer, default=1)
    evidence_count: Mapped[int] = mapped_column(Integer, default=0)
    deepen_count: Mapped[int] = mapped_column(Integer, default=0)
    deepen_phase: Mapped[str] = mapped_column(String(40), default="")
    deepen_directive: Mapped[str] = mapped_column(Text, default="")
    deepen_error: Mapped[str] = mapped_column(Text, default="")
    last_rejection_reason: Mapped[str] = mapped_column(Text, default="")
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    converted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=_now, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)


class MissedSignalEvent(Base):
    """疑似信号不可变的状态与人工操作审计记录。"""
    __tablename__ = "missed_signal_events"
    __table_args__ = (
        Index("ix_missed_signal_events_signal_created", "signal_id", "created_at"),
        Index("ix_missed_signal_events_task_created", "task_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    signal_id: Mapped[str] = mapped_column(
        ForeignKey("missed_signals.id", ondelete="CASCADE"), index=True,
    )
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(40), default="")
    actor_role: Mapped[str] = mapped_column(String(20), default="system")
    from_status: Mapped[str] = mapped_column(String(20), default="")
    to_status: Mapped[str] = mapped_column(String(20), default="")
    reason: Mapped[str] = mapped_column(Text, default="")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class MissedSignalDraft(Base):
    """由已有证据生成、可自动保存并采用乐观锁编辑的报告草稿。"""
    __tablename__ = "missed_signal_drafts"
    __table_args__ = (
        Index("ux_missed_signal_drafts_signal", "signal_id", unique=True),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    signal_id: Mapped[str] = mapped_column(
        ForeignKey("missed_signals.id", ondelete="CASCADE"), index=True,
    )
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id", ondelete="CASCADE"), index=True)
    # generating / ready / failed / confirmed
    status: Mapped[str] = mapped_column(String(20), default="generating", index=True)
    content: Mapped[dict] = mapped_column(JSON, default=dict)
    missing_evidence: Mapped[list] = mapped_column(JSON, default=list)
    provider_trace: Mapped[list] = mapped_column(JSON, default=list)
    last_error: Mapped[str] = mapped_column(Text, default="")
    generation_count: Mapped[int] = mapped_column(Integer, default=0)
    revision: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Killsweep(Base):
    """通杀候选：审核 accepted 一个洞后，通杀 Hunter 分析该系统是否为通用产品、能否一打一片。

    每个源 Finding 对应一个非历史案例；产品指纹只用于检索，不再决定案例身份。
    """
    __tablename__ = "killsweeps"
    __table_args__ = (
        Index("ix_killsweeps_task_product", "task_id", "product_key"),
        Index(
            "ux_killsweeps_origin_finding", "origin_finding_id", unique=True,
            sqlite_where=text("origin_finding_id <> '' AND legacy_without_timeline = 0"),
        ),
        Index("ix_killsweeps_status_finished", "status", "finished_at"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), index=True)
    origin_finding_id: Mapped[str] = mapped_column(String(32), default="")  # 触发分析的源漏洞
    product_key: Mapped[str] = mapped_column(String(120), default="", index=True)  # 产品指纹去重键(归一化)
    product_name: Mapped[str] = mapped_column(String(200), default="")  # 通用产品/框架名称
    vuln_type: Mapped[str] = mapped_column(String(80), default="")
    vuln_summary: Mapped[str] = mapped_column(Text, default="")          # 通杀漏洞说明
    fofa_query: Mapped[str] = mapped_column(Text, default="")            # 圈定同款系统的 FOFA 语法
    fingerprint: Mapped[str] = mapped_column(Text, default="")           # 指纹依据(title/body/server/favicon)
    asset_count: Mapped[int] = mapped_column(Integer, default=0)         # 全网同款资产规模
    edu_count: Mapped[int] = mapped_column(Integer, default=0)           # 教育行业同款规模
    is_killsweep: Mapped[bool] = mapped_column(Boolean, default=False)   # 是否判定可通杀
    confidence: Mapped[str] = mapped_column(String(20), default="")      # confirmed/likely/uncertain
    verified_url: Mapped[str] = mapped_column(String(500), default="")   # 实际验证的同款站点
    verified: Mapped[bool] = mapped_column(Boolean, default=False)       # 是否打了1个同款验证成功
    # 通杀影响明细表：[{school, url, host, title, vuln_title, status, evidence, dedup_key}]
    # 既用于前端展示，也会进入 worker 查重上下文，避免同学校同通杀洞反复提交。
    affected_table: Mapped[list] = mapped_column(JSON, default=list)
    notes: Mapped[str] = mapped_column(Text, default="")                 # 分析结论/批量建议
    # queued / running / succeeded / failed
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    # pending_validation / killsweep / not_killsweep
    automatic_verdict: Mapped[str] = mapped_column(
        String(20), default="pending_validation", index=True,
    )
    # null / confirmed / not_killsweep / invalid；与自动结论并列保留。
    manual_verdict: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    manual_reason: Mapped[str] = mapped_column(Text, default="")
    manual_actor: Mapped[str] = mapped_column(String(40), default="")
    manual_reviewed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    failure_kind: Mapped[str] = mapped_column(String(60), default="")
    failure_message: Mapped[str] = mapped_column(Text, default="")
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    queued_at: Mapped[datetime | None] = mapped_column(DateTime, default=_now, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    legacy_without_timeline: Mapped[bool] = mapped_column(Boolean, default=False)
    # 避免 Killsweep 与 Attempt 互相声明外键造成 SQLite 环形建表。
    current_attempt_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    latest_success_attempt_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)


class KillsweepReanalysisBatch(Base):
    """一次按当前筛选条件选择最多 40 条案例的重析请求。"""
    __tablename__ = "killsweep_reanalysis_batches"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    filters: Mapped[dict] = mapped_column(JSON, default=dict)
    actor_role: Mapped[str] = mapped_column(String(20), default="full")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, index=True)


class KillsweepAttempt(Base):
    """通杀案例的一次不可覆盖分析尝试。"""
    __tablename__ = "killsweep_attempts"
    __table_args__ = (
        Index("ux_killsweep_attempts_case_number", "case_id", "attempt_no", unique=True),
        Index(
            "ux_killsweep_attempts_active_case", "case_id", unique=True,
            sqlite_where=text("status IN ('queued', 'running')"),
        ),
        Index("ix_killsweep_attempts_task_status", "task_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    case_id: Mapped[str] = mapped_column(
        ForeignKey("killsweeps.id", ondelete="CASCADE"), index=True,
    )
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id", ondelete="CASCADE"), index=True)
    batch_id: Mapped[str | None] = mapped_column(
        ForeignKey("killsweep_reanalysis_batches.id", ondelete="SET NULL"),
        nullable=True, index=True,
    )
    attempt_no: Mapped[int] = mapped_column(Integer)
    trigger: Mapped[str] = mapped_column(String(30), default="initial")
    # queued / running / succeeded / failed / cancelled
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    automatic_verdict: Mapped[str] = mapped_column(String(20), default="pending_validation")
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    provider_trace: Mapped[list] = mapped_column(JSON, default=list)
    error_kind: Mapped[str] = mapped_column(String(60), default="")
    error_message: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class EscalationAttempt(Base):
    """一次按 Finding 等级预算执行的扩大危害尝试。"""
    __tablename__ = "escalation_attempts"
    __table_args__ = (
        Index("ux_escalation_attempts_finding", "finding_id", unique=True),
        Index("ix_escalation_attempts_task_status", "task_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    task_id: Mapped[str] = mapped_column(
        ForeignKey("tasks.id", ondelete="CASCADE"), index=True,
    )
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True,
    )
    orig_severity: Mapped[str] = mapped_column(String(10), default="中危")
    round_budget: Mapped[int] = mapped_column(Integer, default=0)
    # queued / running / succeeded / skipped / failed
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    error_kind: Mapped[str] = mapped_column(String(60), default="")
    error_message: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class KillsweepEvent(Base):
    """一次通杀尝试中的完整有序时间线事件。"""
    __tablename__ = "killsweep_events"
    __table_args__ = (
        Index("ix_killsweep_events_case_sequence", "case_id", "sequence"),
        Index("ix_killsweep_events_attempt_sequence", "attempt_id", "sequence"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(
        ForeignKey("killsweeps.id", ondelete="CASCADE"), index=True,
    )
    attempt_id: Mapped[str | None] = mapped_column(
        ForeignKey("killsweep_attempts.id", ondelete="CASCADE"), nullable=True, index=True,
    )
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id", ondelete="CASCADE"), index=True)
    sequence: Mapped[int] = mapped_column(Integer, default=0)
    kind: Mapped[str] = mapped_column(String(50), default="")
    level: Mapped[str] = mapped_column(String(10), default="info")
    summary: Mapped[str] = mapped_column(Text, default="")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class RawEvidence(Base):
    """工具完整原始证据的元数据；正文按频道存入分块表。"""
    __tablename__ = "raw_evidence"
    __table_args__ = (
        Index("ix_raw_evidence_signal_created", "missed_signal_id", "created_at"),
        Index("ix_raw_evidence_killsweep_event", "killsweep_event_id"),
        Index("ix_raw_evidence_task_created", "task_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id", ondelete="CASCADE"), index=True)
    target_id: Mapped[str | None] = mapped_column(
        ForeignKey("targets.id", ondelete="SET NULL"), nullable=True, index=True,
    )
    missed_signal_id: Mapped[str | None] = mapped_column(
        ForeignKey("missed_signals.id", ondelete="SET NULL"), nullable=True, index=True,
    )
    killsweep_event_id: Mapped[int | None] = mapped_column(
        ForeignKey("killsweep_events.id", ondelete="CASCADE"), nullable=True, index=True,
    )
    source_kind: Mapped[str] = mapped_column(String(40), default="")
    # writing / complete / partial / failed / legacy_partial
    capture_status: Mapped[str] = mapped_column(String(20), default="writing", index=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    preview: Mapped[dict] = mapped_column(JSON, default=dict)
    content_hash: Mapped[str] = mapped_column(String(64), default="", index=True)
    # 私有清理注册表：仅记录尚待删除的 `.captures/<id>` 目录，不通过 API/LLM 暴露。
    spool_directory: Mapped[str | None] = mapped_column(Text, nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class GatewayAsset(Base):
    """LiteLLM 网关资产；作为 Target 的一对一专项扫描状态扩展。"""
    __tablename__ = "gateway_assets"
    __table_args__ = (
        ForeignKeyConstraint(
            ["target_id", "task_id"],
            ["targets.id", "targets.task_id"],
            ondelete="CASCADE",
        ),
        Index("ux_gateway_asset_task_origin", "task_id", "origin_key", unique=True),
        Index("ux_gateway_assets_id_task_id", "id", "task_id", unique=True),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    task_id: Mapped[str] = mapped_column(
        ForeignKey("tasks.id", ondelete="CASCADE"), index=True,
    )
    target_id: Mapped[str] = mapped_column(String(32), unique=True)
    profile_id: Mapped[str] = mapped_column(String(40), default="litellm")
    profile_version: Mapped[str] = mapped_column(String(20), default="1")
    canonical_base_url: Mapped[str] = mapped_column(String(700))
    origin_key: Mapped[str] = mapped_column(String(500))
    mount_path: Mapped[str] = mapped_column(String(300), default="")
    fingerprint_status: Mapped[str] = mapped_column(String(20), default="probable")
    fingerprint_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    fingerprint_signals: Mapped[list] = mapped_column(JSON, default=list)
    detected_version: Mapped[str] = mapped_column(String(80), default="")
    auth_state: Mapped[str] = mapped_column(String(20), default="unknown")
    model_names: Mapped[list] = mapped_column(JSON, default=list)
    model_count: Mapped[int] = mapped_column(Integer, default=0)
    scan_state: Mapped[str] = mapped_column(String(40), default="discovered")
    scan_epoch: Mapped[int] = mapped_column(Integer, default=0)
    last_error_kind: Mapped[str] = mapped_column(String(40), default="")
    last_error: Mapped[str] = mapped_column(String(500), default="")
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_scan_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)

    task: Mapped["Task"] = relationship(back_populates="gateway_assets")
    target: Mapped["Target"] = relationship(
        back_populates="gateway_asset",
        primaryjoin="GatewayAsset.target_id == Target.id",
        foreign_keys=[target_id],
    )
    secrets: Mapped[list["GatewaySecret"]] = relationship(
        back_populates="gateway_asset",
        primaryjoin="GatewayAsset.id == GatewaySecret.gateway_asset_id",
        foreign_keys="GatewaySecret.gateway_asset_id",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    observations: Mapped[list["GatewayObservation"]] = relationship(
        back_populates="gateway_asset",
        primaryjoin="GatewayAsset.id == GatewayObservation.gateway_asset_id",
        foreign_keys="GatewayObservation.gateway_asset_id",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class GatewaySecret(Base):
    """网关或其上游 Provider 暴露的凭据及验证状态。"""
    __tablename__ = "gateway_secrets"
    __table_args__ = (
        ForeignKeyConstraint(
            ["gateway_asset_id", "task_id"],
            ["gateway_assets.id", "gateway_assets.task_id"],
            ondelete="CASCADE",
        ),
        Index(
            "ux_gateway_secret_asset_hash",
            "gateway_asset_id", "secret_sha256",
            unique=True,
        ),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    task_id: Mapped[str] = mapped_column(
        ForeignKey("tasks.id", ondelete="CASCADE"), index=True,
    )
    gateway_asset_id: Mapped[str] = mapped_column(String(32), index=True)
    finding_id: Mapped[str | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True,
    )
    secret_type: Mapped[str] = mapped_column(String(40), default="other")
    provider: Mapped[str] = mapped_column(String(40), default="unknown")
    secret_name: Mapped[str] = mapped_column(String(160), default="")
    secret_value: Mapped[str] = mapped_column(Text)
    secret_sha256: Mapped[str] = mapped_column(String(64))
    source_url: Mapped[str] = mapped_column(String(700), default="")
    source_location: Mapped[str] = mapped_column(String(300), default="")
    source_context: Mapped[str] = mapped_column(Text, default="")
    credential_group_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    validation_context: Mapped[dict] = mapped_column(JSON, default=dict)
    validation_status: Mapped[str] = mapped_column(String(30), default="pending", index=True)
    validated_models: Mapped[list] = mapped_column(JSON, default=list)
    validation_evidence_id: Mapped[str | None] = mapped_column(
        ForeignKey("raw_evidence.id", ondelete="SET NULL"), nullable=True,
    )
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    last_validated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)

    gateway_asset: Mapped["GatewayAsset"] = relationship(
        back_populates="secrets",
        primaryjoin="GatewaySecret.gateway_asset_id == GatewayAsset.id",
        foreign_keys=[gateway_asset_id],
    )
    finding: Mapped["Finding | None"] = relationship()
    validation_evidence: Mapped["RawEvidence | None"] = relationship()


class GatewayObservation(Base):
    """专项 Probe 的轻量索引记录，完整请求与响应由 RawEvidence 保存。"""
    __tablename__ = "gateway_observations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["gateway_asset_id", "task_id"],
            ["gateway_assets.id", "gateway_assets.task_id"],
            ondelete="CASCADE",
        ),
        Index(
            "ux_gateway_observation_probe",
            "gateway_asset_id", "scan_epoch", "probe_id", "auth_variant",
            unique=True,
        ),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    task_id: Mapped[str] = mapped_column(
        ForeignKey("tasks.id", ondelete="CASCADE"), index=True,
    )
    gateway_asset_id: Mapped[str] = mapped_column(String(32), index=True)
    gateway_secret_id: Mapped[str | None] = mapped_column(
        ForeignKey("gateway_secrets.id", ondelete="SET NULL"), nullable=True,
    )
    scan_epoch: Mapped[int] = mapped_column(Integer, default=0)
    stage: Mapped[str] = mapped_column(String(40))
    probe_id: Mapped[str] = mapped_column(String(120))
    auth_variant: Mapped[str] = mapped_column(String(20), default="none")
    result: Mapped[str] = mapped_column(String(20), default="inconclusive")
    status_code: Mapped[int] = mapped_column(Integer, default=0)
    content_type: Mapped[str] = mapped_column(String(120), default="")
    evidence_id: Mapped[str | None] = mapped_column(
        ForeignKey("raw_evidence.id", ondelete="SET NULL"), nullable=True,
    )
    observed_at: Mapped[datetime] = mapped_column(DateTime, default=_now, index=True)

    gateway_asset: Mapped["GatewayAsset"] = relationship(
        back_populates="observations",
        primaryjoin="GatewayObservation.gateway_asset_id == GatewayAsset.id",
        foreign_keys=[gateway_asset_id],
    )
    secret: Mapped["GatewaySecret | None"] = relationship()
    evidence: Mapped["RawEvidence | None"] = relationship()


class RawEvidenceChunk(Base):
    """原始证据固定大小分块；同频道按 seq 串流重建。"""
    __tablename__ = "raw_evidence_chunks"
    __table_args__ = (
        Index(
            "ux_raw_evidence_chunks_channel_seq",
            "evidence_id", "channel", "seq", unique=True,
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    evidence_id: Mapped[str] = mapped_column(
        ForeignKey("raw_evidence.id", ondelete="CASCADE"), index=True,
    )
    channel: Mapped[str] = mapped_column(String(30))
    seq: Mapped[int] = mapped_column(Integer)
    data: Mapped[bytes] = mapped_column(LargeBinary)


class MissedSignalEvidence(Base):
    """多条疑似信号共享同一份完整 capture 的关联表。

    ``RawEvidence.missed_signal_id`` 保留为旧库兼容的主关联；新运行时关系
    统一写入这里，因此同一份分块正文不会因规则命中数增加而复制。
    """
    __tablename__ = "missed_signal_evidence"
    __table_args__ = (
        Index("ix_missed_signal_evidence_evidence", "evidence_id"),
    )

    missed_signal_id: Mapped[str] = mapped_column(
        ForeignKey("missed_signals.id", ondelete="CASCADE"), primary_key=True,
    )
    evidence_id: Mapped[str] = mapped_column(
        ForeignKey("raw_evidence.id", ondelete="CASCADE"), primary_key=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class TaskEvent(Base):
    """审计/实时日志事件。"""
    __tablename__ = "task_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), index=True)
    agent: Mapped[str] = mapped_column(String(20), default="")     # orchestrator/collector/worker/reviewer
    level: Mapped[str] = mapped_column(String(10), default="info")  # info/warn/error
    kind: Mapped[str] = mapped_column(String(40), default="")       # 事件类型
    message: Mapped[str] = mapped_column(Text, default="")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    ts: Mapped[datetime] = mapped_column(DateTime, default=_now, index=True)


class Intel(Base):
    """全局情报库（跨任务共享）：沉淀挖洞过程中可复用的知识。

    单表四类，用 kind 区分，避免多表冗余：
      - cred         验证过的有效凭证/撞库结果   match_key=root域
      - fingerprint  指纹→打法映射(CVE/payload/默认口令)  match_key=系统指纹标识
      - endpoint     有效路径/未授权端点          match_key=系统指纹标识
      - profile      目标画像(技术栈/WAF/突破口)   match_key=root域

    去重：(kind, match_key, dedup_hash) 唯一；重复命中只 +hit_count、更新 last_seen，绝不新增行。
    检索：触发式——按当前目标的 root域/系统指纹匹配 match_key，命中才注入，不冗余。
    """
    __tablename__ = "intel"
    __table_args__ = (
        # 全局去重：同类+同检索键+同内容指纹只留一条
        Index("ux_intel_dedup", "kind", "match_key", "dedup_hash", unique=True),
        # 检索加速：按 kind+match_key 查
        Index("ix_intel_lookup", "kind", "match_key"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    kind: Mapped[str] = mapped_column(String(20), index=True)          # cred/fingerprint/endpoint/profile
    match_key: Mapped[str] = mapped_column(String(255), default="")    # 触发检索键(root域 或 系统指纹)
    dedup_hash: Mapped[str] = mapped_column(String(64), default="")    # 内容指纹(去重)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)          # 实际情报内容(按 kind 不同结构)
    summary: Mapped[str] = mapped_column(String(500), default="")      # 一句话摘要(注入 prompt 用)
    source_host: Mapped[str] = mapped_column(String(255), default="")  # 贡献该情报的 host
    source_task_id: Mapped[str] = mapped_column(String(32), default="")
    confidence: Mapped[str] = mapped_column(String(20), default="likely")  # verified(出洞验证)/likely(声称有效)
    hit_count: Mapped[int] = mapped_column(Integer, default=1, index=True)  # 命中/复用次数(越高越可信)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=_now, index=True)


class SystemSettings(Base):
    """全局系统配置（单行 id=global）。任务级配置可覆盖此处默认值。"""
    __tablename__ = "system_settings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default="global")
    llm: Mapped[dict] = mapped_column(JSON, default=dict)       # base_url/api_key/model/temperature
    fofa: Mapped[dict] = mapped_column(JSON, default=dict)      # key/max_pages/page_size/default_intent_mode
    engines: Mapped[dict] = mapped_column(JSON, default=dict)   # {engine_name: {key, base_url, ...}}
    defaults: Mapped[dict] = mapped_column(JSON, default=dict)  # concurrency/skip_score_threshold/engine
    llm_providers: Mapped[list] = mapped_column(JSON, default=list)
    fofa_keys: Mapped[list] = mapped_column(JSON, default=list)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)
