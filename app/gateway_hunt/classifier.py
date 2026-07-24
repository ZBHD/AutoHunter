"""把 LiteLLM Profile/Validator 的结构化结果转换为 Finding 候选。"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from app.db.models import GatewayAsset
from app.gateway_hunt.schemas import SecretArtifact


@dataclass(frozen=True, slots=True)
class FindingCandidate:
    vuln_type: str
    severity: str
    title: str
    description: str
    dedup_key: str
    target_url: str
    evidence_id: str = ""


def _dedup(asset: GatewayAsset, vuln_type: str, impact: str = "") -> str:
    material = "|".join((asset.origin_key, vuln_type, impact))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def classify_probe(asset: GatewayAsset, probe: object) -> FindingCandidate | None:
    result = str(getattr(probe, "result", ""))
    mapping = {
        "anonymous_inference": (
            "litellm_unauthenticated_inference",
            "high",
            "LiteLLM 无 Key 可完成模型推理",
        ),
        "anonymous_models": (
            "litellm_unauthenticated_model_list",
            "low",
            "LiteLLM 无 Key 可读取模型列表",
        ),
        "management_secret": (
            "litellm_management_api_exposure",
            "high",
            "LiteLLM 管理接口暴露敏感信息",
        ),
    }
    item = mapping.get(result)
    if item is None:
        return None
    vuln_type, severity, title = item
    evidence_id = str(getattr(probe, "evidence_id", "") or "")
    return FindingCandidate(
        vuln_type=vuln_type,
        severity=severity,
        title=title,
        description="结构化 LiteLLM Probe 结果确认了该暴露面。",
        dedup_key=_dedup(asset, vuln_type),
        target_url=asset.canonical_base_url,
        evidence_id=evidence_id,
    )


def classify_secret(
    asset: GatewayAsset,
    secret: SecretArtifact,
    *,
    validation_status: str,
) -> FindingCandidate | None:
    if validation_status != "valid":
        return None
    if secret.secret_type in {"master_key", "virtual_key"}:
        vuln_type = (
            "litellm_master_key_leak"
            if secret.secret_type == "master_key"
            else "litellm_virtual_key_leak"
        )
        severity = "critical" if secret.secret_type == "master_key" else "high"
    elif secret.secret_type == "provider_key":
        vuln_type, severity = "provider_api_key_leak", "critical"
    elif secret.secret_type == "database_dsn":
        vuln_type, severity = "litellm_database_dsn_exposure", "critical"
    else:
        return None
    return FindingCandidate(
        vuln_type=vuln_type,
        severity=severity,
        title=f"{secret.provider} 凭据暴露",
        description="Secret 来自网关证据，且对应 Validator 已返回 valid。",
        dedup_key=_dedup(asset, vuln_type, secret.sha256),
        target_url=asset.canonical_base_url,
    )


__all__ = ["FindingCandidate", "classify_probe", "classify_secret"]
