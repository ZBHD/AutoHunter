"""LiteLLM Proxy 的版本化搜索、探测与指纹定义。"""
from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Literal, cast

from app.gateway_hunt.profiles.base import GatewayProfile
from app.gateway_hunt.schemas import (
    FingerprintResult,
    FingerprintSignal,
    HttpObservation,
    JsonValue,
    ModelParseResult,
    ProbeCategory,
    ProbeSpec,
    ResponseClassification,
    SearchSignature,
    SecretPattern,
    SuccessMatcher,
)


_SUPPORTED_ENGINES = ("fofa", "quake", "hunter", "zoomeye", "shodan", "censys")


def _engine_clauses(
    *,
    fofa: str,
    quake: str,
    hunter: str,
    zoomeye: str,
    shodan: str,
    censys: str,
) -> dict[str, str]:
    return {
        "fofa": fofa,
        "quake": quake,
        "hunter": hunter,
        "zoomeye": zoomeye,
        "shodan": shodan,
        "censys": censys,
    }


_SEARCH_SIGNATURES = (
    SearchSignature(
        signature_id="health_alive_exact",
        signal_kind="body",
        strength="high",
        engine_clauses=_engine_clauses(
            fofa='body="I\'m alive!"',
            quake='response:"I\'m alive!"',
            hunter='web.body="I\'m alive!"',
            zoomeye='http.body:"I\'m alive!"',
            shodan='http.html:"I\'m alive!"',
            censys='services.http.response.body:"I\'m alive!"',
        ),
    ),
    SearchSignature(
        signature_id="model_info_schema",
        signal_kind="combined",
        strength="high",
        engine_clauses=_engine_clauses(
            fofa='body="litellm_params" && body="model_info"',
            quake='response:"litellm_params" AND response:"model_info"',
            hunter='web.body="litellm_params" && web.body="model_info"',
            zoomeye='http.body:"litellm_params" && http.body:"model_info"',
            shodan='http.html:"litellm_params" http.html:"model_info"',
            censys=(
                'services.http.response.body:"litellm_params" AND '
                'services.http.response.body:"model_info"'
            ),
        ),
    ),
    SearchSignature(
        signature_id="litellm_brand",
        signal_kind="body",
        strength="medium",
        engine_clauses=_engine_clauses(
            fofa='body="LiteLLM"',
            quake='response:"LiteLLM"',
            hunter='web.body="LiteLLM"',
            zoomeye='http.body:"LiteLLM"',
            shodan='http.html:"LiteLLM"',
            censys='services.http.response.body:"LiteLLM"',
        ),
    ),
)


def _probe(
    probe_id: str,
    path: str,
    category: ProbeCategory,
    *,
    method: Literal["GET", "HEAD", "POST"] = "GET",
    public_by_design: bool = False,
    finding_eligible: bool = True,
    read_only: bool = True,
    fingerprint_probe: bool = False,
    body_template: dict[str, JsonValue] | None = None,
    expected_content_types: tuple[str, ...] = ("application/json",),
    success_matcher: SuccessMatcher,
    request_cost: int = 1,
) -> ProbeSpec:
    headers_template = {"Accept": ", ".join(expected_content_types)}
    if not public_by_design:
        headers_template["Authorization"] = "Bearer {auth_token}"
    if body_template is not None:
        headers_template["Content-Type"] = "application/json"
    return ProbeSpec(
        probe_id=probe_id,
        method=method,
        path=path,
        category=category,
        public_by_design=public_by_design,
        finding_eligible=finding_eligible,
        read_only=read_only,
        fingerprint_probe=fingerprint_probe,
        headers_template=headers_template,
        body_template=body_template,
        expected_content_types=expected_content_types,
        success_matcher=success_matcher,
        request_cost=request_cost,
    )


_PROBES = (
    _probe(
        "health_liveliness",
        "/health/liveliness",
        "public",
        public_by_design=True,
        finding_eligible=False,
        fingerprint_probe=True,
        expected_content_types=("text/plain",),
        success_matcher=SuccessMatcher.EXACT_ALIVE_TEXT,
    ),
    _probe(
        "health_liveness",
        "/health/liveness",
        "public",
        public_by_design=True,
        finding_eligible=False,
        fingerprint_probe=True,
        expected_content_types=("text/plain",),
        success_matcher=SuccessMatcher.EXACT_ALIVE_TEXT,
    ),
    _probe(
        "health_readiness",
        "/health/readiness",
        "public",
        public_by_design=True,
        finding_eligible=False,
        fingerprint_probe=True,
        expected_content_types=("text/plain",),
        success_matcher=SuccessMatcher.EXACT_ALIVE_TEXT,
    ),
    _probe(
        "v1_models",
        "/v1/models",
        "models",
        success_matcher=SuccessMatcher.MODELS_JSON,
    ),
    _probe(
        "models",
        "/models",
        "models",
        success_matcher=SuccessMatcher.MODELS_JSON,
    ),
    _probe(
        "model_info",
        "/model/info",
        "model_info",
        fingerprint_probe=True,
        success_matcher=SuccessMatcher.MODEL_INFO_JSON,
    ),
    _probe(
        "v1_model_info",
        "/v1/model/info",
        "model_info",
        fingerprint_probe=True,
        success_matcher=SuccessMatcher.MODEL_INFO_JSON,
    ),
    _probe(
        "v1_chat_completions",
        "/v1/chat/completions",
        "inference",
        method="POST",
        read_only=False,
        body_template={
            "model": "{model}",
            "messages": [{"role": "user", "content": "{nonce}"}],
            "stream": False,
            "max_tokens": 1,
        },
        success_matcher=SuccessMatcher.OPENAI_CHAT_JSON,
    ),
    _probe(
        "chat_completions",
        "/chat/completions",
        "inference",
        method="POST",
        read_only=False,
        body_template={
            "model": "{model}",
            "messages": [{"role": "user", "content": "{nonce}"}],
            "stream": False,
            "max_tokens": 1,
        },
        success_matcher=SuccessMatcher.OPENAI_CHAT_JSON,
    ),
    _probe(
        "key_info",
        "/key/info",
        "readonly_admin",
        success_matcher=SuccessMatcher.ADMIN_JSON,
    ),
    _probe(
        "key_list",
        "/key/list",
        "readonly_admin",
        success_matcher=SuccessMatcher.ADMIN_JSON,
    ),
    _probe(
        "routes",
        "/routes",
        "readonly_admin",
        success_matcher=SuccessMatcher.ADMIN_JSON,
    ),
    _probe(
        "config_list",
        "/config/list",
        "readonly_admin",
        success_matcher=SuccessMatcher.ADMIN_JSON,
    ),
    _probe(
        "config_callbacks",
        "/get/config/callbacks",
        "readonly_admin",
        success_matcher=SuccessMatcher.ADMIN_JSON,
    ),
)

_SECRET_PATTERNS = (
    SecretPattern(
        pattern_id="litellm_master_key",
        secret_kind="master_key",
        provider="litellm",
        variable_names=(
            "LITELLM_MASTER_KEY",
            "LITELLM_PROXY_MASTER_KEY",
            "MASTER_KEY",
        ),
        value_prefixes=("sk-",),
        description="LiteLLM Proxy master key configuration metadata",
    ),
    SecretPattern(
        pattern_id="litellm_virtual_key",
        secret_kind="virtual_key",
        provider="litellm",
        variable_names=("LITELLM_VIRTUAL_KEY", "LITELLM_API_KEY"),
        value_prefixes=("sk-",),
        description="LiteLLM virtual key configuration metadata",
    ),
)

_PROBES_BY_PATH = {probe.path: probe for probe in _PROBES}
_HEALTH_PATHS = {
    probe.path
    for probe in _PROBES
    if probe.category == "public" and probe.public_by_design
}
_WAF_MARKERS = (
    "web application firewall",
    "access denied",
    "request blocked",
    "cf-ray",
)


def _json_value(body: str) -> JsonValue | None:
    try:
        return cast(JsonValue, json.loads(body))
    except (TypeError, ValueError):
        return None


def _content_type(response: HttpObservation) -> str:
    return response.content_type.partition(";")[0].strip().lower()


def _probe_id(path: str, fallback: str) -> str:
    probe = _PROBES_BY_PATH.get(path)
    return probe.probe_id if probe is not None else fallback


def _deduplicate(values: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


class LiteLLMProfile(GatewayProfile):
    @property
    def profile_id(self) -> str:
        return "litellm"

    @property
    def version(self) -> str:
        return "1"

    def search_signatures(self) -> tuple[SearchSignature, ...]:
        return tuple(signature.model_copy(deep=True) for signature in _SEARCH_SIGNATURES)

    def probes(self) -> tuple[ProbeSpec, ...]:
        return tuple(probe.model_copy(deep=True) for probe in _PROBES)

    def secret_patterns(self) -> tuple[SecretPattern, ...]:
        return tuple(pattern.model_copy(deep=True) for pattern in _SECRET_PATTERNS)

    def parse_models(self, response: HttpObservation) -> ModelParseResult:
        content_type = _content_type(response)
        if not 200 <= response.status_code < 300:
            return ModelParseResult(valid=False, reason="non-success status")
        if content_type != "application/json" and not content_type.endswith("+json"):
            return ModelParseResult(valid=False, reason="response is not JSON")

        payload = _json_value(response.body)
        if not isinstance(payload, dict) or "error" in payload:
            return ModelParseResult(valid=False, reason="JSON object is missing or contains error")
        records = payload.get("data")
        if not isinstance(records, list) or not records:
            return ModelParseResult(valid=False, reason="model data must be a non-empty list")

        if all(
            isinstance(record, dict)
            and isinstance(record.get("model_name"), str)
            and bool(str(record["model_name"]).strip())
            and isinstance(record.get("litellm_params"), dict)
            and isinstance(record.get("model_info"), dict)
            for record in records
        ):
            model_ids = _deduplicate(
                [str(record["model_name"]).strip() for record in records]
            )
            return ModelParseResult(
                valid=True,
                schema_kind="litellm_model_info",
                model_ids=model_ids,
            )

        if all(
            isinstance(record, dict)
            and isinstance(record.get("id"), str)
            and bool(str(record["id"]).strip())
            for record in records
        ):
            model_ids = _deduplicate(
                [str(record["id"]).strip() for record in records]
            )
            return ModelParseResult(
                valid=True,
                schema_kind="openai_models",
                model_ids=model_ids,
            )

        return ModelParseResult(valid=False, reason="model records do not match a supported schema")

    def classify_response(
        self,
        probe: ProbeSpec,
        response: HttpObservation,
    ) -> ResponseClassification:
        content_type = _content_type(response)
        body = response.body.strip()
        body_lower = body.lower()
        if any(marker in body_lower for marker in _WAF_MARKERS):
            return ResponseClassification(
                category="waf_response",
                valid=False,
                reason="response contains a WAF marker",
            )
        if content_type == "text/html" or body_lower.startswith(("<!doctype html", "<html")):
            return ResponseClassification(
                category="html_response",
                valid=False,
                reason="HTML does not satisfy a gateway API matcher",
            )
        if response.status_code in {401, 403}:
            return ResponseClassification(
                category="auth_required",
                valid=False,
                reason="route requires authentication",
            )
        if response.status_code == 429:
            return ResponseClassification(
                category="rate_limited",
                valid=False,
                reason="route is rate limited",
            )
        if response.status_code == 404:
            return ResponseClassification(
                category="not_found",
                valid=False,
                reason="route was not found",
            )
        if response.status_code >= 500:
            return ResponseClassification(
                category="server_error",
                valid=False,
                reason="gateway returned a server error",
            )
        if not 200 <= response.status_code < 300:
            return ResponseClassification(
                category="error_response",
                valid=False,
                reason="route returned a non-success status",
            )

        payload = _json_value(body) if content_type == "application/json" or content_type.endswith("+json") else None
        if isinstance(payload, dict) and "error" in payload:
            return ResponseClassification(
                category="error_response",
                valid=False,
                reason="successful status contains an error object",
            )

        if probe.success_matcher == SuccessMatcher.EXACT_ALIVE_TEXT:
            valid = content_type == "text/plain" and body == "I'm alive!"
            return ResponseClassification(
                category="public_baseline" if valid else "invalid_response",
                valid=valid,
                reason="exact health response matched" if valid else "health response mismatch",
            )

        if probe.success_matcher in {
            SuccessMatcher.MODELS_JSON,
            SuccessMatcher.MODEL_INFO_JSON,
        }:
            parsed = self.parse_models(response)
            expected_schema = (
                "litellm_model_info"
                if probe.success_matcher == SuccessMatcher.MODEL_INFO_JSON
                else "openai_models"
            )
            valid = parsed.valid and parsed.schema_kind == expected_schema
            category = "model_info" if probe.category == "model_info" else "models"
            return ResponseClassification(
                category=category if valid else "invalid_response",
                valid=valid,
                reason="model schema matched" if valid else parsed.reason or "unexpected model schema",
                model_ids=parsed.model_ids if valid else (),
            )

        if probe.success_matcher == SuccessMatcher.OPENAI_CHAT_JSON:
            choices = payload.get("choices") if isinstance(payload, dict) else None
            first_choice = choices[0] if isinstance(choices, list) and choices else None
            message = first_choice.get("message") if isinstance(first_choice, dict) else None
            valid = (
                isinstance(payload, dict)
                and isinstance(payload.get("id"), str)
                and bool(str(payload["id"]).strip())
                and isinstance(payload.get("model"), str)
                and bool(str(payload["model"]).strip())
                and isinstance(message, dict)
                and isinstance(message.get("content"), str)
            )
            return ResponseClassification(
                category="inference" if valid else "invalid_response",
                valid=valid,
                reason="OpenAI chat schema matched" if valid else "OpenAI chat schema mismatch",
            )

        if probe.success_matcher == SuccessMatcher.ADMIN_JSON:
            valid = isinstance(payload, (dict, list))
            return ResponseClassification(
                category="management" if valid else "invalid_response",
                valid=valid,
                reason="admin JSON matched" if valid else "admin JSON schema mismatch",
            )

        return ResponseClassification(
            category="invalid_response",
            valid=False,
            reason="unsupported response matcher",
        )

    def match_fingerprint(
        self,
        observations: Sequence[HttpObservation],
    ) -> FingerprintResult:
        signals: list[FingerprintSignal] = []
        catch_all_responses = {
            (
                observation.status_code,
                observation.content_type.partition(";")[0].strip().lower(),
                observation.body.strip(),
            )
            for observation in observations
            if (observation.path.partition("?")[0].rstrip("/") or "/")
            not in _PROBES_BY_PATH
        }

        for observation in observations:
            path = observation.path.partition("?")[0].rstrip("/") or "/"
            body = observation.body.strip()
            content_type = observation.content_type.partition(";")[0].strip().lower()
            body_lower = body.lower()
            if any(marker in body_lower for marker in _WAF_MARKERS):
                continue

            if (
                path in _HEALTH_PATHS
                and observation.status_code == 200
                and content_type == "text/plain"
                and body == "I'm alive!"
                and (observation.status_code, content_type, body)
                not in catch_all_responses
            ):
                probe = _PROBES_BY_PATH[path]
                signals.append(
                    FingerprintSignal(
                        probe_id=probe.probe_id,
                        signal_kind="body",
                        strength="high",
                        detail="exact LiteLLM health response",
                        public_by_design=True,
                    )
                )
                continue

            headers = {key.lower(): value for key, value in observation.headers.items()}
            if any(key.startswith("x-litellm-") for key in headers):
                signals.append(
                    FingerprintSignal(
                        probe_id=_probe_id(path, "passive_header"),
                        signal_kind="header",
                        strength="high",
                        detail="LiteLLM response header",
                    )
                )
                continue

            if path in {"/model/info", "/v1/model/info"} and content_type in {
                "application/json",
                "application/problem+json",
            }:
                parsed = self.parse_models(observation)
                if parsed.valid and parsed.schema_kind == "litellm_model_info":
                    signals.append(
                        FingerprintSignal(
                            probe_id=_PROBES_BY_PATH[path].probe_id,
                            signal_kind="response_schema",
                            strength="high",
                            detail="LiteLLM model_info schema",
                        )
                    )
                    continue

            if path not in _HEALTH_PATHS and "litellm" in body_lower:
                signals.append(
                    FingerprintSignal(
                        probe_id=_probe_id(path, "passive_body"),
                        signal_kind="body",
                        strength="medium",
                        detail="LiteLLM product marker",
                    )
                )

        high_count = sum(signal.strength == "high" for signal in signals)
        medium_sources = {
            (signal.probe_id, signal.signal_kind)
            for signal in signals
            if signal.strength == "medium"
        }
        if high_count or len(medium_sources) >= 2:
            status = "confirmed"
            confidence = 0.98 if high_count else 0.86
        elif signals:
            status = "probable"
            confidence = 0.6
        else:
            status = "rejected"
            confidence = 0.0

        public_only = bool(signals) and all(
            signal.public_by_design for signal in signals
        )
        return FingerprintResult(
            status=status,
            confidence=confidence,
            signals=tuple(signals),
            public_only=public_only,
            finding_eligible=status == "confirmed" and not public_only,
        )


assert set(_SUPPORTED_ENGINES) == set(_SEARCH_SIGNATURES[0].engine_clauses)

__all__ = ["LiteLLMProfile"]
