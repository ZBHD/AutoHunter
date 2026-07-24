"""LiteLLM Proxy 的版本化搜索、探测与指纹定义。"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Literal

from app.gateway_hunt.profiles.base import GatewayProfile
from app.gateway_hunt.profiles.response_matchers import (
    WAF_MARKERS,
    classify_probe_response,
    parse_models_response,
    response_content_type,
    response_identity,
)
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
def _probe_id(path: str, fallback: str) -> str:
    probe = _PROBES_BY_PATH.get(path)
    return probe.probe_id if probe is not None else fallback


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
        return parse_models_response(response)

    def classify_response(
        self,
        probe: ProbeSpec,
        response: HttpObservation,
    ) -> ResponseClassification:
        return classify_probe_response(probe, response)

    def match_fingerprint(
        self,
        observations: Sequence[HttpObservation],
    ) -> FingerprintResult:
        signals: list[FingerprintSignal] = []
        control_responses = {
            response_identity(observation)
            for observation in observations
            if (observation.path.partition("?")[0].rstrip("/") or "/")
            not in _PROBES_BY_PATH
        }

        for observation in observations:
            path = observation.path.partition("?")[0].rstrip("/") or "/"
            if path not in _PROBES_BY_PATH:
                continue
            if response_identity(observation) in control_responses:
                continue
            body = observation.body.strip()
            content_type = response_content_type(observation)
            body_lower = body.lower()
            if any(marker in body_lower for marker in WAF_MARKERS):
                continue

            if (
                path in _HEALTH_PATHS
                and observation.status_code == 200
                and content_type == "text/plain"
                and body == "I'm alive!"
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
