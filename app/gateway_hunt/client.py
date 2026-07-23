"""受 Gateway Profile 约束的 LiteLLM 异步扫描客户端。"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import httpx

from app.db.models import GatewayAsset
from app.gateway_hunt.auth_diff import compare_auth_variants
from app.gateway_hunt.registry import get_profile
from app.gateway_hunt.schemas import HttpObservation, ProbeSpec, ResponseSample, SecretArtifact
from app.gateway_hunt.secret_extractor import extract_secrets
from app.gateway_hunt.service import GatewayProbeResult, GatewayScanInput


_INVALID_TOKEN = "litellm-invalid-control-token"
_MAX_RESPONSE_CHARS = 512_000


@dataclass(slots=True)
class _Budget:
    limit: int
    used: int = 0
    exhausted: bool = False

    def take(self, cost: int = 1) -> bool:
        if self.used + cost > self.limit:
            self.exhausted = True
            return False
        self.used += cost
        return True


def _probe_url(base_url: str, path: str) -> str:
    parsed = urlsplit(base_url)
    mount = parsed.path.rstrip("/")
    probe_path = "/" + path.lstrip("/")
    return urlunsplit((parsed.scheme, parsed.netloc, f"{mount}{probe_path}", "", ""))


def _content_type(response: httpx.Response) -> str:
    return response.headers.get("content-type", "").partition(";")[0].strip().lower()


def _evidence_id(asset: GatewayAsset, epoch: int, probe_id: str, variant: str) -> str:
    value = f"{asset.id}|{epoch}|{probe_id}|{variant}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


class LiteLLMScanClient:
    """执行固定 Profile Probe；不接受调用方提供任意路径或请求正文。"""

    def __init__(
        self,
        *,
        http_client: httpx.AsyncClient | None = None,
        timeout: httpx.Timeout | None = None,
    ) -> None:
        self._http_client = http_client
        self._timeout = timeout or httpx.Timeout(15.0, connect=5.0)

    async def _request(
        self,
        client: httpx.AsyncClient,
        asset: GatewayAsset,
        probe: ProbeSpec,
        *,
        auth_token: str | None,
        model: str | None,
        nonce: str,
        budget: _Budget,
    ) -> HttpObservation | None:
        if not budget.take(probe.request_cost):
            return None
        url = _probe_url(asset.canonical_base_url, probe.path)
        try:
            response = await client.request(
                probe.method,
                url,
                headers=probe.materialize_headers(auth_token=auth_token),
                json=probe.materialize_body(model=model, nonce=nonce),
                timeout=self._timeout,
                follow_redirects=False,
            )
            return HttpObservation(
                path=probe.path,
                method=probe.method,
                url=str(response.url),
                status_code=response.status_code,
                content_type=_content_type(response),
                body=response.text[:_MAX_RESPONSE_CHARS],
                headers=dict(response.headers),
                redirect_url=response.headers.get("location"),
            )
        except httpx.HTTPError as exc:
            return HttpObservation(
                path=probe.path,
                method=probe.method,
                url=url,
                status_code=599,
                content_type="text/plain",
                body=f"{type(exc).__name__}: {exc}"[:1000],
            )

    async def _control(
        self,
        client: httpx.AsyncClient,
        asset: GatewayAsset,
        budget: _Budget,
    ) -> HttpObservation | None:
        control = ProbeSpec(
            probe_id="control_missing_route",
            method="GET",
            path="/.well-known/autohunter-gateway-control",
            category="public",
            public_by_design=True,
            finding_eligible=False,
            read_only=True,
            fingerprint_probe=False,
            headers_template={"Accept": "application/json, text/plain"},
            body_template=None,
            expected_content_types=("application/json", "text/plain"),
            success_matcher="exact_alive_text",
            request_cost=1,
        )
        return await self._request(
            client,
            asset,
            control,
            auth_token=None,
            model=None,
            nonce="control",
            budget=budget,
        )

    @staticmethod
    def _sample(observation: HttpObservation) -> ResponseSample:
        return ResponseSample(
            observation.status_code,
            observation.content_type,
            observation.body,
        )

    @staticmethod
    def _result(
        asset: GatewayAsset,
        epoch: int,
        probe: ProbeSpec,
        variant: str,
        observation: HttpObservation,
        result: str,
        stage: str,
    ) -> GatewayProbeResult:
        return GatewayProbeResult(
            probe_id=probe.probe_id,
            stage=stage,
            auth_variant=variant,
            result=result,
            status_code=observation.status_code,
            content_type=observation.content_type,
            body=observation.body,
            evidence_id=_evidence_id(asset, epoch, probe.probe_id, variant),
        )

    async def scan(
        self,
        asset: GatewayAsset,
        *,
        scan_epoch: int,
        request_budget: int,
    ) -> GatewayScanInput:
        if request_budget <= 0:
            raise ValueError("request_budget must be positive")
        profile = get_profile(asset.profile_id or "litellm")
        budget = _Budget(request_budget)
        owned_client = self._http_client is None
        client = self._http_client or httpx.AsyncClient()
        observations: list[GatewayProbeResult] = []
        fingerprint_observations: list[HttpObservation] = []
        secrets: dict[str, SecretArtifact] = {}
        model_names: tuple[str, ...] = ()
        auth_state = "unknown"
        nonce = f"autohunter-{scan_epoch}"

        async def collect_secrets(observation: HttpObservation) -> tuple[SecretArtifact, ...]:
            found = extract_secrets(
                observation.body,
                source_url=observation.url,
                source_location="response_body",
            )
            for artifact in found:
                secrets.setdefault(artifact.sha256, artifact)
            return found

        try:
            control = await self._control(client, asset, budget)
            if control is not None:
                fingerprint_observations.append(control)

            fingerprint = profile.match_fingerprint(fingerprint_observations)
            for probe in profile.public_routes():
                response = await self._request(
                    client,
                    asset,
                    probe,
                    auth_token=None,
                    model=None,
                    nonce=nonce,
                    budget=budget,
                )
                if response is None:
                    break
                fingerprint_observations.append(response)
                classification = profile.classify_response(probe, response)
                observations.append(
                    self._result(
                        asset,
                        scan_epoch,
                        probe,
                        "none",
                        response,
                        str(classification.category),
                        "fingerprinting",
                    )
                )
                fingerprint = profile.match_fingerprint(fingerprint_observations)
                if fingerprint.status == "confirmed":
                    break

            if fingerprint.status != "rejected":
                for probe in profile.model_routes():
                    no_auth = await self._request(
                        client, asset, probe, auth_token=None, model=None, nonce=nonce, budget=budget
                    )
                    invalid_auth = await self._request(
                        client,
                        asset,
                        probe,
                        auth_token=_INVALID_TOKEN,
                        model=None,
                        nonce=nonce,
                        budget=budget,
                    )
                    if no_auth is None or invalid_auth is None:
                        break
                    await collect_secrets(no_auth)
                    diff = compare_auth_variants(
                        no_auth=self._sample(no_auth),
                        invalid_auth=self._sample(invalid_auth),
                        candidate=None,
                        public_by_design=False,
                    )
                    observations.extend(
                        (
                            self._result(asset, scan_epoch, probe, "none", no_auth, str(diff.kind), "auth_baseline"),
                            self._result(
                                asset,
                                scan_epoch,
                                probe,
                                "invalid",
                                invalid_auth,
                                str(profile.classify_response(probe, invalid_auth).category),
                                "auth_baseline",
                            ),
                        )
                    )
                    if diff.kind == "anonymous_models":
                        model_names = tuple(diff.model_ids)
                        auth_state = "anonymous_models"
                        break
                    if diff.kind == "protected":
                        auth_state = "protected"
                        break

                if model_names:
                    for probe in profile.inference_routes():
                        no_auth = await self._request(
                            client,
                            asset,
                            probe,
                            auth_token=None,
                            model=model_names[0],
                            nonce=nonce,
                            budget=budget,
                        )
                        invalid_auth = await self._request(
                            client,
                            asset,
                            probe,
                            auth_token=_INVALID_TOKEN,
                            model=model_names[0],
                            nonce=nonce,
                            budget=budget,
                        )
                        if no_auth is None or invalid_auth is None:
                            break
                        diff = compare_auth_variants(
                            no_auth=self._sample(no_auth),
                            invalid_auth=self._sample(invalid_auth),
                            candidate=None,
                            public_by_design=False,
                        )
                        observations.append(
                            self._result(
                                asset, scan_epoch, probe, "none", no_auth, str(diff.kind), "inference_validating"
                            )
                        )
                        if diff.kind == "anonymous_inference":
                            auth_state = "anonymous_inference"
                            break

                for probe in profile.management_routes():
                    no_auth = await self._request(
                        client, asset, probe, auth_token=None, model=None, nonce=nonce, budget=budget
                    )
                    invalid_auth = await self._request(
                        client,
                        asset,
                        probe,
                        auth_token=_INVALID_TOKEN,
                        model=None,
                        nonce=nonce,
                        budget=budget,
                    )
                    if no_auth is None or invalid_auth is None:
                        break
                    found = await collect_secrets(no_auth)
                    classification = profile.classify_response(probe, no_auth)
                    result = "management_secret" if classification.valid and found else str(classification.category)
                    observations.append(
                        self._result(asset, scan_epoch, probe, "none", no_auth, result, "exposure_scanning")
                    )

            return GatewayScanInput(
                fingerprint_status=str(fingerprint.status),
                fingerprint_confidence=fingerprint.confidence,
                auth_state=auth_state,
                model_names=model_names,
                observations=tuple(observations),
                secrets=tuple(secrets.values()),
                request_count=budget.used,
                partial=budget.exhausted or budget.used >= budget.limit,
            )
        finally:
            if owned_client:
                await client.aclose()


__all__ = ["LiteLLMScanClient"]
