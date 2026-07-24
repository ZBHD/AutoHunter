"""网关产品 Profile 的纯逻辑契约。"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence

from app.gateway_hunt.schemas import (
    FingerprintResult,
    HttpObservation,
    ModelParseResult,
    ProbeSpec,
    ResponseClassification,
    SearchSignature,
    SecretPattern,
)


class GatewayProfile(ABC):
    """描述静态签名、探测规范和响应识别，不持有网络客户端。"""

    @property
    @abstractmethod
    def profile_id(self) -> str:
        ...

    @property
    @abstractmethod
    def version(self) -> str:
        ...

    @abstractmethod
    def search_signatures(self) -> tuple[SearchSignature, ...]:
        ...

    @abstractmethod
    def probes(self) -> tuple[ProbeSpec, ...]:
        ...

    def fingerprint_probes(self) -> tuple[ProbeSpec, ...]:
        """产品指纹路由；公开基线是其子集，但模型信息也可提供指纹。"""

        return tuple(probe for probe in self.probes() if probe.fingerprint_probe)

    def public_routes(self) -> tuple[ProbeSpec, ...]:
        return tuple(probe for probe in self.probes() if probe.category == "public")

    def model_routes(self) -> tuple[ProbeSpec, ...]:
        return tuple(
            probe
            for probe in self.probes()
            if probe.category in {"models", "model_info"}
        )

    def inference_routes(self) -> tuple[ProbeSpec, ...]:
        return tuple(probe for probe in self.probes() if probe.category == "inference")

    def management_routes(self) -> tuple[ProbeSpec, ...]:
        return tuple(
            probe for probe in self.probes() if probe.category == "readonly_admin"
        )

    @abstractmethod
    def secret_patterns(self) -> tuple[SecretPattern, ...]:
        ...

    @abstractmethod
    def parse_models(self, response: HttpObservation) -> ModelParseResult:
        ...

    @abstractmethod
    def classify_response(
        self,
        probe: ProbeSpec,
        response: HttpObservation,
    ) -> ResponseClassification:
        ...

    @abstractmethod
    def match_fingerprint(
        self,
        observations: Sequence[HttpObservation],
    ) -> FingerprintResult:
        ...


__all__ = ["GatewayProfile"]
