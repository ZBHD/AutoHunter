"""网关产品 Profile 的纯逻辑契约。"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence

from app.gateway_hunt.schemas import (
    FingerprintResult,
    HttpObservation,
    ProbeSpec,
    SearchSignature,
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

    @abstractmethod
    def match_fingerprint(
        self,
        observations: Sequence[HttpObservation],
    ) -> FingerprintResult:
        ...


__all__ = ["GatewayProfile"]
