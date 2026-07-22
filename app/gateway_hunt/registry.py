"""Gateway Profile 注册表。"""
from __future__ import annotations

from app.gateway_hunt.profiles.base import GatewayProfile
from app.gateway_hunt.profiles.litellm import LiteLLMProfile


class UnknownGatewayProfileError(LookupError):
    def __init__(self, profile_id: str) -> None:
        super().__init__(f"unknown gateway profile: {profile_id}")
        self.profile_id = profile_id


class DuplicateGatewayProfileError(ValueError):
    pass


class GatewayProfileRegistry:
    def __init__(self) -> None:
        self._profiles: dict[str, GatewayProfile] = {}

    def register(self, profile: GatewayProfile) -> None:
        profile_id = profile.profile_id.strip().lower()
        if not profile_id:
            raise ValueError("gateway profile_id must not be empty")
        if profile_id in self._profiles:
            raise DuplicateGatewayProfileError(
                f"gateway profile already registered: {profile_id}"
            )
        self._profiles[profile_id] = profile

    def get(self, profile_id: str) -> GatewayProfile:
        normalized = str(profile_id or "").strip().lower()
        try:
            return self._profiles[normalized]
        except KeyError as exc:
            raise UnknownGatewayProfileError(normalized or "<empty>") from exc

    def list(self) -> tuple[GatewayProfile, ...]:
        return tuple(self._profiles[key] for key in sorted(self._profiles))


_registry = GatewayProfileRegistry()
_registry.register(LiteLLMProfile())


def get_profile(profile_id: str) -> GatewayProfile:
    return _registry.get(profile_id)


def list_profiles() -> tuple[GatewayProfile, ...]:
    return _registry.list()


__all__ = [
    "DuplicateGatewayProfileError",
    "GatewayProfileRegistry",
    "UnknownGatewayProfileError",
    "get_profile",
    "list_profiles",
]
