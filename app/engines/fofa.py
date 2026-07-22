"""FOFA 搜索引擎适配。"""
from __future__ import annotations

from app.engines.base import EngineResult, SearchEngine, register_engine
from app.fofa.client import FofaError, search as fofa_search

BASE = "https://fofa.info"


@register_engine
class FofaEngine(SearchEngine):
    @property
    def name(self) -> str:
        return "fofa"

    @property
    def display_name(self) -> str:
        return "FOFA"

    @property
    def env_key_name(self) -> str:
        return "FOFA"

    def get_default_base_url(self) -> str:
        return BASE

    async def search(
        self,
        api_key: str,
        query: str,
        page: int = 1,
        page_size: int = 100,
        base_url: str | None = None,
        cursor: str | None = None,
    ) -> EngineResult:
        data = await fofa_search(
            api_key,
            query,
            page=page,
            size=page_size,
            fields="host,ip,port,title,domain,org",
            base_url=base_url,
        )
        return EngineResult(
            fields=list(data.get("fields") or []),
            results=data.get("results", []),
            size=data.get("size", 0),
            page=page,
            engine="fofa",
        )


__all__ = ["BASE", "FofaEngine", "FofaError"]
