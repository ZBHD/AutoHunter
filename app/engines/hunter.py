"""Hunter (鹰图) 搜索引擎适配。"""
from __future__ import annotations

import base64

import httpx

from app.engines.base import EngineResult, SearchEngine, register_engine


@register_engine
class HunterEngine(SearchEngine):
    @property
    def name(self) -> str:
        return "hunter"

    @property
    def display_name(self) -> str:
        return "Hunter (鹰图)"

    @property
    def env_key_name(self) -> str:
        return "HUNTER"

    def get_default_base_url(self) -> str:
        return "https://hunter.qianxin.com"

    async def search(
        self,
        api_key: str,
        query: str,
        page: int = 1,
        page_size: int = 100,
        base_url: str | None = None,
        cursor: str | None = None,
    ) -> EngineResult:
        if not api_key:
            raise ValueError("缺少 Hunter API Key")
        base = (base_url or self.get_default_base_url()).rstrip("/")
        encoded_query = base64.urlsafe_b64encode(query.encode("utf-8")).decode("ascii")
        params = {
            "api-key": api_key,
            "search": encoded_query,
            "page": str(page),
            "page_size": str(min(int(page_size or 100), 100)),
            "is_web": "3",
        }
        try:
            async with httpx.AsyncClient(timeout=45) as client:
                resp = await client.get(f"{base}/openApi/search", params=params)
                data = resp.json()
        except Exception as e:
            raise ValueError(f"Hunter 请求失败: {e}") from e

        # 猎鹰返回 code=200 表示成功
        if data.get("code") != 200:
            msg = data.get("message", str(data.get("data", "")))
            raise ValueError(f"Hunter 错误: {msg}")

        payload = data.get("data") or {}
        items = payload.get("arr") or []
        results = []
        for item in items:
            host = item.get("domain") or item.get("ip", "")
            results.append([
                host,
                item.get("ip", ""),
                str(item.get("port", "")),
                item.get("web_title") or item.get("title", ""),
                item.get("domain", ""),
                item.get("company") or item.get("company_name", ""),
            ])

        return EngineResult(
            fields=["host", "ip", "port", "title", "domain", "org"],
            results=results,
            size=int(payload.get("total") or 0),
            page=page,
            engine="hunter",
        )
