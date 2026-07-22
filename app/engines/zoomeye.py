"""ZoomEye 搜索引擎适配。"""
from __future__ import annotations

import base64

import httpx

from app.engines.base import EngineResult, SearchEngine, register_engine


@register_engine
class ZoomEyeEngine(SearchEngine):
    @property
    def name(self) -> str:
        return "zoomeye"

    @property
    def display_name(self) -> str:
        return "ZoomEye"

    @property
    def env_key_name(self) -> str:
        return "ZOOMEYE"

    def get_default_base_url(self) -> str:
        return "https://api.zoomeye.ai"

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
            raise ValueError("缺少 ZoomEye API Key")
        base = (base_url or self.get_default_base_url()).rstrip("/")

        payload = {
            "qbase64": base64.b64encode(query.encode("utf-8")).decode("ascii"),
            "page": int(page or 1),
            "pagesize": int(min(page_size or 20, 1000)),
            "sub_type": "web",
            "fields": "ip,port,domain,hostname,title,url,organization.name",
        }
        headers = {"API-KEY": api_key, "Content-Type": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=45) as client:
                resp = await client.post(f"{base}/v2/search", json=payload, headers=headers)
                data = resp.json()
        except Exception as e:
            raise ValueError(f"ZoomEye 请求失败: {e}") from e

        code = data.get("code")
        if code not in (None, 0, 200, 60000) and not data.get("data"):
            msg = data.get("message") or data.get("error") or str(data)[:200]
            raise ValueError(f"ZoomEye 错误: {msg}")

        items = data.get("data") or data.get("matches") or []
        results = []
        for item in items:
            if not isinstance(item, dict):
                continue
            title = item.get("title") or ""
            if isinstance(title, list):
                title = " | ".join(str(value) for value in title if value)[:200]
            org = ""
            for key in ("organization.name", "org", "organization"):
                value = item.get(key)
                if isinstance(value, dict):
                    org = value.get("name") or ""
                elif value:
                    org = str(value)
                if org:
                    break
            host = (
                item.get("hostname")
                or item.get("domain")
                or item.get("url")
                or item.get("ip")
                or ""
            )
            results.append([
                str(host),
                str(item.get("ip") or ""),
                str(item.get("port") or ""),
                str(title),
                str(item.get("domain") or ""),
                str(org),
            ])

        return EngineResult(
            fields=["host", "ip", "port", "title", "domain", "org"],
            results=results,
            size=int(data.get("total") or 0),
            page=page,
            engine="zoomeye",
        )
