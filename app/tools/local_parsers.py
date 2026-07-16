"""Bounded local-only transformations allowed by the enterprise shell policy."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any
from urllib.parse import quote


_MAX_VALUE_BYTES = 16 * 1024


def parse_local_value(mode: str, value: str) -> Any:
    text = str(value or "")
    if len(text.encode("utf-8")) > _MAX_VALUE_BYTES:
        raise ValueError("输入超过 16 KiB")
    if mode == "json":
        return json.loads(text)
    if mode == "headers":
        headers: dict[str, str] = {}
        for line in text.splitlines():
            if not line.strip():
                continue
            if ":" not in line:
                raise ValueError("Header 行必须使用 Name: Value 格式")
            name, item = line.split(":", 1)
            key = name.strip().lower()
            if not key:
                raise ValueError("Header 名称不能为空")
            headers[key] = item.strip()
        return headers
    if mode == "urlencode":
        return quote(text, safe="")
    raise ValueError(f"未知本地解析模式: {mode}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.tools.local_parsers")
    parser.add_argument("mode", choices=("json", "headers", "urlencode"))
    parser.add_argument("--value", required=True)
    args = parser.parse_args(argv)
    try:
        parsed = parse_local_value(args.mode, args.value)
    except (ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps({"ok": True, "value": parsed}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
