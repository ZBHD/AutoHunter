#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Validate LiteLLM endpoints from litellm_by_model(1).csv.

Success = the (URL, key, model) triple returns a real chat-completion answer.
We POST a trivial prompt to /v1/chat/completions (fallback /chat/completions)
and require choices[0].message.content (or a non-empty streamed/text field).

Outputs:
  litellm_working.csv     -> only confirmed-working triples (with sample reply)
  litellm_tested_all.csv  -> every triple with status/latency/detail
"""
import asyncio
import csv
import sys
import time

import httpx

SRC = r"D:\Projects\AutoHunter\litellm_by_model(1).csv"
OUT_WORKING = r"D:\Projects\AutoHunter\litellm_working.csv"
OUT_ALL = r"D:\Projects\AutoHunter\litellm_tested_all.csv"

CONCURRENCY = 40
TIMEOUT = 15.0
MAX_TOKENS = 16
PROMPT = "Reply with the single word: pong"

# model-name substrings that can't answer a chat completion — skip the chat test
NON_CHAT = (
    "embed", "embedding", "rerank", "reranker", "tei", "bge",
    "dall-e", "gpt-image", "qwen-image", "flux", "sdxl", "image",
)


def is_non_chat(model: str) -> bool:
    m = model.lower()
    return any(k in m for k in NON_CHAT)


def load_rows():
    rows = []
    with open(SRC, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            url = (r.get("URL") or "").strip()
            key = (r.get("可用Key") or "").strip()
            model = (r.get("模型名") or "").strip()
            proto = (r.get("协议") or "").strip()
            if url and key and model:
                rows.append({"url": url, "proto": proto, "key": key, "model": model})
    return rows


def extract_answer(data):
    """Return the assistant text if the JSON body carries a real answer, else None."""
    if not isinstance(data, dict):
        return None
    choices = data.get("choices")
    if isinstance(choices, list) and choices:
        c0 = choices[0]
        if isinstance(c0, dict):
            msg = c0.get("message")
            if isinstance(msg, dict):
                content = msg.get("content")
                if isinstance(content, str) and content.strip():
                    return content.strip()
                # some proxies put content in a list of parts
                if isinstance(content, list):
                    parts = [p.get("text", "") for p in content if isinstance(p, dict)]
                    joined = "".join(parts).strip()
                    if joined:
                        return joined
            txt = c0.get("text")
            if isinstance(txt, str) and txt.strip():
                return txt.strip()
    return None


async def test_one(client: httpx.AsyncClient, row, sem):
    url = row["url"].rstrip("/")
    key = row["key"]
    model = row["model"]

    if is_non_chat(model):
        return {**row, "status": "skip", "latency_ms": "", "detail": "non-chat model (embedding/image/rerank)", "reply": ""}

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": PROMPT}],
        "max_tokens": MAX_TOKENS,
        "stream": False,
    }
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}

    async with sem:
        for path in ("/v1/chat/completions", "/chat/completions"):
            target = url + path
            t0 = time.perf_counter()
            try:
                resp = await client.post(target, json=payload, headers=headers)
            except Exception as e:
                last = f"conn-error: {type(e).__name__}: {str(e)[:80]}"
                continue
            dt = int((time.perf_counter() - t0) * 1000)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except Exception:
                    last = f"200 but non-JSON body[:60]={resp.text[:60]!r}"
                    continue
                ans = extract_answer(data)
                if ans:
                    return {**row, "status": "ok", "latency_ms": dt,
                            "detail": path, "reply": ans[:120]}
                # 200 but no usable content (could be error object in body)
                err = ""
                if isinstance(data, dict):
                    err = str(data.get("error") or data)[:120]
                last = f"200 no-content: {err}"
                continue
            else:
                body = resp.text[:120].replace("\n", " ")
                last = f"HTTP {resp.status_code}: {body}"
                # 404 on /v1 -> try the other path; other codes are terminal-ish but still try fallback
                continue
        return {**row, "status": "fail", "latency_ms": "", "detail": last, "reply": ""}


async def main():
    rows = load_rows()
    total = len(rows)
    print(f"[*] loaded {total} triples from by_model csv", flush=True)

    sem = asyncio.Semaphore(CONCURRENCY)
    limits = httpx.Limits(max_connections=CONCURRENCY, max_keepalive_connections=CONCURRENCY)
    timeout = httpx.Timeout(TIMEOUT, connect=8.0)

    results = []
    done = 0
    async with httpx.AsyncClient(verify=False, timeout=timeout, limits=limits,
                                 follow_redirects=True) as client:
        tasks = [asyncio.create_task(test_one(client, r, sem)) for r in rows]
        for coro in asyncio.as_completed(tasks):
            res = await coro
            results.append(res)
            done += 1
            if res["status"] == "ok":
                print(f"[OK {done}/{total}] {res['url']} | {res['key']} | {res['model']} "
                      f"({res['latency_ms']}ms) -> {res['reply'][:40]!r}", flush=True)
            elif done % 100 == 0:
                print(f"    ...progress {done}/{total}", flush=True)

    # write all
    fields = ["url", "proto", "key", "model", "status", "latency_ms", "detail", "reply"]
    with open(OUT_ALL, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in results:
            w.writerow({k: r.get(k, "") for k in fields})

    working = [r for r in results if r["status"] == "ok"]
    working.sort(key=lambda r: (r["url"], r["model"]))
    with open(OUT_WORKING, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in working:
            w.writerow({k: r.get(k, "") for k in fields})

    ok = len(working)
    skip = sum(1 for r in results if r["status"] == "skip")
    fail = sum(1 for r in results if r["status"] == "fail")
    print("\n===== SUMMARY =====", flush=True)
    print(f"total tested : {total}", flush=True)
    print(f"WORKING      : {ok}", flush=True)
    print(f"failed       : {fail}", flush=True)
    print(f"skipped(non-chat): {skip}", flush=True)
    uniq_urls = sorted({r["url"] for r in working})
    print(f"unique working URLs: {len(uniq_urls)}", flush=True)
    print(f"\n-> {OUT_WORKING}", flush=True)
    print(f"-> {OUT_ALL}", flush=True)


if __name__ == "__main__":
    try:
        import warnings
        warnings.filterwarnings("ignore")
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(1)
