"""LLM User-Agent 与 SDK 指纹头兼容性回归。"""
from __future__ import annotations

import os
import unittest

from app.llm.client import (
    _BROWSER_UA,
    _default_ua_for_model,
    _llm_default_headers,
    _per_request_omit_headers,
    _resolve_user_agent,
)


class UserAgentResolveTests(unittest.TestCase):
    def test_model_family_mapping(self):
        self.assertIn("DeepSeek", _default_ua_for_model("deepseek-chat", ""))
        self.assertIn("Anthropic", _default_ua_for_model("claude-3-5-sonnet", ""))
        self.assertIn("OpenAI", _default_ua_for_model("gpt-4o", ""))
        self.assertIn("zhipuai", _default_ua_for_model("glm-4-plus", ""))
        self.assertIn("dashscope", _default_ua_for_model("qwen-max", ""))
        self.assertIn("moonshot", _default_ua_for_model("kimi-k2", ""))
        self.assertIn("xai", _default_ua_for_model("grok-4", ""))

    def test_unknown_model_falls_back_to_browser(self):
        self.assertEqual(_default_ua_for_model("mystery-model", ""), _BROWSER_UA)

    def test_env_override_browser_auto_and_custom(self):
        for value, expected in (
            ("browser", _BROWSER_UA),
            ("auto", "OpenAI"),
            ("curl/8.7.1", "curl/8.7.1"),
        ):
            os.environ["LLM_USER_AGENT"] = value
            try:
                actual = _resolve_user_agent("gpt-4o", "")
                if value == "auto":
                    self.assertIn(expected, actual)
                else:
                    self.assertEqual(actual, expected)
            finally:
                os.environ.pop("LLM_USER_AGENT", None)

    def test_headers_override_ua_and_strip_stainless(self):
        from openai import OpenAI
        from openai._base_client import FinalRequestOptions

        client = OpenAI(
            base_url="https://relay.example.com/v1",
            api_key="sk-test",
            max_retries=0,
            default_headers=_llm_default_headers("deepseek-chat", ""),
        )
        opts = FinalRequestOptions.construct(
            method="post",
            url="/chat/completions",
            json_data={"model": "x", "messages": []},
            headers=_per_request_omit_headers(),
        )
        request = client._build_request(opts)
        headers = {key.lower(): value for key, value in request.headers.items()}
        self.assertEqual(headers.get("user-agent"), "DeepSeek/1.0 (compatible)")
        self.assertEqual([key for key in headers if key.startswith("x-stainless")], [])


if __name__ == "__main__":
    unittest.main()
