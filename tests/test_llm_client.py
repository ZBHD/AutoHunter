from __future__ import annotations

import pytest

from app.llm.client import _classify_error


class ProviderError(RuntimeError):
    def __init__(self, status_code: int | None, message: str, *, code: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.code = code


@pytest.mark.parametrize(
    ("status", "message", "code", "expected"),
    [
        (500, "upstream reported invalid api key and quota", "", "upstream"),
        (503, "billing service unavailable", "", "upstream"),
        (400, "模型参数无效", "", "unknown"),
        (401, "request rejected", "", "auth"),
        (403, "request rejected", "permission_error", "auth"),
        (403, "forbidden", "", "auth"),
    ],
)
def test_provider_error_classification_respects_status_before_body_keywords(
    status: int,
    message: str,
    code: str,
    expected: str,
) -> None:
    error = _classify_error(ProviderError(status, message, code=code))

    assert error.kind == expected
