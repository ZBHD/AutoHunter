from __future__ import annotations

from urllib.parse import urlsplit

import pytest
from starlette.requests import Request

from app.waf import inspect_request


def _request(url: str) -> Request:
    parsed = urlsplit(url)
    return Request({
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": parsed.scheme or "http",
        "path": parsed.path,
        "raw_path": parsed.path.encode("ascii"),
        "query_string": parsed.query.encode("ascii"),
        "headers": [],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    })


@pytest.mark.parametrize(
    "path",
    [
        "/api/tasks/task-1/findings?q=union+select+password+from+users",
        "/api/tasks/task-1/targets?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    ],
)
def test_task_operation_search_allows_security_terms_in_q(path: str) -> None:
    assert inspect_request(_request(path)).allowed is True


def test_task_operation_search_still_inspects_non_search_parameters() -> None:
    decision = inspect_request(_request(
        "/api/tasks/task-1/findings?q=report&sort=union+select+password+from+users"
    ))

    assert decision.allowed is False
    assert decision.reason == "sqli_union"
