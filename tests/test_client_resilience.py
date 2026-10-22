import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rsc_client  # noqa: E402
from rsc_client import RscClient, RscError  # noqa: E402


class Resp:
    def __init__(self, status=200, body=None):
        self.status_code, self._body, self.text = status, body or {"data": {"ok": 1}}, ""

    def json(self):
        return self._body


def client():
    c = object.__new__(RscClient)  # skip auth
    c.gql_url, c.token, c.token_expiry = "http://x", "t", 1e18
    return c


def scripted(monkeypatch_list, steps):
    it = iter(steps)

    def post(*a, **k):
        s = next(it)
        if isinstance(s, Exception):
            raise s
        return s
    return post


def run(steps, **kw):
    sleeps, real_post, real_sleep = [], requests.post, rsc_client._sleep
    requests.post = scripted(None, steps)
    rsc_client._sleep = sleeps.append
    try:
        return client().query("q", **kw), sleeps
    finally:
        requests.post, rsc_client._sleep = real_post, real_sleep


def test_timeout_then_success_is_retried_with_growing_backoff():
    data, sleeps = run([requests.exceptions.ReadTimeout(), requests.exceptions.ConnectionError(), Resp()])
    assert data == {"ok": 1} and sleeps == [2, 4]


def test_persistent_timeout_raises_rsc_error_after_all_attempts():
    steps = [requests.exceptions.ReadTimeout()] * 5
    try:
        run(steps)
    except RscError as e:
        assert "5 attempts" in str(e)
    else:
        raise AssertionError("expected RscError")


def test_503_still_retried_and_backoff_is_capped():
    assert [rsc_client._backoff(i) for i in range(6)] == [2, 4, 8, 16, 30, 30]
    data, sleeps = run([Resp(503), Resp()])
    assert data == {"ok": 1} and sleeps == [2]


def test_non_retryable_status_fails_immediately():
    try:
        run([Resp(403)])
    except RscError as e:
        assert "403" in str(e)
    else:
        raise AssertionError("expected RscError")


def test_paginate_reports_progress_to_stderr_not_stdout(capsys=None):
    import io
    pages = [{"c": {"count": 25, "nodes": [1, 2], "pageInfo": {"hasNextPage": i < 11, "endCursor": str(i)}}}
             for i in range(12)]
    c = client()
    it = iter(pages)
    c.query = lambda *a, **k: next(it)
    out, err, so, se = io.StringIO(), io.StringIO(), sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        nodes = c.paginate("q", "c")
    finally:
        sys.stdout, sys.stderr = so, se
    assert len(nodes) == 24 and out.getvalue() == ""
    assert "c: 20 of 25 records, 10 pages" in err.getvalue() and err.getvalue().count("pages") == 1
