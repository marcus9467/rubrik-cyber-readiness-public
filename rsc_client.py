"""Minimal RSC GraphQL client: service account auth, retries, auto-pagination."""
import json
import sys
import time
from pathlib import Path

import requests


class RscError(Exception):
    pass


RETRIES = 5
PROGRESS_EVERY = 10  # pages
_sleep = time.sleep  # tests replace this


def _backoff(attempt):
    """2, 4, 8, 16 seconds. A slow page on a large tenant needs room to recover, not a quick second try."""
    return min(2 ** (attempt + 1), 30)


class RscClient:
    def __init__(self, sa_path):
        sa = json.loads(Path(sa_path).expanduser().read_text())
        self.client_id = sa["client_id"]
        self.client_secret = sa["client_secret"]
        self.token_url = sa["access_token_uri"]
        self.gql_url = self.token_url.replace("/api/client_token", "/api/graphql")
        self.token = None
        self.token_expiry = 0
        self._authenticate()

    def _authenticate(self):
        r = requests.post(
            self.token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            timeout=30,
        )
        if r.status_code != 200:
            raise RscError(f"Auth failed ({r.status_code}): {r.text[:200]}")
        body = r.json()
        self.token = body["access_token"]
        self.token_expiry = time.time() + body.get("expires_in", 3600) - 60

    def query(self, gql, variables=None, retries=RETRIES):
        """Run one GraphQL query. Returns the `data` dict; raises RscError on GraphQL errors.

        Timeouts and connection errors are retried like 429 and 5xx: one slow page must not lose a collector."""
        if time.time() > self.token_expiry:
            self._authenticate()
        payload = {"query": gql, "variables": variables or {}}
        headers = {"Authorization": f"Bearer {self.token}"}
        for attempt in range(retries):
            try:
                r = requests.post(self.gql_url, json=payload, headers=headers, timeout=120)
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                if attempt < retries - 1:
                    _sleep(_backoff(attempt))
                    continue
                raise RscError(f"{type(e).__name__} after {retries} attempts") from e
            if r.status_code in (429, 502, 503, 504) and attempt < retries - 1:
                _sleep(_backoff(attempt))
                continue
            if r.status_code != 200:
                raise RscError(f"HTTP {r.status_code}: {r.text[:300]}")
            body = r.json()
            if body.get("errors") and not body.get("data"):
                raise RscError(json.dumps(body["errors"])[:500])
            return body.get("data") or {}
        raise RscError("retries exhausted")

    def paginate(self, gql, path, variables=None):
        """Walk a connection. `gql` must declare $after and select pageInfo.
        `path` is the dotted route to the connection, e.g. 'slaDomains'."""
        nodes, after, pages = [], None, 0
        while True:
            data = self.query(gql, {**(variables or {}), "after": after})
            conn = data
            for key in path.split("."):
                conn = conn[key]
            nodes.extend(conn["nodes"])
            pages += 1
            if pages % PROGRESS_EVERY == 0:
                total = conn.get("count")
                of = f" of {total}" if total else ""
                print(f"  {path}: {len(nodes)}{of} records, {pages} pages", file=sys.stderr, flush=True)
            info = conn["pageInfo"]
            if not info["hasNextPage"]:
                return nodes
            after = info["endCursor"]
