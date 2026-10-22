"""Minimal RSC GraphQL client: service account auth, retries, auto-pagination."""
import json
import time
from pathlib import Path

import requests


class RscError(Exception):
    pass


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

    def query(self, gql, variables=None, retries=3):
        """Run one GraphQL query. Returns the `data` dict; raises RscError on GraphQL errors."""
        if time.time() > self.token_expiry:
            self._authenticate()
        payload = {"query": gql, "variables": variables or {}}
        headers = {"Authorization": f"Bearer {self.token}"}
        for attempt in range(retries):
            r = requests.post(self.gql_url, json=payload, headers=headers, timeout=120)
            if r.status_code in (429, 502, 503, 504) and attempt < retries - 1:
                time.sleep(2 ** attempt)
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
        nodes, after = [], None
        while True:
            data = self.query(gql, {**(variables or {}), "after": after})
            conn = data
            for key in path.split("."):
                conn = conn[key]
            nodes.extend(conn["nodes"])
            info = conn["pageInfo"]
            if not info["hasNextPage"]:
                return nodes
            after = info["endCursor"]
