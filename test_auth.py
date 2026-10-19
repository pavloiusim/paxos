"""Smoke test: the trader app rejects unauthenticated requests on every route class."""
from fastapi.testclient import TestClient

import main


def test_trader_requires_token():
    c = TestClient(main.app, base_url="http://localhost")
    assert c.get("/api/accounts").status_code == 401
    assert c.post("/api/orders", json={}).status_code == 401
    assert c.post("/api/withdrawals", json={}).status_code == 401
    assert c.get("/").status_code == 401
    assert c.get("/static/anything").status_code == 401


def test_trader_launch_url_grants_access():
    c = TestClient(main.app, base_url="http://localhost")
    r = c.get(f"/?t={main.AUTH_TOKEN}", follow_redirects=False)
    assert r.status_code == 303
    assert c.get("/api/accounts").status_code != 401
