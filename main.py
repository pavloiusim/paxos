"""Paxos Trader — FastAPI backend serving the single-page trading UI."""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
import uuid
from typing import Any, Optional

import base64
import logging

import httpx
import websockets
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import FastAPI, HTTPException, Query, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from local_auth import LocalAuthMiddleware, launch_url, new_token

# ── Credential Encryption ─────────────────────────────────────────────────────
# Secrets in custom_accounts.json are encrypted with a Fernet key derived from
# ~/.ssh/id_rsa (primary) or the PAXOS_TRADER_SECRET env var (fallback).
# Plain-text values that pre-date encryption are migrated automatically on
# the next write.

_ENCRYPT_PREFIX = "enc:"
_fernet_instance: Optional[Fernet] = None
_fernet_source: str = "none"

_log = logging.getLogger("trader")


def _build_fernet() -> tuple[Optional[Fernet], str]:
    """Return (Fernet, source_description) or (None, 'none')."""
    _SALT = b"paxos-trader-credentials-v1"

    # 1. Try SSH private keys in priority order.
    for candidate in ["~/.ssh/id_rsa", "~/.ssh/id_ed25519", "~/.ssh/id_ecdsa"]:
        path = os.path.expanduser(candidate)
        if not os.path.exists(path):
            continue
        try:
            with open(path, "rb") as f:
                material = f.read()
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=_SALT, iterations=100_000)
            key = base64.urlsafe_b64encode(kdf.derive(material))
            return Fernet(key), path
        except Exception as exc:
            _log.warning("Could not use %s for encryption: %s", path, exc)

    # 2. Fallback: PAXOS_TRADER_SECRET env var.
    password = os.environ.get("PAXOS_TRADER_SECRET", "")
    if password:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=_SALT, iterations=100_000)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key), "PAXOS_TRADER_SECRET env var"

    _log.warning(
        "No encryption key available (~/.ssh/id_rsa not found, PAXOS_TRADER_SECRET not set). "
        "Custom account credentials will be stored in plain text."
    )
    return None, "none"


def _get_fernet() -> Optional[Fernet]:
    global _fernet_instance, _fernet_source
    if _fernet_instance is None and _fernet_source == "none":
        _fernet_instance, _fernet_source = _build_fernet()
        if _fernet_source != "none":
            _log.info("Credential encryption active — key from: %s", _fernet_source)
    return _fernet_instance


def encrypt_secret(secret: str) -> str:
    """Encrypt and prefix with 'enc:'. Returns plain text if no key available."""
    if not secret:
        return secret
    f = _get_fernet()
    if not f:
        return secret
    return _ENCRYPT_PREFIX + f.encrypt(secret.encode()).decode()


def decrypt_secret(value: str) -> str:
    """Decrypt an 'enc:' prefixed value; pass through plain text for migration."""
    if not value or not value.startswith(_ENCRYPT_PREFIX):
        return value  # legacy plain text — will be encrypted on next save
    f = _get_fernet()
    if not f:
        _log.error("Cannot decrypt secret: no encryption key available")
        return ""
    try:
        return f.decrypt(value[len(_ENCRYPT_PREFIX):].encode()).decode()
    except InvalidToken:
        _log.error(
            "Decryption failed — credential may have been encrypted with a different key. "
            "Re-enter it via the UI."
        )
        return ""


def encryption_status() -> dict:
    _get_fernet()  # ensure initialised
    return {
        "enabled": _fernet_source != "none",
        "source": _fernet_source,
    }


# ── Environment Config ──────────────────────────────────────────────────────

ENV_CONFIG: dict[str, dict[str, str]] = {
    "SANDBOX": {
        "api": "https://api.sandbox.paxos.com/v2",
        "oauth": "https://oauth.sandbox.paxos.com/oauth2/token",
        "ws": "wss://ws.sandbox.paxos.com/",
    },
    "PROD": {
        "api": "https://api.paxos.com/v2",
        "oauth": "https://oauth.paxos.com/oauth2/token",
        "ws": "wss://ws.paxos.com/",
    },
}

TRADING_SCOPES = " ".join([
    "funding:read_profile",
    "funding:write_profile",
    "exchange:read_order",
    "exchange:write_order",
    "transfer:read_transfer",
    "transfer:read_deposit_address",
    "transfer:write_deposit_address",
    "transfer:write_crypto_withdrawal",
    "transfer:write_internal_transfer",
    "exchange:read_quote",
    "exchange:write_quote_execution",
    "exchange:read_quote_execution",
])

WS_SCOPE = "exchange:read_aggregated_marketdata_stream"

# Issuer Quotes scopes are requested one per token, not added to TRADING_SCOPES:
# the OAuth server rejects the whole request if the client lacks any scope, so
# bundling them would break trading for accounts not enabled for Issuer Quotes.
ISSUER_SCOPE_WRITE_QUOTE = "exchange:write_issuer_quote"
ISSUER_SCOPE_WRITE_EXECUTION = "exchange:write_issuer_quote_execution"
ISSUER_SCOPE_READ_EXECUTION = "exchange:read_issuer_quote_execution"

# Requested individually, one scope per token request — never bundled.
# Paxos's OAuth server rejects a scope request outright (400 invalid_scope)
# if the client is disallowed even one of the requested scopes, rather than
# silently granting the allowed subset. Rewards Engine access is granted
# per-scope per-account (e.g. read access without payout-group deletion
# access is common), so a single combined-scope request would make a
# genuinely-enabled account appear entirely disabled the moment it lacks
# just one of the nine scopes. Each route below requests only the scope
# it actually needs; enablement is "is any one of these nine granted".
REWARDS_SCOPE_READ_PAYOUT_GROUPS = "rewards:read_payout_groups"
REWARDS_SCOPE_CREATE_PAYOUT_GROUPS = "rewards:create_payout_groups"
REWARDS_SCOPE_DELETE_PAYOUT_GROUPS = "rewards:delete_payout_groups"
REWARDS_SCOPE_READ_ADDRESSES = "rewards:read_monitoring_address"
REWARDS_SCOPE_WRITE_ADDRESSES = "rewards:write_monitoring_address"
REWARDS_SCOPE_READ_CLAIMS = "rewards:read_claims"
REWARDS_SCOPE_WRITE_CLAIM_SCHEDULE = "rewards:write_claims_schedule"
REWARDS_SCOPE_READ_DETAILS = "rewards:read_rewards_details"
REWARDS_SCOPE_READ_STATEMENTS = "rewards:read_statements"

# For enablement checking only — not requested as a single combined scope.
ALL_REWARDS_SCOPES = [
    REWARDS_SCOPE_READ_PAYOUT_GROUPS,
    REWARDS_SCOPE_CREATE_PAYOUT_GROUPS,
    REWARDS_SCOPE_DELETE_PAYOUT_GROUPS,
    REWARDS_SCOPE_READ_ADDRESSES,
    REWARDS_SCOPE_WRITE_ADDRESSES,
    REWARDS_SCOPE_READ_CLAIMS,
    REWARDS_SCOPE_WRITE_CLAIM_SCHEDULE,
    REWARDS_SCOPE_READ_DETAILS,
    REWARDS_SCOPE_READ_STATEMENTS,
]

# Requested individually, one scope per token request — never bundled,
# for the same reason as ALL_REWARDS_SCOPES above.
IDENTITIES_SCOPE_READ_IDENTITY = "identity:read_identity"
IDENTITIES_SCOPE_WRITE_IDENTITY = "identity:write_identity"
IDENTITIES_SCOPE_READ_ACCOUNT = "identity:read_account"
IDENTITIES_SCOPE_WRITE_ACCOUNT = "identity:write_account"
IDENTITIES_SCOPE_READ_CONTROL = "identity:read_identity_control"
IDENTITIES_SCOPE_WRITE_CONTROL = "identity:write_identity_control"

# For enablement checking only — not requested as a single combined scope.
ALL_IDENTITIES_SCOPES = [
    IDENTITIES_SCOPE_READ_IDENTITY,
    IDENTITIES_SCOPE_WRITE_IDENTITY,
    IDENTITIES_SCOPE_READ_ACCOUNT,
    IDENTITIES_SCOPE_WRITE_ACCOUNT,
    IDENTITIES_SCOPE_READ_CONTROL,
    IDENTITIES_SCOPE_WRITE_CONTROL,
]

# ── Account Discovery ────────────────────────────────────────────────────────

_ID_PATTERN = re.compile(r"^PAXOS_CLIENT_ID_(.+)$")
_CUSTOM_ACCOUNTS_FILE = "custom_accounts.json"


def _load_custom_accounts() -> list[dict]:
    """Load accounts, transparently decrypting any encrypted secrets."""
    try:
        import json as _json
        with open(_CUSTOM_ACCOUNTS_FILE) as f:
            accounts = _json.load(f)
        for acct in accounts:
            if "client_secret" in acct:
                acct["client_secret"] = decrypt_secret(acct["client_secret"])
        return accounts
    except (FileNotFoundError, ValueError):
        return []


def _save_custom_accounts(accounts: list[dict]) -> None:
    """Save accounts, encrypting all secrets before writing to disk."""
    import json as _json
    to_save = []
    for acct in accounts:
        a = dict(acct)
        if "client_secret" in a and a["client_secret"]:
            a["client_secret"] = encrypt_secret(a["client_secret"])
        to_save.append(a)
    with open(_CUSTOM_ACCOUNTS_FILE, "w") as f:
        _json.dump(to_save, f, indent=2)


def discover_accounts() -> list[dict[str, str]]:
    accounts: list[dict[str, str]] = []

    # Accounts from environment variables.
    for key, value in os.environ.items():
        m = _ID_PATTERN.match(key)
        if not m or not value:
            continue
        label = m.group(1)
        env = next((e for e in ENV_CONFIG if label.startswith(e)), None)
        if not env:
            continue
        if not os.environ.get(f"PAXOS_CLIENT_SECRET_{label}", ""):
            continue
        accounts.append({
            "id": label,
            "label": label.replace("_", " "),
            "env": env,
            "client_id": value,
            "custom": False,
        })

    # Accounts added via the UI (stored in custom_accounts.json).
    env_ids = {a["id"] for a in accounts}
    for ca in _load_custom_accounts():
        if ca.get("id") and ca["id"] not in env_ids:
            accounts.append({
                "id": ca["id"],
                "label": ca.get("label", ca["id"]),
                "env": ca["env"],
                "client_id": ca["client_id"],
                "custom": True,
            })

    return sorted(accounts, key=lambda a: (a["env"], a["id"]))


def _get_account(account_id: str) -> dict:
    acct = next((a for a in discover_accounts() if a["id"] == account_id), None)
    if not acct:
        raise HTTPException(404, f"Account '{account_id}' not found")
    return acct


def _get_account_secret(account_id: str) -> str:
    """Return the client secret for an account — env var takes priority over file."""
    env_secret = os.environ.get(f"PAXOS_CLIENT_SECRET_{account_id}", "")
    if env_secret:
        return env_secret
    for ca in _load_custom_accounts():
        if ca.get("id") == account_id:
            return ca.get("client_secret", "")
    return ""


# ── Token Cache ──────────────────────────────────────────────────────────────

# Keyed by "{account_id}:{scope_key}" so trading and WS tokens are cached separately.
_token_cache: dict[str, dict[str, Any]] = {}


async def _fetch_token(account_id: str, scope: str) -> str:
    cache_key = f"{account_id}:{scope}"
    cached = _token_cache.get(cache_key)
    if cached and cached["expires_at"] - 300 > time.time():
        return cached["token"]

    acct = _get_account(account_id)
    cfg = ENV_CONFIG[acct["env"]]
    secret = _get_account_secret(account_id)

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            cfg["oauth"],
            data={
                "grant_type": "client_credentials",
                "client_id": acct["client_id"],
                "client_secret": secret,
                "scope": scope,
            },
        )
        if resp.status_code != 200:
            raise HTTPException(resp.status_code, f"OAuth error: {resp.text}")
        data = resp.json()

    token = data["access_token"]
    expires_in = data.get("expires_in", 3600)
    # RFC 6749 §5.1: "scope" is OPTIONAL if identical to what was requested,
    # REQUIRED if the server narrowed it. Fall back to the requested scope
    # string when omitted, since omission means nothing was narrowed.
    granted_scope = data.get("scope", scope)
    _token_cache[cache_key] = {
        "token": token,
        "expires_at": time.time() + expires_in,
        "granted_scope": granted_scope,
    }
    return token


async def get_token(account_id: str) -> str:
    """Get a trading-scoped token for the given account."""
    return await _fetch_token(account_id, TRADING_SCOPES)


async def get_ws_token(env: str) -> tuple[str, str]:
    """Return (token, account_id) for the WS market-data scope.

    Tries every account in the given environment until one succeeds with
    WS_SCOPE. This is necessary because not all API clients have this scope
    granted — only the ones specifically provisioned for market data access.
    """
    candidates = [a for a in discover_accounts() if a["env"] == env]
    last_err: Optional[Exception] = None
    for acct in candidates:
        try:
            token = await _fetch_token(acct["id"], WS_SCOPE)
            return token, acct["id"]
        except HTTPException as e:
            last_err = e
            continue
    raise HTTPException(
        502,
        f"No account in {env} has '{WS_SCOPE}' scope. "
        f"Last error: {last_err}",
    )


async def get_rewards_token(account_id: str, scope: str) -> str:
    """Get a token for exactly one rewards scope.

    Raises HTTPException (propagated from _fetch_token) if the account
    isn't authorized for this specific scope — callers let that propagate
    as a normal API error for that operation; only /api/rewards/status
    treats a per-scope failure as informational rather than an error.
    """
    return await _fetch_token(account_id, scope)


# scope -> (path, extra query params) for a cheap, side-effect-free GET used
# only to probe real Rewards enrollment (see _probe_rewards_enrollment).
# Ordered read-before-write is enforced by _ENROLLMENT_PROBE_ORDER below —
# this dict only needs an entry for each scope we might probe with.
_ENROLLMENT_PROBE_ENDPOINT = {
    REWARDS_SCOPE_READ_DETAILS: ("/rewards/details", {}),
    REWARDS_SCOPE_READ_PAYOUT_GROUPS: ("/rewards/payout-groups", {"limit": 1}),
    REWARDS_SCOPE_READ_ADDRESSES: ("/rewards/addresses", {"limit": 1}),
    REWARDS_SCOPE_READ_CLAIMS: ("/rewards/claims", {"limit": 1}),
    REWARDS_SCOPE_READ_STATEMENTS: ("/rewards/statements", {"limit": 1}),
}
# Cheapest/most universally-available first.
_ENROLLMENT_PROBE_ORDER = [
    REWARDS_SCOPE_READ_DETAILS,
    REWARDS_SCOPE_READ_PAYOUT_GROUPS,
    REWARDS_SCOPE_READ_ADDRESSES,
    REWARDS_SCOPE_READ_CLAIMS,
    REWARDS_SCOPE_READ_STATEMENTS,
]


async def _probe_rewards_enrollment(account_id: str, scope: str) -> Optional[bool]:
    """Make one real, read-only Rewards API call to check actual enrollment.

    An OAuth scope grant only means the API client is *permitted to
    attempt* an operation — it does not mean the underlying customer is
    actually enrolled in the Rewards program. Paxos signals "not enrolled"
    with a 403 from the real endpoint itself
    (`{"type":"about:blank","title":"Forbidden","status":403,"detail":
    "not enrolled in rewards"}`), completely independent of whether the
    OAuth token request for that scope succeeded.

    Returns True if the account is enrolled (call succeeded), False if
    this specific "not enrolled" 403 came back, or None if the probe was
    inconclusive (any other error) — the caller should try a different
    scope or fall back to a lenient default rather than treat None as
    "not enabled".
    """
    acct = _get_account(account_id)
    base = ENV_CONFIG[acct["env"]]["api"]
    path, params = _ENROLLMENT_PROBE_ENDPOINT[scope]
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            f"{base}{path}",
            params=params,
            headers={"Authorization": f"Bearer {await get_rewards_token(account_id, scope)}"},
        )
    if r.status_code == 200:
        return True
    if r.status_code == 403:
        try:
            detail = str(r.json().get("detail", "")).lower()
        except ValueError:
            detail = ""
        if "not enrolled" in detail:
            return False
    return None


async def _rewards_enabled(account_id: str) -> tuple[bool, list[str]]:
    """(enabled, granted_scopes) — enabled reflects real Rewards
    enrollment, not just OAuth scope grants (see _probe_rewards_enrollment
    for why those are different things). granted_scopes lists every
    rewards:* scope the OAuth server actually granted a token for
    (checked independently — never bundled, see ALL_REWARDS_SCOPES),
    used by the frontend for per-operation UI gating regardless of the
    enrollment verdict.
    """
    async def _check(scope: str) -> Optional[str]:
        try:
            await get_rewards_token(account_id, scope)
            return scope
        except HTTPException:
            return None

    results = await asyncio.gather(*(_check(s) for s in ALL_REWARDS_SCOPES))
    granted_scopes = [s for s in results if s]
    if not granted_scopes:
        return False, []  # client has no rewards permission at all

    for scope in _ENROLLMENT_PROBE_ORDER:
        if scope not in granted_scopes:
            continue
        enrolled = await _probe_rewards_enrollment(account_id, scope)
        if enrolled is False:
            # Keep granted_scopes even though enabled=False: OAuth granted
            # these, but the customer isn't enrolled — a genuinely
            # different failure mode from "no OAuth grant at all" (also
            # reported as enabled=False, but with an empty list), worth
            # being able to tell apart when debugging an account.
            return False, granted_scopes
        if enrolled is True:
            return True, granted_scopes
        # None (inconclusive) -> try the next granted read scope, if any

    # No read scope was grantable (only write scopes), or every probe was
    # inconclusive — default to enabled so a write-only-scoped account (or
    # a transient probe failure) isn't hidden behind a false "not
    # enabled"; a genuine problem still surfaces as a normal per-operation
    # error when the user actually tries something.
    return True, granted_scopes


async def get_identities_token(account_id: str, scope: str) -> str:
    """Get a token for exactly one identity:* scope."""
    return await _fetch_token(account_id, scope)


async def _identities_enabled(account_id: str) -> tuple[bool, list[str]]:
    """(enabled, granted_scopes). enabled is False when the client lacks
    identity:read_identity or a probe call to List Identities errors.
    granted_scopes lists every identity:* scope the OAuth server granted
    (checked independently, never bundled) and drives per-action UI gating.
    """
    async def _check(scope: str) -> Optional[str]:
        try:
            await get_identities_token(account_id, scope)
            return scope
        except HTTPException:
            return None

    results = await asyncio.gather(*(_check(s) for s in ALL_IDENTITIES_SCOPES))
    granted_scopes = [s for s in results if s]
    if IDENTITIES_SCOPE_READ_IDENTITY not in granted_scopes:
        return False, granted_scopes  # can't even list identities

    acct = _get_account(account_id)
    base = ENV_CONFIG[acct["env"]]["api"]
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"{base}/identity/identities",
                params={"limit": 1},
                headers={"Authorization": f"Bearer {await get_identities_token(account_id, IDENTITIES_SCOPE_READ_IDENTITY)}"},
            )
    except httpx.HTTPError:
        return False, granted_scopes
    if r.status_code != 200:
        return False, granted_scopes
    return True, granted_scopes


# ── FastAPI App ──────────────────────────────────────────────────────────────

app = FastAPI(title="Paxos Trader", docs_url=None, redoc_url=None)

# Per-process token required on every HTTP and WebSocket route (see local_auth.py).
AUTH_TOKEN = new_token()
app.add_middleware(LocalAuthMiddleware, token=AUTH_TOKEN)

# Serve frontend static assets
app.mount("/static", StaticFiles(directory="frontend"), name="static")


@app.get("/")
async def index():
    return FileResponse("frontend/index.html")


# ── REST Endpoints ───────────────────────────────────────────────────────────

@app.get("/api/rewards/status")
async def api_rewards_status(account: str = Query(...)):
    _get_account(account)  # 404s if the account doesn't exist
    enabled, granted_scopes = await _rewards_enabled(account)
    return {"enabled": enabled, "granted_scopes": granted_scopes}


@app.get("/api/identities/status")
async def api_identities_status(account: str = Query(...)):
    _get_account(account)  # 404s if the account doesn't exist
    enabled, granted_scopes = await _identities_enabled(account)
    return {"enabled": enabled, "granted_scopes": granted_scopes}


@app.get("/api/accounts")
async def api_accounts():
    return {"accounts": discover_accounts(), "encryption": encryption_status()}


@app.post("/api/accounts")
async def api_add_account(body: dict):
    """Validate credentials then persist a new custom account."""
    env = body.get("env", "").upper()
    label = (body.get("label") or "").strip()
    client_id = (body.get("client_id") or "").strip()
    client_secret = (body.get("client_secret") or "").strip()

    if env not in ENV_CONFIG:
        raise HTTPException(400, f"env must be one of {list(ENV_CONFIG)}")
    if not label:
        raise HTTPException(400, "label is required")
    if not client_id or not client_secret:
        raise HTTPException(400, "client_id and client_secret are required")

    # Generate a stable ID: ENV_SLUG
    slug = re.sub(r"[^A-Z0-9]", "_", label.upper())[:24].strip("_")
    account_id = f"{env}_{slug}"
    # Make unique if collision exists
    existing_ids = {a["id"] for a in discover_accounts()}
    suffix = 1
    base_id = account_id
    while account_id in existing_ids:
        account_id = f"{base_id}_{suffix}"
        suffix += 1

    # Validate credentials by requesting a minimal scope token.
    cfg = ENV_CONFIG[env]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(
            cfg["oauth"],
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "funding:read_profile",
            },
        )
        if r.status_code != 200:
            raise HTTPException(400, f"Credential validation failed: {r.json().get('error_description', r.text)}")

    custom = _load_custom_accounts()
    custom.append({
        "id": account_id,
        "label": label,
        "env": env,
        "client_id": client_id,
        "client_secret": client_secret,
    })
    _save_custom_accounts(custom)
    return {"id": account_id, "label": label, "env": env}


@app.put("/api/accounts/{account_id}")
async def api_update_account(account_id: str, body: dict):
    """Update an existing custom account. Omit client_secret to keep the current one."""
    custom = _load_custom_accounts()
    existing = next((c for c in custom if c.get("id") == account_id), None)
    if not existing:
        raise HTTPException(404, f"Custom account '{account_id}' not found (env-var accounts cannot be edited)")

    env          = (body.get("env") or existing["env"]).upper()
    label        = (body.get("label") or "").strip() or existing["label"]
    client_id    = (body.get("client_id") or "").strip() or existing["client_id"]
    client_secret = (body.get("client_secret") or "").strip() or existing["client_secret"]

    if env not in ENV_CONFIG:
        raise HTTPException(400, f"env must be one of {list(ENV_CONFIG)}")

    # Only re-validate when credentials actually changed.
    credentials_changed = (
        client_id != existing["client_id"] or
        client_secret != existing["client_secret"] or
        env != existing["env"]
    )
    if credentials_changed:
        cfg = ENV_CONFIG[env]
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(
                cfg["oauth"],
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": "funding:read_profile",
                },
            )
            if r.status_code != 200:
                raise HTTPException(400, f"Credential validation failed: {r.json().get('error_description', r.text)}")

    existing.update({"env": env, "label": label, "client_id": client_id, "client_secret": client_secret})
    _save_custom_accounts(custom)

    # Evict cached tokens so the next call fetches a fresh one.
    for key in [k for k in _token_cache if k.startswith(f"{account_id}:")]:
        del _token_cache[key]

    return {"id": account_id, "label": label, "env": env}


@app.delete("/api/accounts/{account_id}")
async def api_remove_account(account_id: str):
    """Remove a custom account. Env-var accounts cannot be removed."""
    custom = _load_custom_accounts()
    original_len = len(custom)
    custom = [c for c in custom if c.get("id") != account_id]
    if len(custom) == original_len:
        raise HTTPException(404, f"Custom account '{account_id}' not found (env-var accounts cannot be removed)")
    _save_custom_accounts(custom)
    # Evict any cached tokens for this account.
    for key in [k for k in _token_cache if k.startswith(f"{account_id}:")]:
        del _token_cache[key]
    return {"removed": account_id}


@app.get("/api/profiles")
async def api_profiles(
    account: str = Query(...),
    search: Optional[str] = Query(None),      # filters by nickname (prefix match)
    limit: int = Query(25),                    # page size
    page_cursor: Optional[str] = Query(None),  # opaque cursor from previous response
):
    acct = _get_account(account)
    token = await get_token(account)
    base = ENV_CONFIG[acct["env"]]["api"]
    params: dict[str, Any] = {"limit": limit, "order": "ASC", "order_by": "CREATED_AT"}
    if search:
        params["nickname"] = search
    if page_cursor:
        params["page_cursor"] = page_cursor
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"{base}/profiles",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.put("/api/profiles/{profile_id}/deactivate")
async def api_deactivate_profile(profile_id: str, account: str = Query(...)):
    acct = _get_account(account)
    token = await get_token(account)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.put(
            f"{base}/profiles/{profile_id}/deactivate",
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code not in (200, 204):
            raise HTTPException(r.status_code, r.text)
    return r.json() if r.content else {"status": "deactivated"}


@app.get("/api/balances")
async def api_balances(account: str = Query(...), profile_id: str = Query(...)):
    acct = _get_account(account)
    token = await get_token(account)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"{base}/profiles/{profile_id}/balances",
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.get("/api/markets")
async def api_markets(response: Response, account: str = Query(...)):
    acct = _get_account(account)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(f"{base}/markets")
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    # Newly-added markets (e.g. HYPEUSD, CCUSD) were reported missing from
    # the dropdown; the upstream call above always returns them fresh when
    # tested directly, so this guards against the browser ever serving a
    # stale cached copy of this endpoint's own response instead of re-fetching.
    response.headers["Cache-Control"] = "no-store"
    return r.json()


@app.get("/api/prices")
async def api_prices(account: str = Query(...), markets: str = Query(...)):
    """Fetch current prices for a comma-separated list of markets (e.g. BTCUSD,ETHUSD)."""
    acct = _get_account(account)
    base = ENV_CONFIG[acct["env"]]["api"]
    market_list = [m.strip() for m in markets.split(",") if m.strip()]
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            f"{base}/all-markets/prices",
            params=[("markets", m) for m in market_list],
        )
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.get("/api/orders")
async def api_list_orders(
    account: str = Query(...),
    profile_id: str = Query(...),
    status: Optional[str] = Query(None),
):
    acct = _get_account(account)
    token = await get_token(account)
    base = ENV_CONFIG[acct["env"]]["api"]
    params: dict[str, Any] = {"limit": 100, "order": "DESC"}
    if status:
        params["status"] = status
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"{base}/profiles/{profile_id}/orders",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.get("/api/executions")
async def api_executions(
    account: str = Query(...),
    profile_id: str = Query(...),
    order_id: str = Query(...),
):
    acct = _get_account(account)
    token = await get_token(account)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"{base}/profiles/{profile_id}/executions",
            params={"order_id": order_id, "limit": 100},
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.post("/api/orders")
async def api_create_order(body: dict):
    account = body.pop("account", None)
    profile_id = body.pop("profile_id", None)
    if not account or not profile_id:
        raise HTTPException(400, "account and profile_id required")

    acct = _get_account(account)
    token = await get_token(account)
    base = ENV_CONFIG[acct["env"]]["api"]
    body.setdefault("ref_id", str(uuid.uuid4()))

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            f"{base}/profiles/{profile_id}/orders",
            json=body,
            headers={
                "Authorization": f"Bearer {token}",
                "X-Order-Routing-Enabled": "true",
            },
        )
        if r.status_code not in (200, 201):
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.delete("/api/orders/{order_id}")
async def api_cancel_order(
    order_id: str,
    account: str = Query(...),
    profile_id: str = Query(...),
):
    acct = _get_account(account)
    token = await get_token(account)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.delete(
            f"{base}/profiles/{profile_id}/orders/{order_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code not in (200, 204):
            raise HTTPException(r.status_code, r.text)
    return r.json() if r.content else {"status": "cancelled"}


@app.get("/api/transfers")
async def api_transfers(
    account: str = Query(...),
    profile_id: str = Query(...),
    limit: int = Query(50),
):
    acct = _get_account(account)
    token = await get_token(account)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"{base}/transfer/transfers",
            params={"profile_ids": profile_id, "limit": limit, "order": "DESC"},
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.get("/api/deposit-addresses")
async def api_deposit_addresses(
    account: str = Query(...),
    profile_id: str = Query(...),
):
    acct = _get_account(account)
    token = await get_token(account)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"{base}/transfer/deposit-addresses",
            params={"profile_ids": profile_id, "limit": 100},
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.post("/api/deposit-addresses")
async def api_create_deposit_address(body: dict):
    account = body.pop("account", None)
    profile_id = body.pop("profile_id", None)
    if not account or not profile_id:
        raise HTTPException(400, "account and profile_id required")
    acct = _get_account(account)
    token = await get_token(account)
    base = ENV_CONFIG[acct["env"]]["api"]
    body["profile_id"] = profile_id
    body.setdefault("ref_id", str(uuid.uuid4()))
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(
            f"{base}/transfer/deposit-addresses",
            json=body,
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code not in (200, 201):
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.post("/api/withdrawals")
async def api_create_withdrawal(body: dict):
    account = body.pop("account", None)
    profile_id = body.pop("profile_id", None)
    if not account or not profile_id:
        raise HTTPException(400, "account and profile_id required")
    acct = _get_account(account)
    token = await get_token(account)
    base = ENV_CONFIG[acct["env"]]["api"]
    body["profile_id"] = profile_id
    body.setdefault("ref_id", str(uuid.uuid4()))
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            f"{base}/transfer/crypto-withdrawals",
            json=body,
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code not in (200, 201):
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.post("/api/internal-transfer")
async def api_internal_transfer(body: dict):
    account = body.pop("account", None)
    if not account:
        raise HTTPException(400, "account required")
    acct = _get_account(account)
    token = await get_token(account)
    base = ENV_CONFIG[acct["env"]]["api"]
    body.setdefault("ref_id", str(uuid.uuid4()))
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(
            f"{base}/transfer/internal",
            json=body,
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code not in (200, 201):
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.get("/api/quotes")
async def api_quotes(account: str = Query(...), market: str = Query(...)):
    acct = _get_account(account)
    base = ENV_CONFIG[acct["env"]]["api"]
    token = await get_token(account)
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            f"{base}/quotes",
            params={"markets": market},
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.post("/api/quote-executions")
async def api_create_quote_execution(body: dict):
    account = body.pop("account", None)
    profile_id = body.pop("profile_id", None)
    if not account or not profile_id:
        raise HTTPException(400, "account and profile_id required")
    acct = _get_account(account)
    token = await get_token(account)
    base = ENV_CONFIG[acct["env"]]["api"]
    body.setdefault("ref_id", str(uuid.uuid4()))
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(
            f"{base}/profiles/{profile_id}/quote-executions",
            json=body,
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code not in (200, 201):
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.get("/api/quote-executions")
async def api_list_quote_executions(
    account: str = Query(...),
    profile_id: str = Query(...),
    market: Optional[str] = Query(None),
    limit: int = Query(50),
):
    acct = _get_account(account)
    token = await get_token(account)
    base = ENV_CONFIG[acct["env"]]["api"]
    params: dict[str, Any] = {"limit": limit, "order": "DESC"}
    if market:
        params["market"] = market
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"{base}/profiles/{profile_id}/quote-executions",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


# ── Issuer Quotes (PAXG mint/redeem at a held rate) ─────────────────────────

@app.get("/api/issuer-quote/settlement-availability")
async def api_issuer_settlement_availability(account: str = Query(...), market: str = Query("PAXGUSD")):
    acct = _get_account(account)
    token = await _fetch_token(account, ISSUER_SCOPE_WRITE_QUOTE)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"{base}/issuer-quote/settlement-availability",
            params={"market": market},
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.post("/api/issuer-quote")
async def api_create_issuer_quote(body: dict):
    account = body.pop("account", None)
    if not account or not body.get("profile_id"):
        raise HTTPException(400, "account and profile_id required")
    acct = _get_account(account)
    token = await _fetch_token(account, ISSUER_SCOPE_WRITE_QUOTE)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(
            f"{base}/issuer-quote",
            json=body,
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code not in (200, 201):
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.post("/api/issuer-quote/{quote_id}/execute")
async def api_execute_issuer_quote(quote_id: str, body: dict):
    account = body.pop("account", None)
    if not account or not body.get("profile_id"):
        raise HTTPException(400, "account and profile_id required")
    acct = _get_account(account)
    token = await _fetch_token(account, ISSUER_SCOPE_WRITE_EXECUTION)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            f"{base}/issuer-quote/{quote_id}",
            json={"profile_id": body["profile_id"]},
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code not in (200, 201):
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.get("/api/issuer-quote-executions")
async def api_list_issuer_quote_executions(
    account: str = Query(...),
    profile_id: str = Query(...),
    limit: int = Query(50),
):
    acct = _get_account(account)
    token = await _fetch_token(account, ISSUER_SCOPE_READ_EXECUTION)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"{base}/issuer-quotes",
            params={"profile_id": profile_id, "limit": limit, "order": "DESC"},
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.get("/api/market-executions")
async def api_market_executions(
    account: str = Query(...),
    market: str = Query(...),
    since: Optional[str] = Query(None),  # ISO-8601 timestamp (e.g. midnight UTC)
    limit: int = Query(1000),
):
    """Fetch recent public market executions for volume backfill."""
    acct = _get_account(account)
    token = await get_token(account)
    base = ENV_CONFIG[acct["env"]]["api"]
    params: dict[str, Any] = {"limit": limit, "order": "DESC"}
    if since:
        params["created_at.gte"] = since
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"{base}/markets/{market}/recent-executions",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.get("/api/rewards/payout-groups")
async def api_rewards_list_payout_groups(
    account: str = Query(...),
    asset_type: Optional[str] = Query(None),
    name_prefix: Optional[str] = Query(None),
    onchain_status: Optional[str] = Query(None),
    limit: int = Query(50),
    page_cursor: Optional[str] = Query(None),
):
    acct = _get_account(account)
    token = await get_rewards_token(account, REWARDS_SCOPE_READ_PAYOUT_GROUPS)
    base = ENV_CONFIG[acct["env"]]["api"]
    params: dict[str, Any] = {"limit": limit}
    if asset_type:
        params["asset_type"] = asset_type
    if name_prefix:
        params["name_prefix"] = name_prefix
    if onchain_status:
        params["onchain_statuses"] = onchain_status
    if page_cursor:
        params["page_cursor"] = page_cursor
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"{base}/rewards/payout-groups",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.post("/api/rewards/payout-groups")
async def api_rewards_create_payout_group(body: dict):
    account = body.pop("account", None)
    if not account:
        raise HTTPException(400, "account required")
    acct = _get_account(account)
    token = await get_rewards_token(account, REWARDS_SCOPE_CREATE_PAYOUT_GROUPS)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(
            f"{base}/rewards/payout-groups",
            json=body,
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code not in (200, 201):
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.put("/api/rewards/payout-groups/{group_id}")
async def api_rewards_update_payout_group(group_id: str, body: dict):
    account = body.pop("account", None)
    if not account:
        raise HTTPException(400, "account required")
    acct = _get_account(account)
    # No distinct "update payout group" scope is documented by Paxos —
    # reusing the create scope as the closest mutating-operation match.
    # Verify against a real account that can create-but-not-update (or
    # vice versa) if this ever needs to be split out.
    token = await get_rewards_token(account, REWARDS_SCOPE_CREATE_PAYOUT_GROUPS)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.put(
            f"{base}/rewards/payout-groups/{group_id}",
            json=body,
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.delete("/api/rewards/payout-groups/{group_id}")
async def api_rewards_delete_payout_group(group_id: str, account: str = Query(...)):
    acct = _get_account(account)
    token = await get_rewards_token(account, REWARDS_SCOPE_DELETE_PAYOUT_GROUPS)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.delete(
            f"{base}/rewards/payout-groups/{group_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code not in (200, 204):
            raise HTTPException(r.status_code, r.text)
    return r.json() if r.content else {"status": "deleted"}


@app.get("/api/rewards/addresses")
async def api_rewards_list_addresses(
    account: str = Query(...),
    payout_group_id: Optional[str] = Query(None),
    ledger: Optional[str] = Query(None),
    asset_type: Optional[str] = Query(None),
    onchain_status: Optional[str] = Query(None),
    verification_status: Optional[str] = Query(None),
    include_balance: Optional[bool] = Query(None),
    limit: int = Query(50),
    page_cursor: Optional[str] = Query(None),
):
    acct = _get_account(account)
    token = await get_rewards_token(account, REWARDS_SCOPE_READ_ADDRESSES)
    base = ENV_CONFIG[acct["env"]]["api"]
    params: dict[str, Any] = {"limit": limit}
    if payout_group_id:
        params["payout_group_id"] = payout_group_id
    if ledger:
        params["ledger"] = ledger
    if asset_type:
        params["asset_type"] = asset_type
    if onchain_status:
        params["onchain_statuses"] = onchain_status
    if verification_status:
        params["verification_statuses"] = verification_status
    if include_balance is not None:
        params["include_balance"] = include_balance
    if page_cursor:
        params["page_cursor"] = page_cursor
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"{base}/rewards/addresses",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.post("/api/rewards/addresses")
async def api_rewards_create_address(body: dict):
    account = body.pop("account", None)
    if not account:
        raise HTTPException(400, "account required")
    acct = _get_account(account)
    token = await get_rewards_token(account, REWARDS_SCOPE_WRITE_ADDRESSES)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(
            f"{base}/rewards/addresses",
            json={"address": body},
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code not in (200, 201):
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.post("/api/rewards/addresses/batch")
async def api_rewards_batch_create_addresses(body: dict):
    account = body.pop("account", None)
    if not account:
        raise HTTPException(400, "account required")
    addresses = body.get("addresses")
    if not isinstance(addresses, list) or not addresses:
        raise HTTPException(400, "addresses must be a non-empty list")
    if len(addresses) > 1000:
        raise HTTPException(400, "addresses cannot exceed 1000 entries per request")
    acct = _get_account(account)
    token = await get_rewards_token(account, REWARDS_SCOPE_WRITE_ADDRESSES)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            f"{base}/rewards/addresses/batch",
            json={"addresses": addresses},
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code not in (200, 201):
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.put("/api/rewards/addresses/{address_id}")
async def api_rewards_update_address(address_id: str, body: dict):
    account = body.pop("account", None)
    if not account:
        raise HTTPException(400, "account required")
    acct = _get_account(account)
    token = await get_rewards_token(account, REWARDS_SCOPE_WRITE_ADDRESSES)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.put(
            f"{base}/rewards/addresses/{address_id}",
            json=body,
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.delete("/api/rewards/addresses/{address_id}")
async def api_rewards_delete_address(address_id: str, account: str = Query(...)):
    acct = _get_account(account)
    token = await get_rewards_token(account, REWARDS_SCOPE_WRITE_ADDRESSES)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.delete(
            f"{base}/rewards/addresses/{address_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code not in (200, 204):
            raise HTTPException(r.status_code, r.text)
    return r.json() if r.content else {"status": "deleted"}


@app.get("/api/rewards/claim-schedules")
async def api_rewards_list_claim_schedules(
    account: str = Query(...),
    payout_group_id: Optional[str] = Query(None),
    limit: int = Query(100),
    page_cursor: Optional[str] = Query(None),
):
    acct = _get_account(account)
    # No distinct "read claim schedules" scope is documented by Paxos —
    # reusing the general claims-read scope as the closest match. Verify
    # against a real account if this ever needs to be split out.
    token = await get_rewards_token(account, REWARDS_SCOPE_READ_CLAIMS)
    base = ENV_CONFIG[acct["env"]]["api"]
    params: dict[str, Any] = {"limit": limit}
    if payout_group_id:
        params["payout_group_id"] = payout_group_id
    if page_cursor:
        params["page_cursor"] = page_cursor
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"{base}/rewards/claim-schedules",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.post("/api/rewards/claim-schedules")
async def api_rewards_create_claim_schedule(body: dict):
    account = body.pop("account", None)
    if not account:
        raise HTTPException(400, "account required")
    acct = _get_account(account)
    token = await get_rewards_token(account, REWARDS_SCOPE_WRITE_CLAIM_SCHEDULE)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(
            f"{base}/rewards/claim-schedules",
            json=body,
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code not in (200, 201):
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.put("/api/rewards/claim-schedules/{schedule_id}")
async def api_rewards_update_claim_schedule(schedule_id: str, body: dict):
    account = body.pop("account", None)
    if not account:
        raise HTTPException(400, "account required")
    acct = _get_account(account)
    token = await get_rewards_token(account, REWARDS_SCOPE_WRITE_CLAIM_SCHEDULE)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.put(
            f"{base}/rewards/claim-schedules/{schedule_id}",
            json=body,
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.delete("/api/rewards/claim-schedules/{schedule_id}")
async def api_rewards_delete_claim_schedule(schedule_id: str, account: str = Query(...)):
    acct = _get_account(account)
    token = await get_rewards_token(account, REWARDS_SCOPE_WRITE_CLAIM_SCHEDULE)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.delete(
            f"{base}/rewards/claim-schedules/{schedule_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code not in (200, 204):
            raise HTTPException(r.status_code, r.text)
    return r.json() if r.content else {"status": "deleted"}


@app.get("/api/rewards/claims")
async def api_rewards_list_claims(
    account: str = Query(...),
    payout_group_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    chain: Optional[str] = Query(None),
    jurisdiction: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    asset_type: Optional[str] = Query(None),
    limit: int = Query(100),
    page_cursor: Optional[str] = Query(None),
):
    acct = _get_account(account)
    token = await get_rewards_token(account, REWARDS_SCOPE_READ_CLAIMS)
    base = ENV_CONFIG[acct["env"]]["api"]
    params: dict[str, Any] = {"limit": limit}
    if payout_group_id:
        params["payout_group_id"] = payout_group_id
    if status:
        params["statuses"] = status
    if chain:
        params["chain"] = chain
    if jurisdiction:
        params["jurisdiction"] = jurisdiction
    if start_time:
        params["start_time"] = start_time
    if end_time:
        params["end_time"] = end_time
    if asset_type:
        params["asset_type"] = asset_type
    if page_cursor:
        params["page_cursor"] = page_cursor
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"{base}/rewards/claims",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.get("/api/rewards/details")
async def api_rewards_details(account: str = Query(...), asset_type: Optional[str] = Query(None)):
    acct = _get_account(account)
    token = await get_rewards_token(account, REWARDS_SCOPE_READ_DETAILS)
    base = ENV_CONFIG[acct["env"]]["api"]
    params: dict[str, Any] = {}
    if asset_type:
        params["asset_type"] = asset_type
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"{base}/rewards/details",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.get("/api/rewards/statements")
async def api_rewards_list_statements(
    account: str = Query(...),
    asset_type: Optional[str] = Query(None),
    statement_type: Optional[str] = Query(None, alias="type"),
    limit: int = Query(12),
    page_cursor: Optional[str] = Query(None),
):
    acct = _get_account(account)
    token = await get_rewards_token(account, REWARDS_SCOPE_READ_STATEMENTS)
    base = ENV_CONFIG[acct["env"]]["api"]
    params: dict[str, Any] = {"limit": limit}
    if asset_type:
        params["asset_type"] = asset_type
    if statement_type:
        params["type"] = statement_type
    if page_cursor:
        params["page_cursor"] = page_cursor
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"{base}/rewards/statements",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.get("/api/rewards/statements/{statement_id}")
async def api_rewards_get_statement(statement_id: str, account: str = Query(...)):
    acct = _get_account(account)
    token = await get_rewards_token(account, REWARDS_SCOPE_READ_STATEMENTS)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"{base}/rewards/statements/{statement_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


# ── Identities ───────────────────────────────────────────────────────────────

def _add_date_range_params(params: dict, field: str, lt, lte, eq, gte, gt) -> None:
    """Forward Paxos's '<field>.<op>' RFC3339 filter params when present."""
    for suffix, val in (("lt", lt), ("lte", lte), ("eq", eq), ("gte", gte), ("gt", gt)):
        if val:
            params[f"{field}.{suffix}"] = val


@app.get("/api/identities")
async def api_list_identities(
    account: str = Query(...),
    limit: int = Query(50),
    page_cursor: Optional[str] = Query(None),
    order: Optional[str] = Query(None),
    order_by: Optional[str] = Query(None),
    summary_status: Optional[str] = Query(None),
    identity_type: Optional[str] = Query(None),
    control_types: Optional[str] = Query(None),
    control_reason_codes: Optional[str] = Query(None),
    created_at_lt: Optional[str] = Query(None, alias="created_at.lt"),
    created_at_lte: Optional[str] = Query(None, alias="created_at.lte"),
    created_at_eq: Optional[str] = Query(None, alias="created_at.eq"),
    created_at_gte: Optional[str] = Query(None, alias="created_at.gte"),
    created_at_gt: Optional[str] = Query(None, alias="created_at.gt"),
    updated_at_lt: Optional[str] = Query(None, alias="updated_at.lt"),
    updated_at_lte: Optional[str] = Query(None, alias="updated_at.lte"),
    updated_at_eq: Optional[str] = Query(None, alias="updated_at.eq"),
    updated_at_gte: Optional[str] = Query(None, alias="updated_at.gte"),
    updated_at_gt: Optional[str] = Query(None, alias="updated_at.gt"),
):
    acct = _get_account(account)
    token = await get_identities_token(account, IDENTITIES_SCOPE_READ_IDENTITY)
    base = ENV_CONFIG[acct["env"]]["api"]
    params: dict[str, Any] = {"limit": limit}
    if page_cursor:
        params["page_cursor"] = page_cursor
    if order:
        params["order"] = order
    if order_by:
        params["order_by"] = order_by
    if summary_status:
        params["summary_status"] = summary_status
    if identity_type:
        params["identity_type"] = identity_type
    if control_types:
        params["control_types"] = control_types
    if control_reason_codes:
        params["control_reason_codes"] = control_reason_codes
    _add_date_range_params(params, "created_at", created_at_lt, created_at_lte, created_at_eq, created_at_gte, created_at_gt)
    _add_date_range_params(params, "updated_at", updated_at_lt, updated_at_lte, updated_at_eq, updated_at_gte, updated_at_gt)
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(f"{base}/identity/identities", params=params, headers={"Authorization": f"Bearer {token}"})
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.post("/api/identities")
async def api_create_identity(body: dict):
    account = body.pop("account", None)
    if not account:
        raise HTTPException(400, "account required")
    acct = _get_account(account)
    token = await get_identities_token(account, IDENTITIES_SCOPE_WRITE_IDENTITY)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(f"{base}/identity/identities", json=body, headers={"Authorization": f"Bearer {token}"})
        if r.status_code not in (200, 201):
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.get("/api/identities/{identity_id}")
async def api_get_identity(identity_id: str, account: str = Query(...)):
    acct = _get_account(account)
    token = await get_identities_token(account, IDENTITIES_SCOPE_READ_IDENTITY)
    base = ENV_CONFIG[acct["env"]]["api"]
    # person_details/institution_details are encrypted at rest and omitted
    # by default -- found during Task 10 (the frontend View flow otherwise
    # renders blank fields for every identity) and confirmed directly
    # against the real API: without these two flags, GET never returns
    # person_details/institution_details at all.
    params = {"include_details": "true", "include_institution_members": "true"}
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(f"{base}/identity/identities/{identity_id}", params=params, headers={"Authorization": f"Bearer {token}"})
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.put("/api/identities/{identity_id}")
async def api_update_identity(identity_id: str, body: dict):
    account = body.pop("account", None)
    if not account:
        raise HTTPException(400, "account required")
    acct = _get_account(account)
    token = await get_identities_token(account, IDENTITIES_SCOPE_WRITE_IDENTITY)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.put(f"{base}/identity/identities/{identity_id}", json=body, headers={"Authorization": f"Bearer {token}"})
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


# ── Institution Members ───────────────────────────────────────────────────────

@app.post("/api/identities/institution-members")
async def api_add_institution_members(body: dict):
    account = body.pop("account", None)
    if not account:
        raise HTTPException(400, "account required")
    acct = _get_account(account)
    token = await get_identities_token(account, IDENTITIES_SCOPE_WRITE_IDENTITY)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(f"{base}/identity/institution-members", json=body, headers={"Authorization": f"Bearer {token}"})
        if r.status_code not in (200, 201):
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.delete("/api/identities/institution-members/{member_id}")
async def api_remove_institution_member(member_id: str, account: str = Query(...)):
    acct = _get_account(account)
    token = await get_identities_token(account, IDENTITIES_SCOPE_WRITE_IDENTITY)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.delete(f"{base}/identity/institution-members/{member_id}", headers={"Authorization": f"Bearer {token}"})
        if r.status_code not in (200, 204):
            raise HTTPException(r.status_code, r.text)
    return r.json() if r.content else {"status": "removed"}


# ── Identity Accounts ──────────────────────────────────────────────────────────

@app.get("/api/identity-accounts")
async def api_list_identity_accounts(
    account: str = Query(...),
    limit: int = Query(50),
    page_cursor: Optional[str] = Query(None),
    order: Optional[str] = Query(None),
    order_by: Optional[str] = Query(None),
    identity_id: Optional[str] = Query(None),
    created_at_lt: Optional[str] = Query(None, alias="created_at.lt"),
    created_at_lte: Optional[str] = Query(None, alias="created_at.lte"),
    created_at_eq: Optional[str] = Query(None, alias="created_at.eq"),
    created_at_gte: Optional[str] = Query(None, alias="created_at.gte"),
    created_at_gt: Optional[str] = Query(None, alias="created_at.gt"),
    updated_at_lt: Optional[str] = Query(None, alias="updated_at.lt"),
    updated_at_lte: Optional[str] = Query(None, alias="updated_at.lte"),
    updated_at_eq: Optional[str] = Query(None, alias="updated_at.eq"),
    updated_at_gte: Optional[str] = Query(None, alias="updated_at.gte"),
    updated_at_gt: Optional[str] = Query(None, alias="updated_at.gt"),
):
    acct = _get_account(account)
    token = await get_identities_token(account, IDENTITIES_SCOPE_READ_ACCOUNT)
    base = ENV_CONFIG[acct["env"]]["api"]
    params: dict[str, Any] = {"limit": limit}
    if page_cursor:
        params["page_cursor"] = page_cursor
    if order:
        params["order"] = order
    if order_by:
        params["order_by"] = order_by
    if identity_id:
        params["identity_id"] = identity_id
    _add_date_range_params(params, "created_at", created_at_lt, created_at_lte, created_at_eq, created_at_gte, created_at_gt)
    _add_date_range_params(params, "updated_at", updated_at_lt, updated_at_lte, updated_at_eq, updated_at_gte, updated_at_gt)
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(f"{base}/identity/accounts", params=params, headers={"Authorization": f"Bearer {token}"})
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.post("/api/identity-accounts")
async def api_create_identity_account(body: dict):
    account = body.pop("account", None)
    if not account:
        raise HTTPException(400, "account required")
    acct = _get_account(account)
    token = await get_identities_token(account, IDENTITIES_SCOPE_WRITE_ACCOUNT)
    base = ENV_CONFIG[acct["env"]]["api"]
    # Paxos API expects account fields wrapped in "account" key
    paxos_payload = {"account": body}
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(f"{base}/identity/accounts", json=paxos_payload, headers={"Authorization": f"Bearer {token}"})
        if r.status_code not in (200, 201):
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.get("/api/identity-accounts/{account_id}")
async def api_get_identity_account(account_id: str, account: str = Query(...)):
    acct = _get_account(account)
    token = await get_identities_token(account, IDENTITIES_SCOPE_READ_ACCOUNT)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(f"{base}/identity/accounts/{account_id}", headers={"Authorization": f"Bearer {token}"})
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.put("/api/identity-accounts")
async def api_update_identity_account(body: dict):
    # The real Update Account payload has a top-level "account" key (per
    # Paxos docs: account.id, account.description, ...), which collides
    # with this file's usual "account" = trader-account-selector
    # convention. This route alone uses "_trader_account" for the
    # selector instead, to avoid clobbering the real payload.
    trader_account = body.pop("_trader_account", None)
    if not trader_account:
        raise HTTPException(400, "_trader_account required")
    acct = _get_account(trader_account)
    token = await get_identities_token(trader_account, IDENTITIES_SCOPE_WRITE_ACCOUNT)
    base = ENV_CONFIG[acct["env"]]["api"]
    # For PUT, body already has the expected structure with "account" key, send as-is
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.put(f"{base}/identity/accounts", json=body, headers={"Authorization": f"Bearer {token}"})
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


# ── Account Members ───────────────────────────────────────────────────────────

@app.post("/api/identities/account-members")
async def api_add_account_members(body: dict):
    account = body.pop("account", None)
    if not account:
        raise HTTPException(400, "account required")
    acct = _get_account(account)
    token = await get_identities_token(account, IDENTITIES_SCOPE_WRITE_ACCOUNT)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(f"{base}/identity/account-members", json=body, headers={"Authorization": f"Bearer {token}"})
        if r.status_code not in (200, 201):
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.delete("/api/identities/account-members/{member_id}")
async def api_remove_account_member(member_id: str, account: str = Query(...)):
    acct = _get_account(account)
    token = await get_identities_token(account, IDENTITIES_SCOPE_WRITE_ACCOUNT)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.delete(f"{base}/identity/account-members/{member_id}", headers={"Authorization": f"Bearer {token}"})
        if r.status_code not in (200, 204):
            raise HTTPException(r.status_code, r.text)
    return r.json() if r.content else {"status": "removed"}


# ── Identity Documents ────────────────────────────────────────────────────────

@app.get("/api/identities/{identity_id}/documents")
async def api_list_identity_documents(
    identity_id: str,
    account: str = Query(...),
    include_pending_docs: Optional[bool] = Query(None),
):
    acct = _get_account(account)
    token = await get_identities_token(account, IDENTITIES_SCOPE_READ_IDENTITY)
    base = ENV_CONFIG[acct["env"]]["api"]
    params: dict[str, Any] = {}
    if include_pending_docs is not None:
        params["include_pending_docs"] = include_pending_docs
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(f"{base}/identity/identities/{identity_id}/documents", params=params, headers={"Authorization": f"Bearer {token}"})
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.put("/api/identities/{identity_id}/documents")
async def api_get_identity_document_upload_url(identity_id: str, body: dict):
    """Returns {file_id, name, upload_url}. The browser then PUTs the raw
    file bytes directly to upload_url — this backend is not involved in
    that second step (matches the Paxos docs' curl example)."""
    account = body.pop("account", None)
    if not account:
        raise HTTPException(400, "account required")
    acct = _get_account(account)
    token = await get_identities_token(account, IDENTITIES_SCOPE_WRITE_IDENTITY)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.put(f"{base}/identity/identities/{identity_id}/documents", json=body, headers={"Authorization": f"Bearer {token}"})
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


# ── Sandbox-only actions ───────────────────────────────────────────────────────

@app.put("/api/identities/{identity_id}/sandbox-status")
async def api_set_identity_sandbox_status(identity_id: str, body: dict):
    account = body.pop("account", None)
    if not account:
        raise HTTPException(400, "account required")
    acct = _get_account(account)
    if acct["env"] != "SANDBOX":
        raise HTTPException(400, "Sandbox status can only be set for SANDBOX accounts")
    token = await get_identities_token(account, IDENTITIES_SCOPE_WRITE_IDENTITY)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.put(f"{base}/identity/identities/{identity_id}/sandbox-status", json=body, headers={"Authorization": f"Bearer {token}"})
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


# ── Identity Controls ──────────────────────────────────────────────────────────

@app.get("/api/identity-controls")
async def api_list_identity_controls(
    account: str = Query(...),
    identity_id: str = Query(...),
    include_deleted: Optional[bool] = Query(None),
):
    acct = _get_account(account)
    token = await get_identities_token(account, IDENTITIES_SCOPE_READ_CONTROL)
    base = ENV_CONFIG[acct["env"]]["api"]
    params: dict[str, Any] = {"identity_id": identity_id}
    if include_deleted is not None:
        params["include_deleted"] = include_deleted
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(f"{base}/identity/controls", params=params, headers={"Authorization": f"Bearer {token}"})
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.post("/api/identity-controls")
async def api_create_identity_control(body: dict):
    account = body.pop("account", None)
    if not account:
        raise HTTPException(400, "account required")
    acct = _get_account(account)
    token = await get_identities_token(account, IDENTITIES_SCOPE_WRITE_CONTROL)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(f"{base}/identity/controls", json=body, headers={"Authorization": f"Bearer {token}"})
        if r.status_code not in (200, 201):
            raise HTTPException(r.status_code, r.text)
    return r.json()


@app.delete("/api/identity-controls")
async def api_delete_identity_control(account: str = Query(...), id: str = Query(...)):
    acct = _get_account(account)
    token = await get_identities_token(account, IDENTITIES_SCOPE_WRITE_CONTROL)
    base = ENV_CONFIG[acct["env"]]["api"]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.delete(f"{base}/identity/controls", params={"control_id": id}, headers={"Authorization": f"Bearer {token}"})
        if r.status_code not in (200, 204):
            raise HTTPException(r.status_code, r.text)
    return r.json() if r.content else {"status": "deleted"}


# ── WebSocket Proxy ──────────────────────────────────────────────────────────

import logging as _logging
_ws_log = _logging.getLogger("trader.ws")


@app.websocket("/ws/orderbook")
async def ws_orderbook(
    websocket: WebSocket,
    account: str = Query(...),
    market: str = Query(...),
):
    await websocket.accept()
    _ws_log.info("browser connected: account=%s market=%s", account, market)

    async def _run():
        acct = _get_account(account)
        env = acct["env"]
        token, ws_account = await get_ws_token(env)
        ws_url = ENV_CONFIG[env]["ws"]
        _ws_log.info("connecting to Paxos WS via %s token", ws_account)

        async with websockets.connect(
            ws_url,
            additional_headers=[("Authorization", f"Bearer {token}")],
            ping_interval=None,   # let Paxos own keepalive; our pings caused drops
            open_timeout=15,
        ) as paxos_ws:
            await paxos_ws.send(json.dumps({
                "type": "subscribe",
                "channels": [
                    {"type": "heartbeat"},
                    {"type": "market_data",        "params": {"market": market}},
                    {"type": "execution_data",     "params": {"market": market}},
                ],
            }))
            _ws_log.info("subscribed to %s (market_data + heartbeat + execution_data)", market)

            async def relay_paxos_to_browser():
                # Log the first few messages to confirm which channels Paxos acks.
                msg_count = 0
                async for raw in paxos_ws:
                    text = raw if isinstance(raw, str) else raw.decode()
                    if msg_count < 5:
                        try:
                            parsed = json.loads(text)
                            ch = parsed.get("channel") or parsed.get("type", "?")
                            # Log subscribe acks so we can confirm execution_data accepted.
                            if parsed.get("type") == "subscribe":
                                for c in parsed.get("channels", []):
                                    _ws_log.info(
                                        "Paxos subscribe ack: %s success=%s",
                                        c.get("type"), c.get("success")
                                    )
                            else:
                                _ws_log.debug("early msg %d: channel=%s", msg_count + 1, ch)
                        except Exception:
                            pass
                    msg_count += 1
                    await websocket.send_text(text)

            async def relay_browser_to_paxos():
                async for msg in websocket.iter_text():
                    await paxos_ws.send(msg)

            # Use FIRST_COMPLETED so one side closing cancels the other immediately.
            t1 = asyncio.create_task(relay_paxos_to_browser())
            t2 = asyncio.create_task(relay_browser_to_paxos())
            try:
                done, pending = await asyncio.wait(
                    {t1, t2}, return_when=asyncio.FIRST_COMPLETED
                )
                # Propagate any exception from the finished task.
                for task in done:
                    task.result()
            finally:
                for task in (t1, t2):
                    task.cancel()
                    try:
                        await task
                    except (asyncio.CancelledError, Exception):
                        pass

    try:
        await _run()
    except WebSocketDisconnect:
        _ws_log.info("browser disconnected cleanly")
    except Exception as e:
        _ws_log.warning("ws error: %s", e)
        try:
            await websocket.send_text(json.dumps({"type": "error", "message": str(e)}))
        except Exception:
            pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
        _ws_log.info("ws handler done")


def main():
    import argparse
    import sys

    import uvicorn

    parser = argparse.ArgumentParser(description="Paxos Trader (binds 127.0.0.1 only)")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    print(f"Open {launch_url(args.port, AUTH_TOKEN)}", file=sys.stderr, flush=True)
    uvicorn.run(app, host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
