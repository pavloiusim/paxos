# Paxos Trader

A FastAPI backend + single-file vanilla-JS frontend that lets an operator drive the Paxos partner REST/WebSocket API from a browser, against sandbox or prod, for any configured OAuth2 client-credentials account.

## Features

Four top-level tabs in the UI. Rewards and Identities appear only for accounts enabled for them.

- **Trading**: place and cancel orders (market, limit, post-only, quote), view open orders, executions and trade details, balances, and aggregated market data over WebSocket. PAXG accounts enabled for Issuer Quotes can also request and execute issuer quotes (mint or redeem PAXG directly with Paxos) and see those executions in the orders table.
- **Transfers**: recent transfers, deposit addresses, crypto withdrawals, and profile-to-profile transfers within an account. Transaction hashes link to the matching block explorer, using testnets in sandbox.
- **Rewards**: Rewards Engine operations (Payout Groups, Reward Addresses, Claims, Reward Details, Statements), with read-only vs full-CRUD gating based on which OAuth scopes the account actually has.
- **Identities**: browse and manage identities and identity accounts (details below).

An account switcher lets you flip between environments and any number of configured accounts without restarting the server.

## Identities tab

The tab is hidden unless the selected account's client has the `identity:read_identity` scope and a probe call to List Identities succeeds. Scopes are checked one at a time, and create, edit, delete and upload controls are hidden for any scope the account lacks, so a read-only client gets a read-only view.

- **Identities list**: filter by summary status (Pending, Approved, Denied, Error, Disabled) and type (Person, Institution), search by identity ID, and page through results.
- **Identity detail**: create or edit an identity's core fields (person or institution), manage institution members, view and upload documents, and add or remove identity controls.
- **Accounts**: list identity accounts, filter by identity ID, open an account to edit it, and manage its account members.
- **Sandbox only**:
  - **Generate Test Identity** creates a random Individual, Corporation, LLC, Trust, Partnership or Sole Proprietorship identity (with a member person for institutions).
  - **Sandbox Status** buttons set ID verification, sanctions, document and screening statuses to Approved or Denied so a test identity can be moved through onboarding.

Both sandbox actions are hidden in prod, and the backend rejects the sandbox-status call for non-sandbox accounts.

## Requirements

- Python 3.10+
- An OAuth2 client-credentials pair (client ID + secret) for each Paxos account you want to drive, per environment

## Installation

From this directory (`tools/trader`):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuring accounts

Accounts can come from either source, and both work at the same time:

**Environment variables** (set before starting the server):

```bash
export PAXOS_CLIENT_ID_SANDBOX_MYACCOUNT=<client_id>
export PAXOS_CLIENT_SECRET_SANDBOX_MYACCOUNT=<client_secret>
```

The suffix after `PAXOS_CLIENT_ID_` becomes the account label; the prefix up to the first `_` (`SANDBOX` or `PROD`) selects the environment. Both the ID and matching SECRET var must be set for the account to appear.

**Added from the UI** — accounts added through the app itself are stored in `custom_accounts.json` (gitignored, created on first use). Client secrets in that file are encrypted at rest with a Fernet key derived from `~/.ssh/id_rsa` (or `~/.ssh/id_ed25519` / `~/.ssh/id_ecdsa` if that doesn't exist). If none of those keys are present, set `PAXOS_TRADER_SECRET` to any passphrase before starting the server, otherwise secrets are stored in plain text and the server logs a warning on startup.

## Running

```bash
cd tools/trader
source .venv/bin/activate
python main.py --port 8000
```

The server prints a one-time URL like `http://127.0.0.1:8000/?t=<token>`. Open that URL: it sets a session cookie and redirects to the app. Requests without the cookie get 401, and a new token is generated on every start. The server binds `127.0.0.1` only and rejects other `Host` headers and cross-origin POSTs, so do not put it behind a proxy or pass `--host` to uvicorn. Pick a different `--port` if 8000 is taken.

The server must be started with this directory (`tools/trader`) as the working directory — the frontend is served from the relative path `frontend/index.html`.

## Tests

```bash
pip install pytest
pytest test_auth.py
```

## Notes

- Environment endpoints (API/OAuth/WebSocket base URLs for sandbox and prod) are hardcoded in `main.py`'s `ENV_CONFIG` — there's nothing to configure there.
- `custom_accounts.json` never gets committed (see `.gitignore`); treat it like any other credentials file.
