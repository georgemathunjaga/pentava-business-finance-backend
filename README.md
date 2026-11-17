# Pentava Business Finances API

FastAPI backend with a local-development Google Sheets integration.

## Requirements

- Python 3.11 or newer
- A Google Cloud project with the Google Sheets API and Google Drive API enabled
- A Google OAuth web application client

## Setup

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
Copy-Item .env.example .env
```

Set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in `.env`. Add this exact
redirect URI to the OAuth client in Google Cloud:
`http://localhost:8000/auth/google/callback`.

## Run

```powershell
python run.py
```

The API is available at `http://127.0.0.1:8000`. Interactive API documentation is at `http://127.0.0.1:8000/docs`.

## Google Sheets endpoints

- `GET /auth/google` starts Google authorization.
- `GET /auth/google/callback` completes authorization.
- `GET /google/sheets` lists accessible spreadsheets.
- `GET /google/sheets/{spreadsheet_id}` reads spreadsheet metadata.
- `GET /google/sheets/{spreadsheet_id}/values?range=Sheet1!A1:Z100` reads cell values.
- `POST /google/sheets/{spreadsheet_id}/values?range=Sheet1!A:Z` appends one row; send `{"values":["date","description","amount"]}`.

OAuth credentials are saved under `tokens/` for the single local development
user. They are not encrypted; do not use this storage or the development user
identity in production. Before deploying, connect OAuth state and credentials
to the website's authenticated user, store tokens in a protected database, and
encrypt them at rest. The Google Drive metadata scope is used only to list
spreadsheet files; the Sheets scope is used to read and write spreadsheet data.

## Test

```powershell
pytest
```


## Google-only identity and storage

The browser no longer needs PocketBase for sign-in. Google Identity Services returns an ID token bound to a server nonce; `/auth/google/session` verifies Google's signature, issuer, audience, expiry, verified email and nonce, then establishes a revocable HttpOnly session cookie. Browser mutation calls send `X-Pentava-CSRF` from the authenticated session response. `/auth/me` restores identity and lists owned businesses; `/auth/logout` revokes the session.

Configure server-side `GOOGLE_CLIENT_ID` (public OAuth web client ID), `GOOGLE_CLIENT_SECRET` (Sheets authorization only), `FRONTEND_URL`, `FRONTEND_ORIGINS`, `GOOGLE_REDIRECT_URI`, `DATA_DIRECTORY`, `SESSION_COOKIE_SECURE` and `SESSION_COOKIE_SAMESITE`. Never put the client secret in Vite or browser code. Add the exact frontend URL to the OAuth client's authorized JavaScript origins. Google Sheets redirect must match the registered callback exactly.

Local example: frontend `http://localhost:15684`, same-origin API proxy to port 8001, `GOOGLE_REDIRECT_URI=http://localhost:15684/api/auth/google/callback`, `SESSION_COOKIE_SECURE=false`. Production should use HTTPS, a same-origin API reverse proxy, secure cookies, and an explicit frontend-origin allowlist. A cross-site deployment additionally needs a deliberate credentialed-CORS/cookie policy; do not enable wildcard origins.

`DATA_DIRECTORY/identity.sqlite3` stores Google user metadata, hashed opaque session identifiers, login challenges, and encrypted transaction records. Keep this directory on a persistent Railway volume. No database passwords, Google identity tokens or raw browser session tokens are written into transaction records. Existing PocketBase records are left untouched; transferring historical records requires a separate owner-verified migration. The old PocketBase integration file remains for reference, but active web identity/transaction routes use the Google/SQLite adapters.

Sign-in endpoints: `GET /auth/config`, `POST /auth/google/challenge`, `POST /auth/google/session` with `{ "credential": "<Google ID token>" }`, `GET /auth/me`, `POST /auth/logout`. The login challenge is one-use and browser-bound. `GOOGLE_CLIENT_ID` is required; verification fails closed if missing/unavailable.

Google Sheets consent is separate: authenticated `GET /auth/google` begins consent for the current Google-backed user; callback returns to frontend `/setup/`. It no longer silently uses the shared development account. Existing transaction encryption format is unchanged. Paired device credentials remain separate, scoped, and checked against active device/business ownership.

Run `python -m pytest tests -q` for session, nonce, CSRF, owner-isolation and storage tests. Test credentials are synthetic and the Google verifier is mocked in tests; no real Google accounts or client spreadsheets are changed. A real browser sign-in requires deploying these changes and configuring the Google OAuth client. Business destination mapping persistence and continuous Sheets synchronization remain separate backend work.

