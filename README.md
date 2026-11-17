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

