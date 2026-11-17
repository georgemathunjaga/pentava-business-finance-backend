import os
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from google.auth.exceptions import GoogleAuthError
from googleapiclient.errors import HttpError
from pydantic import BaseModel, Field

from .config import GoogleConfigurationError
from .crypto import router as crypto_router
from .errors import error_response, validation_exception_handler
from .google_auth import (
    DEVELOPMENT_USER_ID,
    GoogleNotConnectedError,
    GoogleOAuthError,
    consume_oauth_state,
    exchange_code,
    get_authorization_url,
    save_credentials,
)
from .google_sheets import (
    append_sheet_row,
    create_spreadsheet,
    get_sheet_values,
    get_spreadsheet,
    list_spreadsheets,
)
from .pairing_router import businesses_router, pairing_router
from .identity import router as identity_router, require_user, set_cookie
from .transactions import router as transactions_router


app = FastAPI(
    title="Pentava Business Finances API",
    version="0.2.0",
)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.include_router(transactions_router)
app.include_router(crypto_router)
app.include_router(identity_router)
app.include_router(pairing_router)
app.include_router(businesses_router)

_bearer = HTTPBearer(auto_error=False)


# ── Shared Google user resolver ───────────────────────────────────────────────

async def _google_user_id(request: Request) -> str:
    return (await require_user(request)).id


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["health"])
def health_check() -> dict[str, str]:
    return {"status": "ok"}


# ── Google OAuth ──────────────────────────────────────────────────────────────

@app.get("/auth/google", tags=["Google"])
async def google_login(request: Request) -> RedirectResponse:
    user_id = (await require_user(request)).id
    try:
        authorization_url, state = get_authorization_url(user_id)
    except GoogleConfigurationError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error

    response = RedirectResponse(authorization_url)
    set_cookie(response, f"google_oauth_state_{state}", state, request, 600)
    return response


@app.get("/auth/google/callback", tags=["Google"])
async def google_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> RedirectResponse:
    if error:
        raise HTTPException(status_code=400, detail="Google authorization was denied.")
    if not code or not state:
        raise HTTPException(
            status_code=400,
            detail="Google authorization response is missing required parameters.",
        )

    cookie_name = f"google_oauth_state_{state}"
    if request.cookies.get(cookie_name) != state:
        raise HTTPException(status_code=400, detail="Google authorization cookie is missing. Restart Connect Google Sheets and check GOOGLE_REDIRECT_URI uses the frontend /api/auth/google/callback URL.")
    current_user = await require_user(request)
    user_id = consume_oauth_state(state)
    if user_id is None:
        raise HTTPException(
            status_code=400,
            detail="Google authorization state is invalid or expired.",
        )

    if current_user.id != user_id:
        raise HTTPException(status_code=403, detail='Google authorization belongs to another session.')

    try:
        credentials = exchange_code(code, state)
        save_credentials(user_id, credentials)
    except (GoogleConfigurationError, GoogleOAuthError) as exception:
        raise HTTPException(status_code=400, detail=str(exception)) from exception

    response = RedirectResponse(os.getenv("FRONTEND_URL", "http://localhost:15684").rstrip("/") + "/setup/", status_code=303)
    response.delete_cookie(cookie_name, path="/")
    return response


# ── Google Sheets ─────────────────────────────────────────────────────────────

class CreateSpreadsheetRequest(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    sheet_name: str = Field(default="Transactions", min_length=1, max_length=100)


class SheetRow(BaseModel):
    values: list[str | int | float | bool | None] = Field(min_length=1)


def _raise_google_api_error(error: HttpError) -> None:
    status_code = error.resp.status if error.resp else 502
    if status_code in (401, 403, 404):
        raise HTTPException(
            status_code=status_code,
            detail="Google could not access the requested resource.",
        ) from error
    raise HTTPException(status_code=502, detail="Google Sheets service request failed.") from error


@app.post("/google/sheets", status_code=201, tags=["Google Sheets"])
async def create_google_sheet(
    body: CreateSpreadsheetRequest,
    user_id: str = Depends(_google_user_id),
) -> dict[str, Any]:
    try:
        result = create_spreadsheet(body.title, body.sheet_name, user_id)
    except GoogleConfigurationError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except GoogleNotConnectedError as error:
        raise HTTPException(status_code=401, detail=str(error)) from error
    except GoogleAuthError as error:
        raise HTTPException(status_code=401, detail="Google credentials are invalid.") from error
    except HttpError as error:
        _raise_google_api_error(error)
    return {
        "success": True,
        "spreadsheet_id": result["spreadsheetId"],
        "url": result["spreadsheetUrl"],
        "title": result["properties"]["title"],
        "sheet_name": result["sheets"][0]["properties"]["title"],
        "headers": ["Date", "Amount", "Currency", "Type", "Category", "Description", "Reference", "Recorded By"],
    }


@app.get("/google/sheets", tags=["Google Sheets"])
async def google_sheets(
    page_token: str | None = Query(default=None, min_length=1),
    user_id: str = Depends(_google_user_id),
) -> dict[str, Any]:
    try:
        result = list_spreadsheets(page_token, user_id)
    except GoogleConfigurationError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except GoogleNotConnectedError as error:
        raise HTTPException(status_code=401, detail=str(error)) from error
    except GoogleAuthError as error:
        raise HTTPException(status_code=401, detail="Google credentials are invalid.") from error
    except HttpError as error:
        _raise_google_api_error(error)
    return {"success": True, **result}


@app.get("/google/sheets/{spreadsheet_id}", tags=["Google Sheets"])
async def google_spreadsheet(
    spreadsheet_id: str,
    user_id: str = Depends(_google_user_id),
) -> dict[str, Any]:
    try:
        spreadsheet = get_spreadsheet(spreadsheet_id, user_id)
    except GoogleConfigurationError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except GoogleNotConnectedError as error:
        raise HTTPException(status_code=401, detail=str(error)) from error
    except GoogleAuthError as error:
        raise HTTPException(status_code=401, detail="Google credentials are invalid.") from error
    except HttpError as error:
        _raise_google_api_error(error)
    return {
        "success": True,
        "spreadsheet": spreadsheet,
        "sheets": spreadsheet.get("sheets", []),   # top-level alias for compat
    }


@app.get("/google/sheets/{spreadsheet_id}/values", tags=["Google Sheets"])
async def google_sheet_values(
    spreadsheet_id: str,
    sheet_range: str = Query(
        default="Sheet1!A1:Z100",
        alias="range",
        min_length=1,
        max_length=1000,
    ),
    user_id: str = Depends(_google_user_id),
) -> dict[str, Any]:
    try:
        result = get_sheet_values(spreadsheet_id, sheet_range, user_id)
    except GoogleConfigurationError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except GoogleNotConnectedError as error:
        raise HTTPException(status_code=401, detail=str(error)) from error
    except GoogleAuthError as error:
        raise HTTPException(status_code=401, detail="Google credentials are invalid.") from error
    except HttpError as error:
        _raise_google_api_error(error)
    return {
        "success": True,
        "range": result.get("range"),
        "values": result.get("values", []),
    }


@app.post("/google/sheets/{spreadsheet_id}/values", tags=["Google Sheets"])
async def append_google_sheet_row(
    spreadsheet_id: str,
    row: SheetRow,
    sheet_range: str = Query(
        default="Sheet1!A:Z",
        alias="range",
        min_length=1,
        max_length=1000,
    ),
    user_id: str = Depends(_google_user_id),
) -> dict[str, Any]:
    try:
        result = append_sheet_row(spreadsheet_id, sheet_range, row.values, user_id)
    except GoogleConfigurationError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except GoogleNotConnectedError as error:
        raise HTTPException(status_code=401, detail=str(error)) from error
    except GoogleAuthError as error:
        raise HTTPException(status_code=401, detail="Google credentials are invalid.") from error
    except HttpError as error:
        _raise_google_api_error(error)
    updates_data = result.get("updates")
    return {"success": True, "updated": updates_data, "updates": updates_data}
