import re
import time
from pathlib import Path

from google.auth.exceptions import GoogleAuthError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from oauthlib.oauth2 import OAuth2Error

from .config import (
    GOOGLE_SCOPES,
    get_google_settings,
)

DEVELOPMENT_USER_ID = "local-development-user"
OAUTH_STATE_TTL_SECONDS = 600
# state → {"user_id": str, "expires_at": float}
_pending_states: dict[str, dict] = {}

_SAFE_USER_ID = re.compile(r"^[A-Za-z0-9._\-]{1,128}$")


class GoogleOAuthError(Exception):
    pass


class GoogleNotConnectedError(Exception):
    pass


def create_google_flow(state: str | None = None) -> Flow:
    settings = get_google_settings()
    client_config = {
        "web": {
            "client_id": settings.client_id,
            "client_secret": settings.client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [settings.redirect_uri],
        }
    }
    return Flow.from_client_config(
        client_config,
        scopes=GOOGLE_SCOPES,
        state=state,
        redirect_uri=settings.redirect_uri,
    )


def get_authorization_url(user_id: str = DEVELOPMENT_USER_ID) -> tuple[str, str]:
    now = time.time()
    expired = [s for s, d in list(_pending_states.items()) if d["expires_at"] <= now]
    for s in expired:
        del _pending_states[s]

    flow = create_google_flow()
    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    _pending_states[state] = {"user_id": user_id, "expires_at": now + OAUTH_STATE_TTL_SECONDS}
    return authorization_url, state


def consume_oauth_state(state: str) -> str | None:
    """Return the user_id bound to this state if valid; None otherwise."""
    data = _pending_states.pop(state, None)
    if data is None or data["expires_at"] <= time.time():
        return None
    return data["user_id"]


def _token_file(user_id: str) -> Path:
    if not _SAFE_USER_ID.match(user_id):
        raise ValueError(f"Invalid user_id: {user_id!r}")
    return get_google_settings().token_directory / f"{user_id}.json"


def exchange_code(code: str, state: str) -> Credentials:
    try:
        flow = create_google_flow(state=state)
        flow.fetch_token(code=code)
    except (GoogleAuthError, OAuth2Error) as error:
        raise GoogleOAuthError("Google authorization could not be completed.") from error
    return flow.credentials


def save_credentials(user_id: str, credentials: Credentials) -> None:
    token_file = _token_file(user_id)
    token_file.parent.mkdir(parents=True, exist_ok=True)

    if not credentials.refresh_token and token_file.exists():
        existing = Credentials.from_authorized_user_file(str(token_file), GOOGLE_SCOPES)
        credentials.refresh_token = existing.refresh_token

    token_file.write_text(credentials.to_json(), encoding="utf-8")


def load_credentials(user_id: str) -> Credentials | None:
    token_file = _token_file(user_id)
    if not token_file.exists():
        return None

    credentials = Credentials.from_authorized_user_file(str(token_file), GOOGLE_SCOPES)
    if credentials.expired and credentials.refresh_token:
        try:
            credentials.refresh(Request())
        except GoogleAuthError as error:
            raise GoogleOAuthError("Google credentials could not be refreshed.") from error
        save_credentials(user_id, credentials)

    return credentials


def require_credentials(user_id: str) -> Credentials:
    credentials = load_credentials(user_id)
    if credentials is None:
        raise GoogleNotConnectedError("Google account is not connected.")
    return credentials
