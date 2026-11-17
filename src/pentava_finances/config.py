import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

GOOGLE_SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive.file",
]


@dataclass(frozen=True)
class GoogleSettings:
    client_id: str
    client_secret: str
    redirect_uri: str
    token_directory: Path


class GoogleConfigurationError(Exception):
    pass


def get_google_settings() -> GoogleSettings:
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")

    if not client_id or not client_secret:
        raise GoogleConfigurationError(
            "Google OAuth is not configured. Set GOOGLE_CLIENT_ID and "
            "GOOGLE_CLIENT_SECRET."
        )

    token_directory = Path(
        os.getenv(
            "GOOGLE_TOKEN_DIRECTORY",
            str(Path(__file__).resolve().parents[2] / "tokens"),
        )
    )

    return GoogleSettings(
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=os.getenv(
            "GOOGLE_REDIRECT_URI",
            "http://localhost:8000/auth/google/callback",
        ),
        token_directory=token_directory,
    )
