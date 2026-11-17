"""In-memory pairing session store with TTL cleanup.
Sessions expire after PAIRING_TTL seconds; expired entries are pruned lazily.
"""
import secrets
import time
import uuid
from dataclasses import dataclass, field

PAIRING_TTL = 10 * 60  # 10 minutes


@dataclass
class PairingSession:
    id: str
    status: str           # pending | scanned | linked | rejected | expired | cancelled
    purpose: str          # link_device | website_signin
    business_id: str
    user_id: str
    device_label: str
    scan_token: str       # one-time token for the phone
    poll_token: str       # separate token for the browser
    created_at: float
    expires_at: float
    business_name: str = ""
    scanned_at: float | None = None
    device_id: str | None = None
    # Credentials are set once after approval then cleared on first read
    _credentials: dict | None = field(default=None, repr=False)

    def is_expired(self) -> bool:
        return time.time() > self.expires_at


_sessions: dict[str, PairingSession] = {}


def _cleanup() -> None:
    cutoff = time.time() - 60  # keep expired entries for 1 min for polling
    stale = [sid for sid, s in _sessions.items() if s.expires_at < cutoff]
    for sid in stale:
        del _sessions[sid]


def create_pairing_session(
    purpose: str,
    business_id: str,
    user_id: str,
    device_label: str,
    business_name: str = "",
) -> PairingSession:
    _cleanup()
    now = time.time()
    session = PairingSession(
        id=f"pair_{uuid.uuid4().hex[:12]}",
        status="pending",
        purpose=purpose,
        business_id=business_id,
        user_id=user_id,
        device_label=device_label,
        scan_token=secrets.token_urlsafe(32),
        poll_token=secrets.token_urlsafe(32),
        created_at=now,
        expires_at=now + PAIRING_TTL,
        business_name=business_name,
    )
    _sessions[session.id] = session
    return session


def get_session(session_id: str) -> PairingSession | None:
    session = _sessions.get(session_id)
    if session and session.is_expired() and session.status == "pending":
        session.status = "expired"
    return session


def pop_credentials(session_id: str) -> dict | None:
    """Return device credentials exactly once then clear them."""
    session = _sessions.get(session_id)
    if not session:
        return None
    creds = session._credentials
    session._credentials = None
    return creds
