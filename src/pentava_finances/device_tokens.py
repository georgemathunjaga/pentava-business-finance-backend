import os
import secrets
import time
import uuid

import jwt

_secret: str = os.getenv("DEVICE_JWT_SECRET") or secrets.token_hex(32)
_ALGORITHM = "HS256"

DEVICE_ACCESS_TTL = 900          # 15 minutes
DEVICE_REFRESH_TTL = 7 * 24 * 3600  # 7 days


def issue_device_tokens(device_id: str, business_id: str, user_id: str) -> dict:
    now = int(time.time())
    access = jwt.encode(
        {
            "sub": device_id,
            "device_id": device_id,
            "business_id": business_id,
            "user_id": user_id,
            "scope": "transactions:ingest sync:status",
            "type": "access",
            "iat": now,
            "exp": now + DEVICE_ACCESS_TTL,
        },
        _secret,
        algorithm=_ALGORITHM,
    )
    refresh = jwt.encode(
        {
            "sub": device_id,
            "device_id": device_id,
            "business_id": business_id,
            "user_id": user_id,
            "type": "refresh",
            "jti": uuid.uuid4().hex,
            "iat": now,
            "exp": now + DEVICE_REFRESH_TTL,
        },
        _secret,
        algorithm=_ALGORITHM,
    )
    return {
        "access_token": access,
        "refresh_token": refresh,
        "expires_in": DEVICE_ACCESS_TTL,
    }


def verify_device_token(token: str, token_type: str = "access") -> dict:
    """Decode and verify a device token. Raises jwt.InvalidTokenError on failure."""
    payload = jwt.decode(token, _secret, algorithms=[_ALGORITHM])
    if payload.get("type") != token_type:
        raise jwt.InvalidTokenError(f"Expected {token_type!r} token, got {payload.get('type')!r}")
    return payload
