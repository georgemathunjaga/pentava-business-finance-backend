import time
import uuid
from datetime import datetime, timezone
from typing import Any

import jwt as pyjwt
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from .device_tokens import DEVICE_ACCESS_TTL, issue_device_tokens, verify_device_token
from .pairing import PAIRING_TTL, PairingSession, create_pairing_session, get_session
from .pocketbase import (
    PocketBaseRequestError,
    PocketBaseUnavailableError,
    PocketBaseUser,
    authenticate_user,
)
from .storage import (
    create_business,
    create_device,
    get_business,
    get_device,
    list_business_devices,
    list_user_businesses,
    revoke_device,
    update_business,
    update_device,
)

pairing_router = APIRouter(tags=["Pairing"])
businesses_router = APIRouter(prefix="/businesses", tags=["Businesses"])
bearer_scheme = HTTPBearer(auto_error=False)


# ── Auth helpers ──────────────────────────────────────────────────────────────

async def _require_web_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> PocketBaseUser:
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="A PocketBase bearer token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return await authenticate_user(credentials.credentials)
    except PocketBaseRequestError as error:
        code = 401 if error.status_code in (401, 403) else 502
        raise HTTPException(status_code=code, detail="PocketBase rejected the token.") from error
    except PocketBaseUnavailableError as error:
        raise HTTPException(status_code=502, detail=str(error)) from error


def _require_device_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict:
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="A device access token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return verify_device_token(credentials.credentials, "access")
    except pyjwt.InvalidTokenError as error:
        raise HTTPException(status_code=401, detail="Device token is invalid or expired.") from error


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Business models ───────────────────────────────────────────────────────────

class CreateBusinessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    owner_name: str | None = None
    email: str | None = None
    currency: str = "KES"
    timezone: str = "Africa/Nairobi"


class PatchBusinessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=200)
    currency: str | None = None
    week_starts_on: str | None = None


# ── Business endpoints ────────────────────────────────────────────────────────

@businesses_router.post("", status_code=201)
async def create_business_endpoint(
    body: CreateBusinessRequest,
    user: PocketBaseUser = Depends(_require_web_user),
) -> dict[str, Any]:
    business = {
        "id": f"biz_{uuid.uuid4().hex[:12]}",
        "name": body.name,
        "owner_id": user.id,
        "owner_name": body.owner_name,
        "email": body.email,
        "currency": body.currency,
        "timezone": body.timezone,
        "week_starts_on": "monday",
        "role": "owner",
        "onboarding": {"moneychat": "pending", "sheets": "pending"},
    }
    return create_business(business)


@businesses_router.get("/{business_id}")
async def get_business_endpoint(
    business_id: str,
    user: PocketBaseUser = Depends(_require_web_user),
) -> dict[str, Any]:
    biz = _assert_owned(business_id, user.id)
    return biz


@businesses_router.patch("/{business_id}")
async def patch_business_endpoint(
    business_id: str,
    body: PatchBusinessRequest,
    user: PocketBaseUser = Depends(_require_web_user),
) -> dict[str, Any]:
    biz = _assert_owned(business_id, user.id)
    biz.update(body.model_dump(exclude_none=True))
    return update_business(biz)


@businesses_router.get("/{business_id}/onboarding")
async def get_onboarding(
    business_id: str,
    user: PocketBaseUser = Depends(_require_web_user),
) -> dict[str, Any]:
    _assert_owned(business_id, user.id)
    devices = list_business_devices(business_id)
    moneychat_linked = len(devices) > 0
    next_step = "sheets_setup" if moneychat_linked else "moneychat_link"
    return {
        "account_complete": True,
        "moneychat_linked": moneychat_linked,
        "sheet_configured": False,
        "next_step": next_step,
    }


@businesses_router.get("/{business_id}/devices")
async def list_devices_endpoint(
    business_id: str,
    user: PocketBaseUser = Depends(_require_web_user),
) -> dict[str, Any]:
    _assert_owned(business_id, user.id)
    return {"items": list_business_devices(business_id)}


@businesses_router.delete("/{business_id}/devices/{device_id}", status_code=204)
async def revoke_device_endpoint(
    business_id: str,
    device_id: str,
    user: PocketBaseUser = Depends(_require_web_user),
) -> None:
    _assert_owned(business_id, user.id)
    device = get_device(device_id)
    if not device or device.get("business_id") != business_id:
        raise HTTPException(status_code=404, detail="Device not found.")
    revoke_device(device_id)


def _assert_owned(business_id: str, user_id: str) -> dict[str, Any]:
    biz = get_business(business_id)
    if not biz or biz.get("owner_id") != user_id:
        raise HTTPException(status_code=404, detail="Business not found.")
    return biz


# ── Pairing models ────────────────────────────────────────────────────────────

class CreatePairingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    purpose: str = Field(default="link_device", pattern="^(link_device|website_signin)$")
    business_id: str = Field(min_length=1)
    device_label: str = Field(default="Phone", min_length=1, max_length=100)


class ResolveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str = Field(min_length=1)
    scan_token: str = Field(min_length=1)


class ApproveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan_token: str = Field(min_length=1)
    device: dict[str, Any]


class RejectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan_token: str = Field(min_length=1)


class RefreshDeviceTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_id: str = Field(min_length=1)
    refresh_token: str = Field(min_length=1)


# ── Pairing endpoints ─────────────────────────────────────────────────────────

@pairing_router.post("/moneychat/pairing-sessions", status_code=201)
async def create_pairing_session_endpoint(
    body: CreatePairingRequest,
    user: PocketBaseUser = Depends(_require_web_user),
) -> dict[str, Any]:
    biz = _assert_owned(body.business_id, user.id)
    session = create_pairing_session(
        purpose=body.purpose,
        business_id=body.business_id,
        user_id=user.id,
        device_label=body.device_label,
        business_name=biz.get("name", ""),
    )
    path = "connect" if body.purpose == "link_device" else "signin"
    qr_payload = f"moneychat://{path}?session_id={session.id}&token={session.scan_token}"
    return {
        "id": session.id,
        "status": session.status,
        "qr_payload": qr_payload,
        "expires_at": datetime.fromtimestamp(session.expires_at, tz=timezone.utc).isoformat(),
        "poll_after_seconds": 2,
    }


@pairing_router.post("/moneychat/pairing-sessions/resolve")
async def resolve_pairing_session(body: ResolveRequest) -> dict[str, Any]:
    """Phone scans QR — sees the business details before deciding to approve."""
    session = _get_active_session(body.session_id)
    if session.status != "pending":
        raise HTTPException(status_code=409, detail="Pairing session already used.", headers={"X-Error-Code": "PAIRING_ALREADY_USED"})
    if session.scan_token != body.scan_token:
        raise HTTPException(status_code=403, detail="Invalid scan token.")

    session.status = "scanned"
    session.scanned_at = time.time()

    biz = get_business(session.business_id)
    return {
        "session_id": session.id,
        "purpose": session.purpose,
        "business": {
            "id": session.business_id,
            "name": biz.get("name", "") if biz else session.business_name,
        },
        "requested_permissions": ["transactions:ingest", "sync:status"],
        "expires_at": datetime.fromtimestamp(session.expires_at, tz=timezone.utc).isoformat(),
    }


@pairing_router.post("/moneychat/pairing-sessions/{session_id}/approve")
async def approve_pairing_session(
    session_id: str, body: ApproveRequest,
) -> dict[str, Any]:
    """Phone approves after showing the user the verified business details."""
    session = _get_active_session(session_id)
    if session.status != "scanned":
        raise HTTPException(status_code=409, detail="Session must be in scanned state to approve.", headers={"X-Error-Code": "PAIRING_ALREADY_USED"})
    if session.scan_token != body.scan_token:
        raise HTTPException(status_code=403, detail="Invalid scan token.")

    dev_info = body.device
    device = {
        "id": f"dev_{uuid.uuid4().hex[:12]}",
        "business_id": session.business_id,
        "user_id": session.user_id,
        "name": session.device_label,
        "installation_id": dev_info.get("installation_id"),
        "platform": dev_info.get("platform"),
        "app_version": dev_info.get("app_version"),
        "status": "connected",
        "linked_at": _now_iso(),
        "last_seen_at": _now_iso(),
    }
    create_device(device)

    credentials = issue_device_tokens(
        device_id=device["id"],
        business_id=session.business_id,
        user_id=session.user_id,
    )

    session.status = "linked"
    session.device_id = device["id"]
    session._credentials = credentials

    return {
        "status": "linked",
        "business_id": session.business_id,
        "device": {"id": device["id"], "name": device["name"]},
        "device_credentials": credentials,
    }


@pairing_router.get("/moneychat/pairing-sessions/{session_id}")
async def poll_pairing_session(
    session_id: str,
    user: PocketBaseUser = Depends(_require_web_user),
) -> dict[str, Any]:
    """Browser polls this until status becomes linked/rejected/expired."""
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Pairing session not found.")
    if session.user_id != user.id:
        raise HTTPException(status_code=403, detail="Not authorized to view this session.")

    result: dict[str, Any] = {"id": session.id, "status": session.status}
    if session.device_id:
        device = get_device(session.device_id)
        result["device"] = {
            "id": session.device_id,
            "name": device.get("name", "") if device else session.device_label,
        }
        result["next_step"] = "sheets_setup"
    return result


@pairing_router.post("/moneychat/pairing-sessions/{session_id}/reject")
async def reject_pairing_session(
    session_id: str, body: RejectRequest,
) -> dict[str, Any]:
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Pairing session not found.")
    if session.scan_token != body.scan_token:
        raise HTTPException(status_code=403, detail="Invalid scan token.")
    session.status = "rejected"
    return {"status": "rejected"}


@pairing_router.delete("/moneychat/pairing-sessions/{session_id}", status_code=204)
async def cancel_pairing_session(
    session_id: str,
    user: PocketBaseUser = Depends(_require_web_user),
) -> None:
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Pairing session not found.")
    if session.user_id != user.id:
        raise HTTPException(status_code=403, detail="Not authorized to cancel this session.")
    session.status = "cancelled"


# ── Device token refresh ──────────────────────────────────────────────────────

@pairing_router.post("/moneychat/device-sessions/refresh")
async def refresh_device_token(body: RefreshDeviceTokenRequest) -> dict[str, Any]:
    try:
        payload = verify_device_token(body.refresh_token, "refresh")
    except pyjwt.InvalidTokenError as error:
        raise HTTPException(status_code=401, detail="Refresh token is invalid or expired.") from error

    if payload.get("device_id") != body.device_id:
        raise HTTPException(status_code=403, detail="Device ID does not match the token.")

    device = get_device(body.device_id)
    if not device or device.get("status") == "revoked":
        raise HTTPException(status_code=401, detail="Device has been revoked.")

    update_device(body.device_id, {"last_seen_at": _now_iso()})

    return issue_device_tokens(
        device_id=payload["device_id"],
        business_id=payload["business_id"],
        user_id=payload["user_id"],
    )


# ── Website sign-in via MoneyChat QR ─────────────────────────────────────────

class CreateSignInSessionRequest(BaseModel):
    return_to: str | None = Field(default="/auth/callback")


@pairing_router.post("/auth/moneychat/sessions", status_code=201)
async def create_signin_session(body: CreateSignInSessionRequest) -> dict[str, Any]:
    """Website shows a QR code that the authenticated MoneyChat phone owner scans to sign in."""
    session = create_pairing_session(
        purpose="website_signin",
        business_id="",
        user_id="",
        device_label="browser",
    )
    qr_payload = f"moneychat://signin?session_id={session.id}&token={session.scan_token}"
    return {
        "id": session.id,
        "qr_payload": qr_payload,
        "expires_at": datetime.fromtimestamp(session.expires_at, tz=timezone.utc).isoformat(),
    }


@pairing_router.get("/auth/moneychat/sessions/{session_id}")
async def poll_signin_session(session_id: str) -> dict[str, Any]:
    """Browser polls until the phone owner has approved the sign-in."""
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Sign-in session not found.")
    result: dict[str, Any] = {"status": session.status}
    if session.status == "linked":
        result["next_step"] = "business_setup"
    return result


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_active_session(session_id: str) -> PairingSession:
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Pairing session not found.")
    if session.is_expired() or session.status == "expired":
        raise HTTPException(
            status_code=410,
            detail="Pairing session has expired.",
            headers={"X-Error-Code": "PAIRING_EXPIRED"},
        )
    if session.status in ("cancelled", "rejected"):
        raise HTTPException(
            status_code=409,
            detail="Pairing session was cancelled or rejected.",
            headers={"X-Error-Code": "PAIRING_ALREADY_USED"},
        )
    return session
