"""Inbound webhook — receives messages from MoneyChat and writes straight to Google Sheets."""
import hashlib
import hmac
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .transaction_events import notify_transaction_received

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])

MAX_BULK_EVENTS = 2000


def _verify_secret(secret_header: str | None) -> None:
    webhook_secret = os.getenv("WEBHOOK_SECRET", "")
    if not webhook_secret:
        raise HTTPException(status_code=503, detail="Webhook secret is not configured.")
    if not secret_header or not hmac.compare_digest(secret_header, webhook_secret):
        raise HTTPException(status_code=401, detail="Invalid webhook secret.")


def _resolve_destination(
    business_id: str | None,
    spreadsheet_id: str | None,
    sheet_name: str | None,
    user_id: str | None,
) -> tuple[str, str, str, str] | str:
    """Resolves (spreadsheet_id, sheet_name, user_id, currency). Payload values
    win; the business record is the fallback. Returns an error string instead
    of a tuple when the destination can't be resolved."""
    from .storage import get_business

    currency = "KES"
    sheet_name = sheet_name or "Transactions"

    if not spreadsheet_id and business_id:
        biz = get_business(business_id)
        if not biz:
            return "business not found"
        spreadsheet_id = spreadsheet_id or biz.get("spreadsheet_id")
        sheet_name = sheet_name if sheet_name != "Transactions" else biz.get("sheet_name", "Transactions")
        user_id = user_id or biz.get("owner_id")
        currency = biz.get("currency", "KES")

    if not spreadsheet_id:
        return "no spreadsheet_id — send it in the payload or link one to the business"

    if not user_id:
        return "no user_id — send it in the payload or link the business"

    return spreadsheet_id, sheet_name, user_id, currency


def _row_from_payload(payload: dict[str, Any], currency: str, device_id: str | None) -> list[Any]:
    return [
        payload.get("date") or datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        payload.get("amount", ""),
        payload.get("currency") or currency,
        payload.get("type", "expense"),
        payload.get("category", ""),
        payload.get("description") or payload.get("note", ""),
        payload.get("reference", ""),
        payload.get("recorded_by") or device_id or "",
    ]


class InboundMessage(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: str = Field(default="transaction", min_length=1, max_length=60)
    business_id: str | None = None
    device_id: str | None = None
    # App can send these directly — no pre-configuration needed
    spreadsheet_id: str | None = None
    sheet_name: str | None = None
    user_id: str | None = None
    payload: dict[str, Any]


def _write_to_sheet(body: InboundMessage) -> str | None:
    """Append one row. Resolves spreadsheet_id from payload first, then business record."""
    try:
        from .google_sheets import append_sheet_row
        from .google_auth import GoogleNotConnectedError

        destination = _resolve_destination(
            body.business_id, body.spreadsheet_id, body.sheet_name, body.user_id
        )
        if isinstance(destination, str):
            return destination
        spreadsheet_id, sheet_name, user_id, currency = destination

        row = _row_from_payload(body.payload, currency, body.device_id)
        append_sheet_row(spreadsheet_id, f"{sheet_name}!A:H", row, user_id)
        return None
    except GoogleNotConnectedError:
        return "google not connected"
    except Exception as e:
        return str(e)


@router.post("/inbound", status_code=200)
async def inbound_webhook(
    body: InboundMessage,
    x_webhook_secret: str | None = Header(default=None),
) -> dict[str, Any]:
    _verify_secret(x_webhook_secret)

    sheet_error = _write_to_sheet(body)
    if sheet_error:
        raise HTTPException(status_code=422, detail=f"Could not write to sheet: {sheet_error}")

    if body.type == "transaction" and body.business_id:
        notify_transaction_received(body.business_id)

    return {"status": "ok", "id": f"msg_{uuid.uuid4().hex[:16]}"}


class BulkInboundMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    business_id: str | None = None
    device_id: str | None = None
    spreadsheet_id: str | None = None
    sheet_name: str | None = None
    user_id: str | None = None
    events: list[dict[str, Any]] = Field(min_length=1, max_length=MAX_BULK_EVENTS)


@router.post("/inbound/bulk", status_code=200)
async def inbound_webhook_bulk(
    body: BulkInboundMessage,
    x_webhook_secret: str | None = Header(default=None),
) -> dict[str, Any]:
    """Appends many transactions in a single Sheets API call. Resolves the
    destination once for the whole batch — same rules as /inbound."""
    _verify_secret(x_webhook_secret)

    try:
        from .google_sheets import append_sheet_rows
        from .google_auth import GoogleNotConnectedError

        destination = _resolve_destination(
            body.business_id, body.spreadsheet_id, body.sheet_name, body.user_id
        )
        if isinstance(destination, str):
            raise HTTPException(status_code=422, detail=f"Could not write to sheet: {destination}")
        spreadsheet_id, sheet_name, user_id, currency = destination

        rows = [_row_from_payload(event, currency, body.device_id) for event in body.events]
        append_sheet_rows(spreadsheet_id, f"{sheet_name}!A:H", rows, user_id)
    except HTTPException:
        raise
    except GoogleNotConnectedError:
        raise HTTPException(status_code=422, detail="Could not write to sheet: google not connected")
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Could not write to sheet: {e}")

    if body.business_id:
        notify_transaction_received(body.business_id)

    return {
        "status": "ok",
        "id": f"msg_{uuid.uuid4().hex[:16]}",
        "appended": len(body.events),
    }
