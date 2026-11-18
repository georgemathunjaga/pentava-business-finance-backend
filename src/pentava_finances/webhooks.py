"""Inbound webhook — receives messages from MoneyChat and writes straight to Google Sheets."""
import hashlib
import hmac
import os
import time
import uuid
from typing import Any

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])


def _verify_secret(secret_header: str | None) -> None:
    webhook_secret = os.getenv("WEBHOOK_SECRET", "")
    if not webhook_secret:
        raise HTTPException(status_code=503, detail="Webhook secret is not configured.")
    if not secret_header or not hmac.compare_digest(secret_header, webhook_secret):
        raise HTTPException(status_code=401, detail="Invalid webhook secret.")


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
    """Append to the sheet. Resolves spreadsheet_id from payload first, then business record."""
    try:
        from .storage import get_business
        from .google_sheets import append_sheet_row
        from .google_auth import GoogleNotConnectedError
        from datetime import datetime, timezone

        # Resolve spreadsheet_id: payload wins, fall back to business record
        spreadsheet_id = body.spreadsheet_id
        sheet_name = body.sheet_name or "Transactions"
        user_id = body.user_id
        currency = "KES"

        if not spreadsheet_id and body.business_id:
            biz = get_business(body.business_id)
            if not biz:
                return "business not found"
            spreadsheet_id = biz.get("spreadsheet_id")
            sheet_name = body.sheet_name or biz.get("sheet_name", "Transactions")
            user_id = user_id or biz.get("owner_id")
            currency = biz.get("currency", "KES")

        if not spreadsheet_id:
            return "no spreadsheet_id — send it in the payload or link one to the business"

        if not user_id:
            return "no user_id — send it in the payload or link the business"

        p = body.payload
        row = [
            p.get("date") or datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            p.get("amount", ""),
            p.get("currency") or currency,
            p.get("type", "expense"),
            p.get("category", ""),
            p.get("description") or p.get("note", ""),
            p.get("reference", ""),
            p.get("recorded_by") or body.device_id or "",
        ]

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

    return {"status": "ok", "id": f"msg_{uuid.uuid4().hex[:16]}"}


