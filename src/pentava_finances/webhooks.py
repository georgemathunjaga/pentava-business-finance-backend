"""Inbound webhook — receives messages posted by the MoneyChat app."""
import hashlib
import hmac
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])


@contextmanager
def _db():
    root = Path(os.getenv("DATA_DIRECTORY", str(Path(__file__).resolve().parents[2] / "data")))
    root.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(root / "identity.sqlite3", timeout=20)
    db.row_factory = sqlite3.Row
    db.execute("""
        CREATE TABLE IF NOT EXISTS webhook_messages (
            id TEXT PRIMARY KEY,
            business_id TEXT,
            device_id TEXT,
            type TEXT NOT NULL,
            payload TEXT NOT NULL,
            received_at REAL NOT NULL
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_wm_business ON webhook_messages(business_id)")
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _verify_secret(secret_header: str | None) -> None:
    webhook_secret = os.getenv("WEBHOOK_SECRET", "")
    if not webhook_secret:
        raise HTTPException(status_code=503, detail="Webhook secret is not configured.")
    if not secret_header or not hmac.compare_digest(secret_header, webhook_secret):
        raise HTTPException(status_code=401, detail="Invalid webhook secret.")


class InboundMessage(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: str = Field(default="message", min_length=1, max_length=60)
    business_id: str | None = None
    device_id: str | None = None
    payload: dict[str, Any]


@router.post("/inbound", status_code=200)
async def inbound_webhook(
    body: InboundMessage,
    x_webhook_secret: str | None = Header(default=None),
) -> dict[str, Any]:
    _verify_secret(x_webhook_secret)

    import json
    message_id = f"msg_{uuid.uuid4().hex[:16]}"
    now = time.time()

    with _db() as db:
        db.execute(
            "INSERT INTO webhook_messages VALUES (?,?,?,?,?,?)",
            (
                message_id,
                body.business_id,
                body.device_id,
                body.type,
                json.dumps(body.payload),
                now,
            ),
        )

    return {"id": message_id, "status": "received", "received_at": now}


@router.get("/inbound", status_code=200)
async def list_inbound_messages(
    business_id: str | None = None,
    limit: int = 50,
    x_webhook_secret: str | None = Header(default=None),
) -> dict[str, Any]:
    _verify_secret(x_webhook_secret)

    import json
    limit = min(limit, 200)

    with _db() as db:
        if business_id:
            rows = db.execute(
                "SELECT * FROM webhook_messages WHERE business_id=? ORDER BY received_at DESC LIMIT ?",
                (business_id, limit),
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM webhook_messages ORDER BY received_at DESC LIMIT ?",
                (limit,),
            ).fetchall()

    items = [
        {
            "id": r["id"],
            "business_id": r["business_id"],
            "device_id": r["device_id"],
            "type": r["type"],
            "payload": json.loads(r["payload"]),
            "received_at": r["received_at"],
        }
        for r in rows
    ]
    return {"items": items, "count": len(items)}
