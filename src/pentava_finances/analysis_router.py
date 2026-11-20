"""FastAPI router — exposes FinancialAgent over HTTP.

Endpoints
---------
POST /analysis          — JSON array of transaction records
POST /analysis/csv      — multipart CSV file upload
POST /analysis/sheets/{spreadsheet_id}  — analyze a linked Google Sheet
"""
from __future__ import annotations

import csv
import io
import tempfile
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from google.auth.exceptions import GoogleAuthError
from googleapiclient.errors import HttpError
from pydantic import BaseModel, Field

from .config import GoogleConfigurationError
from .financial_agent import FinancialAgent
from .google_auth import GoogleNotConnectedError
from .identity import User, require_user
from .reports import fetch_transactions

router = APIRouter(prefix="/analysis", tags=["Financial Analysis"])

_MAX_RECORDS = 50_000
_MAX_CSV_BYTES = 20 * 1024 * 1024  # 20 MB


class AnalyzeRequest(BaseModel):
    records: list[dict[str, Any]] = Field(min_length=1, max_length=_MAX_RECORDS)
    forecast_days: int = Field(default=30, ge=1, le=3650)
    anomaly_z_threshold: float = Field(default=3.5, ge=1.0, le=10.0)


def _run(records, *, forecast_days: int = 30, anomaly_z_threshold: float = 3.5) -> dict[str, Any]:
    agent = FinancialAgent(forecast_days=forecast_days, anomaly_z_threshold=anomaly_z_threshold)
    return agent.analyze(records)


@router.post("", summary="Analyze JSON transaction records")
async def analyze_json(
    body: AnalyzeRequest,
    user: User = Depends(require_user),
) -> dict[str, Any]:
    """
    Pass an array of transaction records as JSON.  Each record must have
    **Date**, **Amount**, **Currency** and **Type** (income | expense).
    Optional fields: Category, Description, Reference, Recorded_By.
    """
    result = _run(
        body.records,
        forecast_days=body.forecast_days,
        anomaly_z_threshold=body.anomaly_z_threshold,
    )
    return {"success": True, "report": result}


@router.post("/csv", summary="Analyze a CSV file upload")
async def analyze_csv(
    file: UploadFile = File(..., description="CSV with headers: Date,Amount,Currency,Type[,Category,Description,Reference,Recorded_By]"),
    forecast_days: int = Query(default=30, ge=1, le=3650),
    anomaly_z_threshold: float = Query(default=3.5, ge=1.0, le=10.0),
    user: User = Depends(require_user),
) -> dict[str, Any]:
    """Upload a CSV file and receive a full financial analysis report."""
    if file.content_type and "csv" not in file.content_type and "text" not in file.content_type:
        raise HTTPException(status_code=415, detail="Upload must be a CSV file.")

    raw = await file.read()
    if len(raw) > _MAX_CSV_BYTES:
        raise HTTPException(status_code=413, detail=f"CSV file exceeds {_MAX_CSV_BYTES // (1024*1024)} MB limit.")

    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(status_code=422, detail="CSV file must be UTF-8 encoded.")

    reader = csv.DictReader(io.StringIO(text))
    records = list(reader)
    if not records:
        raise HTTPException(status_code=422, detail="CSV file is empty or has no data rows.")

    agent = FinancialAgent(forecast_days=forecast_days, anomaly_z_threshold=anomaly_z_threshold)
    result = agent.analyze(records)
    return {"success": True, "report": result}


@router.post(
    "/sheets/{spreadsheet_id}",
    summary="Analyze a linked Google Sheet",
)
async def analyze_sheet(
    spreadsheet_id: str,
    sheet_name: str = Query(default="Transactions", min_length=1, max_length=100),
    forecast_days: int = Query(default=30, ge=1, le=3650),
    anomaly_z_threshold: float = Query(default=3.5, ge=1.0, le=10.0),
    user: User = Depends(require_user),
) -> dict[str, Any]:
    """
    Fetch rows from a Google Sheet (the user must have connected Google Sheets)
    and run the full financial analysis on them.  The sheet must have a header
    row matching the standard transaction columns.
    """
    try:
        transactions = fetch_transactions(spreadsheet_id, sheet_name, user.id)
    except GoogleConfigurationError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except GoogleNotConnectedError as error:
        raise HTTPException(status_code=401, detail=str(error)) from error
    except GoogleAuthError as error:
        raise HTTPException(status_code=401, detail="Google credentials are invalid.") from error
    except HttpError as error:
        status = error.resp.status if error.resp else 502
        if status in (401, 403, 404):
            raise HTTPException(status_code=status, detail="Google could not access the spreadsheet.") from error
        raise HTTPException(status_code=502, detail="Google Sheets request failed.") from error

    if not transactions:
        raise HTTPException(status_code=422, detail="The sheet has no data rows to analyze.")

    agent = FinancialAgent(forecast_days=forecast_days, anomaly_z_threshold=anomaly_z_threshold)
    result = agent.analyze(transactions)
    return {"success": True, "spreadsheet_id": spreadsheet_id, "sheet_name": sheet_name, "report": result}
