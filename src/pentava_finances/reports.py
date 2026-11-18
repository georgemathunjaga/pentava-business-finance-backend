"""Read a business's linked Google Sheet and compute financial reports."""
from __future__ import annotations

from collections import defaultdict
from datetime import date, timedelta, timezone, datetime
from typing import Any

from .google_sheets import get_sheet_values
from .google_auth import DEVELOPMENT_USER_ID

# Matches the column order set in create_spreadsheet()
_COLUMNS = ["date", "amount", "currency", "type", "category", "description", "reference", "recorded_by"]


# ── Period helpers ────────────────────────────────────────────────────────────

def _period_range(period: str) -> tuple[date | None, date | None]:
    today = date.today()
    if period == "today":
        return today, today
    if period == "week":
        start = today - timedelta(days=today.weekday())
        return start, today
    if period == "month":
        return today.replace(day=1), today
    if period == "year":
        return today.replace(month=1, day=1), today
    return None, None  # "all"


def _in_range(row_date: str, start: date | None, end: date | None) -> bool:
    if start is None:
        return True
    try:
        d = date.fromisoformat(row_date[:10])
        return start <= d <= end
    except (ValueError, TypeError):
        return False


# ── Sheet parsing ─────────────────────────────────────────────────────────────

def _parse_rows(raw_rows: list[list]) -> list[dict[str, Any]]:
    rows = []
    for r in raw_rows:
        padded = list(r) + [""] * (len(_COLUMNS) - len(r))
        entry = dict(zip(_COLUMNS, padded))
        try:
            entry["amount"] = float(str(entry["amount"]).replace(",", "") or 0)
        except (ValueError, TypeError):
            entry["amount"] = 0.0
        entry["type"] = str(entry.get("type", "")).strip().lower()
        entry["category"] = str(entry.get("category", "")).strip().lower() or "uncategorised"
        rows.append(entry)
    return rows


def fetch_transactions(
    spreadsheet_id: str,
    sheet_name: str = "Transactions",
    user_id: str = DEVELOPMENT_USER_ID,
) -> list[dict[str, Any]]:
    result = get_sheet_values(spreadsheet_id, f"{sheet_name}!A2:H", user_id)
    raw = result.get("values", [])
    return _parse_rows(raw)


# ── Calculations ──────────────────────────────────────────────────────────────

def _safe_div(a: float, b: float) -> float:
    return round(a / b, 2) if b else 0.0


def compute_report(
    transactions: list[dict[str, Any]],
    period: str = "month",
    currency: str = "KES",
) -> dict[str, Any]:
    start, end = _period_range(period)
    rows = [r for r in transactions if _in_range(r["date"], start, end)]

    total_income = sum(r["amount"] for r in rows if r["type"] == "income")
    total_expenses = sum(r["amount"] for r in rows if r["type"] == "expense")
    net = total_income - total_expenses

    # By category (expenses only for category breakdown)
    by_category: dict[str, float] = defaultdict(float)
    for r in rows:
        if r["type"] == "expense":
            by_category[r["category"]] += r["amount"]

    category_list = sorted(
        [{"category": k, "amount": round(v, 2), "pct": _safe_div(v * 100, total_expenses)}
         for k, v in by_category.items()],
        key=lambda x: x["amount"],
        reverse=True,
    )

    # By type summary
    income_rows = [r for r in rows if r["type"] == "income"]
    expense_rows = [r for r in rows if r["type"] == "expense"]

    # Daily trend — last 30 days or within period
    daily: dict[str, dict[str, float]] = defaultdict(lambda: {"income": 0.0, "expense": 0.0})
    for r in rows:
        d = r["date"][:10] if r["date"] else ""
        if d:
            daily[d][r["type"] if r["type"] in ("income", "expense") else "other"] += r["amount"]

    trend = [
        {"date": d, "income": round(v["income"], 2), "expense": round(v["expense"], 2)}
        for d, v in sorted(daily.items())
    ]

    # Recent transactions (last 10)
    recent = sorted(rows, key=lambda r: r["date"], reverse=True)[:10]

    return {
        "period": period,
        "currency": currency,
        "summary": {
            "total_income": round(total_income, 2),
            "total_expenses": round(total_expenses, 2),
            "net": round(net, 2),
            "transaction_count": len(rows),
            "income_count": len(income_rows),
            "expense_count": len(expense_rows),
        },
        "by_category": category_list,
        "trend": trend,
        "recent": recent,
    }
