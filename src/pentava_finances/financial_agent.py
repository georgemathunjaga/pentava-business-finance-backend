"""Pentava Business financial intelligence engine (stdlib-only).

Import FinancialAgent, then call analyze(records) or analyze_csv(path).
All money is grouped by currency; never sum unlike currencies.
Forecasts and flags are statistical heuristics, not accounting or fraud findings.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Iterable, Mapping

VERSION = "1.0.0"


def _money(value: Decimal) -> float:
    return round(float(value), 2)


def _median(values: list[float]) -> float:
    return statistics.median(values) if values else 0.0


def _parse_date(value: Any) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value).strip()[:10])


class FinancialAgent:
    """Stateless financial assessment service, suitable for FastAPI or scheduled jobs."""

    def __init__(self, *, anomaly_z_threshold: float = 3.5, forecast_days: int = 30):
        self.anomaly_z_threshold = anomaly_z_threshold
        self.forecast_days = forecast_days

    def analyze_csv(self, path: str | Path) -> dict[str, Any]:
        with open(path, encoding="utf-8-sig", newline="") as f:
            return self.analyze(csv.DictReader(f))

    def analyze(self, records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
        tx, issues = [], []
        required = ("Date", "Amount", "Currency", "Type")
        for index, raw in enumerate(records, start=1):
            row = {str(k).strip().lower().replace("_", " "): v for k, v in raw.items() if k is not None}
            try:
                missing = [k for k in required if not str(row.get(k.lower(), "")).strip()]
                if missing:
                    raise ValueError("Missing: " + ", ".join(missing))
                amount = Decimal(str(row["amount"]).strip().replace(",", ""))
                if not amount.is_finite() or amount <= 0:
                    raise ValueError("Amount must be positive and finite")
                kind = str(row["type"]).strip().lower()
                if kind not in ("income", "expense"):
                    raise ValueError("Type must be income or expense")
                currency = str(row["currency"]).strip().upper()
                if not (len(currency) == 3 and currency.isalpha()):
                    raise ValueError("Currency must be a three-letter code")
                tx.append({
                    "date": _parse_date(row["date"]), "amount": amount,
                    "currency": currency, "type": kind,
                    "category": str(row.get("category") or "uncategorized").strip(),
                    "description": str(row.get("description") or "").strip(),
                    "reference": str(row.get("reference") or "").strip(),
                    "recorded_by": str(row.get("recorded by") or "").strip(),
                    "source_row": index,
                })
            except (ValueError, TypeError, InvalidOperation, OverflowError) as exc:
                issues.append({"row": index, "issue": str(exc)})
        tx.sort(key=lambda x: x["date"])
        output = {
            "engine": "pentava-financial-agent", "version": VERSION,
            "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "data_quality": self._quality(tx, issues),
            "scope": {"valid_transactions": len(tx), "currencies": sorted({t["currency"] for t in tx}),
                      "first_date": tx[0]["date"].isoformat() if tx else None,
                      "last_date": tx[-1]["date"].isoformat() if tx else None},
            "by_currency": {},
        }
        for currency in output["scope"]["currencies"]:
            subset = [t for t in tx if t["currency"] == currency]
            output["by_currency"][currency] = self._assess(subset, currency)
        return output

    def _quality(self, tx, issues):
        references = defaultdict(list)
        for t in tx:
            if t["reference"]:
                references[(t["currency"], t["reference"].casefold())].append(t)
        duplicates = [{"currency": c, "reference": ref, "rows": [t["source_row"] for t in rows]}
                      for (c, ref), rows in references.items() if len(rows) > 1]
        missing = {field: sum(not t[field] for t in tx)
                   for field in ("category", "description", "reference", "recorded_by")}
        return {"invalid_rows": issues, "invalid_count": len(issues),
                "duplicate_reference_groups": duplicates,
                "missing_optional_fields": missing,
                "note": "Duplicate references are review candidates, not proof of duplicate payments."}

    def _assess(self, tx, currency):
        income = sum((t["amount"] for t in tx if t["type"] == "income"), Decimal(0))
        expenses = sum((t["amount"] for t in tx if t["type"] == "expense"), Decimal(0))
        net = income - expenses
        days = (tx[-1]["date"] - tx[0]["date"]).days + 1
        daily = defaultdict(lambda: {"income": Decimal(0), "expense": Decimal(0), "count": 0})
        monthly = defaultdict(lambda: {"income": Decimal(0), "expense": Decimal(0), "count": 0})
        categories = defaultdict(lambda: {"income": Decimal(0), "expense": Decimal(0), "count": 0})
        counterparties = defaultdict(lambda: {"income": Decimal(0), "expense": Decimal(0), "count": 0})
        for t in tx:
            for target, key in ((daily, t["date"].isoformat()), (monthly, t["date"].strftime("%Y-%m")),
                                (categories, t["category"]), (counterparties, t["description"] or "(unknown)")):
                target[key][t["type"]] += t["amount"]
                target[key]["count"] += 1
        def format_group(group, *, net_value=False):
            result = []
            for key, value in sorted(group.items()):
                entry = {"key": key, "income": _money(value["income"]),
                         "expense": _money(value["expense"]), "transactions": value["count"]}
                if net_value:
                    entry["net_flow"] = _money(value["income"] - value["expense"])
                result.append(entry)
            return result
        anomalies = []
        for kind in ("income", "expense"):
            group = [t for t in tx if t["type"] == kind]
            if len(group) < 8:
                continue
            logs = [math.log(float(t["amount"])) for t in group]
            center = _median(logs)
            mad = _median([abs(v - center) for v in logs])
            if mad == 0:
                continue
            for t, value in zip(group, logs):
                score = 0.6745 * (value - center) / mad
                if abs(score) >= self.anomaly_z_threshold:
                    anomalies.append({"date": t["date"].isoformat(), "row": t["source_row"],
                                      "type": kind, "amount": _money(t["amount"]),
                                      "description": t["description"], "reference": t["reference"],
                                      "robust_z_score": round(score, 2),
                                      "reason": "Amount unusual relative to same-type transactions"})
        anomalies.sort(key=lambda a: abs(a["robust_z_score"]), reverse=True)
        recurring_groups = defaultdict(set)
        for t in tx:
            if t["description"]:
                recurring_groups[(t["type"], t["description"].casefold(), t["amount"])].add(t["date"])
        recurring = []
        for (kind, name, amount), dates in recurring_groups.items():
            ordered = sorted(dates)
            if len(ordered) < 3:
                continue
            gaps = [(b-a).days for a, b in zip(ordered, ordered[1:])]
            median_gap = _median(gaps)
            if median_gap <= 0:
                continue
            regularity = sum(abs(g-median_gap) <= max(2, median_gap * .25) for g in gaps) / len(gaps)
            if regularity >= .6:
                recurring.append({"type": kind, "description": name, "amount": _money(amount),
                                  "occurrences": len(ordered), "median_gap_days": median_gap,
                                  "regularity": round(regularity, 2),
                                  "last_seen": ordered[-1].isoformat()})
        forecast = {"horizon_days": self.forecast_days, "method": "historical_daily_average",
                    "estimated_income": _money(income / days * self.forecast_days),
                    "estimated_expenses": _money(expenses / days * self.forecast_days),
                    "estimated_net_flow": _money(net / days * self.forecast_days),
                    "confidence": "insufficient_history" if days < 60 else "baseline_only",
                    "warning": "Not a bank balance or reliable forward cash position; excludes seasonality, obligations and opening balances."}
        alerts = []
        if net < 0:
            alerts.append({"code": "NEGATIVE_NET_FLOW", "severity": "warning",
                           "message": "Observed outflows exceed inflows in the covered period."})
        if len(tx) < 30 or days < 30:
            alerts.append({"code": "LIMITED_HISTORY", "severity": "info",
                           "message": "Limited transaction history; forecasts and anomaly flags may be unreliable."})
        if anomalies:
            alerts.append({"code": "AMOUNT_OUTLIERS", "severity": "review",
                           "message": f"{len(anomalies)} unusual transaction amounts flagged for review."})
        return {
            "summary": {"currency": currency, "income": _money(income), "expenses": _money(expenses),
                        "net_flow": _money(net), "transaction_count": len(tx),
                        "income_transactions": sum(t["type"] == "income" for t in tx),
                        "expense_transactions": sum(t["type"] == "expense" for t in tx),
                        "observed_calendar_days": days,
                        "expense_to_income_ratio": round(float(expenses/income), 4) if income else None,
                        "note": "Net flow is not accounting profit; transfers, liabilities, balances and taxes may be absent."},
            "daily_trends": format_group(daily, net_value=True),
            "monthly_trends": format_group(monthly, net_value=True),
            "categories": format_group(categories),
            "counterparties": format_group(counterparties),
            "anomalies": anomalies,
            "recurring_candidates": recurring,
            "forecast": forecast,
            "alerts": alerts,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Pentava financial intelligence assessments")
    parser.add_argument("csv_file", help="Path to a transactions CSV file")
    parser.add_argument("--output", "-o", help="Write JSON to this file instead of stdout")
    parser.add_argument("--forecast-days", type=int, default=30)
    args = parser.parse_args()
    if args.forecast_days < 1:
        parser.error("--forecast-days must be positive")
    report = FinancialAgent(forecast_days=args.forecast_days).analyze_csv(args.csv_file)
    result = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(result + "\n", encoding="utf-8")
        print(f"Report saved to {args.output}")
    else:
        print(result)


if __name__ == "__main__":
    main()
