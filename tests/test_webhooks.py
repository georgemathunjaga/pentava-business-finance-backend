import pytest
from fastapi.testclient import TestClient

from pentava_finances.main import app
from pentava_finances import storage


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("DATA_DIRECTORY", str(tmp_path))
    monkeypatch.setenv("WEBHOOK_SECRET", "test-secret")
    return TestClient(app)


def _business(**overrides):
    business = {
        "id": "biz_123",
        "name": "Amani Kitchen",
        "owner_id": "google_owner123",
        "currency": "KES",
    }
    business.update(overrides)
    return business


def test_rejects_when_secret_not_configured(monkeypatch, tmp_path):
    monkeypatch.setenv("DATA_DIRECTORY", str(tmp_path))
    monkeypatch.delenv("WEBHOOK_SECRET", raising=False)
    client = TestClient(app)

    response = client.post(
        "/webhooks/inbound",
        json={"business_id": "biz_123", "payload": {"amount": 100}},
        headers={"x-webhook-secret": "anything"},
    )

    assert response.status_code == 503


def test_rejects_wrong_secret(client):
    response = client.post(
        "/webhooks/inbound",
        json={"business_id": "biz_123", "payload": {"amount": 100}},
        headers={"x-webhook-secret": "wrong"},
    )

    assert response.status_code == 401


def test_resolves_spreadsheet_and_user_from_business_record(client, monkeypatch):
    storage.create_business(_business(spreadsheet_id="sheet_abc", sheet_name="Transactions"))

    calls = []
    # _write_to_sheet imports append_sheet_row from .google_sheets at call time;
    # patch it there so the local import inside the function picks it up.
    import pentava_finances.google_sheets as google_sheets

    monkeypatch.setattr(
        google_sheets,
        "append_sheet_row",
        lambda spreadsheet_id, sheet_range, row, user_id: calls.append(
            (spreadsheet_id, sheet_range, row, user_id)
        ),
    )

    response = client.post(
        "/webhooks/inbound",
        json={
            "business_id": "biz_123",
            "payload": {
                "date": "2026-11-17",
                "amount": 245.0,
                "currency": "KES",
                "type": "income",
                "category": "mpesa",
                "description": "Amani Kitchen",
            },
        },
        headers={"x-webhook-secret": "test-secret"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert len(calls) == 1
    spreadsheet_id, sheet_range, row, user_id = calls[0]
    assert spreadsheet_id == "sheet_abc"
    assert sheet_range == "Transactions!A:H"
    assert user_id == "google_owner123"  # resolved from business.owner_id, not sent by the client
    assert row[1] == 245.0


def test_payload_can_still_override_resolved_values(client, monkeypatch):
    storage.create_business(_business(spreadsheet_id="sheet_abc"))

    calls = []
    import pentava_finances.google_sheets as google_sheets

    monkeypatch.setattr(
        google_sheets,
        "append_sheet_row",
        lambda spreadsheet_id, sheet_range, row, user_id: calls.append((spreadsheet_id, user_id)),
    )

    response = client.post(
        "/webhooks/inbound",
        json={
            "business_id": "biz_123",
            "spreadsheet_id": "sheet_override",
            "user_id": "google_other_user",
            "payload": {"amount": 100},
        },
        headers={"x-webhook-secret": "test-secret"},
    )

    assert response.status_code == 200
    assert calls == [("sheet_override", "google_other_user")]


def test_errors_clearly_when_business_has_no_spreadsheet_configured(client):
    storage.create_business(_business(spreadsheet_id=None))

    response = client.post(
        "/webhooks/inbound",
        json={"business_id": "biz_123", "payload": {"amount": 100}},
        headers={"x-webhook-secret": "test-secret"},
    )

    assert response.status_code == 422
    assert "spreadsheet_id" in response.json()["detail"]


def test_errors_clearly_when_business_is_unknown(client):
    response = client.post(
        "/webhooks/inbound",
        json={"business_id": "biz_does_not_exist", "payload": {"amount": 100}},
        headers={"x-webhook-secret": "test-secret"},
    )

    assert response.status_code == 422


def test_bulk_appends_all_rows_in_one_sheets_call(client, monkeypatch):
    storage.create_business(_business(spreadsheet_id="sheet_abc", sheet_name="Transactions"))

    calls = []
    import pentava_finances.google_sheets as google_sheets

    monkeypatch.setattr(
        google_sheets,
        "append_sheet_rows",
        lambda spreadsheet_id, sheet_range, rows, user_id: calls.append(
            (spreadsheet_id, sheet_range, rows, user_id)
        ),
    )

    response = client.post(
        "/webhooks/inbound/bulk",
        json={
            "business_id": "biz_123",
            "events": [
                {"date": "2026-11-17", "amount": 100.0, "type": "income"},
                {"date": "2026-11-18", "amount": 200.0, "type": "expense"},
                {"date": "2026-11-19", "amount": 300.0, "type": "income"},
            ],
        },
        headers={"x-webhook-secret": "test-secret"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "id": response.json()["id"],
        "appended": 3,
    }
    assert len(calls) == 1  # one Sheets API call for the whole batch
    spreadsheet_id, sheet_range, rows, user_id = calls[0]
    assert spreadsheet_id == "sheet_abc"
    assert sheet_range == "Transactions!A:H"
    assert user_id == "google_owner123"
    assert len(rows) == 3
    assert [row[1] for row in rows] == [100.0, 200.0, 300.0]


def test_bulk_errors_clearly_when_business_has_no_spreadsheet(client):
    storage.create_business(_business(spreadsheet_id=None))

    response = client.post(
        "/webhooks/inbound/bulk",
        json={"business_id": "biz_123", "events": [{"amount": 100}]},
        headers={"x-webhook-secret": "test-secret"},
    )

    assert response.status_code == 422
    assert "spreadsheet_id" in response.json()["detail"]


def test_bulk_rejects_empty_or_oversized_event_lists(client):
    storage.create_business(_business(spreadsheet_id="sheet_abc"))

    empty = client.post(
        "/webhooks/inbound/bulk",
        json={"business_id": "biz_123", "events": []},
        headers={"x-webhook-secret": "test-secret"},
    )
    assert empty.status_code == 422

    too_many = client.post(
        "/webhooks/inbound/bulk",
        json={"business_id": "biz_123", "events": [{"amount": 1}] * 2001},
        headers={"x-webhook-secret": "test-secret"},
    )
    assert too_many.status_code == 422


def test_bulk_rejects_wrong_secret(client):
    storage.create_business(_business(spreadsheet_id="sheet_abc"))

    response = client.post(
        "/webhooks/inbound/bulk",
        json={"business_id": "biz_123", "events": [{"amount": 1}]},
        headers={"x-webhook-secret": "wrong"},
    )

    assert response.status_code == 401
