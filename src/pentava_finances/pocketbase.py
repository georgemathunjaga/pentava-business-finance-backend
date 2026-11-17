import json
import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx


class PocketBaseConfigurationError(Exception):
    pass


class PocketBaseUnavailableError(Exception):
    pass


class PocketBaseRequestError(Exception):
    def __init__(self, status_code: int) -> None:
        super().__init__("PocketBase rejected the request.")
        self.status_code = status_code


@dataclass(frozen=True)
class PocketBaseSettings:
    base_url: str
    users_collection: str
    transactions_collection: str


@dataclass(frozen=True)
class PocketBaseUser:
    id: str
    token: str


def get_pocketbase_settings() -> PocketBaseSettings:
    base_url = os.getenv("POCKETBASE_URL", "http://127.0.0.1:8090").rstrip("/")
    if not base_url.startswith(("http://", "https://")):
        raise PocketBaseConfigurationError(
            "POCKETBASE_URL must use an http:// or https:// URL."
        )
    return PocketBaseSettings(
        base_url=base_url,
        users_collection=os.getenv("POCKETBASE_USERS_COLLECTION", "users"),
        transactions_collection=os.getenv(
            "POCKETBASE_TRANSACTIONS_COLLECTION",
            "transactions",
        ),
    )


def _collection_path(collection_name: str, suffix: str) -> str:
    return f"/api/collections/{quote(collection_name, safe='')}/{suffix}"


async def _request_json(
    method: str,
    path: str,
    token: str,
    *,
    params: dict[str, str | int] | None = None,
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    settings = get_pocketbase_settings()
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.request(
                method,
                f"{settings.base_url}{path}",
                headers={"Authorization": token},
                params=params,
                json=body,
            )
    except httpx.RequestError as error:
        raise PocketBaseUnavailableError("PocketBase could not be reached.") from error

    if response.status_code >= 400:
        raise PocketBaseRequestError(response.status_code)
    if response.status_code == 204:
        return {}
    try:
        result = response.json()
    except (ValueError, json.JSONDecodeError) as error:
        raise PocketBaseUnavailableError(
            "PocketBase returned an invalid response."
        ) from error
    if not isinstance(result, dict):
        raise PocketBaseUnavailableError("PocketBase returned an invalid response.")
    return result


async def authenticate_user(token: str) -> PocketBaseUser:
    settings = get_pocketbase_settings()
    result = await _request_json(
        "POST",
        _collection_path(settings.users_collection, "auth-refresh"),
        token,
        body={},
    )
    record = result.get("record")
    user_id = record.get("id") if isinstance(record, dict) else None
    if not isinstance(user_id, str) or not user_id:
        raise PocketBaseUnavailableError(
            "PocketBase did not return an authenticated user record."
        )
    return PocketBaseUser(id=user_id, token=token)


async def list_transaction_records(
    user: PocketBaseUser,
    page: int,
    per_page: int,
) -> dict[str, Any]:
    settings = get_pocketbase_settings()
    return await _request_json(
        "GET",
        _collection_path(settings.transactions_collection, "records"),
        user.token,
        params={
            "page": page,
            "perPage": per_page,
            "filter": f"owner = {json.dumps(user.id)}",
            "sort": "-created",
        },
    )


async def get_transaction_record(
    user: PocketBaseUser,
    record_id: str,
) -> dict[str, Any]:
    settings = get_pocketbase_settings()
    return await _request_json(
        "GET",
        _collection_path(
            settings.transactions_collection,
            f"records/{quote(record_id, safe='')}",
        ),
        user.token,
    )


async def create_transaction_record(
    user: PocketBaseUser,
    encrypted_payload: str,
    client_event_id: str | None = None,
) -> dict[str, Any]:
    settings = get_pocketbase_settings()
    body: dict[str, Any] = {
        "owner": user.id,
        "encrypted_payload": encrypted_payload,
    }
    if client_event_id:
        body["client_event_id"] = client_event_id
    return await _request_json(
        "POST",
        _collection_path(settings.transactions_collection, "records"),
        user.token,
        body=body,
    )


async def update_transaction_record(
    user: PocketBaseUser,
    record_id: str,
    encrypted_payload: str,
) -> dict[str, Any]:
    settings = get_pocketbase_settings()
    return await _request_json(
        "PATCH",
        _collection_path(
            settings.transactions_collection,
            f"records/{quote(record_id, safe='')}",
        ),
        user.token,
        body={"encrypted_payload": encrypted_payload},
    )


async def delete_transaction_record(user: PocketBaseUser, record_id: str) -> None:
    settings = get_pocketbase_settings()
    await _request_json(
        "DELETE",
        _collection_path(
            settings.transactions_collection,
            f"records/{quote(record_id, safe='')}",
        ),
        user.token,
    )

