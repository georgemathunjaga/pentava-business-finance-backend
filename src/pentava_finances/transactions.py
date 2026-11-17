from typing import Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, JsonValue

from .identity import User, require_user
from .repository import (
    RecordRequestError,
    RecordUnavailableError,
    create_transaction_record, delete_transaction_record, get_transaction_record,
    list_transaction_records, update_transaction_record,
)

from .transaction_crypto import (
    EncryptionConfigurationError,
    TransactionDecryptionError,
    decrypt_transaction,
    encrypt_transaction,
)

router = APIRouter(prefix="/transactions", tags=["Transactions"])
bearer_scheme = HTTPBearer(auto_error=False)


class TransactionPayload(BaseModel):
    """Typed transaction payload. Extra fields are allowed for forward compat."""
    model_config = ConfigDict(extra="allow")

    # identity — set by the backend or validated on ingest
    business_id: str | None = None
    client_event_id: str | None = None
    device_id: str | None = None

    # core finance fields
    reference: str | None = None
    occurred_at: str | None = None          # ISO 8601 with offset
    counterparty_name: str | None = None
    source: str | None = None               # mpesa | bank | cash | card | …
    direction: Literal["income", "expense"] | None = None
    amount_minor: int | None = None         # e.g. 2450000 → KES 24,500.00
    currency: str | None = None             # ISO 4217
    review_status: Literal["unmatched", "matched", "pending"] | None = None
    invoice_id: str | None = None


class TransactionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    payload: dict[str, JsonValue] = Field(min_length=1)


class ClientEncryptedRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    envelope: str = Field(min_length=1)


get_current_user = require_user


def _raise_record_error(error: RecordRequestError) -> None:
    if error.status_code in (401, 403):
        raise HTTPException(
            status_code=403,
            detail="Storage denied access to this transaction.",
        ) from error
    if error.status_code == 404:
        raise HTTPException(status_code=404, detail="Transaction not found.") from error
    raise HTTPException(
        status_code=502,
        detail="Transaction storage rejected the request.",
    ) from error


def _decrypt_record(record: dict[str, Any], user: User) -> dict[str, Any]:
    if record.get("owner") != user.id:
        raise HTTPException(status_code=404, detail="Transaction not found.")
    encrypted_payload = record.get("encrypted_payload")
    if not isinstance(encrypted_payload, str):
        raise HTTPException(
            status_code=500,
            detail="Stored transaction data is invalid.",
        )
    try:
        payload = decrypt_transaction(encrypted_payload)
    except EncryptionConfigurationError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except TransactionDecryptionError as error:
        raise HTTPException(
            status_code=500,
            detail="Stored transaction data could not be decrypted.",
        ) from error
    if user.device_id and (payload.get('device_id') != user.device_id or payload.get('business_id') != user.business_id):
        raise HTTPException(status_code=403, detail='Transaction does not belong to this device connection.')
    return {"id": record.get("id"), "payload": payload}


@router.post("", status_code=201)
async def create_transaction(
    transaction: TransactionRequest,
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    try:
        encrypted_payload = encrypt_transaction(transaction.payload)
        record = await create_transaction_record(user, encrypted_payload)
    except EncryptionConfigurationError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except RecordRequestError as error:
        _raise_record_error(error)
    except RecordUnavailableError as error:
        raise HTTPException(status_code=502, detail=str(error)) from error
    return _decrypt_record(record, user)


@router.get("")
async def read_transactions(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=30, ge=1, le=100),
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    try:
        result = await list_transaction_records(user, page, per_page)
    except RecordRequestError as error:
        _raise_record_error(error)
    except RecordUnavailableError as error:
        raise HTTPException(status_code=502, detail=str(error)) from error

    items = result.get("items")
    if not isinstance(items, list):
        raise HTTPException(
            status_code=502,
            detail="Transaction storage returned an invalid list.",
        )
    return {
        "page": result.get("page"),
        "per_page": result.get("perPage"),
        "total_items": result.get("totalItems"),
        "total_pages": result.get("totalPages"),
        "items": [_decrypt_record(item, user) for item in items],
    }


@router.post("/from-client", status_code=201)
async def create_transaction_from_client(
    transaction: ClientEncryptedRequest,
    user: User = Depends(get_current_user),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> dict[str, Any]:
    """
    Accept a pre-encrypted envelope from the mobile app.
    The app must encrypt using RSA-OAEP-SHA256 + AES-256-GCM with the public
    key from GET /crypto/public-key. The backend decrypts to validate, then
    stores the envelope as-is.

    Pass Idempotency-Key: <client_event_id> to safely retry without duplicates.
    """
    try:
        payload = decrypt_transaction(transaction.envelope)
    except EncryptionConfigurationError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except TransactionDecryptionError as error:
        raise HTTPException(
            status_code=422,
            detail="The envelope could not be decrypted — verify the encryption scheme and key_id.",
        ) from error

    if user.device_id and (payload.get('device_id') != user.device_id or payload.get('business_id') != user.business_id):
        raise HTTPException(status_code=403, detail='Transaction does not belong to this device connection.')

    client_event_id = idempotency_key or (
        payload.get("client_event_id") if isinstance(payload.get("client_event_id"), str) else None
    )

    try:
        record = await create_transaction_record(user, transaction.envelope, client_event_id)
    except RecordRequestError as error:
        _raise_record_error(error)
    except RecordUnavailableError as error:
        raise HTTPException(status_code=502, detail=str(error)) from error

    return {
        "id": record.get("id"),
        "client_event_id": client_event_id,
        "ingestion_status": "accepted",
        "payload": payload,
    }


@router.put("/{record_id}/from-client")
async def replace_transaction_from_client(
    record_id: str,
    transaction: ClientEncryptedRequest,
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """
    Replace a transaction's data using a pre-encrypted envelope from the mobile app.
    """
    try:
        payload = decrypt_transaction(transaction.envelope)
    except EncryptionConfigurationError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except TransactionDecryptionError as error:
        raise HTTPException(
            status_code=422,
            detail="The envelope could not be decrypted — verify the encryption scheme and key_id.",
        ) from error
    if user.device_id and (payload.get('device_id') != user.device_id or payload.get('business_id') != user.business_id):
        raise HTTPException(status_code=403, detail='Transaction does not belong to this device connection.')
    try:
        existing = await get_transaction_record(user, record_id)
        if existing.get("owner") != user.id:
            raise HTTPException(status_code=404, detail="Transaction not found.")
        _decrypt_record(existing, user)
        record = await update_transaction_record(user, record_id, transaction.envelope)
    except EncryptionConfigurationError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except RecordRequestError as error:
        _raise_record_error(error)
    except RecordUnavailableError as error:
        raise HTTPException(status_code=502, detail=str(error)) from error
    return {"id": record.get("id"), "payload": payload}


@router.get("/{record_id}")
async def read_transaction(
    record_id: str,
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    try:
        record = await get_transaction_record(user, record_id)
    except RecordRequestError as error:
        _raise_record_error(error)
    except RecordUnavailableError as error:
        raise HTTPException(status_code=502, detail=str(error)) from error
    return _decrypt_record(record, user)


@router.put("/{record_id}")
async def replace_transaction(
    record_id: str,
    transaction: TransactionRequest,
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    try:
        existing = await get_transaction_record(user, record_id)
        if existing.get("owner") != user.id:
            raise HTTPException(status_code=404, detail="Transaction not found.")
        encrypted_payload = encrypt_transaction(transaction.payload)
        record = await update_transaction_record(user, record_id, encrypted_payload)
    except EncryptionConfigurationError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except RecordRequestError as error:
        _raise_record_error(error)
    except RecordUnavailableError as error:
        raise HTTPException(status_code=502, detail=str(error)) from error
    return _decrypt_record(record, user)


@router.delete("/{record_id}", status_code=204)
async def remove_transaction(
    record_id: str,
    user: User = Depends(get_current_user),
) -> None:
    try:
        record = await get_transaction_record(user, record_id)
        if record.get("owner") != user.id:
            raise HTTPException(status_code=404, detail="Transaction not found.")
        await delete_transaction_record(user, record_id)
    except RecordRequestError as error:
        _raise_record_error(error)
    except RecordUnavailableError as error:
        raise HTTPException(status_code=502, detail=str(error)) from error

