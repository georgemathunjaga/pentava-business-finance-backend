from typing import Any

from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, JsonValue

from .pocketbase import (
    PocketBaseRequestError,
    PocketBaseUnavailableError,
    PocketBaseUser,
    authenticate_user,
)
from .transaction_crypto import (
    EncryptionConfigurationError,
    TransactionDecryptionError,
    decrypt_transaction,
    encrypt_transaction,
    load_encryption_keys,
)

router = APIRouter(prefix="/crypto", tags=["Crypto"])
bearer_scheme = HTTPBearer(auto_error=False)


class EncryptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    payload: dict[str, JsonValue] = Field(min_length=1)


class DecryptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    envelope: str = Field(min_length=1)


async def _require_user(
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
        status_code = 401 if error.status_code in (401, 403) else 502
        detail = (
            "PocketBase rejected the bearer token."
            if status_code == 401
            else "PocketBase authentication failed."
        )
        raise HTTPException(status_code=status_code, detail=detail) from error
    except PocketBaseUnavailableError as error:
        raise HTTPException(status_code=502, detail=str(error)) from error


@router.get("/public-key")
def get_public_key() -> dict[str, str]:
    """Return the PEM-encoded RSA public key so clients can encrypt locally."""
    try:
        keys = load_encryption_keys()
    except EncryptionConfigurationError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    pem = keys.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return {"key_id": keys.key_id, "public_key": pem}


@router.get("/status")
def crypto_status() -> dict[str, Any]:
    """Check that the encryption keys are loaded and valid."""
    try:
        keys = load_encryption_keys()
        key_size = keys.private_key.key_size
    except EncryptionConfigurationError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    return {
        "status": "ok",
        "key_id": keys.key_id,
        "algorithm": "RSA-OAEP-SHA256 + AES-256-GCM",
        "rsa_key_bits": key_size,
    }


@router.post("/encrypt")
async def encrypt_data(
    body: EncryptRequest,
    _user: PocketBaseUser = Depends(_require_user),
) -> dict[str, str]:
    """Encrypt a JSON payload. Returns a compact encrypted envelope."""
    try:
        envelope = encrypt_transaction(body.payload)
    except EncryptionConfigurationError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    return {"envelope": envelope}


@router.post("/decrypt")
async def decrypt_data(
    body: DecryptRequest,
    _user: PocketBaseUser = Depends(_require_user),
) -> dict[str, Any]:
    """Decrypt an envelope produced by /crypto/encrypt."""
    try:
        payload = decrypt_transaction(body.envelope)
    except EncryptionConfigurationError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except TransactionDecryptionError as error:
        raise HTTPException(
            status_code=422,
            detail="The envelope could not be decrypted.",
        ) from error
    return {"payload": payload}
