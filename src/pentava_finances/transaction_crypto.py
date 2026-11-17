import base64
import binascii
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EncryptionConfigurationError(Exception):
    pass


class TransactionDecryptionError(Exception):
    pass


@dataclass(frozen=True)
class EncryptionKeys:
    public_key: rsa.RSAPublicKey
    private_key: rsa.RSAPrivateKey
    key_id: str


def _key_paths() -> tuple[Path, Path, str]:
    project_root = Path(__file__).resolve().parents[2]
    public_path = Path(
        os.getenv("ENCRYPTION_PUBLIC_KEY_PATH", str(project_root / "keys" / "public.pem"))
    )
    private_path = Path(
        os.getenv(
            "ENCRYPTION_PRIVATE_KEY_PATH",
            str(project_root / "keys" / "private.pem"),
        )
    )
    key_id = os.getenv("ENCRYPTION_KEY_ID", "local-v1")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", key_id):
        raise EncryptionConfigurationError("ENCRYPTION_KEY_ID has an invalid format.")
    return public_path, private_path, key_id


def load_encryption_keys() -> EncryptionKeys:
    public_path, private_path, key_id = _key_paths()
    try:
        public_key = serialization.load_pem_public_key(public_path.read_bytes())
        private_key = serialization.load_pem_private_key(
            private_path.read_bytes(),
            password=None,
        )
    except (OSError, TypeError, ValueError) as error:
        raise EncryptionConfigurationError(
            "Encryption keys are unavailable or invalid. Generate the local key pair."
        ) from error

    if not isinstance(public_key, rsa.RSAPublicKey) or not isinstance(
        private_key, rsa.RSAPrivateKey
    ):
        raise EncryptionConfigurationError("Transaction encryption requires RSA keys.")
    if public_key.public_numbers() != private_key.public_key().public_numbers():
        raise EncryptionConfigurationError("The configured encryption keys do not match.")

    return EncryptionKeys(public_key, private_key, key_id)


def _associated_data(key_id: str) -> bytes:
    return f"pentava-transactions:v1:{key_id}".encode("utf-8")


def _encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def encrypt_transaction(payload: dict[str, Any]) -> str:
    keys = load_encryption_keys()
    plaintext = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    data_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    associated_data = _associated_data(keys.key_id)

    ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, associated_data)
    wrapped_key = keys.public_key.encrypt(
        data_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=associated_data,
        ),
    )

    return json.dumps(
        {
            "version": 1,
            "key_id": keys.key_id,
            "nonce": _encode(nonce),
            "encrypted_key": _encode(wrapped_key),
            "ciphertext": _encode(ciphertext),
        },
        separators=(",", ":"),
    )


def decrypt_transaction(envelope_json: str) -> dict[str, Any]:
    try:
        envelope = json.loads(envelope_json)
        if not isinstance(envelope, dict) or envelope.get("version") != 1:
            raise TransactionDecryptionError("Unsupported encrypted transaction format.")

        keys = load_encryption_keys()
        key_id = envelope.get("key_id")
        if key_id != keys.key_id:
            raise TransactionDecryptionError("No matching key is configured.")
        associated_data = _associated_data(key_id)
        nonce = base64.b64decode(envelope["nonce"], altchars=b"-_", validate=True)
        wrapped_key = base64.b64decode(
            envelope["encrypted_key"],
            altchars=b"-_",
            validate=True,
        )
        ciphertext = base64.b64decode(
            envelope["ciphertext"],
            altchars=b"-_",
            validate=True,
        )
        data_key = keys.private_key.decrypt(
            wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=associated_data,
            ),
        )
        plaintext = AESGCM(data_key).decrypt(nonce, ciphertext, associated_data)
        payload = json.loads(plaintext)
    except EncryptionConfigurationError:
        raise
    except TransactionDecryptionError:
        raise
    except (
        binascii.Error,
        InvalidTag,
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        raise TransactionDecryptionError(
            "Stored transaction data could not be decrypted."
        ) from error

    if not isinstance(payload, dict):
        raise TransactionDecryptionError("Stored transaction payload is invalid.")
    return payload

