from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .transaction_crypto import _key_paths


def generate_key_pair() -> tuple[Path, Path]:
    public_path, private_path, _ = _key_paths()
    if public_path.exists() or private_path.exists():
        raise FileExistsError(
            "An encryption key file already exists; refusing to overwrite keys."
        )

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    private_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return public_path, private_path


def main() -> None:
    public_path, private_path = generate_key_pair()
    print(f"Generated public key: {public_path}")
    print(f"Generated private key: {private_path}")
    print("Keep the private key secret and backed up; do not commit it.")


if __name__ == "__main__":
    main()

