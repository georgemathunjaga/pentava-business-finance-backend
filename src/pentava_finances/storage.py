"""Simple JSON-file backed store for businesses and devices.
Suitable for development; migrate to PocketBase collections or a DB for production.
"""
import json
import os
from pathlib import Path
from typing import Any


def _data_dir() -> Path:
    return Path(
        os.getenv(
            "DATA_DIRECTORY",
            str(Path(__file__).resolve().parents[2] / "data"),
        )
    )


def _load(name: str) -> dict[str, Any]:
    path = _data_dir() / f"{name}.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save(name: str, data: dict[str, Any]) -> None:
    path = _data_dir() / f"{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


# ── Businesses ────────────────────────────────────────────────────────────────

def get_business(business_id: str) -> dict[str, Any] | None:
    return _load("businesses").get(business_id)


def list_user_businesses(user_id: str) -> list[dict[str, Any]]:
    return [b for b in _load("businesses").values() if b.get("owner_id") == user_id]


def create_business(data: dict[str, Any]) -> dict[str, Any]:
    businesses = _load("businesses")
    businesses[data["id"]] = data
    _save("businesses", businesses)
    return data


def update_business(data: dict[str, Any]) -> dict[str, Any]:
    businesses = _load("businesses")
    businesses[data["id"]] = data
    _save("businesses", businesses)
    return data


# ── Devices ───────────────────────────────────────────────────────────────────

def get_device(device_id: str) -> dict[str, Any] | None:
    return _load("devices").get(device_id)


def list_business_devices(business_id: str) -> list[dict[str, Any]]:
    return [
        d
        for d in _load("devices").values()
        if d.get("business_id") == business_id and d.get("status") != "revoked"
    ]


def create_device(data: dict[str, Any]) -> dict[str, Any]:
    devices = _load("devices")
    devices[data["id"]] = data
    _save("devices", devices)
    return data


def update_device(device_id: str, patch: dict[str, Any]) -> dict[str, Any] | None:
    devices = _load("devices")
    if device_id not in devices:
        return None
    devices[device_id].update(patch)
    _save("devices", devices)
    return devices[device_id]


def revoke_device(device_id: str) -> bool:
    devices = _load("devices")
    if device_id not in devices:
        return False
    devices[device_id]["status"] = "revoked"
    _save("devices", devices)
    return True
