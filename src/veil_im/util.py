from __future__ import annotations

import base64
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
ONION_RE = re.compile(r"^[a-z2-7]{56}\.onion$")


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(value: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError("base64 value must be text")
    if "=" in value or not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        raise ValueError("invalid unpadded base64url value")
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.b64decode(
            (value + padding).encode("ascii"), altchars=b"-_", validate=True
        )
    except Exception as exc:  # binascii.Error differs across Python versions
        raise ValueError("invalid base64url value") from exc


def strict_json_loads(value: str | bytes) -> Any:
    """Decode JSON while rejecting duplicate object keys and NaN/Infinity."""
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if not isinstance(value, str):
        raise TypeError("JSON input must be text or UTF-8 bytes")

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON object key: {key}")
            result[key] = item
        return result

    def reject_constant(constant: str) -> None:
        raise ValueError(f"non-finite JSON number is not allowed: {constant}")

    return json.loads(
        value, object_pairs_hook=object_pairs, parse_constant=reject_constant
    )


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def validate_username(username: str) -> str:
    username = username.strip()
    if not USERNAME_RE.fullmatch(username):
        raise ValueError(
            "username must be 1-32 characters: letters, digits, dot, underscore, or hyphen"
        )
    return username


def validate_onion(onion: str) -> str:
    onion = onion.strip().lower()
    if not ONION_RE.fullmatch(onion):
        raise ValueError("expected a Tor v3 .onion address")
    return onion


def atomic_write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except PermissionError:
        pass

    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        try:
            os.chmod(path, 0o600)
        except PermissionError:
            pass
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise
