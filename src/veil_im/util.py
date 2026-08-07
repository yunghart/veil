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
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except Exception as exc:  # binascii.Error differs across Python versions
        raise ValueError("invalid base64url value") from exc


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
