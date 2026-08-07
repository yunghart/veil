from __future__ import annotations

import json
from dataclasses import dataclass

from .crypto import fingerprint
from .util import b64u_decode, b64u_encode, canonical_json, validate_onion, validate_username

PREFIX = "veil1:"


@dataclass(frozen=True, slots=True)
class Invite:
    username: str
    onion: str
    identity_key: bytes
    version: int = 1

    def __post_init__(self) -> None:
        validate_username(self.username)
        validate_onion(self.onion)
        if len(self.identity_key) != 32:
            raise ValueError("invite identity key must be 32 bytes")
        if self.version != 1:
            raise ValueError("unsupported invite version")

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.identity_key)

    def encode(self) -> str:
        payload = {
            "v": self.version,
            "u": self.username,
            "o": self.onion,
            "k": b64u_encode(self.identity_key),
        }
        return PREFIX + b64u_encode(canonical_json(payload))

    @classmethod
    def decode(cls, code: str) -> "Invite":
        code = code.strip()
        if not code.startswith(PREFIX):
            raise ValueError("invite must start with veil1:")
        raw = b64u_decode(code[len(PREFIX) :])
        if len(raw) > 2048:
            raise ValueError("invite is too large")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ValueError("invalid invite payload") from exc
        if not isinstance(payload, dict):
            raise ValueError("invite payload must be an object")
        expected = {"v", "u", "o", "k"}
        if set(payload) != expected:
            raise ValueError("invite contains missing or unexpected fields")
        return cls(
            version=int(payload["v"]),
            username=str(payload["u"]),
            onion=str(payload["o"]),
            identity_key=b64u_decode(str(payload["k"])),
        )
