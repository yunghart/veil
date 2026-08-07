from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .util import b64u_encode

DOMAIN_IDENTITY_BINDING = b"veil-im/noise-identity-binding/v2\x00"


@dataclass(frozen=True, slots=True)
class KDFParams:
    time_cost: int = 3
    memory_cost_kib: int = 65536
    parallelism: int = 2
    length: int = 32

    def to_dict(self) -> dict[str, int]:
        return {
            "time_cost": self.time_cost,
            "memory_cost_kib": self.memory_cost_kib,
            "parallelism": self.parallelism,
            "length": self.length,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "KDFParams":
        params = cls(
            time_cost=int(data["time_cost"]),
            memory_cost_kib=int(data["memory_cost_kib"]),
            parallelism=int(data["parallelism"]),
            length=int(data.get("length", 32)),
        )
        if not (1 <= params.time_cost <= 20):
            raise ValueError("invalid Argon2 time cost")
        if not (8192 <= params.memory_cost_kib <= 1024 * 1024):
            raise ValueError("invalid Argon2 memory cost")
        if not (1 <= params.parallelism <= 16):
            raise ValueError("invalid Argon2 parallelism")
        if params.length != 32:
            raise ValueError("vault KDF output must be 32 bytes")
        return params


def derive_passphrase_key(passphrase: str, salt: bytes, params: KDFParams) -> bytes:
    if len(salt) < 16:
        raise ValueError("salt must be at least 16 bytes")
    if not passphrase:
        raise ValueError("passphrase may not be empty")
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost_kib,
        parallelism=params.parallelism,
        hash_len=params.length,
        type=Type.ID,
    )


def generate_ed25519_private_bytes() -> bytes:
    key = ed25519.Ed25519PrivateKey.generate()
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def ed25519_private_from_bytes(raw: bytes) -> ed25519.Ed25519PrivateKey:
    if len(raw) != 32:
        raise ValueError("Ed25519 private key seed must be 32 bytes")
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw)


def ed25519_public_bytes(private_raw: bytes) -> bytes:
    return ed25519_private_from_bytes(private_raw).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def sign_identity_binding(private_raw: bytes, payload: bytes) -> bytes:
    """Sign a Noise static-key/application-identity binding for protocol v2."""
    return ed25519_private_from_bytes(private_raw).sign(DOMAIN_IDENTITY_BINDING + payload)


def verify_identity_binding(public_raw: bytes, payload: bytes, signature: bytes) -> None:
    if len(public_raw) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    ed25519.Ed25519PublicKey.from_public_bytes(public_raw).verify(
        signature, DOMAIN_IDENTITY_BINDING + payload
    )


def fingerprint(public_key: bytes, groups: int = 8) -> str:
    """Return a 32-character human comparison fingerprint in eight groups."""
    digest = hashlib.sha256(b"veil-im/fingerprint/v1\x00" + public_key).digest()[:20]
    text = base64.b32encode(digest).decode("ascii").rstrip("=")
    return "-".join(text[index : index + 4] for index in range(0, groups * 4, 4))


def short_fingerprint(public_key: bytes) -> str:
    return fingerprint(public_key, groups=4)


def identity_key_text(private_raw: bytes) -> str:
    return b64u_encode(ed25519_public_bytes(private_raw))
