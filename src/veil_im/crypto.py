from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .util import b64u_encode

DOMAIN_HELLO = b"veil-im/hello/v1\x00"
DOMAIN_SESSION = b"veil-im/session/v1"


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


def sign(private_raw: bytes, payload: bytes) -> bytes:
    return ed25519_private_from_bytes(private_raw).sign(DOMAIN_HELLO + payload)


def verify(public_raw: bytes, payload: bytes, signature: bytes) -> None:
    if len(public_raw) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    ed25519.Ed25519PublicKey.from_public_bytes(public_raw).verify(
        signature, DOMAIN_HELLO + payload
    )


def generate_x25519() -> tuple[x25519.X25519PrivateKey, bytes]:
    private = x25519.X25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private, public


def derive_session_keys(
    private_key: x25519.X25519PrivateKey,
    peer_public_raw: bytes,
    transcript_hash: bytes,
) -> tuple[bytes, bytes]:
    if len(peer_public_raw) != 32:
        raise ValueError("X25519 public key must be 32 bytes")
    shared = private_key.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public_raw))
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=transcript_hash,
        info=DOMAIN_SESSION,
    ).derive(shared)
    return material[:32], material[32:]


def fingerprint(public_key: bytes, groups: int = 8) -> str:
    """Return a 32-character human comparison fingerprint in eight groups."""
    digest = hashlib.sha256(b"veil-im/fingerprint/v1\x00" + public_key).digest()[:20]
    text = base64.b32encode(digest).decode("ascii").rstrip("=")
    return "-".join(text[index : index + 4] for index in range(0, groups * 4, 4))


def short_fingerprint(public_key: bytes) -> str:
    return fingerprint(public_key, groups=4)


def identity_key_text(private_raw: bytes) -> str:
    return b64u_encode(ed25519_public_bytes(private_raw))
