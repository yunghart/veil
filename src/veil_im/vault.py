from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .crypto import KDFParams, derive_passphrase_key
from .models import VaultData
from .util import atomic_write_private, b64u_decode, b64u_encode, canonical_json

VAULT_FORMAT = "veil-vault-v1"
VAULT_AAD = b"veil-im/vault/v1"


class VaultError(Exception):
    """Base vault error."""


class VaultUnlockError(VaultError):
    """Wrong passphrase or damaged vault."""


def encrypt_vault(
    data: VaultData,
    passphrase: str,
    *,
    params: KDFParams | None = None,
    salt: bytes | None = None,
    nonce: bytes | None = None,
) -> bytes:
    params = params or KDFParams()
    salt = salt or os.urandom(16)
    nonce = nonce or os.urandom(12)
    if len(nonce) != 12:
        raise ValueError("ChaCha20-Poly1305 nonce must be 12 bytes")

    key = derive_passphrase_key(passphrase, salt, params)
    plaintext = canonical_json(data.to_dict())
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, VAULT_AAD)
    envelope = {
        "format": VAULT_FORMAT,
        "kdf": "argon2id",
        "kdf_params": params.to_dict(),
        "salt": b64u_encode(salt),
        "cipher": "chacha20-poly1305",
        "nonce": b64u_encode(nonce),
        "ciphertext": b64u_encode(ciphertext),
    }
    return canonical_json(envelope) + b"\n"


def decrypt_vault(blob: bytes, passphrase: str) -> VaultData:
    try:
        envelope: dict[str, Any] = json.loads(blob.decode("utf-8"))
        if envelope.get("format") != VAULT_FORMAT:
            raise VaultError("unsupported vault format")
        if envelope.get("kdf") != "argon2id":
            raise VaultError("unsupported vault KDF")
        if envelope.get("cipher") != "chacha20-poly1305":
            raise VaultError("unsupported vault cipher")
        params = KDFParams.from_dict(envelope["kdf_params"])
        salt = b64u_decode(envelope["salt"])
        nonce = b64u_decode(envelope["nonce"])
        ciphertext = b64u_decode(envelope["ciphertext"])
        if len(nonce) != 12:
            raise VaultError("invalid vault nonce")
        key = derive_passphrase_key(passphrase, salt, params)
        plaintext = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, VAULT_AAD)
        decoded = json.loads(plaintext.decode("utf-8"))
        return VaultData.from_dict(decoded)
    except InvalidTag as exc:
        raise VaultUnlockError("wrong passphrase or damaged vault") from exc
    except VaultError:
        raise
    except Exception as exc:
        raise VaultError("invalid or damaged vault") from exc


def save_vault(path: Path, data: VaultData, passphrase: str) -> None:
    atomic_write_private(path, encrypt_vault(data, passphrase))


def load_vault(path: Path, passphrase: str) -> VaultData:
    try:
        blob = path.read_bytes()
    except FileNotFoundError as exc:
        raise VaultError(f"vault does not exist: {path}") from exc
    return decrypt_vault(blob, passphrase)
