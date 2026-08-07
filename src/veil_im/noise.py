"""Minimal Noise XX implementation for Veil IM.

This module implements exactly one fixed Noise protocol:
Noise_XX_25519_ChaChaPoly_SHA256 (Noise revision 34 semantics).

Keeping the implementation narrow makes it possible to test against published
Noise vectors and avoids protocol negotiation or application-defined token
sequences. It is still project code and has not received an independent audit.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from enum import Enum, auto

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

PROTOCOL_NAME = b"Noise_XX_25519_ChaChaPoly_SHA256"
DHLEN = 32
HASHLEN = 32
MAX_NONCE = (1 << 64) - 1


class NoiseError(ValueError):
    """Invalid Noise state transition, key material, or ciphertext."""


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hmac_hash(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf(chaining_key: bytes, input_key_material: bytes, outputs: int = 2) -> tuple[bytes, ...]:
    """Noise HKDF using HMAC-SHA256, as specified by revision 34."""
    if outputs not in (2, 3):
        raise ValueError("Noise HKDF supports two or three outputs")
    temp_key = _hmac_hash(chaining_key, input_key_material)
    out1 = _hmac_hash(temp_key, b"\x01")
    out2 = _hmac_hash(temp_key, out1 + b"\x02")
    if outputs == 2:
        return out1, out2
    out3 = _hmac_hash(temp_key, out2 + b"\x03")
    return out1, out2, out3


def _nonce_bytes(counter: int) -> bytes:
    if not 0 <= counter <= MAX_NONCE:
        raise NoiseError("Noise nonce exhausted")
    # Noise ChaChaPoly: 32 zero bits || little-endian uint64 nonce.
    return b"\x00" * 4 + counter.to_bytes(8, "little")


def _private_from_raw(raw: bytes | None) -> x25519.X25519PrivateKey:
    if raw is None:
        return x25519.X25519PrivateKey.generate()
    if len(raw) != DHLEN:
        raise NoiseError("X25519 private key must be 32 bytes")
    return x25519.X25519PrivateKey.from_private_bytes(raw)


def public_bytes(private: x25519.X25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def private_bytes(private: x25519.X25519PrivateKey) -> bytes:
    return private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def dh(private: x25519.X25519PrivateKey, remote_public: bytes) -> bytes:
    if len(remote_public) != DHLEN:
        raise NoiseError("X25519 public key must be 32 bytes")
    try:
        return private.exchange(x25519.X25519PublicKey.from_public_bytes(remote_public))
    except (ValueError, TypeError) as exc:
        raise NoiseError("invalid X25519 public key") from exc


class CipherState:
    """Noise CipherState for ChaChaPoly."""

    __slots__ = ("_key", "nonce")

    def __init__(self, key: bytes | None = None) -> None:
        self._key: bytes | None = None
        self.nonce = 0
        if key is not None:
            self.initialize_key(key)

    @property
    def has_key(self) -> bool:
        return self._key is not None

    def initialize_key(self, key: bytes) -> None:
        if len(key) != 32:
            raise NoiseError("Noise cipher key must be 32 bytes")
        self._key = bytes(key)
        self.nonce = 0

    def encrypt_with_ad(self, ad: bytes, plaintext: bytes) -> bytes:
        if self._key is None:
            return bytes(plaintext)
        if self.nonce >= MAX_NONCE:
            raise NoiseError("Noise nonce exhausted")
        ciphertext = ChaCha20Poly1305(self._key).encrypt(
            _nonce_bytes(self.nonce), bytes(plaintext), bytes(ad)
        )
        self.nonce += 1
        return ciphertext

    def decrypt_with_ad(self, ad: bytes, ciphertext: bytes) -> bytes:
        if self._key is None:
            return bytes(ciphertext)
        if self.nonce >= MAX_NONCE:
            raise NoiseError("Noise nonce exhausted")
        try:
            plaintext = ChaCha20Poly1305(self._key).decrypt(
                _nonce_bytes(self.nonce), bytes(ciphertext), bytes(ad)
            )
        except InvalidTag as exc:
            raise NoiseError("Noise authentication failed") from exc
        self.nonce += 1
        return plaintext

    def rekey(self) -> None:
        """Apply Noise's default REKEY() without resetting the nonce."""
        if self._key is None:
            raise NoiseError("cannot rekey an unkeyed cipher")
        material = ChaCha20Poly1305(self._key).encrypt(
            _nonce_bytes(MAX_NONCE), b"\x00" * 32, b""
        )
        self._key = material[:32]

    def destroy(self) -> None:
        # Python cannot guarantee physical memory erasure; dropping the reference
        # still shortens key lifetime and prevents accidental reuse through this object.
        self._key = None
        self.nonce = 0


class SymmetricState:
    __slots__ = ("ck", "h", "cipher")

    def __init__(self, prologue: bytes = b"") -> None:
        if len(PROTOCOL_NAME) <= HASHLEN:
            self.h = PROTOCOL_NAME + b"\x00" * (HASHLEN - len(PROTOCOL_NAME))
        else:
            self.h = _sha256(PROTOCOL_NAME)
        self.ck = self.h
        self.cipher = CipherState()
        self.mix_hash(prologue)

    def mix_hash(self, data: bytes) -> None:
        self.h = _sha256(self.h + bytes(data))

    def mix_key(self, input_key_material: bytes) -> None:
        self.ck, temp_k = hkdf(self.ck, bytes(input_key_material), 2)
        self.cipher.initialize_key(temp_k)

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        ciphertext = self.cipher.encrypt_with_ad(self.h, bytes(plaintext))
        self.mix_hash(ciphertext)
        return ciphertext

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        plaintext = self.cipher.decrypt_with_ad(self.h, bytes(ciphertext))
        self.mix_hash(ciphertext)
        return plaintext

    def split(self) -> tuple[CipherState, CipherState]:
        k1, k2 = hkdf(self.ck, b"", 2)
        return CipherState(k1), CipherState(k2)


class _Stage(Enum):
    INIT = auto()
    MESSAGE1 = auto()
    MESSAGE2 = auto()
    COMPLETE = auto()


@dataclass(slots=True)
class NoiseSplit:
    send: CipherState
    receive: CipherState
    handshake_hash: bytes
    remote_static: bytes


class NoiseXX:
    """Strict state machine for Noise_XX_25519_ChaChaPoly_SHA256."""

    def __init__(
        self,
        *,
        initiator: bool,
        prologue: bytes = b"",
        static_private: bytes | None = None,
        ephemeral_private: bytes | None = None,
    ) -> None:
        self.initiator = initiator
        self.symmetric = SymmetricState(prologue)
        self.s = _private_from_raw(static_private)
        self.e: x25519.X25519PrivateKey | None = (
            _private_from_raw(ephemeral_private) if ephemeral_private is not None else None
        )
        self.rs: bytes | None = None
        self.re: bytes | None = None
        self._stage = _Stage.INIT

    @property
    def static_public(self) -> bytes:
        return public_bytes(self.s)

    @property
    def handshake_hash(self) -> bytes:
        return self.symmetric.h

    def _ensure_ephemeral(self) -> x25519.X25519PrivateKey:
        if self.e is None:
            self.e = x25519.X25519PrivateKey.generate()
        return self.e

    def write_message1(self, payload: bytes = b"") -> bytes:
        if not self.initiator or self._stage is not _Stage.INIT:
            raise NoiseError("unexpected Noise XX message 1 write")
        e_pub = public_bytes(self._ensure_ephemeral())
        self.symmetric.mix_hash(e_pub)
        out = e_pub + self.symmetric.encrypt_and_hash(payload)
        self._stage = _Stage.MESSAGE1
        return out

    def read_message1(self, message: bytes) -> bytes:
        if self.initiator or self._stage is not _Stage.INIT:
            raise NoiseError("unexpected Noise XX message 1 read")
        if len(message) < DHLEN:
            raise NoiseError("truncated Noise XX message 1")
        self.re = bytes(message[:DHLEN])
        self.symmetric.mix_hash(self.re)
        payload = self.symmetric.decrypt_and_hash(message[DHLEN:])
        self._stage = _Stage.MESSAGE1
        return payload

    def write_message2(self, payload: bytes = b"") -> bytes:
        if self.initiator or self._stage is not _Stage.MESSAGE1 or self.re is None:
            raise NoiseError("unexpected Noise XX message 2 write")
        e = self._ensure_ephemeral()
        e_pub = public_bytes(e)
        self.symmetric.mix_hash(e_pub)
        self.symmetric.mix_key(dh(e, self.re))  # ee
        encrypted_static = self.symmetric.encrypt_and_hash(self.static_public)
        self.symmetric.mix_key(dh(self.s, self.re))  # es
        encrypted_payload = self.symmetric.encrypt_and_hash(payload)
        self._stage = _Stage.MESSAGE2
        return e_pub + encrypted_static + encrypted_payload

    def read_message2(self, message: bytes) -> bytes:
        if not self.initiator or self._stage is not _Stage.MESSAGE1 or self.e is None:
            raise NoiseError("unexpected Noise XX message 2 read")
        # e (32) + encrypted s (32 + tag 16) + encrypted payload (tag >= 16)
        if len(message) < DHLEN + DHLEN + 16 + 16:
            raise NoiseError("truncated Noise XX message 2")
        self.re = bytes(message[:DHLEN])
        self.symmetric.mix_hash(self.re)
        self.symmetric.mix_key(dh(self.e, self.re))  # ee
        encrypted_static = message[DHLEN : DHLEN + DHLEN + 16]
        self.rs = self.symmetric.decrypt_and_hash(encrypted_static)
        if len(self.rs) != DHLEN:
            raise NoiseError("invalid responder Noise static key")
        self.symmetric.mix_key(dh(self.e, self.rs))  # es
        payload = self.symmetric.decrypt_and_hash(message[DHLEN + DHLEN + 16 :])
        self._stage = _Stage.MESSAGE2
        return payload

    def write_message3(self, payload: bytes = b"") -> bytes:
        if (
            not self.initiator
            or self._stage is not _Stage.MESSAGE2
            or self.re is None
        ):
            raise NoiseError("unexpected Noise XX message 3 write")
        encrypted_static = self.symmetric.encrypt_and_hash(self.static_public)
        self.symmetric.mix_key(dh(self.s, self.re))  # se
        encrypted_payload = self.symmetric.encrypt_and_hash(payload)
        self._stage = _Stage.COMPLETE
        return encrypted_static + encrypted_payload

    def read_message3(self, message: bytes) -> bytes:
        if self.initiator or self._stage is not _Stage.MESSAGE2 or self.e is None:
            raise NoiseError("unexpected Noise XX message 3 read")
        if len(message) < DHLEN + 16 + 16:
            raise NoiseError("truncated Noise XX message 3")
        encrypted_static = message[: DHLEN + 16]
        self.rs = self.symmetric.decrypt_and_hash(encrypted_static)
        if len(self.rs) != DHLEN:
            raise NoiseError("invalid initiator Noise static key")
        self.symmetric.mix_key(dh(self.e, self.rs))  # se
        payload = self.symmetric.decrypt_and_hash(message[DHLEN + 16 :])
        self._stage = _Stage.COMPLETE
        return payload

    def split(self) -> NoiseSplit:
        if self._stage is not _Stage.COMPLETE or self.rs is None:
            raise NoiseError("Noise handshake is not complete")
        first, second = self.symmetric.split()
        if self.initiator:
            send, receive = first, second
        else:
            send, receive = second, first
        result = NoiseSplit(send, receive, self.symmetric.h, self.rs)
        # The handshake CipherState is no longer needed after Split().
        self.symmetric.cipher.destroy()
        return result
