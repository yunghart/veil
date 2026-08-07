from __future__ import annotations

import asyncio
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from cryptography.exceptions import InvalidSignature

from .crypto import (
    ed25519_public_bytes,
    fingerprint,
    sign_identity_binding,
    verify_identity_binding,
)
from .framing import FrameError, read_frame, write_frame
from .invite import Invite
from .models import Identity
from .noise import NoiseError, NoiseSplit, NoiseXX
from .util import (
    b64u_decode,
    b64u_encode,
    canonical_json,
    strict_json_loads,
    validate_onion,
    validate_username,
)

PROTOCOL_VERSION = 2
NOISE_PROLOGUE = b"veil-im/v2/noise-xx"
MAX_MESSAGE_BYTES = 8 * 1024
MAX_EVENT_BYTES = 12 * 1024
PADDING_BUCKETS = (256, 512, 1024, 2048, 4096, 8192, 16384)
REKEY_INTERVAL = 1024

IDENTITY_REQUIRED_FIELDS = {
    "type",
    "v",
    "role",
    "username",
    "identity_key",
    "noise_static_key",
    "source_onion",
    "target_onion",
    "signature",
}


class ProtocolError(Exception):
    """Malformed, unauthenticated, or unsupported peer protocol data."""


class PeerRejected(ProtocolError):
    """The remote peer explicitly rejected the connection."""


@dataclass(frozen=True, slots=True)
class PeerInfo:
    username: str
    onion: str
    identity_key: bytes

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.identity_key)


@dataclass(frozen=True, slots=True)
class ReceivedMessage:
    message_id: str
    body: str
    timestamp: int


def _encode_padded_event(event: dict[str, Any], *, random_bytes=os.urandom) -> bytes:
    raw = canonical_json(event)
    if len(raw) > MAX_EVENT_BYTES:
        raise ProtocolError("encrypted event is too large")
    needed = 2 + len(raw)
    bucket = next((size for size in PADDING_BUCKETS if size >= needed), None)
    if bucket is None:
        raise ProtocolError("encrypted event exceeds padding buckets")
    padding_len = bucket - needed
    return len(raw).to_bytes(2, "big") + raw + random_bytes(padding_len)


def _decode_padded_event(plaintext: bytes) -> dict[str, Any]:
    if len(plaintext) < 2:
        raise ProtocolError("truncated encrypted event")
    length = int.from_bytes(plaintext[:2], "big")
    if length < 2 or length > MAX_EVENT_BYTES or length > len(plaintext) - 2:
        raise ProtocolError("invalid encrypted event length")
    raw = plaintext[2 : 2 + length]
    try:
        event = strict_json_loads(raw)
    except Exception as exc:
        raise ProtocolError("invalid encrypted event") from exc
    if not isinstance(event, dict):
        raise ProtocolError("encrypted event must be an object")
    return event




def _initial_payload(local_onion: str, target_onion: str) -> bytes:
    return canonical_json(
        {
            "type": "init",
            "v": PROTOCOL_VERSION,
            "source_onion": validate_onion(local_onion),
            "target_onion": validate_onion(target_onion),
        }
    )


def _verify_initial_payload(raw: bytes, *, expected_target_onion: str) -> str:
    try:
        value = strict_json_loads(raw)
    except Exception as exc:
        raise ProtocolError("invalid Noise XX initial payload") from exc
    if not isinstance(value, dict) or set(value) != {
        "type", "v", "source_onion", "target_onion"
    }:
        raise ProtocolError("invalid Noise XX initial payload fields")
    try:
        if value["type"] != "init" or int(value["v"]) != PROTOCOL_VERSION:
            raise ValueError("wrong init version")
        source = validate_onion(str(value["source_onion"]))
        target = validate_onion(str(value["target_onion"]))
    except Exception as exc:
        raise ProtocolError("invalid Noise XX initial payload value") from exc
    if target != validate_onion(expected_target_onion):
        raise ProtocolError("connection targeted a different onion endpoint")
    return source


def _identity_binding(
    identity: Identity,
    *,
    role: str,
    local_onion: str,
    target_onion: str,
    noise_static_key: bytes,
) -> bytes:
    if role not in {"initiator", "responder"}:
        raise ValueError("invalid identity binding role")
    payload: dict[str, Any] = {
        "type": "identity",
        "v": PROTOCOL_VERSION,
        "role": role,
        "username": identity.username,
        "identity_key": b64u_encode(ed25519_public_bytes(identity.signing_private)),
        "noise_static_key": b64u_encode(noise_static_key),
        "source_onion": validate_onion(local_onion),
        "target_onion": validate_onion(target_onion),
    }
    signature = sign_identity_binding(identity.signing_private, canonical_json(payload))
    return canonical_json(payload | {"signature": b64u_encode(signature)})


def _verify_identity_binding(
    raw: bytes,
    *,
    expected_role: str,
    expected_noise_static: bytes,
    expected_source_onion: str | None = None,
    expected_target_onion: str | None = None,
    expected_identity_key: bytes | None = None,
) -> PeerInfo:
    try:
        decoded = strict_json_loads(raw)
    except Exception as exc:
        raise ProtocolError("invalid encrypted identity payload") from exc
    if not isinstance(decoded, dict) or not IDENTITY_REQUIRED_FIELDS.issubset(decoded):
        raise ProtocolError("identity payload has missing fields")

    try:
        if decoded["type"] != "identity" or int(decoded["v"]) != PROTOCOL_VERSION:
            raise ValueError("wrong identity payload version")
        if decoded["role"] != expected_role:
            raise ValueError("wrong identity role")
        username = validate_username(str(decoded["username"]))
        source_onion = validate_onion(str(decoded["source_onion"]))
        target_onion = validate_onion(str(decoded["target_onion"]))
        identity_key = b64u_decode(str(decoded["identity_key"]))
        noise_static_key = b64u_decode(str(decoded["noise_static_key"]))
        signature = b64u_decode(str(decoded["signature"]))
    except Exception as exc:
        raise ProtocolError("invalid identity payload field") from exc

    if len(identity_key) != 32 or len(noise_static_key) != 32 or len(signature) != 64:
        raise ProtocolError("invalid identity key or signature length")
    if noise_static_key != expected_noise_static:
        raise ProtocolError("identity signature is not bound to the Noise static key")
    if expected_source_onion is not None and source_onion != validate_onion(expected_source_onion):
        raise ProtocolError("peer onion does not match expected endpoint")
    if expected_target_onion is not None and target_onion != validate_onion(expected_target_onion):
        raise ProtocolError("peer targeted a different onion endpoint")
    if expected_identity_key is not None and identity_key != expected_identity_key:
        raise ProtocolError("peer identity does not match invite")

    unsigned = {key: value for key, value in decoded.items() if key != "signature"}
    try:
        verify_identity_binding(identity_key, canonical_json(unsigned), signature)
    except (InvalidSignature, ValueError) as exc:
        raise ProtocolError("invalid identity binding signature") from exc

    return PeerInfo(username=username, onion=source_onion, identity_key=identity_key)


class SecureSession:
    """Ordered Noise transport channel with padding and automatic Noise REKEY()."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        peer: PeerInfo,
        split: NoiseSplit,
        *,
        rekey_interval: int = REKEY_INTERVAL,
    ) -> None:
        if rekey_interval < 1:
            raise ValueError("rekey interval must be positive")
        self.reader = reader
        self.writer = writer
        self.peer = peer
        self._send_cipher = split.send
        self._recv_cipher = split.receive
        self._handshake_hash = split.handshake_hash
        self._send_count = 0
        self._recv_count = 0
        self._rekey_interval = rekey_interval
        self._send_lock = asyncio.Lock()
        self._recv_lock = asyncio.Lock()
        self._closed = False

    @property
    def channel_binding(self) -> str:
        return self._handshake_hash.hex()

    @property
    def send_count(self) -> int:
        return self._send_count

    @property
    def receive_count(self) -> int:
        return self._recv_count

    async def send_event(self, event: dict[str, Any]) -> None:
        plaintext = _encode_padded_event(event)
        async with self._send_lock:
            try:
                ciphertext = self._send_cipher.encrypt_with_ad(b"", plaintext)
                await write_frame(self.writer, ciphertext)
            except (NoiseError, FrameError) as exc:
                raise ProtocolError(str(exc)) from exc
            self._send_count += 1
            if self._send_count % self._rekey_interval == 0:
                self._send_cipher.rekey()

    async def receive_event(self) -> dict[str, Any]:
        async with self._recv_lock:
            try:
                ciphertext = await read_frame(self.reader)
                plaintext = self._recv_cipher.decrypt_with_ad(b"", ciphertext)
            except (NoiseError, FrameError) as exc:
                raise ProtocolError(str(exc)) from exc
            self._recv_count += 1
            if self._recv_count % self._rekey_interval == 0:
                self._recv_cipher.rekey()
        return _decode_padded_event(plaintext)

    async def send_chat(self, body: str) -> str:
        body = body.strip()
        if not body:
            raise ValueError("message may not be empty")
        if len(body.encode("utf-8")) > MAX_MESSAGE_BYTES:
            raise ValueError(f"message exceeds {MAX_MESSAGE_BYTES} UTF-8 bytes")
        message_id = str(uuid.uuid4())
        await self.send_event(
            {
                "type": "message",
                "id": message_id,
                "timestamp": int(time.time()),
                "body": body,
            }
        )
        return message_id

    async def receive_chat(self) -> ReceivedMessage:
        event = await self.receive_event()
        if set(event) != {"type", "id", "timestamp", "body"} or event.get("type") != "message":
            raise ProtocolError("unsupported encrypted event")
        try:
            message_id = str(uuid.UUID(str(event["id"])))
            timestamp = int(event["timestamp"])
            body = str(event["body"])
        except Exception as exc:
            raise ProtocolError("invalid chat message fields") from exc
        if timestamp < 0:
            raise ProtocolError("invalid chat timestamp")
        if len(body.encode("utf-8")) > MAX_MESSAGE_BYTES:
            raise ProtocolError("received message is too large")
        return ReceivedMessage(message_id, body, timestamp)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._send_cipher.destroy()
        self._recv_cipher.destroy()
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except (ConnectionError, RuntimeError):
            pass


AuthorizeCallback = Callable[[PeerInfo], Awaitable[bool]]


async def _read_noise_frame(reader: asyncio.StreamReader) -> bytes:
    try:
        return await read_frame(reader)
    except FrameError as exc:
        raise ProtocolError(str(exc)) from exc


async def _write_noise_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    try:
        await write_frame(writer, payload)
    except FrameError as exc:
        raise ProtocolError(str(exc)) from exc


async def client_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    identity: Identity,
    local_onion: str,
    expected: Invite,
) -> SecureSession:
    local_onion = validate_onion(local_onion)
    expected_onion = validate_onion(expected.onion)
    noise = NoiseXX(initiator=True, prologue=NOISE_PROLOGUE)
    try:
        await _write_noise_frame(
            writer, noise.write_message1(_initial_payload(local_onion, expected_onion))
        )
        responder_payload = noise.read_message2(await _read_noise_frame(reader))
        if noise.rs is None:
            raise ProtocolError("Noise responder static key is missing")
        peer = _verify_identity_binding(
            responder_payload,
            expected_role="responder",
            expected_noise_static=noise.rs,
            expected_source_onion=expected_onion,
            expected_target_onion=local_onion,
            expected_identity_key=expected.identity_key,
        )

        initiator_payload = _identity_binding(
            identity,
            role="initiator",
            local_onion=local_onion,
            target_onion=expected_onion,
            noise_static_key=noise.static_public,
        )
        await _write_noise_frame(writer, noise.write_message3(initiator_payload))
        session = SecureSession(reader, writer, peer, noise.split())
        auth = await session.receive_event()
        if set(auth) != {"type", "status"} or auth.get("type") != "authorization":
            await session.close()
            raise ProtocolError("invalid peer authorization response")
        if auth.get("status") != "accepted":
            await session.close()
            raise PeerRejected("peer rejected the connection")
        return session
    except (NoiseError, FrameError) as exc:
        raise ProtocolError(str(exc)) from exc


async def server_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    identity: Identity,
    local_onion: str,
    authorize: AuthorizeCallback,
) -> SecureSession:
    local_onion = validate_onion(local_onion)
    noise = NoiseXX(initiator=False, prologue=NOISE_PROLOGUE)
    try:
        first_payload = noise.read_message1(await _read_noise_frame(reader))
        initiator_onion = _verify_initial_payload(
            first_payload, expected_target_onion=local_onion
        )

        responder_payload = _identity_binding(
            identity,
            role="responder",
            local_onion=local_onion,
            target_onion=initiator_onion,
            noise_static_key=noise.static_public,
        )
        await _write_noise_frame(writer, noise.write_message2(responder_payload))

        initiator_payload = noise.read_message3(await _read_noise_frame(reader))
        split = noise.split()
        peer = _verify_identity_binding(
            initiator_payload,
            expected_role="initiator",
            expected_noise_static=split.remote_static,
            expected_source_onion=initiator_onion,
            expected_target_onion=local_onion,
        )

        session = SecureSession(reader, writer, peer, split)
        accepted = await authorize(peer)
        await session.send_event(
            {"type": "authorization", "status": "accepted" if accepted else "rejected"}
        )
        if not accepted:
            await session.close()
            raise PeerRejected("incoming peer was rejected")
        return session
    except (NoiseError, FrameError) as exc:
        raise ProtocolError(str(exc)) from exc
