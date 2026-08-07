from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .crypto import (
    derive_session_keys,
    ed25519_public_bytes,
    fingerprint,
    generate_x25519,
    sign,
    verify,
)
from .invite import Invite
from .models import Identity
from .util import b64u_decode, b64u_encode, canonical_json, validate_onion, validate_username

PROTOCOL_VERSION = 1
MAX_FRAME = 64 * 1024
MAX_MESSAGE_BYTES = 8 * 1024
HELLO_FIELDS = {
    "type",
    "v",
    "role",
    "username",
    "identity_key",
    "ephemeral_key",
    "nonce",
    "source_onion",
    "target_onion",
    "timestamp",
}
RESPONDER_EXTRA_FIELDS = {"peer_hello_hash"}


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


async def _read_frame(reader: asyncio.StreamReader) -> bytes:
    try:
        header = await reader.readexactly(4)
    except asyncio.IncompleteReadError as exc:
        raise ProtocolError("peer closed the connection") from exc
    length = int.from_bytes(header, "big")
    if length < 1 or length > MAX_FRAME:
        raise ProtocolError("invalid frame length")
    try:
        return await reader.readexactly(length)
    except asyncio.IncompleteReadError as exc:
        raise ProtocolError("truncated frame") from exc


async def _write_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    if not payload or len(payload) > MAX_FRAME:
        raise ProtocolError("invalid outgoing frame length")
    writer.write(len(payload).to_bytes(4, "big") + payload)
    await writer.drain()


async def _read_json_frame(reader: asyncio.StreamReader) -> dict[str, Any]:
    raw = await _read_frame(reader)
    try:
        value = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ProtocolError("invalid JSON frame") from exc
    if not isinstance(value, dict):
        raise ProtocolError("protocol frame must be an object")
    return value


async def _write_json_frame(writer: asyncio.StreamWriter, value: dict[str, Any]) -> None:
    await _write_frame(writer, canonical_json(value))


def _hash_transcript(first: dict[str, Any], second: dict[str, Any]) -> bytes:
    first_raw = canonical_json(first)
    second_raw = canonical_json(second)
    encoded = (
        len(first_raw).to_bytes(4, "big")
        + first_raw
        + len(second_raw).to_bytes(4, "big")
        + second_raw
    )
    return hashlib.sha256(encoded).digest()


def _signed_hello(identity: Identity, payload: dict[str, Any]) -> dict[str, Any]:
    return payload | {"signature": b64u_encode(sign(identity.signing_private, canonical_json(payload)))}


def _verify_hello(frame: dict[str, Any], expected_role: str) -> tuple[dict[str, Any], PeerInfo, bytes]:
    if "signature" not in frame:
        raise ProtocolError("unsigned hello")
    payload = {key: value for key, value in frame.items() if key != "signature"}
    expected_fields = HELLO_FIELDS | (RESPONDER_EXTRA_FIELDS if expected_role == "responder" else set())
    if set(payload) != expected_fields:
        raise ProtocolError("hello has missing or unexpected fields")
    if payload.get("type") != "hello" or int(payload.get("v", -1)) != PROTOCOL_VERSION:
        raise ProtocolError("unsupported protocol version")
    if payload.get("role") != expected_role:
        raise ProtocolError("unexpected handshake role")

    try:
        username = validate_username(str(payload["username"]))
        source_onion = validate_onion(str(payload["source_onion"]))
        validate_onion(str(payload["target_onion"]))
        identity_key = b64u_decode(str(payload["identity_key"]))
        ephemeral_key = b64u_decode(str(payload["ephemeral_key"]))
        nonce = b64u_decode(str(payload["nonce"]))
        signature = b64u_decode(str(frame["signature"]))
        timestamp = int(payload["timestamp"])
    except Exception as exc:
        raise ProtocolError("invalid hello field") from exc

    if len(identity_key) != 32 or len(ephemeral_key) != 32 or len(nonce) != 16:
        raise ProtocolError("invalid handshake key or nonce length")
    if timestamp < 0:
        raise ProtocolError("invalid handshake timestamp")
    try:
        verify(identity_key, canonical_json(payload), signature)
    except (InvalidSignature, ValueError) as exc:
        raise ProtocolError("invalid handshake signature") from exc

    return payload, PeerInfo(username, source_onion, identity_key), ephemeral_key


class SecureSession:
    """An ordered, transcript-bound AEAD channel over one TCP stream."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        peer: PeerInfo,
        send_key: bytes,
        recv_key: bytes,
        transcript_hash: bytes,
        send_label: bytes,
        recv_label: bytes,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.peer = peer
        self._send_cipher = ChaCha20Poly1305(send_key)
        self._recv_cipher = ChaCha20Poly1305(recv_key)
        self._transcript_hash = transcript_hash
        self._send_label = send_label
        self._recv_label = recv_label
        self._send_counter = 0
        self._recv_counter = 0
        self._send_lock = asyncio.Lock()
        self._closed = False

    @staticmethod
    def _nonce(label: bytes, counter: int) -> bytes:
        if len(label) != 4:
            raise ValueError("direction label must be four bytes")
        if counter < 0 or counter >= 2**64:
            raise ProtocolError("session nonce space exhausted")
        return label + counter.to_bytes(8, "big")

    def _aad(self, label: bytes) -> bytes:
        return b"veil-im/frame/v1\x00" + self._transcript_hash + label

    async def send_event(self, event: dict[str, Any]) -> None:
        plaintext = canonical_json(event)
        if len(plaintext) > MAX_MESSAGE_BYTES + 1024:
            raise ProtocolError("message event is too large")
        async with self._send_lock:
            nonce = self._nonce(self._send_label, self._send_counter)
            ciphertext = self._send_cipher.encrypt(nonce, plaintext, self._aad(self._send_label))
            await _write_frame(self.writer, ciphertext)
            self._send_counter += 1

    async def receive_event(self) -> dict[str, Any]:
        ciphertext = await _read_frame(self.reader)
        nonce = self._nonce(self._recv_label, self._recv_counter)
        try:
            plaintext = self._recv_cipher.decrypt(
                nonce, ciphertext, self._aad(self._recv_label)
            )
        except InvalidTag as exc:
            raise ProtocolError("message authentication failed") from exc
        self._recv_counter += 1
        try:
            event = json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise ProtocolError("invalid encrypted message") from exc
        if not isinstance(event, dict):
            raise ProtocolError("encrypted event must be an object")
        return event

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
        if len(body.encode("utf-8")) > MAX_MESSAGE_BYTES:
            raise ProtocolError("received message is too large")
        return ReceivedMessage(message_id, body, timestamp)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except (ConnectionError, RuntimeError):
            pass


AuthorizeCallback = Callable[[PeerInfo], Awaitable[bool]]


async def client_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    identity: Identity,
    local_onion: str,
    expected: Invite,
) -> SecureSession:
    local_onion = validate_onion(local_onion)
    ephemeral_private, ephemeral_public = generate_x25519()
    payload = {
        "type": "hello",
        "v": PROTOCOL_VERSION,
        "role": "initiator",
        "username": identity.username,
        "identity_key": b64u_encode(ed25519_public_bytes(identity.signing_private)),
        "ephemeral_key": b64u_encode(ephemeral_public),
        "nonce": b64u_encode(os.urandom(16)),
        "source_onion": local_onion,
        "target_onion": expected.onion,
        "timestamp": int(time.time()),
    }
    client_frame = _signed_hello(identity, payload)
    await _write_json_frame(writer, client_frame)

    response = await _read_json_frame(reader)
    if response.get("type") == "error":
        message = str(response.get("message", "connection rejected"))
        if response.get("code") == "rejected":
            raise PeerRejected(message)
        raise ProtocolError(message)

    server_payload, peer, server_ephemeral = _verify_hello(response, "responder")
    if peer.identity_key != expected.identity_key:
        raise ProtocolError("responder identity does not match invite")
    if peer.onion != expected.onion:
        raise ProtocolError("responder onion does not match invite")
    if server_payload["target_onion"] != local_onion:
        raise ProtocolError("responder did not bind the reply to our onion")
    client_hash = hashlib.sha256(canonical_json(client_frame)).hexdigest()
    if server_payload["peer_hello_hash"] != client_hash:
        raise ProtocolError("responder transcript binding is invalid")

    transcript_hash = _hash_transcript(client_frame, response)
    first, second = derive_session_keys(ephemeral_private, server_ephemeral, transcript_hash)
    return SecureSession(
        reader,
        writer,
        peer,
        send_key=first,
        recv_key=second,
        transcript_hash=transcript_hash,
        send_label=b"CLNT",
        recv_label=b"SRVR",
    )


async def server_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    identity: Identity,
    local_onion: str,
    authorize: AuthorizeCallback,
) -> SecureSession:
    local_onion = validate_onion(local_onion)
    client_frame = await _read_json_frame(reader)
    client_payload, peer, client_ephemeral = _verify_hello(client_frame, "initiator")
    if client_payload["target_onion"] != local_onion:
        raise ProtocolError("initiator targeted a different onion service")

    if not await authorize(peer):
        await _write_json_frame(
            writer,
            {"type": "error", "code": "rejected", "message": "peer rejected the request"},
        )
        raise PeerRejected("incoming peer rejected")

    ephemeral_private, ephemeral_public = generate_x25519()
    payload = {
        "type": "hello",
        "v": PROTOCOL_VERSION,
        "role": "responder",
        "username": identity.username,
        "identity_key": b64u_encode(ed25519_public_bytes(identity.signing_private)),
        "ephemeral_key": b64u_encode(ephemeral_public),
        "nonce": b64u_encode(os.urandom(16)),
        "source_onion": local_onion,
        "target_onion": peer.onion,
        "timestamp": int(time.time()),
        "peer_hello_hash": hashlib.sha256(canonical_json(client_frame)).hexdigest(),
    }
    server_frame = _signed_hello(identity, payload)
    await _write_json_frame(writer, server_frame)

    transcript_hash = _hash_transcript(client_frame, server_frame)
    first, second = derive_session_keys(ephemeral_private, client_ephemeral, transcript_hash)
    return SecureSession(
        reader,
        writer,
        peer,
        send_key=second,
        recv_key=first,
        transcript_hash=transcript_hash,
        send_label=b"SRVR",
        recv_label=b"CLNT",
    )
