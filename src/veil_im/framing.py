from __future__ import annotations

import asyncio

MAX_WIRE_FRAME = 65535


class FrameError(ValueError):
    """Invalid length-prefixed Noise frame."""


def parse_frame_header(header: bytes) -> int:
    """Parse a Noise-style two-byte big-endian frame length."""
    if len(header) != 2:
        raise FrameError("frame header must be exactly two bytes")
    length = int.from_bytes(header, "big")
    if length < 1 or length > MAX_WIRE_FRAME:
        raise FrameError("invalid frame length")
    return length


def encode_frame(payload: bytes) -> bytes:
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise TypeError("frame payload must be bytes-like")
    raw = bytes(payload)
    if not raw or len(raw) > MAX_WIRE_FRAME:
        raise FrameError("invalid outgoing frame length")
    return len(raw).to_bytes(2, "big") + raw


async def read_frame(reader: asyncio.StreamReader) -> bytes:
    try:
        header = await reader.readexactly(2)
    except asyncio.IncompleteReadError as exc:
        raise FrameError("peer closed the connection") from exc
    length = parse_frame_header(header)
    try:
        return await reader.readexactly(length)
    except asyncio.IncompleteReadError as exc:
        raise FrameError("truncated frame") from exc


async def write_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    writer.write(encode_frame(payload))
    await writer.drain()
