from __future__ import annotations

import asyncio

from .util import validate_onion


class SocksError(ConnectionError):
    """SOCKS5 negotiation failed."""


SOCKS_REPLIES = {
    1: "general SOCKS failure",
    2: "connection not allowed",
    3: "network unreachable",
    4: "host unreachable",
    5: "connection refused",
    6: "TTL expired",
    7: "command not supported",
    8: "address type not supported",
}


async def open_socks5_connection(
    proxy_host: str,
    proxy_port: int,
    onion: str,
    destination_port: int,
    *,
    timeout: float = 45.0,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a TCP stream through SOCKS5 without resolving the onion locally."""
    onion = validate_onion(onion)
    if not (1 <= destination_port <= 65535):
        raise ValueError("invalid destination port")
    if not (1 <= proxy_port <= 65535):
        raise ValueError("invalid SOCKS port")

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(proxy_host, proxy_port), timeout=timeout
    )
    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        greeting = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if greeting != b"\x05\x00":
            raise SocksError("SOCKS proxy does not permit no-auth connections")

        host_bytes = onion.encode("ascii")
        if len(host_bytes) > 255:
            raise ValueError("destination hostname is too long")
        request = (
            b"\x05\x01\x00\x03"
            + bytes([len(host_bytes)])
            + host_bytes
            + destination_port.to_bytes(2, "big")
        )
        writer.write(request)
        await writer.drain()

        prefix = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        version, reply, reserved, address_type = prefix
        if version != 5 or reserved != 0:
            raise SocksError("invalid SOCKS response")
        if reply != 0:
            raise SocksError(SOCKS_REPLIES.get(reply, f"SOCKS error {reply}"))

        if address_type == 1:
            await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        elif address_type == 3:
            length = (await asyncio.wait_for(reader.readexactly(1), timeout=timeout))[0]
            await asyncio.wait_for(reader.readexactly(length), timeout=timeout)
        elif address_type == 4:
            await asyncio.wait_for(reader.readexactly(16), timeout=timeout)
        else:
            raise SocksError("SOCKS proxy returned an unknown address type")
        await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        return reader, writer
    except Exception:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        raise
