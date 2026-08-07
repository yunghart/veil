from __future__ import annotations

import asyncio

import pytest

from veil_im.transport import open_socks5_connection


@pytest.mark.asyncio
async def test_socks5_uses_domain_name_for_onion() -> None:
    onion = "a" * 56 + ".onion"
    observed: asyncio.Future[tuple[str, int]] = asyncio.get_running_loop().create_future()

    async def fake_proxy(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            assert await reader.readexactly(3) == b"\x05\x01\x00"
            writer.write(b"\x05\x00")
            await writer.drain()

            prefix = await reader.readexactly(5)
            assert prefix[:4] == b"\x05\x01\x00\x03"
            host_len = prefix[4]
            host = (await reader.readexactly(host_len)).decode("ascii")
            port = int.from_bytes(await reader.readexactly(2), "big")
            observed.set_result((host, port))

            writer.write(b"\x05\x00\x00\x01" + b"\x7f\x00\x00\x01" + b"\x00\x00")
            await writer.drain()
            await reader.read()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(fake_proxy, "127.0.0.1", 0)
    proxy_port = server.sockets[0].getsockname()[1]
    reader, writer = await open_socks5_connection(
        "127.0.0.1", proxy_port, onion, 9736, timeout=2
    )
    assert await asyncio.wait_for(observed, 1) == (onion, 9736)
    writer.close()
    await writer.wait_closed()
    server.close()
    await server.wait_closed()
