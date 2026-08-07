from __future__ import annotations

import asyncio

import pytest

from veil_im.crypto import ed25519_public_bytes, generate_ed25519_private_bytes
from veil_im.invite import Invite
from veil_im.models import Identity
from veil_im.protocol import client_handshake, server_handshake


@pytest.mark.asyncio
async def test_authenticated_encrypted_chat_round_trip() -> None:
    alice = Identity("alice", generate_ed25519_private_bytes())
    bob = Identity("bob", generate_ed25519_private_bytes())
    alice_onion = "a" * 56 + ".onion"
    bob_onion = "b" * 56 + ".onion"
    bob_invite = Invite("bob", bob_onion, ed25519_public_bytes(bob.signing_private))

    server_session_future: asyncio.Future = asyncio.get_running_loop().create_future()

    async def authorize(peer) -> bool:
        return peer.identity_key == ed25519_public_bytes(alice.signing_private)

    async def handle(reader, writer) -> None:
        try:
            session = await server_handshake(reader, writer, bob, bob_onion, authorize)
            server_session_future.set_result(session)
        except Exception as exc:
            server_session_future.set_exception(exc)

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    client = await client_handshake(reader, writer, alice, alice_onion, bob_invite)
    responder = await asyncio.wait_for(server_session_future, 2)

    await client.send_chat("hello bob")
    incoming = await responder.receive_chat()
    assert incoming.body == "hello bob"

    await responder.send_chat("hello alice")
    reply = await client.receive_chat()
    assert reply.body == "hello alice"

    await client.close()
    await responder.close()
    server.close()
    await server.wait_closed()


@pytest.mark.asyncio
async def test_client_rejects_wrong_expected_identity() -> None:
    alice = Identity("alice", generate_ed25519_private_bytes())
    bob = Identity("bob", generate_ed25519_private_bytes())
    impostor_key = generate_ed25519_private_bytes()
    alice_onion = "a" * 56 + ".onion"
    bob_onion = "b" * 56 + ".onion"
    wrong_invite = Invite("bob", bob_onion, ed25519_public_bytes(impostor_key))

    async def handle(reader, writer) -> None:
        try:
            await server_handshake(reader, writer, bob, bob_onion, lambda peer: _yes())
        except Exception:
            writer.close()

    async def _yes() -> bool:
        return True

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    with pytest.raises(Exception, match="identity does not match invite"):
        await client_handshake(reader, writer, alice, alice_onion, wrong_invite)
    writer.close()
    server.close()
    await server.wait_closed()
