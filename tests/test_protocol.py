from __future__ import annotations

import asyncio

import pytest

from veil_im.crypto import ed25519_public_bytes, generate_ed25519_private_bytes
from veil_im.invite import Invite
from veil_im.models import Identity
from veil_im.protocol import (
    PADDING_BUCKETS,
    PeerRejected,
    ProtocolError,
    _decode_padded_event,
    _encode_padded_event,
    client_handshake,
    server_handshake,
)


async def _yes(_peer=None) -> bool:
    return True


@pytest.mark.asyncio
async def test_authenticated_encrypted_chat_round_trip_and_rekey() -> None:
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

    assert client.channel_binding == responder.channel_binding
    assert client.peer.identity_key == ed25519_public_bytes(bob.signing_private)
    assert responder.peer.identity_key == ed25519_public_bytes(alice.signing_private)

    # Exercise automatic Noise REKEY() without sending a thousand messages.
    client._rekey_interval = 3
    responder._rekey_interval = 3
    for index in range(8):
        await client.send_chat(f"hello bob {index}")
        incoming = await responder.receive_chat()
        assert incoming.body == f"hello bob {index}"

        await responder.send_chat(f"hello alice {index}")
        reply = await client.receive_chat()
        assert reply.body == f"hello alice {index}"

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
            await server_handshake(reader, writer, bob, bob_onion, _yes)
        except Exception:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    with pytest.raises(ProtocolError, match="identity does not match invite"):
        await client_handshake(reader, writer, alice, alice_onion, wrong_invite)
    writer.close()
    server.close()
    await server.wait_closed()


@pytest.mark.asyncio
async def test_server_rejection_is_authenticated() -> None:
    alice = Identity("alice", generate_ed25519_private_bytes())
    bob = Identity("bob", generate_ed25519_private_bytes())
    alice_onion = "a" * 56 + ".onion"
    bob_onion = "b" * 56 + ".onion"
    bob_invite = Invite("bob", bob_onion, ed25519_public_bytes(bob.signing_private))

    server_done: asyncio.Future = asyncio.get_running_loop().create_future()

    async def no(_peer) -> bool:
        return False

    async def handle(reader, writer) -> None:
        try:
            await server_handshake(reader, writer, bob, bob_onion, no)
        except PeerRejected:
            server_done.set_result(True)
        except Exception as exc:
            server_done.set_exception(exc)

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    with pytest.raises(PeerRejected):
        await client_handshake(reader, writer, alice, alice_onion, bob_invite)
    assert await asyncio.wait_for(server_done, 2)
    server.close()
    await server.wait_closed()


def test_padded_events_hide_exact_message_length_within_bucket() -> None:
    short = _encode_padded_event({"type": "x", "body": "a"}, random_bytes=lambda n: b"p" * n)
    longer = _encode_padded_event({"type": "x", "body": "a" * 100}, random_bytes=lambda n: b"q" * n)
    assert len(short) == len(longer) == PADDING_BUCKETS[0]
    assert _decode_padded_event(short)["body"] == "a"
    assert _decode_padded_event(longer)["body"] == "a" * 100


def test_padded_event_rejects_bad_inner_length() -> None:
    with pytest.raises(ProtocolError):
        _decode_padded_event(b"\xff\xff{}")
