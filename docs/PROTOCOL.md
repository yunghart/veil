# Veil wire protocol v1

This document describes the implemented MVP protocol, not a finalized standard.

## Transport

TCP streams are carried to v3 onion services through Tor SOCKS5. The responder's onion service maps virtual port `9736` to a loopback-only TCP listener.

## Framing

Every clear or encrypted protocol record is encoded as canonical UTF-8 JSON and prefixed with a four-byte unsigned big-endian length. Frames larger than 64 KiB are rejected.

## Handshake

Each side owns a long-term Ed25519 signing key. For every connection, each side creates a fresh X25519 key pair and random 16-byte nonce.

The initiator sends a signed hello containing:

- protocol version and role
- display username
- Ed25519 public key
- ephemeral X25519 public key
- random nonce
- source onion and intended target onion
- Unix timestamp

The responder verifies the signature, target onion, syntax, and optional contact policy. Its signed reply includes the corresponding fields plus the SHA-256 hash of the initiator frame. The initiator verifies the responder public key against the invite code and checks the onion bindings.

Both sides calculate X25519 shared secret material and derive 64 bytes with HKDF-SHA256. The transcript hash is used as salt and protocol/domain strings are used as `info`. The first and second 32-byte halves are assigned by role as directional send keys.

## Message encryption

Each direction uses ChaCha20-Poly1305. Nonces are a fixed four-byte direction label followed by an unsigned 64-bit counter. Counters begin at zero and advance only after a successful operation. Associated data contains the transcript hash and direction label.

Encrypted plaintext is canonical JSON with message type, UUID, local timestamp, and UTF-8 body. TCP ordering plus strict counters causes reordered or replayed ciphertext to fail authentication.

## Authentication meaning

The protocol proves that the peer controls the private key corresponding to the public key shown in the handshake. A username is not globally unique and is not proof of a person's real-world identity. Users should compare fingerprints through a separate trusted channel.
