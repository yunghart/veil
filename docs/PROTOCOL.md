# Veil wire protocol v2

This document describes the implemented Veil 0.2 protocol. It is a development protocol, not a frozen standard.

## Goals and non-goals

The wire protocol aims to authenticate a Veil application identity, bind that identity to the contacted onion endpoint, establish fresh transport secrets, reject malformed state transitions, and encrypt one-to-one chat events. It does not provide offline delivery, group messaging, a Double Ratchet, post-compromise recovery, or complete traffic-analysis resistance.

## Outer transport

TCP streams travel to Tor v3 onion services through a SOCKS5 proxy. The responder creates an ephemeral onion service whose virtual port (default `9736`) maps to a loopback-only local TCP listener.

The `.onion` hostname is passed to Tor's SOCKS interface; Veil does not perform local DNS resolution for onion destinations.

## Record framing

Every Noise handshake message and Noise transport ciphertext is framed as:

```text
+----------------------+-------------------------+
| uint16_be length (2) | payload (1..65535 bytes)|
+----------------------+-------------------------+
```

Zero-length, oversized, and truncated frames are rejected. This bound is also exercised by mutation/fuzz tests.

## Noise suite

Veil uses exactly:

```text
Noise_XX_25519_ChaChaPoly_SHA256
```

with prologue:

```text
veil-im/v2/noise-xx
```

The XX pattern is:

```text
-> e
<- e, ee, s, es
-> s, se
```

Veil's Noise implementation follows Noise revision 34 semantics and is tested against a published Cacophony vector committed under `tests/vectors/`. It remains unaudited application code.

## Why two identity layers exist

Noise XX authenticates Noise static X25519 keys. Veil's durable contact identity is instead an Ed25519 key stored in the encrypted vault and invite code.

For every connection, Veil generates a fresh Noise static X25519 key. During the encrypted portions of XX, each peer sends an application identity object containing:

- protocol version
- role (`initiator` or `responder`)
- display username
- long-term Ed25519 public key
- current Noise static X25519 public key
- source onion
- target onion
- Ed25519 signature over the canonical unsigned object with a Veil v2 domain separator

The signature therefore binds the durable application identity to the Noise key and onion endpoints used for that session.

## Handshake flow

### Message 1: initiator -> responder

Noise token: `e`.

The Noise payload contains a strict canonical JSON `init` object with protocol version, source onion, and intended target onion. XX message 1 does not yet provide payload confidentiality; this data is already carried inside the Tor onion-service connection and becomes part of the Noise transcript.

The responder rejects a target onion that does not match the onion service receiving the connection.

### Message 2: responder -> initiator

Noise tokens: `e, ee, s, es`.

The encrypted payload contains the responder's signed Veil identity binding. The initiator verifies:

- Noise state and ciphertext authentication
- signed Ed25519 identity binding
- binding to the responder's actual Noise static public key
- source/target onion values
- exact Ed25519 public key from the invite code

A username is not used as an authentication credential.

### Message 3: initiator -> responder

Noise tokens: `s, se`.

The encrypted payload contains the initiator's signed Veil identity binding. The responder performs equivalent syntax, signature, Noise-key, and onion checks.

After the handshake, the responder applies the contact/approval policy. Unknown identities require explicit local user approval. Accepted/rejected authorization is itself sent through the encrypted Noise transport.

## Transport cipher states

Noise `Split()` produces independent sending and receiving ChaChaPoly cipher states. Nonces are the monotonically increasing Noise `uint64` nonce values. TCP ordering plus the Noise nonce state means replayed, omitted, corrupted, or reordered transport ciphertext does not silently become a valid later event.

Veil calls Noise `REKEY()` independently on each direction every **1,024 successfully processed transport messages**.

Important: Noise `REKEY()` updates the current symmetric key. It is **not** a Diffie-Hellman ratchet, does not continuously delete all recoverable message keys in Signal's sense, and does not provide post-compromise recovery.

## Application event encoding and padding

An encrypted application event is canonical UTF-8 JSON. Before Noise encryption it is wrapped as:

```text
uint16_be json_length || json || random_padding
```

The plaintext is padded to the smallest configured bucket that fits:

```text
256, 512, 1024, 2048, 4096, 8192, 16384 bytes
```

This prevents an observer at an endpoint from learning the exact application JSON length from every transport frame. It does not hide timing, message count, the selected bucket, or broader traffic patterns.

Chat bodies are capped at 8 KiB of UTF-8 data. Decrypted events are strictly required to be JSON objects.

## Channel binding

Each `SecureSession` exposes the final Noise handshake hash as a hexadecimal channel-binding value. This is useful for tests/debugging and could later support an additional human safety-number UX. It is not currently presented as a standalone real-world identity proof.

## Invite format

Veil protocol v2 intentionally retains the `veil1:` invite serialization because the invite schema itself did not need to change. An invite carries:

- display username
- v3 onion address
- long-term Ed25519 public key

The invite's identity key and onion endpoint are pinned during outgoing authentication.

## Failure behavior

Malformed frames, invalid Noise state transitions, invalid signatures, mismatched identity/onion bindings, wrong invite identities, malformed encrypted events, timeouts, and rejected approval all terminate the relevant connection rather than downgrading authentication.

## Version negotiation

There is currently **no protocol negotiation or downgrade path**. Veil 0.2 speaks protocol v2 only. A v1 peer will fail rather than silently falling back to the retired custom handshake.
