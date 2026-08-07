# Veil IM

Veil IM is an **experimental, peer-to-peer terminal messenger** for Debian-family Linux systems such as Parrot OS. Each running client exposes a Tor v3 onion service, authenticates peers with an Ed25519 identity, negotiates an ephemeral X25519 session key, and encrypts every chat frame with ChaCha20-Poly1305.

> **Alpha warning:** this is a working MVP and a development base, not an audited anonymity product. Do not rely on it for life-critical, journalistic-source, military, or similarly high-risk communication. Tor reduces network exposure; it does not make endpoint compromise, screenshots, typing patterns, contact disclosure, or operational mistakes disappear.

## What works

- Full-screen terminal interface using `prompt_toolkit`
- Local passphrase-protected identity vault using Argon2id and ChaCha20-Poly1305
- Persistent identities or a fresh temporary identity per launch
- Tor v3 ephemeral onion services through Tor's control protocol
- SOCKS5 connections that resolve `.onion` destinations inside Tor
- Signed peer handshake using Ed25519 plus ephemeral X25519 key agreement
- Per-session encrypted messages with ordered nonces and transcript-bound AEAD
- Human-readable fingerprints and shareable invite codes
- Optional encrypted contact book
- Explicit incoming connection approval for unknown identities
- No message history written by default

## Deliberately absent in v0.1

- No central username directory
- No offline message server
- No group chat, attachments, voice, or presence tracking
- No multi-device identity syncing
- No post-compromise security/double-ratchet protocol yet
- No claim that temporary mode erases swap, terminal scrollback, crash dumps, or forensic traces

## Quick start on Parrot OS

```bash
sudo apt update
sudo apt install tor python3-venv python3-pip

# Tor must expose a control port to the local user. See docs/TOR_SETUP.md.
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

veil init --username alice
veil run
```

For a disposable session:

```bash
veil run --temporary --username ghost
```

Inside the app:

```text
/help
/invite
/connect veil1:...
/contacts
/msg alice hello through the onion
/accept 4fd82c alice-laptop
/reject 4fd82c
/quit
```

## Security model in one paragraph

A username is cosmetic. The cryptographic identity is the Ed25519 public key in the invite code. The onion address identifies the Tor service endpoint; the signed handshake binds the peer identity, onion endpoints, ephemeral key, and transcript. Session keys come from X25519 plus HKDF-SHA256. Messages use ChaCha20-Poly1305 with monotonically increasing nonces. The encrypted vault contains the long-term signing key, contacts, and—when persistent mode is selected—the Tor onion-service private key.

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [docs/PROTOCOL.md](docs/PROTOCOL.md), and [SECURITY.md](SECURITY.md) before treating this as more than a prototype.

## Development

```bash
python -m pytest -q
python -m pip wheel . --no-deps -w dist
```

A Debian/Parrot packaging skeleton is under `debian/`. Build it on a Debian-family system with the packaging dependencies installed:

```bash
dpkg-buildpackage -us -uc -b
```

## License

GPL-3.0-or-later. See `LICENSE`.
