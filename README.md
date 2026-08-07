# Veil IM

Veil IM is an **experimental peer-to-peer terminal messenger** for Debian-family Linux systems such as Parrot OS. Each running client exposes a Tor v3 onion service, uses a long-term Ed25519 application identity, establishes a fresh `Noise_XX_25519_ChaChaPoly_SHA256` channel, and encrypts chat traffic with ChaCha20-Poly1305.

> **Alpha warning:** Veil IM 0.2 is a research/development build, not an audited anonymity product. Do not rely on it for high-risk, life-critical, journalistic-source, military, or similarly sensitive communication. Using Tor and standard cryptographic constructions does not make an unaudited application safe by default.

## What changed in 0.2

The v0.1 custom signed key-exchange protocol has been removed. Veil 0.2 now uses the standard Noise XX pattern with deterministic conformance tests against a published Cacophony vector. Veil still contains its own small Noise state-machine implementation, so this is **not equivalent to an independent audit**.

Other 0.2 hardening work includes:

- strict 2-byte framing with a 65,535-byte hard limit
- Ed25519 signatures binding the long-term Veil identity to the Noise static key and onion endpoints
- automatic Noise `REKEY()` every 1,024 transport messages per direction
- bucketed encrypted-message padding to reduce exact application-message length leakage
- deterministic Veil protocol vectors
- parser/state-machine mutation smoke tests plus optional Atheris fuzz harnesses
- Tor control-host refusal for non-loopback TCP addresses
- `veil doctor` checks for exposed Tor listeners and control-cookie configuration
- handshake, approval, and pending-request limits
- core-dump/process-dump hardening on Linux where available
- `--strict-ephemeral` mode, which refuses to start while Linux swap is active
- multi-session unread counters and `/qr` invite rendering when `qrencode` is installed
- reproducible binary `.deb` build script and GitHub release/provenance workflow

Noise rekeying is **not a Double Ratchet**. Veil 0.2 still does not provide Signal-style per-message forward secrecy or post-compromise recovery.

## What works

- Full-screen ASCII terminal interface using `prompt_toolkit`
- Local passphrase-protected vault using Argon2id and ChaCha20-Poly1305
- Persistent identities or a fresh ephemeral identity per launch
- Tor v3 ephemeral onion services through Tor's authenticated control interface
- SOCKS5 connections that pass `.onion` names to Tor instead of resolving them locally
- Noise XX authenticated encrypted sessions
- Ed25519 application identities, fingerprints, and shareable invite codes
- Explicit approval/rejection of unknown inbound peers
- Optional encrypted contact book
- Multiple live one-to-one sessions with unread counters
- No chat history written by Veil by default

## Deliberately absent

- No central username directory
- No offline message server
- No group chat, attachments, voice, or presence tracking
- No multi-device identity syncing
- No Double Ratchet / post-compromise recovery
- No promise of forensic erasure in ephemeral mode
- No independent cryptographic or application security audit

## Quick start on Parrot OS

```bash
sudo apt update
sudo apt install tor python3-venv python3-pip qrencode

# Tor must expose an authenticated local control interface. See docs/TOR_SETUP.md.
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

veil doctor
veil init --username alice
veil run
```

For an application-level ephemeral identity:

```bash
veil run --ephemeral --username ghost
```

To refuse ephemeral mode when Linux swap is currently active:

```bash
veil run --ephemeral --strict-ephemeral --username ghost
```

Inside the app:

```text
/help
/invite
/qr
/connect veil1:...
/contacts
/sessions
/use <fingerprint>
/msg <fingerprint> hello through the onion
/accept <request-id> [contact-name]
/reject <request-id>
/quit
```

## Security model in one paragraph

A username is cosmetic. The long-term Veil identity is an Ed25519 public key carried in the invite code. A fresh Noise XX handshake creates the transport channel. Inside the encrypted handshake, each side signs a canonical binding containing its Ed25519 identity, Noise static key, role, and onion endpoints. For an outgoing connection, the responder's Ed25519 identity and onion endpoint must match the invite. Transport messages use Noise ChaChaPoly cipher states, strict ordered nonces, padding buckets, and periodic Noise rekeying. The encrypted vault holds the long-term Ed25519 signing seed, contacts, and—when persistent mode is used—the Tor onion-service private key.

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [docs/PROTOCOL.md](docs/PROTOCOL.md), [docs/TOR_SETUP.md](docs/TOR_SETUP.md), and [SECURITY.md](SECURITY.md) before experimenting with it.

## Development and testing

```bash
python -m pip install -e '.[dev]'
pytest -q
python -m compileall -q src tests
ruff check .
```

Coverage-guided fuzz harnesses are under `fuzz/`:

```bash
python -m pip install -e '.[fuzz]'
python fuzz/fuzz_framing.py -max_total_time=60
python fuzz/fuzz_invite.py -max_total_time=60
python fuzz/fuzz_event.py -max_total_time=60
python fuzz/fuzz_noise.py -max_total_time=60
```

Protocol vectors are committed under `tests/vectors/` so another implementation can reproduce handshake and application-level outputs without reading the Python implementation.

## Packages and releases

Build the simple binary Debian package reproducibly:

```bash
SOURCE_DATE_EPOCH=1786132800 ./scripts/build-binary-deb.sh
```

Or build with Debian tooling:

```bash
sudo apt build-dep .
dpkg-buildpackage -us -uc -b
```

A `v*` Git tag triggers the GitHub release workflow, which runs tests, builds a wheel and `.deb`, publishes SHA-256 checksums, and requests GitHub artifact provenance attestations. Maintainers should use a signed Git tag when they have a configured signing key; provenance is not a substitute for an independent security audit.

## Security status

Veil 0.2 materially reduces protocol risk compared with 0.1, but it remains an **unaudited alpha**. The highest-value next cryptographic work is a reviewed ratcheting design and independent review of the Noise integration, identity binding, Tor lifecycle, vault, and parser/state machine. See [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md) and [docs/ROADMAP.md](docs/ROADMAP.md).

## License

GPL-3.0-or-later. See `LICENSE`.
