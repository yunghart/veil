# Threat model

## Goals

Veil IM aims to:

1. Avoid exposing either peer's public IP address directly to the other peer by using Tor onion services.
2. Avoid a mandatory central account, contact, or message server.
3. Encrypt message content end to end between authenticated cryptographic identities.
4. Make identity verification possible through invite codes and fingerprints.
5. Keep long-term application secrets encrypted at rest behind a passphrase.
6. Avoid writing chat history by default.
7. Fail closed on malformed protocol state rather than falling back to an unauthenticated mode.

## Adversaries considered

- A passive network observer outside the endpoints
- A malicious peer choosing arbitrary usernames and malformed network input
- A man-in-the-middle relaying or modifying application traffic
- Theft of an encrypted vault without the passphrase
- Random connections to the onion service
- Accidental exposure of a Tor TCP control listener to a non-loopback address

## Protections provided by the current design

- Tor onion services prevent peers from learning each other's ordinary public IP directly through Veil's connection protocol when Tor is functioning and configured correctly.
- Noise XX establishes fresh X25519-based transport secrets and authenticates possession of Noise static keys.
- Ed25519 signatures bind those per-session Noise static keys to Veil's long-term application identities and onion endpoints.
- An initiator pins the responder's long-term identity and onion endpoint from the invite code.
- ChaCha20-Poly1305 provides transport confidentiality and integrity.
- Periodic Noise `REKEY()` rotates transport keys after 1,024 events in each direction.
- Padding buckets reduce disclosure of exact application-event lengths.
- Unknown identities require explicit local approval.

## Important limitations

### No Double Ratchet or post-compromise recovery

Noise XX supplies fresh handshake secrets for a new connection. Veil additionally applies Noise symmetric `REKEY()` during a connection. This does **not** provide Signal-style per-message key deletion or post-compromise recovery. A live endpoint/session compromise remains severe, and a stolen long-term identity key permits future impersonation until contacts replace it.

### Metadata and traffic analysis

Tor obscures network paths but does not make traffic analysis impossible. Message timing, volume, connection duration, endpoint-local observations, and padded size buckets can still leak information. A sufficiently capable observer may attempt traffic correlation.

### Endpoint compromise

A compromised OS, kernel, terminal emulator, Python runtime, Tor process, account, accessibility service, screen recorder, or malware can bypass Veil's cryptography by observing plaintext or keys at the endpoint.

### Tor controller

The Tor controller can create/remove onion services and alter Tor configuration. Veil refuses a non-loopback TCP control host by default and `veil doctor` inspects reported listener exposure, but any local process that already possesses appropriate Tor-control credentials remains within the trust boundary.

## Out of scope

- A compromised endpoint or Tor daemon
- A coercive adversary or physical surveillance
- Global traffic confirmation against Tor
- Stylometry and typing cadence
- Complete traffic-shape hiding or cover traffic
- Reliable forensic erasure from RAM, swap, hibernation, backups, crash artifacts, terminal scrollback, SSD wear-leveling, or firmware
- Malicious attachments (Veil does not transfer files)
- Human identity proof beyond out-of-band comparison of a cryptographic identity
- Protection after a long-term identity key is stolen, other than users replacing/re-verifying that identity

## Trust boundaries

- Tor is trusted for onion routing and onion-service reachability.
- `cryptography` and Argon2 implementations are trusted for their primitives.
- Veil's Noise integration, identity-binding protocol, parsers, vault integration, and state machine are **not independently audited**.
- The local OS account is trusted while the vault is unlocked.
- Contact fingerprints/invites must be exchanged or checked through a separately trusted channel for meaningful human identity assurance.

## Ephemeral mode

`veil run --ephemeral` creates a fresh signing identity and onion-service key for the process lifetime and does not save a Veil vault. Veil also sets a restrictive umask, disables process core dumps, and asks Linux not to expose the process as dumpable where supported.

This is application-level ephemerality, **not forensic erasure**. Python may copy secret values internally; the OS may swap or hibernate memory; terminals and screenshots can retain plaintext; and a compromised kernel can read process memory.

`--strict-ephemeral` adds one narrow safety check: Veil refuses to start ephemeral mode if active Linux swap is detected. It does not prove that no other persistence channel exists.
