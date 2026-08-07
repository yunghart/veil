# Changelog

## 0.2.0 - 2026-08-07

### Security/protocol

- Replaced the Veil v1 custom handshake with `Noise_XX_25519_ChaChaPoly_SHA256`.
- Added Ed25519-signed bindings between Veil identity, Noise static key, role, and onion endpoints.
- Added strict 16-bit frame boundaries and handshake/approval timeouts.
- Added automatic Noise transport `REKEY()` every 1,024 messages in each direction.
- Added application-event padding buckets.
- Added deterministic published Noise conformance vectors and Veil application vectors.
- Added mutation smoke tests and optional Atheris fuzz harnesses.
- Refuse non-loopback TCP Tor-control hosts; extend `veil doctor` with listener/auth checks.
- Harden process defaults against core dumps and add `--strict-ephemeral` swap refusal.

### UX

- Add multi-session unread counters.
- Add `/qr` terminal invite rendering with optional `qrencode`.
- Rename user-facing temporary mode language to "ephemeral" while retaining `--temporary` as an alias.

### Release engineering

- Add deterministic simple `.deb` build support.
- Add GitHub tag-release workflow with tests, checksums, and artifact provenance attestation.
- Expand security-reporting and external-review documentation.

## 0.1.1 - 2026-08-07

- Refreshed the terminal UI with an ASCII VEIL masthead and node sidebar.

## 0.1.0 - 2026-08-07

- Initial experimental MVP.
