# Security policy

## Status

Veil IM 0.1 is an unaudited alpha. The code intentionally labels itself experimental and must not be advertised as "untraceable," "guaranteed anonymous," or "military-grade."

## Reporting

Do not open a public issue for a vulnerability that exposes identities, keys, plaintext, or onion-service secrets. Use a private maintainer channel once the project has one. Until then, keep findings local and include:

- affected version and commit
- reproducible steps
- impact and attacker prerequisites
- a minimal proof of concept
- suggested remediation, if known

## Cryptographic scope

The MVP uses standard primitives from `cryptography`; it does not implement the internals of those primitives. It does implement a small custom handshake and framing protocol, which is exactly why independent review is required before high-risk use.

## Known limitations

- No double ratchet or automatic key rotation inside a session
- Long-term identity compromise permits future impersonation
- Metadata such as contact timing and message sizes may remain observable at endpoints
- Python cannot guarantee reliable in-memory secret zeroization
- Terminal emulators, swap, hibernation, core dumps, malware, accessibility tools, and screenshots may retain plaintext
- Tor controller access is security-sensitive; another process with control access can manipulate the local Tor instance
- Unknown-peer approval verifies possession of a key, not the human behind it
