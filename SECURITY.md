# Security policy

## Status

Veil IM 0.2 is an **unaudited alpha**. It must not be advertised as untraceable, guaranteed anonymous, military-grade, audited, or safe for high-risk communications.

The v0.1 custom handshake has been replaced by `Noise_XX_25519_ChaChaPoly_SHA256`, and the implementation is checked against a published Noise/Cacophony test vector. That improves protocol discipline; it does **not** make Veil's implementation independently reviewed.

## Reporting a vulnerability

Please do **not** open a public issue for a vulnerability that could expose plaintext, identities, signing keys, onion-service keys, vault contents, or a reliable anonymity bypass.

If GitHub Private Vulnerability Reporting is enabled for this repository, use:

**Repository -> Security -> Advisories -> Report a vulnerability**

Include, when possible:

- affected Veil version and commit
- operating system and Tor version/configuration relevant to the issue
- attacker prerequisites
- reproducible steps or a minimal proof of concept
- expected versus observed behavior
- impact
- a suggested remediation, if you have one

Maintainers should enable **Settings -> Security -> Private vulnerability reporting** before inviting outside testing. Until a private reporting channel is enabled, do not publish sensitive exploit details in a GitHub issue.

## Cryptographic scope

Veil relies on `cryptography` for Ed25519, X25519, ChaCha20-Poly1305, and hashing primitives, and on Argon2id for vault key derivation. Veil implements a deliberately narrow Noise XX state machine around those primitives. The Noise behavior is covered by deterministic external test vectors, but the integration and application protocol remain Veil code and require independent review.

The long-term Ed25519 identity is separate from the per-session Noise X25519 static key. The application identity signs a canonical binding containing the Noise static public key, endpoint onions, and handshake role. Outgoing connections pin the responder's Ed25519 identity from the invite code.

## Known limitations

- Noise `REKEY()` is key rotation, **not** a Double Ratchet and not post-compromise recovery.
- A stolen long-term Ed25519 identity key permits future impersonation until contacts replace/revoke it.
- A live compromise of an endpoint or current session state can expose plaintext and session secrets.
- Message padding reduces exact application-message length leakage but does not hide timing, total traffic, padding bucket, or endpoint behavior.
- A sufficiently capable observer may attempt traffic correlation against Tor.
- Python cannot guarantee reliable zeroization of immutable/copyable secret objects.
- Ephemeral mode does not guarantee erasure from swap, hibernation, kernel memory, crash artifacts, terminal scrollback, screenshots, backups, or storage firmware.
- `--strict-ephemeral` only refuses startup when Linux swap is detected as active; it does not prove an absence of other persistence mechanisms.
- Tor controller access is highly privileged. Veil refuses non-loopback TCP control hosts by default, but another local process with controller credentials can still manipulate Tor.
- Unknown-peer approval proves possession of a cryptographic identity, not the real-world human behind it.
- The application has not received an independent security audit.

## Supported versions

Only the current development release receives security fixes. Pre-0.2 builds use the retired custom v1 handshake and should be treated as obsolete research artifacts.

## Disclosure

Please allow maintainers reasonable time to reproduce, patch, test, and publish a fix before public disclosure. No response-time SLA is promised for this volunteer alpha project.
