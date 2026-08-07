# Roadmap

## 0.1 MVP — complete

- encrypted identity vault
- persistent and temporary identity modes
- v3 onion-service creation
- custom authenticated encrypted one-to-one sessions
- invite codes, contacts, incoming approval
- terminal UI and Debian package skeleton

## 0.2 foundation/hardening — implemented in this tree

- retire the custom v1 handshake
- adopt `Noise_XX_25519_ChaChaPoly_SHA256`
- bind Ed25519 application identity to Noise static key and onion endpoints
- strict bounded framing and protocol-state rejection
- Noise transport rekeying
- message-size padding buckets
- deterministic external Noise vector and Veil application vectors
- parser/invite/event fuzz-smoke tests
- optional Atheris coverage-guided fuzz harnesses
- Tor control-listener hardening and `veil doctor` audit output
- process core-dump hardening and honest ephemeral-mode warnings
- optional strict-ephemeral swap refusal
- multiple simultaneous sessions and unread counters
- terminal QR invite rendering through `qrencode`
- reproducible simple `.deb` build script
- release CI with checksums and artifact provenance
- private vulnerability-reporting instructions

## 0.3 cryptographic follow-up

- choose and formally document a ratcheting construction; do not invent one ad hoc
- add per-message key evolution and skipped-message handling
- add fresh Diffie-Hellman input for post-compromise recovery if adopting a Double-Ratchet-style design
- produce deterministic ratchet vectors and interoperability tests
- add safety-number/key-change UX and explicit contact re-verification
- investigate a maintained/reviewed Noise implementation or independently review Veil's narrow implementation
- extend coverage-guided fuzzing to asynchronous handshake/state transitions

## 0.4 usability

- better multi-chat navigation
- QR import as well as terminal export
- optional encrypted local history with explicit retention controls
- reconnect/backoff UX
- accessibility and terminal compatibility pass
- packaging/install polish across Debian/Parrot releases

## Before 1.0 — release blockers

- independent cryptographic/application security review
- remediation of review findings
- threat-model review by people experienced with Tor and applied cryptography
- stable protocol specification and migration/versioning design
- long-running fuzz campaigns with retained regression corpora
- reproducible release verification by an independent builder
- clear key-compromise/revocation story

Veil should remain visibly alpha until these blockers are addressed. UI polish is not a substitute for protocol review.
