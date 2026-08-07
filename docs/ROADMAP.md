# Roadmap

## 0.1 MVP

- encrypted identity vault
- temporary and persistent identity modes
- v3 onion service creation
- authenticated encrypted one-to-one sessions
- invite codes, contacts, incoming approval
- terminal UI and Debian package skeleton

## 0.2 hardening

- replace the custom session protocol with a reviewed Noise pattern or audited equivalent
- replay-resistant prekeys and a double ratchet for post-compromise security
- deterministic protocol test vectors
- fuzzing for frame/parser state machines
- onion client authorization option
- safer passphrase handling and configurable KDF calibration
- reproducible Debian builds and signed releases

## 0.3 usability

- multiple simultaneous chats and unread counters
- QR import/export
- optional encrypted local history with explicit retention controls
- contact safety-number change alerts
- accessibility and terminal compatibility pass

## Before 1.0

- independent security audit
- threat-model review by Tor and applied-cryptography specialists
- stable protocol specification and migration design
- abuse handling that does not introduce central surveillance
