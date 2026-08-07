# Threat model

## Goals

Veil IM aims to:

1. Avoid exposing either peer's public IP address to the other peer.
2. Avoid a mandatory central account, contact, or message server.
3. Encrypt message content end to end between authenticated cryptographic identities.
4. Make identity verification possible through invite codes and fingerprints.
5. Keep long-term secrets encrypted at rest behind a passphrase.
6. Avoid writing chat history by default.

## Adversaries considered

- A passive network observer outside the endpoints
- A malicious peer attempting to impersonate another username
- A man-in-the-middle relaying or modifying application traffic
- Theft of an encrypted vault without the passphrase
- Random internet connections to the onion service

## Out of scope

- A compromised endpoint, kernel, terminal emulator, Python runtime, or Tor process
- A coercive adversary or physical surveillance
- Global traffic confirmation against Tor
- Stylometry, typing cadence, message-size analysis, and social-graph inference
- Malicious files, because the MVP does not transfer files
- Reliable forensic erasure from disks, swap, hibernation, backups, or SSD wear-leveling
- Protection after the long-term identity key has been stolen

## Trust boundaries

- Tor is trusted to provide onion routing and onion-service reachability.
- `cryptography` and Argon2 implementations are trusted for primitives.
- The local OS account is trusted while the vault is unlocked.
- Contact fingerprints must be verified out of band for meaningful human identity assurance.

## Temporary mode

Temporary mode creates a new signing identity and onion-service key for the process lifetime and does not save a vault. It is "temporary" at the application level only. It cannot promise forensic erasure.
