# External security review brief

Veil IM has not been independently audited. This document defines the review we want rather than pretending that automated tests are an audit.

## Highest-priority review targets

1. `src/veil_im/noise.py`
   - Noise revision-34 conformance
   - nonce handling, DH ordering, `MixHash`, `MixKey`, `Split`, and `REKEY`
   - failure behavior and state-transition enforcement
2. `src/veil_im/protocol.py`
   - binding between Ed25519 application identity, Noise static key, roles, and onion endpoints
   - invite pinning and unknown-peer authorization
   - transcript/channel-binding assumptions
   - padding/event parsing and replay/order behavior
3. `src/veil_im/framing.py` and network state
   - length handling, truncation, memory/DoS bounds, timeout behavior
4. `src/veil_im/tor.py` and `src/veil_im/transport.py`
   - SOCKS hostname handling
   - onion-service lifecycle
   - Tor control credential/listener assumptions
5. `src/veil_im/vault.py` and `src/veil_im/runtime.py`
   - Argon2 parameters and vault AEAD
   - filesystem permissions
   - secret lifetime and ephemeral-mode claims

## Questions for reviewers

- Does the exact Noise XX integration provide the authentication properties Veil's documentation claims?
- Can an active peer substitute an application identity, onion endpoint, Noise key, or role without detection?
- Is any downgrade, parser confusion, or state-machine skip possible?
- Are transport nonces/rekeys synchronized and failure-safe?
- Are frame/event bounds sufficient against straightforward memory/CPU denial of service?
- Does Tor setup accidentally create a clearnet/DNS fallback path?
- Are vault permissions/KDF defaults reasonable for the stated threat model?
- Which claims in `README.md`, `SECURITY.md`, or `docs/THREAT_MODEL.md` are too strong?

## Evidence supplied with the repository

- published Noise Cacophony vector under `tests/vectors/noise_xx_25519_chachapoly_sha256.json`
- deterministic Veil application vector under `tests/vectors/veil_v2.json`
- unit/integration tests under `tests/`
- fuzz targets under `fuzz/`
- protocol and threat-model documents under `docs/`

## Not a bounty promise

There is currently no bug bounty, SLA, or paid audit commitment. Enable GitHub Private Vulnerability Reporting before soliciting confidential reports.
