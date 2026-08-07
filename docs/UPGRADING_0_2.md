# Upgrading from 0.1.x to 0.2.0

Veil 0.2 intentionally removes the v1 custom handshake. Protocol v1 and v2 peers are not wire-compatible and there is no downgrade fallback.

## Vault compatibility

The encrypted vault format remains `veil-vault-v1`, so an existing 0.1.1 vault can be opened by 0.2.0. Invite serialization also remains `veil1:` because the invite schema (username, onion endpoint, Ed25519 identity key) did not change.

Back up the vault before upgrading any alpha software.

## Source checkout upgrade

After updating the repository:

```bash
source .venv/bin/activate
python -m pip install -e .
veil --version
pytest -q
```

Expected version:

```text
veil-im 0.2.0
```

## Peer compatibility

Both peers must be on 0.2.x for the Noise v2 handshake. Do not add a v1 fallback merely to restore compatibility; silent downgrade paths would undermine the security migration.
