from __future__ import annotations

import json

import pytest

from veil_im.crypto import KDFParams, generate_ed25519_private_bytes
from veil_im.models import Contact, Identity, VaultData
from veil_im.vault import VaultUnlockError, decrypt_vault, encrypt_vault


def test_vault_round_trip_and_no_plaintext() -> None:
    vault = VaultData(
        identity=Identity("alice", generate_ed25519_private_bytes()),
        contacts={
            "bob": Contact(
                alias="bob",
                username="bob",
                onion="b" * 56 + ".onion",
                identity_key=b"k" * 32,
                added_at=123,
            )
        },
    )
    blob = encrypt_vault(
        vault,
        "correct horse battery staple",
        params=KDFParams(time_cost=1, memory_cost_kib=8192, parallelism=1),
        salt=b"s" * 16,
        nonce=b"n" * 12,
    )
    assert b"alice" not in blob
    assert b"correct horse" not in blob
    decoded = decrypt_vault(blob, "correct horse battery staple")
    assert decoded.identity.username == "alice"
    assert decoded.contacts["bob"].onion == "b" * 56 + ".onion"


def test_wrong_passphrase_is_rejected() -> None:
    vault = VaultData(identity=Identity("alice", generate_ed25519_private_bytes()))
    blob = encrypt_vault(
        vault,
        "a very long passphrase",
        params=KDFParams(time_cost=1, memory_cost_kib=8192, parallelism=1),
    )
    with pytest.raises(VaultUnlockError):
        decrypt_vault(blob, "the wrong passphrase")


def test_tampered_vault_is_rejected() -> None:
    vault = VaultData(identity=Identity("alice", generate_ed25519_private_bytes()))
    blob = encrypt_vault(
        vault,
        "a very long passphrase",
        params=KDFParams(time_cost=1, memory_cost_kib=8192, parallelism=1),
    )
    envelope = json.loads(blob)
    ciphertext = envelope["ciphertext"]
    envelope["ciphertext"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
    with pytest.raises(Exception):
        decrypt_vault(json.dumps(envelope).encode(), "a very long passphrase")


def test_saved_vault_permissions(tmp_path) -> None:
    from veil_im.vault import save_vault

    path = tmp_path / "private" / "identity.vault"
    vault = VaultData(identity=Identity("alice", generate_ed25519_private_bytes()))
    save_vault(path, vault, "correct horse battery staple")
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
