from __future__ import annotations

import hashlib

from veil_im.crypto import derive_session_keys, fingerprint, generate_x25519


def test_x25519_hkdf_agrees() -> None:
    left_private, left_public = generate_x25519()
    right_private, right_public = generate_x25519()
    transcript = hashlib.sha256(b"test transcript").digest()
    left = derive_session_keys(left_private, right_public, transcript)
    right = derive_session_keys(right_private, left_public, transcript)
    assert left == right
    assert left[0] != left[1]


def test_fingerprint_is_grouped_and_stable() -> None:
    value = fingerprint(b"p" * 32)
    assert value == fingerprint(b"p" * 32)
    assert len(value.split("-")) == 8
    assert all(len(group) == 4 for group in value.split("-"))
