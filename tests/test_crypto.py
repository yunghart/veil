from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidSignature

from veil_im.crypto import (
    ed25519_public_bytes,
    fingerprint,
    generate_ed25519_private_bytes,
    sign_identity_binding,
    verify_identity_binding,
)


def test_identity_binding_signature_verifies_and_detects_tampering() -> None:
    private = generate_ed25519_private_bytes()
    public = ed25519_public_bytes(private)
    payload = b"noise-static-key-binding"
    signature = sign_identity_binding(private, payload)

    verify_identity_binding(public, payload, signature)
    with pytest.raises(InvalidSignature):
        verify_identity_binding(public, payload + b"!", signature)


def test_fingerprint_is_grouped_and_stable() -> None:
    value = fingerprint(b"p" * 32)
    assert value == fingerprint(b"p" * 32)
    assert len(value.split("-")) == 8
    assert all(len(group) == 4 for group in value.split("-"))
