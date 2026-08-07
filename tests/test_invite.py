from __future__ import annotations

import pytest

from veil_im.invite import Invite


def test_invite_round_trip() -> None:
    invite = Invite("alice", "a" * 56 + ".onion", b"p" * 32)
    decoded = Invite.decode(invite.encode())
    assert decoded == invite
    assert len(decoded.fingerprint.split("-")) == 8


def test_invite_rejects_non_v3_onion() -> None:
    with pytest.raises(ValueError):
        Invite("alice", "example.onion", b"p" * 32)


def test_invite_rejects_extra_fields() -> None:
    code = Invite("alice", "a" * 56 + ".onion", b"p" * 32).encode()
    with pytest.raises(ValueError):
        Invite.decode(code + "junk")


def test_invite_rejects_noncanonical_base64_characters() -> None:
    with pytest.raises(ValueError):
        Invite.decode("veil1:!!!!")
