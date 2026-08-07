from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from veil_im.crypto import ed25519_public_bytes, fingerprint
from veil_im.invite import Invite
from veil_im.models import Identity
from veil_im.protocol import _encode_padded_event, _identity_binding, _initial_payload


def test_veil_v2_application_vectors_are_stable() -> None:
    path = Path(__file__).parent / "vectors" / "veil_v2.json"
    vector = json.loads(path.read_text())
    seed = bytes.fromhex(vector["ed25519_private_seed"])
    noise_private = x25519.X25519PrivateKey.from_private_bytes(
        bytes.fromhex(vector["noise_static_private"])
    )
    noise_public = noise_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    identity = Identity("alice", seed)

    assert ed25519_public_bytes(seed).hex() == vector["ed25519_public"]
    assert fingerprint(ed25519_public_bytes(seed)) == vector["fingerprint"]
    assert noise_public.hex() == vector["noise_static_public"]
    assert Invite("alice", vector["source_onion"], ed25519_public_bytes(seed)).encode() == vector["invite"]
    assert _initial_payload(vector["source_onion"], vector["target_onion"]).hex() == vector["initial_payload"]
    assert _identity_binding(
        identity,
        role="initiator",
        local_onion=vector["source_onion"],
        target_onion=vector["target_onion"],
        noise_static_key=noise_public,
    ).hex() == vector["identity_binding"]
    assert _encode_padded_event(
        vector["event"], random_bytes=lambda n: b"\0" * n
    ).hex() == vector["padded_event_256_zero_pad"]
