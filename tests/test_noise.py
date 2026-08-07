from __future__ import annotations

import json
from pathlib import Path

from veil_im.noise import CipherState, NoiseXX, hkdf


def _vector() -> dict:
    path = Path(__file__).parent / "vectors" / "noise_xx_25519_chachapoly_sha256.json"
    return json.loads(path.read_text())


def test_noise_xx_matches_published_cacophony_vector() -> None:
    v = _vector()
    messages = v["messages"]
    prologue = bytes.fromhex(v["init_prologue"])
    initiator = NoiseXX(
        initiator=True,
        prologue=prologue,
        static_private=bytes.fromhex(v["init_static"]),
        ephemeral_private=bytes.fromhex(v["init_ephemeral"]),
    )
    responder = NoiseXX(
        initiator=False,
        prologue=prologue,
        static_private=bytes.fromhex(v["resp_static"]),
        ephemeral_private=bytes.fromhex(v["resp_ephemeral"]),
    )

    msg1 = initiator.write_message1(bytes.fromhex(messages[0]["payload"]))
    assert msg1.hex() == messages[0]["ciphertext"]
    assert responder.read_message1(msg1).hex() == messages[0]["payload"]

    msg2 = responder.write_message2(bytes.fromhex(messages[1]["payload"]))
    assert msg2.hex() == messages[1]["ciphertext"]
    assert initiator.read_message2(msg2).hex() == messages[1]["payload"]

    msg3 = initiator.write_message3(bytes.fromhex(messages[2]["payload"]))
    assert msg3.hex() == messages[2]["ciphertext"]
    assert responder.read_message3(msg3).hex() == messages[2]["payload"]

    assert initiator.handshake_hash.hex() == v["handshake_hash"]
    assert responder.handshake_hash == initiator.handshake_hash

    i = initiator.split()
    r = responder.split()

    msg4 = r.send.encrypt_with_ad(b"", bytes.fromhex(messages[3]["payload"]))
    assert msg4.hex() == messages[3]["ciphertext"]
    assert i.receive.decrypt_with_ad(b"", msg4).hex() == messages[3]["payload"]

    msg5 = i.send.encrypt_with_ad(b"", bytes.fromhex(messages[4]["payload"]))
    assert msg5.hex() == messages[4]["ciphertext"]
    assert r.receive.decrypt_with_ad(b"", msg5).hex() == messages[4]["payload"]

    msg6 = r.send.encrypt_with_ad(b"", bytes.fromhex(messages[5]["payload"]))
    assert msg6.hex() == messages[5]["ciphertext"]
    assert i.receive.decrypt_with_ad(b"", msg6).hex() == messages[5]["payload"]


def test_cipher_rekey_stays_synchronized() -> None:
    key = b"k" * 32
    sender = CipherState(key)
    receiver = CipherState(key)
    for round_index in range(3):
        for i in range(5):
            plaintext = f"round={round_index};msg={i}".encode()
            ciphertext = sender.encrypt_with_ad(b"veil-test", plaintext)
            assert receiver.decrypt_with_ad(b"veil-test", ciphertext) == plaintext
        sender.rekey()
        receiver.rekey()


def test_noise_hkdf_is_deterministic_and_separates_outputs() -> None:
    out = hkdf(b"c" * 32, b"input", 3)
    assert out == hkdf(b"c" * 32, b"input", 3)
    assert len(set(out)) == 3
    assert all(len(value) == 32 for value in out)
