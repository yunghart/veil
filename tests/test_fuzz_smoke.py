"""Deterministic parser mutation smoke tests.

These are intentionally dependency-free so every CI run exercises hostile input.
The `fuzz/` directory contains Atheris entry points for longer coverage-guided runs.
"""
from __future__ import annotations

import random
import string

from veil_im.framing import FrameError, parse_frame_header
from veil_im.invite import Invite
from veil_im.noise import NoiseError, NoiseXX
from veil_im.protocol import ProtocolError, _decode_padded_event


def test_frame_header_fuzz_smoke() -> None:
    rng = random.Random(0x5645494C)
    for _ in range(5000):
        size = rng.randrange(0, 8)
        raw = bytes(rng.randrange(0, 256) for _ in range(size))
        try:
            length = parse_frame_header(raw)
        except FrameError:
            continue
        assert len(raw) == 2
        assert 1 <= length <= 65535


def test_event_parser_fuzz_smoke() -> None:
    rng = random.Random(0x4E4F4953)
    for _ in range(3000):
        size = rng.randrange(0, 600)
        raw = bytes(rng.randrange(0, 256) for _ in range(size))
        try:
            event = _decode_padded_event(raw)
        except ProtocolError:
            continue
        assert isinstance(event, dict)


def test_invite_parser_fuzz_smoke() -> None:
    rng = random.Random(0x544F52)
    alphabet = string.ascii_letters + string.digits + "_-:.$%"
    for _ in range(2000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 180)))
        try:
            invite = Invite.decode(text)
        except (ValueError, TypeError):
            continue
        assert invite.onion.endswith(".onion")


def test_event_parser_rejects_duplicate_json_keys() -> None:
    raw = b'{"type":"x","type":"y"}'
    padded = len(raw).to_bytes(2, "big") + raw
    try:
        _decode_padded_event(padded)
    except ProtocolError:
        return
    raise AssertionError("duplicate JSON keys must be rejected")


def test_noise_state_machine_mutation_smoke() -> None:
    rng = random.Random(0x58584E4F495345)
    operations = (
        "write_message1",
        "read_message1",
        "write_message2",
        "read_message2",
        "write_message3",
        "read_message3",
        "split",
    )
    for _ in range(2000):
        machine = NoiseXX(initiator=bool(rng.getrandbits(1)), prologue=b"veil-fuzz")
        for _ in range(rng.randrange(1, 8)):
            operation = rng.choice(operations)
            payload = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 180)))
            try:
                if operation.startswith("write_"):
                    getattr(machine, operation)(payload)
                elif operation.startswith("read_"):
                    getattr(machine, operation)(payload)
                else:
                    machine.split()
            except NoiseError:
                pass
