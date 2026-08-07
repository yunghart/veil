"""Coverage-guided hostile-state/message fuzzing for the fixed Noise XX machine."""
from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from veil_im.noise import NoiseError, NoiseXX


OPS = (
    "write_message1",
    "read_message1",
    "write_message2",
    "read_message2",
    "write_message3",
    "read_message3",
    "split",
)


def test_one_input(data: bytes) -> None:
    if not data:
        return
    initiator = bool(data[0] & 1)
    machine = NoiseXX(initiator=initiator, prologue=b"veil-fuzz")
    cursor = 1
    # Drive arbitrary state transitions and arbitrary attacker-controlled message
    # bytes. NoiseError is the intended fail-closed result; anything else is a bug.
    while cursor < len(data):
        op = OPS[data[cursor] % len(OPS)]
        cursor += 1
        take = data[cursor] if cursor < len(data) else 0
        cursor += 1
        payload = data[cursor : cursor + take]
        cursor += take
        try:
            if op.startswith("write_"):
                getattr(machine, op)(payload)
            elif op.startswith("read_"):
                getattr(machine, op)(payload)
            else:
                machine.split()
        except NoiseError:
            pass


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
