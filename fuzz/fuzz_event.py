from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from veil_im.protocol import ProtocolError, _decode_padded_event


def test_one_input(data: bytes) -> None:
    try:
        _decode_padded_event(data)
    except (ProtocolError, ValueError, TypeError):
        pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
