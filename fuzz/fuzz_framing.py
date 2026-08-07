from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from veil_im.framing import FrameError, parse_frame_header


def test_one_input(data: bytes) -> None:
    try:
        parse_frame_header(data)
    except (FrameError, ValueError, TypeError):
        pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
