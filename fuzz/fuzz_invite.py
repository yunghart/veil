from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from veil_im.invite import Invite


def test_one_input(data: bytes) -> None:
    try:
        text = data.decode("utf-8", errors="ignore")
        Invite.decode(text)
    except (ValueError, TypeError):
        pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
