from __future__ import annotations

import pytest

from veil_im.framing import FrameError, encode_frame, parse_frame_header


def test_frame_encoding_uses_two_byte_noise_style_length() -> None:
    framed = encode_frame(b"abc")
    assert framed == b"\x00\x03abc"
    assert parse_frame_header(framed[:2]) == 3


def test_frame_rejects_zero_and_wrong_header_size() -> None:
    with pytest.raises(FrameError):
        parse_frame_header(b"\x00\x00")
    with pytest.raises(FrameError):
        parse_frame_header(b"\x01")
