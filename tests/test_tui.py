from veil_im.tui import ASCII_LOGO, compact_onion


def test_ascii_logo_is_ascii_and_spells_veil_shape() -> None:
    ASCII_LOGO.encode("ascii")
    assert "_____" in ASCII_LOGO
    assert len(ASCII_LOGO.splitlines()) == 5


def test_compact_onion_preserves_short_and_compacts_long() -> None:
    short = "abc.onion"
    assert compact_onion(short, 20) == short

    long = "a" * 56 + ".onion"
    result = compact_onion(long, 28)
    assert len(result) == 28
    assert "..." in result
    assert result.endswith(".onion")
