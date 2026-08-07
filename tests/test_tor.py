from __future__ import annotations

import pytest

from veil_im.tor import TorController, TorError, assess_listener_exposure


def test_listener_audit_flags_remote_control_port() -> None:
    items = assess_listener_exposure(
        [("127.0.0.1", 9051), ("0.0.0.0", 19051)],
        [("127.0.0.1", 9050)],
    )
    control = next(item for item in items if item.name == "control-listener")
    assert not control.ok
    assert "0.0.0.0:19051" in control.detail


def test_listener_audit_accepts_loopback_only() -> None:
    items = assess_listener_exposure(
        [("127.0.0.1", 9051), ("::1", 9051)],
        [("127.0.0.1", 9050)],
    )
    assert all(item.ok for item in items)


def test_controller_refuses_remote_control_by_default() -> None:
    controller = TorController(host="192.0.2.50")
    with pytest.raises(TorError, match="non-loopback"):
        controller._connect_sync()
