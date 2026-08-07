from __future__ import annotations

from veil_im.runtime import harden_process


def test_runtime_hardening_is_safe_to_call() -> None:
    report = harden_process()
    assert isinstance(report.core_dumps_disabled, bool)
    assert isinstance(report.dumpable_disabled, bool)
    assert isinstance(report.swap_active, bool)
