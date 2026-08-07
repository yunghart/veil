from __future__ import annotations

import ctypes
import os
import resource
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class RuntimeHardening:
    core_dumps_disabled: bool
    dumpable_disabled: bool
    swap_active: bool


def swap_is_active() -> bool:
    path = Path("/proc/swaps")
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return False
    return len([line for line in lines[1:] if line.strip()]) > 0


def _disable_dumpable_linux() -> bool:
    if os.name != "posix" or not Path("/proc").exists():
        return False
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        # Linux prctl(PR_SET_DUMPABLE, 0). Keep the literal local to avoid a
        # Linux-only dependency in this small cross-platform helper.
        result = libc.prctl(4, 0, 0, 0, 0)
        return result == 0
    except Exception:
        return False


def harden_process() -> RuntimeHardening:
    """Apply low-risk process hardening and return what succeeded.

    This does not provide forensic erasure. Python objects may be copied by the
    runtime, kernel memory can still exist elsewhere, and active swap remains a
    separate risk.
    """
    os.umask(0o077)
    core_disabled = False
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        core_disabled = True
    except (ValueError, OSError):
        pass
    return RuntimeHardening(
        core_dumps_disabled=core_disabled,
        dumpable_disabled=_disable_dumpable_linux(),
        swap_active=swap_is_active(),
    )
