from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from platformdirs import user_data_path


@dataclass(frozen=True, slots=True)
class Paths:
    data_dir: Path
    vault: Path


def default_paths() -> Paths:
    data_dir = Path(user_data_path("veil-im", appauthor=False))
    return Paths(data_dir=data_dir, vault=data_dir / "identity.vault")
