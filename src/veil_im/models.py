from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .util import b64u_decode, b64u_encode, validate_onion, validate_username


@dataclass(slots=True)
class Identity:
    username: str
    signing_private: bytes
    onion_key_type: str | None = None
    onion_key: str | None = None

    def __post_init__(self) -> None:
        self.username = validate_username(self.username)
        if len(self.signing_private) != 32:
            raise ValueError("Ed25519 private key seed must be 32 bytes")
        if (self.onion_key_type is None) != (self.onion_key is None):
            raise ValueError("onion key type and key must be present together")

    def to_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "signing_private": b64u_encode(self.signing_private),
            "onion_key_type": self.onion_key_type,
            "onion_key": self.onion_key,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Identity":
        return cls(
            username=str(data["username"]),
            signing_private=b64u_decode(str(data["signing_private"])),
            onion_key_type=data.get("onion_key_type"),
            onion_key=data.get("onion_key"),
        )


@dataclass(slots=True)
class Contact:
    alias: str
    username: str
    onion: str
    identity_key: bytes
    added_at: int

    def __post_init__(self) -> None:
        self.alias = validate_username(self.alias)
        self.username = validate_username(self.username)
        self.onion = validate_onion(self.onion)
        if len(self.identity_key) != 32:
            raise ValueError("contact Ed25519 public key must be 32 bytes")

    def to_dict(self) -> dict[str, Any]:
        return {
            "alias": self.alias,
            "username": self.username,
            "onion": self.onion,
            "identity_key": b64u_encode(self.identity_key),
            "added_at": self.added_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Contact":
        return cls(
            alias=str(data["alias"]),
            username=str(data["username"]),
            onion=str(data["onion"]),
            identity_key=b64u_decode(str(data["identity_key"])),
            added_at=int(data["added_at"]),
        )


@dataclass(slots=True)
class VaultData:
    identity: Identity
    contacts: dict[str, Contact] = field(default_factory=dict)
    version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "identity": self.identity.to_dict(),
            "contacts": {
                alias: contact.to_dict() for alias, contact in sorted(self.contacts.items())
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VaultData":
        version = int(data.get("version", 0))
        if version != 1:
            raise ValueError(f"unsupported vault data version: {version}")
        contacts_raw = data.get("contacts", {})
        if not isinstance(contacts_raw, dict):
            raise ValueError("contacts must be an object")
        contacts = {
            str(alias): Contact.from_dict(contact_data)
            for alias, contact_data in contacts_raw.items()
        }
        return cls(
            version=version,
            identity=Identity.from_dict(data["identity"]),
            contacts=contacts,
        )

    def public_summary(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "username": self.identity.username,
            "persistent_onion": self.identity.onion_key is not None,
            "contacts": [asdict(contact) | {"identity_key": "<redacted>"} for contact in self.contacts.values()],
        }
