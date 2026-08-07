from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass
from typing import Any


class TorError(RuntimeError):
    """Tor controller setup or onion service creation failed."""


@dataclass(frozen=True, slots=True)
class OnionService:
    address: str
    private_key_type: str | None
    private_key: str | None


@dataclass(frozen=True, slots=True)
class TorAuditItem:
    name: str
    ok: bool
    detail: str
    warning: bool = False


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def assess_listener_exposure(
    control_listeners: list[tuple[str, int]],
    socks_listeners: list[tuple[str, int]],
) -> list[TorAuditItem]:
    """Pure helper used by `veil doctor` and unit tests."""
    items: list[TorAuditItem] = []
    if control_listeners:
        remote = [f"{host}:{port}" for host, port in control_listeners if not _is_loopback_host(host)]
        items.append(
            TorAuditItem(
                "control-listener",
                not remote,
                "loopback only" if not remote else f"non-loopback control listener(s): {', '.join(remote)}",
            )
        )
    else:
        items.append(TorAuditItem("control-listener", True, "no TCP control listener reported"))

    if socks_listeners:
        remote = [f"{host}:{port}" for host, port in socks_listeners if not _is_loopback_host(host)]
        items.append(
            TorAuditItem(
                "socks-listener",
                not remote,
                "loopback only" if not remote else f"non-loopback SOCKS listener(s): {', '.join(remote)}",
                warning=bool(remote),
            )
        )
    return items


class TorController:
    """Thin async wrapper around Stem's blocking controller API.

    Veil refuses a non-loopback TCP control host by default. A Tor control port is
    highly privileged; accidentally exposing it is materially worse than a normal
    service port.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 9051,
        socket_path: str | None = None,
        *,
        allow_remote_control: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.socket_path = socket_path
        self.allow_remote_control = allow_remote_control
        self._controller: Any | None = None
        self._service_id: str | None = None

    async def connect(self) -> None:
        await asyncio.to_thread(self._connect_sync)

    def _connect_sync(self) -> None:
        if not self.socket_path and not self.allow_remote_control and not _is_loopback_host(self.host):
            raise TorError(
                "refusing non-loopback Tor control host; use a local ControlSocket/ControlPort"
            )
        try:
            from stem.control import Controller

            if self.socket_path:
                controller = Controller.from_socket_file(path=self.socket_path)
            else:
                controller = Controller.from_port(address=self.host, port=self.port)
            controller.authenticate()
            self._controller = controller
        except TorError:
            raise
        except Exception as exc:
            raise TorError(
                "could not authenticate to Tor control interface; check docs/TOR_SETUP.md"
            ) from exc

    async def audit(self) -> list[TorAuditItem]:
        if self._controller is None:
            raise TorError("Tor controller is not connected")
        return await asyncio.to_thread(self._audit_sync)

    def _audit_sync(self) -> list[TorAuditItem]:
        controller = self._controller
        if controller is None:
            raise TorError("Tor controller is not connected")
        items: list[TorAuditItem] = []
        try:
            from stem.control import Listener

            control_listeners = list(controller.get_listeners(Listener.CONTROL))
            socks_listeners = list(controller.get_listeners(Listener.SOCKS))
            items.extend(assess_listener_exposure(control_listeners, socks_listeners))
        except Exception as exc:
            items.append(TorAuditItem("listeners", True, f"could not inspect listeners: {exc}", warning=True))

        try:
            cookie = str(controller.get_conf("CookieAuthentication", default="0")).strip()
            enabled = cookie == "1"
            items.append(
                TorAuditItem(
                    "cookie-auth",
                    True,
                    "enabled" if enabled else "not enabled; authenticated control access still succeeded",
                    warning=not enabled,
                )
            )
        except Exception as exc:
            items.append(TorAuditItem("cookie-auth", True, f"could not inspect: {exc}", warning=True))
        return items

    async def create_onion_service(
        self,
        local_port: int,
        *,
        virtual_port: int = 9736,
        key_type: str | None = None,
        key_content: str | None = None,
        await_publication: bool = True,
    ) -> OnionService:
        if self._controller is None:
            raise TorError("Tor controller is not connected")
        if (key_type is None) != (key_content is None):
            raise ValueError("onion key type and content must be provided together")
        return await asyncio.to_thread(
            self._create_sync,
            local_port,
            virtual_port,
            key_type,
            key_content,
            await_publication,
        )

    def _create_sync(
        self,
        local_port: int,
        virtual_port: int,
        key_type: str | None,
        key_content: str | None,
        await_publication: bool,
    ) -> OnionService:
        try:
            kwargs: dict[str, Any] = {
                "await_publication": await_publication,
                "timeout": 120,
            }
            if key_type is None:
                kwargs.update(key_type="NEW", key_content="ED25519-V3")
            else:
                kwargs.update(key_type=key_type, key_content=key_content)
            response = self._controller.create_ephemeral_hidden_service(
                {virtual_port: f"127.0.0.1:{local_port}"},
                **kwargs,
            )
            self._service_id = response.service_id
            return OnionService(
                address=f"{response.service_id}.onion",
                private_key_type=getattr(response, "private_key_type", None),
                private_key=getattr(response, "private_key", None),
            )
        except Exception as exc:
            raise TorError("Tor failed to create or publish the onion service") from exc

    async def close(self) -> None:
        await asyncio.to_thread(self._close_sync)

    def _close_sync(self) -> None:
        controller = self._controller
        if controller is None:
            return
        try:
            if self._service_id:
                try:
                    controller.remove_ephemeral_hidden_service(self._service_id)
                except Exception:
                    pass
        finally:
            try:
                controller.close()
            finally:
                self._controller = None
                self._service_id = None

    async def __aenter__(self) -> "TorController":
        await self.connect()
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.close()
