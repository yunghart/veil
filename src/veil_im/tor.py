from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any


class TorError(RuntimeError):
    """Tor controller setup or onion service creation failed."""


@dataclass(frozen=True, slots=True)
class OnionService:
    address: str
    private_key_type: str | None
    private_key: str | None


class TorController:
    """Thin async wrapper around Stem's blocking controller API."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 9051,
        socket_path: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.socket_path = socket_path
        self._controller: Any | None = None
        self._service_id: str | None = None

    async def connect(self) -> None:
        await asyncio.to_thread(self._connect_sync)

    def _connect_sync(self) -> None:
        try:
            from stem.control import Controller

            if self.socket_path:
                controller = Controller.from_socket_file(path=self.socket_path)
            else:
                controller = Controller.from_port(address=self.host, port=self.port)
            controller.authenticate()
            self._controller = controller
        except Exception as exc:
            raise TorError(
                "could not authenticate to Tor control interface; check docs/TOR_SETUP.md"
            ) from exc

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
