from __future__ import annotations

import asyncio
import contextlib
import secrets
from dataclasses import dataclass
from typing import TypeAlias

from .crypto import ed25519_public_bytes, fingerprint, short_fingerprint
from .invite import Invite
from .models import Contact, Identity, VaultData
from .protocol import (
    PeerInfo,
    PeerRejected,
    ProtocolError,
    SecureSession,
    client_handshake,
    server_handshake,
)
from .transport import open_socks5_connection


@dataclass(frozen=True, slots=True)
class StatusEvent:
    message: str


@dataclass(frozen=True, slots=True)
class IncomingRequestEvent:
    request_id: str
    peer: PeerInfo


@dataclass(frozen=True, slots=True)
class ConnectedEvent:
    peer: PeerInfo
    inbound: bool


@dataclass(frozen=True, slots=True)
class MessageEvent:
    peer: PeerInfo
    body: str
    timestamp: int


@dataclass(frozen=True, slots=True)
class DisconnectedEvent:
    peer: PeerInfo
    reason: str


@dataclass(frozen=True, slots=True)
class ErrorEvent:
    message: str


NodeEvent: TypeAlias = (
    StatusEvent
    | IncomingRequestEvent
    | ConnectedEvent
    | MessageEvent
    | DisconnectedEvent
    | ErrorEvent
)


@dataclass(slots=True)
class PendingApproval:
    peer: PeerInfo
    future: asyncio.Future[bool]


class NetworkNode:
    def __init__(
        self,
        vault: VaultData,
        *,
        socks_host: str = "127.0.0.1",
        socks_port: int = 9050,
        virtual_port: int = 9736,
        approval_timeout: float = 120.0,
    ) -> None:
        self.vault = vault
        self.identity: Identity = vault.identity
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.virtual_port = virtual_port
        self.approval_timeout = approval_timeout
        self.onion: str | None = None
        self.events: asyncio.Queue[NodeEvent] = asyncio.Queue()
        self._server: asyncio.AbstractServer | None = None
        self._sessions: dict[str, SecureSession] = {}
        self._receive_tasks: dict[str, asyncio.Task[None]] = {}
        self._pending: dict[str, PendingApproval] = {}
        self._stopping = False

    @property
    def local_port(self) -> int:
        if self._server is None or not self._server.sockets:
            raise RuntimeError("listener is not running")
        return int(self._server.sockets[0].getsockname()[1])

    @property
    def sessions(self) -> dict[str, SecureSession]:
        return dict(self._sessions)

    async def start_listener(self) -> None:
        if self._server is not None:
            return
        self._server = await asyncio.start_server(self._handle_incoming, "127.0.0.1", 0)
        await self.events.put(StatusEvent(f"local listener ready on 127.0.0.1:{self.local_port}"))

    def set_onion(self, onion: str) -> None:
        self.onion = onion

    def invite(self) -> Invite:
        if self.onion is None:
            raise RuntimeError("onion service is not ready")
        return Invite(
            username=self.identity.username,
            onion=self.onion,
            identity_key=ed25519_public_bytes(self.identity.signing_private),
        )

    def _known_contact(self, peer: PeerInfo) -> Contact | None:
        for contact in self.vault.contacts.values():
            if contact.identity_key == peer.identity_key and contact.onion == peer.onion:
                return contact
        return None

    async def _authorize(self, peer: PeerInfo) -> bool:
        if self._known_contact(peer) is not None:
            return True
        loop = asyncio.get_running_loop()
        request_id = secrets.token_hex(3)
        while request_id in self._pending:
            request_id = secrets.token_hex(3)
        future: asyncio.Future[bool] = loop.create_future()
        self._pending[request_id] = PendingApproval(peer=peer, future=future)
        await self.events.put(IncomingRequestEvent(request_id, peer))
        try:
            return await asyncio.wait_for(future, timeout=self.approval_timeout)
        except TimeoutError:
            await self.events.put(StatusEvent(f"incoming request {request_id} expired"))
            return False
        finally:
            self._pending.pop(request_id, None)

    def pending_peer(self, request_id: str) -> PeerInfo | None:
        item = self._pending.get(request_id)
        return item.peer if item else None

    def resolve_request(self, request_id: str, accepted: bool) -> bool:
        item = self._pending.get(request_id)
        if item is None or item.future.done():
            return False
        item.future.set_result(accepted)
        return True

    async def _handle_incoming(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if self._stopping or self.onion is None:
            writer.close()
            return
        session: SecureSession | None = None
        try:
            session = await server_handshake(
                reader, writer, self.identity, self.onion, self._authorize
            )
            await self._register_session(session, inbound=True)
        except PeerRejected:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        except Exception as exc:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            if not self._stopping:
                await self.events.put(ErrorEvent(f"incoming connection failed: {exc}"))

    async def connect(self, invite: Invite) -> PeerInfo:
        if self.onion is None:
            raise RuntimeError("local onion service is not ready")
        reader, writer = await open_socks5_connection(
            self.socks_host,
            self.socks_port,
            invite.onion,
            self.virtual_port,
        )
        try:
            session = await client_handshake(
                reader, writer, self.identity, self.onion, invite
            )
        except Exception:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            raise
        await self._register_session(session, inbound=False)
        return session.peer

    async def _register_session(self, session: SecureSession, *, inbound: bool) -> None:
        key = fingerprint(session.peer.identity_key)
        old = self._sessions.get(key)
        if old is not None:
            await old.close()
            task = self._receive_tasks.pop(key, None)
            if task:
                task.cancel()
        self._sessions[key] = session
        task = asyncio.create_task(self._receive_loop(key, session))
        self._receive_tasks[key] = task
        await self.events.put(ConnectedEvent(session.peer, inbound))

    async def _receive_loop(self, key: str, session: SecureSession) -> None:
        reason = "connection closed"
        try:
            while True:
                message = await session.receive_chat()
                await self.events.put(
                    MessageEvent(session.peer, message.body, message.timestamp)
                )
        except asyncio.CancelledError:
            reason = "session replaced or application stopped"
            raise
        except ProtocolError as exc:
            reason = str(exc)
        except Exception as exc:
            reason = f"network error: {exc}"
        finally:
            if self._sessions.get(key) is session:
                self._sessions.pop(key, None)
                self._receive_tasks.pop(key, None)
                await session.close()
                if not self._stopping:
                    await self.events.put(DisconnectedEvent(session.peer, reason))

    def _match_session(self, target: str) -> SecureSession:
        target_lower = target.lower()
        matches: list[SecureSession] = []
        contact = self.vault.contacts.get(target)
        if contact is not None:
            exact = self._sessions.get(fingerprint(contact.identity_key))
            if exact is not None:
                return exact
        for full_fp, session in self._sessions.items():
            candidates = {
                full_fp.lower(),
                full_fp.replace("-", "").lower(),
                short_fingerprint(session.peer.identity_key).lower(),
                session.peer.username.lower(),
            }
            if any(candidate.startswith(target_lower) for candidate in candidates):
                matches.append(session)
        unique = {id(session): session for session in matches}
        if not unique:
            raise KeyError(f"no connected peer matches {target!r}")
        if len(unique) > 1:
            raise KeyError(f"target {target!r} is ambiguous")
        return next(iter(unique.values()))

    async def send(self, target: str, body: str) -> PeerInfo:
        session = self._match_session(target)
        await session.send_chat(body)
        return session.peer

    def contact_invite(self, alias: str) -> Invite:
        try:
            contact = self.vault.contacts[alias]
        except KeyError as exc:
            raise KeyError(f"unknown contact {alias!r}") from exc
        return Invite(contact.username, contact.onion, contact.identity_key)

    async def stop(self) -> None:
        if self._stopping:
            return
        self._stopping = True
        for pending in list(self._pending.values()):
            if not pending.future.done():
                pending.future.set_result(False)
        self._pending.clear()
        tasks = list(self._receive_tasks.values())
        for task in tasks:
            task.cancel()
        for session in list(self._sessions.values()):
            await session.close()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._sessions.clear()
        self._receive_tasks.clear()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
