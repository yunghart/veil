from __future__ import annotations

import asyncio
import shlex
import time
from collections.abc import Awaitable, Callable

from prompt_toolkit.application import Application
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, Layout, VSplit, Window
from prompt_toolkit.layout.controls import BufferControl, FormattedTextControl
from prompt_toolkit.layout.dimension import Dimension
from prompt_toolkit.styles import Style
from prompt_toolkit.widgets import Frame, TextArea

from .crypto import fingerprint, short_fingerprint
from .invite import Invite
from .models import Contact
from .network import (
    ConnectedEvent,
    DisconnectedEvent,
    ErrorEvent,
    IncomingRequestEvent,
    MessageEvent,
    NetworkNode,
    StatusEvent,
)
from .util import validate_username

PersistCallback = Callable[[], Awaitable[None]]

ASCII_LOGO = r""" __     __  _____  ___  _
 \ \   / / | ____||_ _|| |
  \ \ / /  |  _|   | | | |
   \ V /   | |___  | | | |___
    \_/    |_____||___||_____|"""


def compact_onion(onion: str | None, width: int = 26) -> str:
    if not onion:
        return "publishing..."
    if len(onion) <= width:
        return onion
    left = max(6, (width - 3) // 2)
    right = max(6, width - 3 - left)
    return f"{onion[:left]}...{onion[-right:]}"


HELP_TEXT = """Commands:
  /invite                         show your shareable invite code
  /add <invite> [alias]           save a peer in the encrypted contact book
  /connect <invite-or-alias>      connect through Tor
  /msg <peer> <text>              send a message
  /use <peer>                     select a peer for plain-text messages
  /accept <request-id> [alias]    approve unknown inbound peer; optional save
  /reject <request-id>            reject unknown inbound peer
  /contacts                       list saved contacts
  /sessions                       list connected peers
  /fingerprint                    show your identity fingerprint
  /help                           show this help
  /quit                           exit without writing message history
"""


class VeilTUI:
    def __init__(self, node: NetworkNode, persist: PersistCallback | None = None) -> None:
        self.node = node
        self.persist = persist
        self.active_target: str | None = None
        self._lines: list[str] = []
        self._event_task: asyncio.Task[None] | None = None

        self.output = TextArea(
            text="",
            read_only=True,
            scrollbar=True,
            focusable=False,
            wrap_lines=True,
        )
        self.input_buffer = Buffer(multiline=False)
        self.input_control = BufferControl(buffer=self.input_buffer)
        self.header_control = FormattedTextControl(self._header_text)
        self.status_control = FormattedTextControl(self._status_text)
        self.sidebar_control = FormattedTextControl(self._sidebar_text)

        bindings = KeyBindings()

        @bindings.add("enter")
        def _submit(event) -> None:  # prompt_toolkit callback signature
            line = self.input_buffer.text
            self.input_buffer.text = ""
            asyncio.create_task(self._handle_line(line))

        @bindings.add("c-c")
        @bindings.add("c-q")
        def _quit(event) -> None:
            event.app.exit()

        input_row = VSplit(
            [
                Window(
                    FormattedTextControl([("class:prompt", " veil> ")]),
                    width=7,
                    height=1,
                    style="class:prompt",
                ),
                Window(
                    self.input_control,
                    height=Dimension(min=1, max=3),
                    style="class:input",
                ),
            ]
        )

        main_panel = VSplit(
            [
                Frame(
                    self.output,
                    title=" secure session / memory only ",
                    style="class:frame",
                ),
                Window(width=1, char=" "),
                Frame(
                    Window(
                        self.sidebar_control,
                        width=Dimension(min=26, preferred=30, max=34),
                        wrap_lines=True,
                        style="class:sidebar",
                    ),
                    title=" node ",
                    style="class:frame",
                ),
            ]
        )

        root = HSplit(
            [
                Window(self.header_control, height=5, style="class:header"),
                Window(self.status_control, height=1, style="class:status"),
                main_panel,
                Window(height=1, char="-", style="class:separator"),
                input_row,
                Window(
                    FormattedTextControl(
                        HTML(
                            " <b>ENTER</b> send   <b>CTRL-Q</b> quit   "
                            "<b>/help</b> commands   <b>/invite</b> identity"
                        )
                    ),
                    height=1,
                    style="class:footer",
                ),
            ]
        )
        self.application: Application[None] = Application(
            layout=Layout(root, focused_element=self.input_control),
            key_bindings=bindings,
            full_screen=True,
            mouse_support=True,
            style=Style.from_dict(
                {
                    "header": "bg:#0f111a #7dcfff bold",
                    "logo": "bg:#0f111a #7dcfff bold",
                    "tagline": "bg:#0f111a #9aa5ce",
                    "status": "bg:#161821 #73daca bold",
                    "status.key": "bg:#161821 #565f89",
                    "status.value": "bg:#161821 #c0caf5 bold",
                    "separator": "#3b4261",
                    "prompt": "bg:#1a1b26 #7dcfff bold",
                    "input": "bg:#1a1b26 #c0caf5",
                    "footer": "bg:#24283b #9aa5ce",
                    "sidebar": "bg:#11131b #a9b1d6",
                    "sidebar.heading": "#7dcfff bold",
                    "sidebar.key": "#565f89",
                    "sidebar.value": "#c0caf5 bold",
                    "sidebar.good": "#9ece6a bold",
                    "frame": "bg:#11131b",
                    "frame.label": "#bb9af7 bold",
                    "frame.border": "#3b4261",
                }
            ),
        )

    def _header_text(self):
        lines = ASCII_LOGO.splitlines()
        return [("class:logo", line + "\n" if i < len(lines) - 1 else line) for i, line in enumerate(lines)]

    def _status_text(self):
        onion = compact_onion(self.node.onion, 28)
        active = self.active_target or "none"
        return [
            ("class:status", " [ONLINE] "),
            ("class:status.key", "user "),
            ("class:status.value", self.node.identity.username),
            ("class:status.key", "  onion "),
            ("class:status.value", onion),
            ("class:status.key", "  peers "),
            ("class:status.value", str(len(self.node.sessions))),
            ("class:status.key", "  target "),
            ("class:status.value", active),
        ]

    def _sidebar_text(self):
        try:
            public = self.node.invite().identity_key
            fp = fingerprint(public)
        except Exception:
            fp = "unavailable"

        mode = "TEMP / RAM" if self.persist is None else "PERSISTENT"
        onion = compact_onion(self.node.onion, 29)
        active = self.active_target or "none"

        return [
            ("class:sidebar.heading", "IDENTITY\n"),
            ("class:sidebar.key", "user       "),
            ("class:sidebar.value", f"{self.node.identity.username}\n"),
            ("class:sidebar.key", "mode       "),
            ("class:sidebar.value", f"{mode}\n"),
            ("class:sidebar.key", "fingerprint\n"),
            ("class:sidebar.value", f"{fp}\n\n"),
            ("class:sidebar.heading", "ROUTE\n"),
            ("class:sidebar.key", "tor        "),
            ("class:sidebar.good", "ONION / READY\n"),
            ("class:sidebar.key", "address\n"),
            ("class:sidebar.value", f"{onion}\n\n"),
            ("class:sidebar.heading", "SESSION\n"),
            ("class:sidebar.key", "peers      "),
            ("class:sidebar.value", f"{len(self.node.sessions)}\n"),
            ("class:sidebar.key", "active     "),
            ("class:sidebar.value", f"{active}\n"),
            ("class:sidebar.key", "history    "),
            ("class:sidebar.good", "RAM ONLY\n\n"),
            ("class:sidebar.heading", "QUICK COMMANDS\n"),
            ("class:sidebar.value", "/invite\n/connect <peer>\n/contacts\n/help"),
        ]

    def _append(self, text: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        for line in text.splitlines() or [""]:
            self._lines.append(f"[{stamp}] {line}")
        if len(self._lines) > 2000:
            self._lines = self._lines[-2000:]
        self.output.text = "\n".join(self._lines)
        self.output.buffer.cursor_position = len(self.output.text)
        self.application.invalidate()

    async def run(self) -> None:
        self._append("[SYS] VEIL node online | message history: RAM only")
        self._append("[TIP] /invite to share identity | /connect <invite-or-alias> to link")
        self._event_task = asyncio.create_task(self._event_loop())
        try:
            await self.application.run_async()
        finally:
            if self._event_task:
                self._event_task.cancel()
                await asyncio.gather(self._event_task, return_exceptions=True)

    async def _event_loop(self) -> None:
        while True:
            event = await self.node.events.get()
            if isinstance(event, StatusEvent):
                self._append(f"[SYS] {event.message}")
            elif isinstance(event, IncomingRequestEvent):
                fp = short_fingerprint(event.peer.identity_key)
                self._append(
                    f"[REQ] {event.request_id} | {event.peer.username} [{fp}]\n"
                    f"      from {event.peer.onion}\n"
                    f"      /accept {event.request_id} [alias]  |  /reject {event.request_id}"
                )
            elif isinstance(event, ConnectedEvent):
                fp = short_fingerprint(event.peer.identity_key)
                direction = "incoming" if event.inbound else "outgoing"
                self.active_target = fp
                self._append(
                    f"[LINK] {direction} | {event.peer.username} [{fp}] | verify fingerprint out-of-band"
                )
            elif isinstance(event, MessageEvent):
                fp = short_fingerprint(event.peer.identity_key)
                self.active_target = fp
                self._append(f"[IN ] {event.peer.username} [{fp}] :: {event.body}")
            elif isinstance(event, DisconnectedEvent):
                fp = short_fingerprint(event.peer.identity_key)
                self._append(f"[OFF] {event.peer.username} [{fp}] | {event.reason}")
            elif isinstance(event, ErrorEvent):
                self._append(f"[ERR] {event.message}")
            self.application.invalidate()

    async def _save(self) -> None:
        if self.persist is None:
            self._append("[RAM] temporary mode: contact change is memory-only")
            return
        await self.persist()
        self._append("[OK ] encrypted contact book saved")

    async def _handle_line(self, raw: str) -> None:
        raw = raw.strip()
        if not raw:
            return
        try:
            if not raw.startswith("/"):
                if self.active_target is None:
                    raise ValueError("no active peer; use /msg or /use first")
                peer = await self.node.send(self.active_target, raw)
                self._append(f"[YOU] -> {peer.username} :: {raw}")
                return

            parts = shlex.split(raw)
            command = parts[0].lower()
            args = parts[1:]
            if command == "/help":
                self._append(HELP_TEXT.rstrip())
            elif command == "/invite":
                invite = self.node.invite()
                self._append(
                    f"Your fingerprint: {invite.fingerprint}\n"
                    f"Invite code:\n{invite.encode()}\n"
                    "Share it through a separate channel and compare fingerprints."
                )
            elif command == "/fingerprint":
                public = self.node.invite().identity_key
                self._append(f"identity fingerprint: {fingerprint(public)}")
            elif command == "/contacts":
                if not self.node.vault.contacts:
                    self._append("contact book is empty")
                else:
                    rows = ["contacts:"]
                    for alias, contact in sorted(self.node.vault.contacts.items()):
                        rows.append(
                            f"  {alias}: {contact.username} [{short_fingerprint(contact.identity_key)}] {contact.onion}"
                        )
                    self._append("\n".join(rows))
            elif command == "/sessions":
                sessions = self.node.sessions
                if not sessions:
                    self._append("no connected peers")
                else:
                    rows = ["connected peers:"]
                    for session in sessions.values():
                        rows.append(
                            f"  {session.peer.username} [{short_fingerprint(session.peer.identity_key)}] {session.peer.onion}"
                        )
                    self._append("\n".join(rows))
            elif command == "/add":
                if not args:
                    raise ValueError("usage: /add <invite> [alias]")
                invite = Invite.decode(args[0])
                alias = validate_username(args[1] if len(args) > 1 else invite.username)
                if alias in self.node.vault.contacts:
                    raise ValueError(f"contact alias {alias!r} already exists")
                self.node.vault.contacts[alias] = Contact(
                    alias=alias,
                    username=invite.username,
                    onion=invite.onion,
                    identity_key=invite.identity_key,
                    added_at=int(time.time()),
                )
                await self._save()
                self._append(f"added {alias} [{short_fingerprint(invite.identity_key)}]")
            elif command == "/connect":
                if len(args) != 1:
                    raise ValueError("usage: /connect <invite-or-alias>")
                invite = (
                    Invite.decode(args[0])
                    if args[0].startswith("veil1:")
                    else self.node.contact_invite(args[0])
                )
                self._append(f"[TOR] dialing {invite.username} through onion route...")
                peer = await self.node.connect(invite)
                self.active_target = short_fingerprint(peer.identity_key)
            elif command == "/msg":
                if len(args) < 2:
                    raise ValueError("usage: /msg <peer> <text>")
                target, body = args[0], " ".join(args[1:])
                peer = await self.node.send(target, body)
                self.active_target = short_fingerprint(peer.identity_key)
                self._append(f"[YOU] -> {peer.username} :: {body}")
            elif command == "/use":
                if len(args) != 1:
                    raise ValueError("usage: /use <peer>")
                session = self.node._match_session(args[0])
                self.active_target = short_fingerprint(session.peer.identity_key)
                self._append(f"active peer: {session.peer.username} [{self.active_target}]")
            elif command == "/accept":
                if not (1 <= len(args) <= 2):
                    raise ValueError("usage: /accept <request-id> [alias]")
                request_id = args[0]
                peer = self.node.pending_peer(request_id)
                if peer is None:
                    raise ValueError("unknown or expired request id")
                if len(args) == 2:
                    alias = validate_username(args[1])
                    if alias in self.node.vault.contacts:
                        raise ValueError(f"contact alias {alias!r} already exists")
                    self.node.vault.contacts[alias] = Contact(
                        alias=alias,
                        username=peer.username,
                        onion=peer.onion,
                        identity_key=peer.identity_key,
                        added_at=int(time.time()),
                    )
                    await self._save()
                if not self.node.resolve_request(request_id, True):
                    raise ValueError("request was already resolved")
                self._append(f"[OK ] accepted incoming peer {peer.username}")
            elif command == "/reject":
                if len(args) != 1:
                    raise ValueError("usage: /reject <request-id>")
                if not self.node.resolve_request(args[0], False):
                    raise ValueError("unknown, expired, or resolved request id")
                self._append(f"[NO ] rejected request {args[0]}")
            elif command == "/quit":
                self.application.exit()
            else:
                raise ValueError(f"unknown command {command}; use /help")
        except Exception as exc:
            self._append(f"[ERR] {exc}")
