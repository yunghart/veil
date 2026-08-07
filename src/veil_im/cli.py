from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import socket
import sys
from pathlib import Path

from .config import default_paths
from .crypto import ed25519_public_bytes, fingerprint, generate_ed25519_private_bytes
from .models import Identity, VaultData
from .network import NetworkNode
from .tor import TorController, TorError
from .tui import VeilTUI
from .util import validate_username
from .vault import VaultError, VaultUnlockError, load_vault, save_vault


def _vault_path(value: str | None) -> Path:
    return Path(value).expanduser() if value else default_paths().vault


def _new_passphrase() -> str:
    first = getpass.getpass("Create vault passphrase (12+ characters): ")
    if len(first) < 12:
        raise ValueError("passphrase must be at least 12 characters")
    second = getpass.getpass("Repeat passphrase: ")
    if first != second:
        raise ValueError("passphrases do not match")
    return first


def _unlock_passphrase() -> str:
    return getpass.getpass("Vault passphrase: ")


def _cmd_init(args: argparse.Namespace) -> int:
    path = _vault_path(args.vault)
    if path.exists() and not args.force:
        print(f"Refusing to overwrite existing vault: {path}", file=sys.stderr)
        print("Use --force only after making a backup.", file=sys.stderr)
        return 2
    username = validate_username(args.username or input("Username: "))
    passphrase = _new_passphrase()
    vault = VaultData(
        identity=Identity(
            username=username,
            signing_private=generate_ed25519_private_bytes(),
        )
    )
    save_vault(path, vault, passphrase)
    public = ed25519_public_bytes(vault.identity.signing_private)
    print(f"Created encrypted vault: {path}")
    print(f"Identity fingerprint: {fingerprint(public)}")
    print("Run: veil run")
    return 0


async def _run_async(args: argparse.Namespace) -> int:
    path = _vault_path(args.vault)
    temporary = bool(args.temporary)
    passphrase: str | None = None

    if temporary:
        username = validate_username(args.username or input("Temporary username: "))
        vault = VaultData(
            identity=Identity(
                username=username,
                signing_private=generate_ed25519_private_bytes(),
            )
        )
    else:
        if not path.exists():
            raise VaultError(f"vault not found: {path}; create it with 'veil init'")
        passphrase = _unlock_passphrase()
        vault = load_vault(path, passphrase)

    node = NetworkNode(
        vault,
        socks_host=args.tor_socks_host,
        socks_port=args.tor_socks_port,
        virtual_port=args.virtual_port,
    )
    tor = TorController(
        host=args.tor_control_host,
        port=args.tor_control_port,
        socket_path=args.tor_control_socket,
    )

    async def persist() -> None:
        if temporary or passphrase is None:
            return
        await asyncio.to_thread(save_vault, path, vault, passphrase)

    try:
        await node.start_listener()
        print("Connecting to Tor control interface…")
        await tor.connect()
        print("Publishing Tor v3 onion service…")
        service = await tor.create_onion_service(
            node.local_port,
            virtual_port=args.virtual_port,
            key_type=vault.identity.onion_key_type if not temporary else None,
            key_content=vault.identity.onion_key if not temporary else None,
            await_publication=not args.no_wait_publication,
        )
        node.set_onion(service.address)

        if not temporary and vault.identity.onion_key is None:
            if service.private_key_type and service.private_key:
                vault.identity.onion_key_type = service.private_key_type
                vault.identity.onion_key = service.private_key
                await persist()
            else:
                print(
                    "Warning: Tor did not return the onion private key; this address may change next run.",
                    file=sys.stderr,
                )

        tui = VeilTUI(node, persist=None if temporary else persist)
        await tui.run()
        return 0
    finally:
        await node.stop()
        await tor.close()


def _cmd_run(args: argparse.Namespace) -> int:
    try:
        return asyncio.run(_run_async(args))
    except (VaultUnlockError, VaultError, TorError, ValueError, OSError) as exc:
        print(f"veil: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


def _cmd_show(args: argparse.Namespace) -> int:
    path = _vault_path(args.vault)
    try:
        vault = load_vault(path, _unlock_passphrase())
    except VaultError as exc:
        print(f"veil: {exc}", file=sys.stderr)
        return 1
    public = ed25519_public_bytes(vault.identity.signing_private)
    print(f"Vault: {path}")
    print(f"Username: {vault.identity.username}")
    print(f"Fingerprint: {fingerprint(public)}")
    print(f"Persistent onion key: {'yes' if vault.identity.onion_key else 'not created yet'}")
    print(f"Contacts: {len(vault.contacts)}")
    return 0


async def _doctor_async(args: argparse.Namespace) -> int:
    failures = 0
    print(f"Checking SOCKS at {args.tor_socks_host}:{args.tor_socks_port}…", end=" ")
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(args.tor_socks_host, args.tor_socks_port), timeout=3
        )
        writer.close()
        await writer.wait_closed()
        print("reachable")
    except Exception as exc:
        failures += 1
        print(f"failed ({exc})")

    print("Checking Tor controller authentication…", end=" ")
    tor = TorController(
        host=args.tor_control_host,
        port=args.tor_control_port,
        socket_path=args.tor_control_socket,
    )
    try:
        await tor.connect()
        print("ok")
    except Exception as exc:
        failures += 1
        print(f"failed ({exc})")
    finally:
        await tor.close()
    return 1 if failures else 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    try:
        return asyncio.run(_doctor_async(args))
    except KeyboardInterrupt:
        return 130


def _add_tor_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--tor-socks-host", default="127.0.0.1")
    parser.add_argument("--tor-socks-port", type=int, default=9050)
    parser.add_argument("--tor-control-host", default="127.0.0.1")
    parser.add_argument("--tor-control-port", type=int, default=9051)
    parser.add_argument("--tor-control-socket")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="veil",
        description="Experimental encrypted terminal messenger over Tor onion services",
    )
    parser.add_argument("--version", action="version", version="veil-im 0.1.1")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="create an encrypted persistent identity vault")
    init.add_argument("--username")
    init.add_argument("--vault")
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=_cmd_init)

    run = sub.add_parser("run", help="start the terminal messenger")
    run.add_argument("--vault")
    run.add_argument("--temporary", action="store_true")
    run.add_argument("--username", help="required only for non-interactive temporary mode")
    run.add_argument("--virtual-port", type=int, default=9736)
    run.add_argument("--no-wait-publication", action="store_true")
    _add_tor_args(run)
    run.set_defaults(func=_cmd_run)

    show = sub.add_parser("show", help="show non-secret vault identity information")
    show.add_argument("--vault")
    show.set_defaults(func=_cmd_show)

    doctor = sub.add_parser("doctor", help="check local Tor SOCKS and controller access")
    _add_tor_args(doctor)
    doctor.set_defaults(func=_cmd_doctor)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ValueError as exc:
        print(f"veil: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
