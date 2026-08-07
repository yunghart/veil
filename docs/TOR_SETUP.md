# Tor setup on Parrot OS / Debian

Veil needs two local Tor interfaces:

- a SOCKS listener, normally `127.0.0.1:9050`
- an authenticated controller, normally `127.0.0.1:9051` or a Unix control socket

The Tor controller is highly privileged. Veil deliberately refuses to connect to a **non-loopback TCP control host**.

## Basic local setup

Install Tor:

```bash
sudo apt update
sudo apt install tor
```

Add or confirm equivalent local-only settings in `/etc/tor/torrc`:

```text
SocksPort 127.0.0.1:9050
ControlPort 127.0.0.1:9051
CookieAuthentication 1
```

Restart Tor:

```bash
sudo systemctl restart tor
sudo systemctl status tor --no-pager
```

Cookie permissions vary by distribution. Prefer granting the least privilege necessary to your account rather than weakening the cookie file globally. Do not make the control cookie world-readable.

Verify listeners locally:

```bash
ss -lnt | grep -E ':(9050|9051)\b'
```

Then let Veil inspect the controller:

```bash
veil doctor
```

A non-loopback Tor **control** listener is treated as a failure. A non-loopback SOCKS listener is flagged as a warning because it may expose a proxy to other hosts.

## Unix control socket

If your Tor installation provides a permissioned Unix control socket, Veil can use it instead of TCP:

```bash
veil doctor --tor-control-socket /run/tor/control
veil run --tor-control-socket /run/tor/control
```

Use the actual socket path and permissions configured by your distribution.

## Non-default local ports

```bash
veil run --tor-socks-port 9150 --tor-control-port 9151
```

Do not point `--tor-control-host` at a remote address. Veil intentionally refuses that configuration.

## AnonSurf

Veil does not need a second Tor daemon merely because AnonSurf is active. If AnonSurf exposes a compatible local SOCKS interface and authenticated local control interface, Veil can use those endpoints. Run `veil doctor` while AnonSurf is active and only proceed when the control connection authenticates and the listener audit is acceptable.

Do not assume stacking multiple Tor/proxy layers automatically improves anonymity; it can instead create confusing routing and failure behavior.
