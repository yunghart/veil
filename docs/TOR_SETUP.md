# Tor setup on Parrot OS / Debian

Veil needs two local Tor interfaces:

- a SOCKS listener, normally `127.0.0.1:9050`
- a controller, normally `127.0.0.1:9051`, authenticated with Tor's cookie

Install Tor:

```bash
sudo apt update
sudo apt install tor
```

Add or confirm these lines in `/etc/tor/torrc`:

```text
SocksPort 127.0.0.1:9050
ControlPort 127.0.0.1:9051
CookieAuthentication 1
```

Restart and inspect status:

```bash
sudo systemctl restart tor
sudo systemctl status tor --no-pager
```

Tor's cookie permissions vary by distribution. Prefer granting the least privilege needed to your user rather than weakening cookie permissions globally. On Debian-family systems, membership in the Tor service group may be appropriate, but confirm the actual cookie location and group ownership on your system.

Verify locally:

```bash
ss -lnt | grep -E ':(9050|9051)\b'
```

Veil can use non-default ports:

```bash
veil run --tor-socks-port 9150 --tor-control-port 9151
```

Do not expose the control port to non-loopback interfaces. Control access can reconfigure Tor and create or remove onion services.
