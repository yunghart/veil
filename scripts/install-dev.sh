#!/bin/sh
set -eu
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
printf '\nInstalled. Configure Tor per docs/TOR_SETUP.md, then run: .venv/bin/veil doctor\n'
