#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

PYTHON=${PYTHON:-python3}
: "${SOURCE_DATE_EPOCH:=1786129200}"
export SOURCE_DATE_EPOCH

PYTHONPATH=src "$PYTHON" -m pytest -q
"$PYTHON" -m compileall -q src tests fuzz

if command -v ruff >/dev/null 2>&1; then
  ruff check .
else
  printf '%s\n' 'warning: ruff not installed; lint step skipped locally' >&2
fi

rm -rf dist
mkdir -p dist
"$PYTHON" -m pip wheel . --no-deps --no-build-isolation -w dist
OUT_DIR="$ROOT/dist" ./scripts/build-binary-deb.sh >/dev/null

SECOND=$(mktemp -d)
trap 'rm -rf "$SECOND"' EXIT INT TERM
OUT_DIR="$SECOND" ./scripts/build-binary-deb.sh >/dev/null
cmp "$ROOT/dist/veil-im_0.2.0-1_all.deb" "$SECOND/veil-im_0.2.0-1_all.deb"

printf '%s\n' 'release checks passed (tests, compile, wheel, reproducible binary deb)'
