#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=${VEIL_DEB_VERSION:-0.2.0-1}
OUT_DIR=${OUT_DIR:-"$ROOT/dist"}
# Release timestamp used when callers do not provide one. Override it with the
# source commit timestamp for tagged releases.
: "${SOURCE_DATE_EPOCH:=1786129200}"
export SOURCE_DATE_EPOCH

PKGROOT=$(mktemp -d)
trap 'rm -rf "$PKGROOT"' EXIT INT TERM

mkdir -p \
  "$PKGROOT/DEBIAN" \
  "$PKGROOT/usr/bin" \
  "$PKGROOT/usr/lib/python3/dist-packages/veil_im" \
  "$PKGROOT/usr/share/doc/veil-im" \
  "$OUT_DIR"

cp -a "$ROOT/src/veil_im/." "$PKGROOT/usr/lib/python3/dist-packages/veil_im/"
find "$PKGROOT" -type d -name __pycache__ -prune -exec rm -rf {} +

cat > "$PKGROOT/usr/bin/veil" <<'WRAPPER'
#!/bin/sh
exec /usr/bin/python3 -m veil_im.cli "$@"
WRAPPER
chmod 0755 "$PKGROOT/usr/bin/veil"

cp "$ROOT/README.md" "$ROOT/SECURITY.md" "$ROOT/CHANGELOG.md" "$ROOT/LICENSE" \
  "$PKGROOT/usr/share/doc/veil-im/"
cp -a "$ROOT/docs/." "$PKGROOT/usr/share/doc/veil-im/"

cat > "$PKGROOT/DEBIAN/control" <<CONTROL
Package: veil-im
Version: $VERSION
Section: net
Priority: optional
Architecture: all
Maintainer: Veil IM contributors <maintainers@example.invalid>
Depends: python3 (>= 3.11), python3-argon2, python3-cryptography, python3-platformdirs, python3-prompt-toolkit, python3-stem, tor
Recommends: qrencode
Description: experimental encrypted terminal messenger over Tor
 Veil IM is a terminal-based one-to-one messenger using Tor v3 onion
 services, Noise XX transport encryption, and Ed25519 application identities.
 .
 This is an unaudited alpha and should not be used for high-risk operations.
CONTROL

# Keep the handcrafted package byte-for-byte reproducible for identical source,
# toolchain, VERSION, and SOURCE_DATE_EPOCH.
find "$PKGROOT" -type d -exec chmod 0755 {} + -exec chmod g-s {} +
find "$PKGROOT/usr/lib/python3/dist-packages/veil_im" -type f -exec chmod 0644 {} +
find "$PKGROOT/usr/share/doc/veil-im" -type f -exec chmod 0644 {} +
chmod 0644 "$PKGROOT/DEBIAN/control"
find "$PKGROOT" -print0 | xargs -0 touch -h -d "@$SOURCE_DATE_EPOCH"

OUT="$OUT_DIR/veil-im_${VERSION}_all.deb"
dpkg-deb --root-owner-group --build "$PKGROOT" "$OUT" >/dev/null
printf '%s\n' "$OUT"
