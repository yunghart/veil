#!/bin/sh
set -eu
command -v dpkg-buildpackage >/dev/null 2>&1 || {
  echo "dpkg-buildpackage is required" >&2
  exit 1
}
dpkg-buildpackage -us -uc -b
