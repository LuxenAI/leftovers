#!/bin/sh
set -eu

umask 077
export PYTHONDONTWRITEBYTECODE=1
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
PYTHON=${LEFTOVERS_INSTALL_PYTHON:-$(command -v python3 2>/dev/null || true)}
if [ -z "$PYTHON" ]; then
  echo "Python 3.11 or newer is required" >&2
  exit 2
fi
MANIFEST="$ROOT/PACKAGE-MANIFEST.json"
if [ -f "$MANIFEST" ] || [ -h "$MANIFEST" ]; then
  if [ -n "${LEFTOVERS_PACKAGE_ARCHIVE:-}" ] || [ -n "${LEFTOVERS_PACKAGE_ARCHIVE_SHA256:-}" ]; then
    if [ -z "${LEFTOVERS_PACKAGE_ARCHIVE:-}" ] || [ -z "${LEFTOVERS_PACKAGE_ARCHIVE_SHA256:-}" ]; then
      echo "set both LEFTOVERS_PACKAGE_ARCHIVE and LEFTOVERS_PACKAGE_ARCHIVE_SHA256, or neither" >&2
      exit 2
    fi
    "$PYTHON" "$ROOT/scripts/verify_macos_package.py" --root "$ROOT" \
      --archive "$LEFTOVERS_PACKAGE_ARCHIVE" \
      --archive-sha256 "$LEFTOVERS_PACKAGE_ARCHIVE_SHA256"
  else
    "$PYTHON" "$ROOT/scripts/verify_macos_package.py" --root "$ROOT"
  fi
elif [ -n "${LEFTOVERS_PACKAGE_ARCHIVE:-}" ] || [ -n "${LEFTOVERS_PACKAGE_ARCHIVE_SHA256:-}" ]; then
  echo "archive verification variables require an extracted package manifest" >&2
  exit 2
else
  GIT=${LEFTOVERS_INSTALL_GIT:-$(command -v git 2>/dev/null || true)}
  if [ -z "$GIT" ]; then
    echo "PACKAGE-MANIFEST.json is missing and Git is unavailable" >&2
    exit 2
  fi
  SOURCE_ROOT=$("$GIT" -C "$ROOT" rev-parse --show-toplevel 2>/dev/null || true)
  if [ "$SOURCE_ROOT" != "$ROOT" ]; then
    echo "PACKAGE-MANIFEST.json is missing and this is not a Git checkout root" >&2
    exit 2
  fi
fi
exec "$PYTHON" "$ROOT/scripts/install_macos.py" "$@"
