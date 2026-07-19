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
exec "$PYTHON" "$ROOT/scripts/status_macos.py" "$@"
