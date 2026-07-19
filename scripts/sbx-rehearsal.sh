#!/bin/sh
set -eu
umask 077

PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

ROOT=$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")/.." && /bin/pwd -P)
PYTHON=/Library/Frameworks/Python.framework/Versions/3.12/bin/python3

if [ ! -x "$PYTHON" ] || ! "$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "Leftovers requires Python 3.11 or newer." >&2
  exit 2
fi

case ${HOME-} in
  /*) ;;
  *)
    echo "HOME must be an absolute path." >&2
    exit 2
    ;;
esac

cd "$ROOT"
PRIVATE_ROOT=$(/usr/bin/mktemp -d /private/tmp/leftovers-sbx-rehearsal.XXXXXX)
cleanup_private_root() {
  status=$?
  trap - EXIT HUP INT TERM
  if ! /bin/rmdir "$PRIVATE_ROOT" 2>/dev/null; then
    echo "Leftovers retained ambiguous rehearsal evidence at: $PRIVATE_ROOT" >&2
  fi
  exit "$status"
}
trap cleanup_private_root EXIT
trap 'exit 130' HUP INT TERM

env -i \
  HOME="$HOME" \
  PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
  PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH="$ROOT/src" \
  "$PYTHON" -m leftovers \
  --config "$ROOT/config/leftovers.example.toml" \
  sbx-rehearsal "$@" --private-temp-root "$PRIVATE_ROOT"
