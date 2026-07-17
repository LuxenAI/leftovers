#!/bin/sh
set -eu

umask 077
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DEFAULT_PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin
PATH=$DEFAULT_PATH${PATH:+:$PATH}
export PATH

BOOTSTRAP_PYTHON=$(command -v python3 2>/dev/null || true)
if [ -z "$BOOTSTRAP_PYTHON" ]; then
  echo "python3 is required to validate the scheduler environment file" >&2
  exit 1
fi

ENV_FILE_WAS_SET=${LEFTOVERS_ENV_FILE+x}
ENV_FILE=${LEFTOVERS_ENV_FILE:-"$ROOT/.leftovers/scheduler.env"}

load_scheduler_environment() {
  env_file=$1
  if [ ! -e "$env_file" ] && [ ! -L "$env_file" ]; then
    if [ "$ENV_FILE_WAS_SET" = "x" ]; then
      echo "Configured scheduler environment file does not exist: $env_file" >&2
      exit 1
    fi
    return
  fi

  "$BOOTSTRAP_PYTHON" -c '
import os
import stat
import sys

path = sys.argv[1]
info = os.lstat(path)
if not stat.S_ISREG(info.st_mode):
    raise SystemExit("scheduler environment must be a regular, non-symlink file")
if info.st_uid != os.getuid():
    raise SystemExit("scheduler environment must be owned by the current user")
if not info.st_mode & stat.S_IRUSR or info.st_mode & 0o7177:
    raise SystemExit("scheduler environment permissions must be 0600 or 0400")
' "$env_file"

  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      ''|'#'*) continue ;;
    esac
    key=${line%%=*}
    if [ "$key" = "$line" ]; then
      echo "Invalid scheduler environment line (expected KEY=value)" >&2
      exit 1
    fi
    case "$key" in
      ''|[0-9]*|*[!A-Za-z0-9_]*)
        echo "Invalid scheduler environment variable name: $key" >&2
        exit 1
        ;;
    esac
    value=${line#*=}
    export "$key=$value"
  done < "$env_file"
}

load_scheduler_environment "$ENV_FILE"

CONFIG=${LEFTOVERS_CONFIG:-"$ROOT/config/leftovers.toml"}
LOCK=${LEFTOVERS_LOCK_FILE:-"$ROOT/.leftovers/run.lock"}
PYTHON=${LEFTOVERS_PYTHON:-$BOOTSTRAP_PYTHON}
case "$PYTHON" in
  /*) ;;
  *)
    echo "LEFTOVERS_PYTHON must be an absolute path" >&2
    exit 1
    ;;
esac
if [ ! -x "$PYTHON" ]; then
  echo "Configured Python is not executable: $PYTHON" >&2
  exit 1
fi

# A kernel advisory lock is released automatically on exit, SIGKILL, or machine restart. The
# descriptor is inherited across exec so it protects the complete Leftovers cycle without a stale
# recovery directory.
exec "$PYTHON" - "$ROOT" "$LOCK" "$CONFIG" "${LEFTOVERS_PUBLISH:-0}" <<'PY'
import fcntl
import os
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
lock_path = Path(sys.argv[2]).expanduser()
if not lock_path.is_absolute():
    lock_path = root / lock_path
config_path = Path(sys.argv[3]).expanduser()
if not config_path.is_absolute():
    config_path = root / config_path
config = str(config_path)
publish = sys.argv[4] == "1"
lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
if lock_path.is_symlink() or lock_path.is_dir():
    raise SystemExit(f"Leftovers lock must be a regular non-symlink file: {lock_path}")
flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(lock_path, flags, 0o600)
info = os.fstat(descriptor)
if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
    raise SystemExit("Leftovers lock has unsafe type or ownership")
os.fchmod(descriptor, 0o600)
try:
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    print("Leftovers cycle already active; exiting without overlap", file=sys.stderr)
    raise SystemExit(0)
os.set_inheritable(descriptor, True)
environment = dict(os.environ)
environment["PYTHONPATH"] = str(root / "src")
arguments = [sys.executable, "-m", "leftovers", "--config", config, "run", "--execute"]
if publish:
    arguments.append("--publish")
os.chdir(root)
os.execve(sys.executable, arguments, environment)
PY
