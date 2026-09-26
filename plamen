#!/usr/bin/env bash
# Source-tree launcher. Installed launchers bind their managed interpreter.
# Never fall through to an arbitrary `python3` (notably Homebrew Python 3.14).
PLAMEN_PYTHON=""
if [ -n "${HOME:-}" ] && [ -x "$HOME/.local/share/plamen/runtime/py312/bin/python" ]; then
  PLAMEN_PYTHON="$HOME/.local/share/plamen/runtime/py312/bin/python"
else
  PLAMEN_PYTHON=$(command -v python3.12 2>/dev/null || true)
fi
if [ -z "$PLAMEN_PYTHON" ]; then
  echo "Plamen requires CPython 3.12. Install Python 3.12, then rerun this command." >&2
  exit 126
fi
exec "$PLAMEN_PYTHON" -I -B "$(dirname "$0")/plamen.py" "$@"
