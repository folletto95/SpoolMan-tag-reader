#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -z "$VIRTUAL_ENV" ]; then
  VENV_DIR="$SCRIPT_DIR/.venv"
  if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
  fi
  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"
fi

python -m pip install -r "$SCRIPT_DIR/requirements.txt"
python "$SCRIPT_DIR/spoolman_tag_reader.py" "$@"
