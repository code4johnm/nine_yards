#!/usr/bin/env bash
# Single-command install + DEMO load + dashboard on localhost:8787
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

PY="${PYTHON:-python3}"
if [[ ! -d .venv ]]; then
  echo "[9yards] creating venv with $PY"
  "$PY" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install -q --upgrade pip
python -m pip install -q -r requirements.txt

mkdir -p data/capture
chmod 700 data data/capture 2>/dev/null || true

python -m nids.demo --ensure

export NIDS_HOST="${NIDS_HOST:-127.0.0.1}"
export NIDS_PORT="${NIDS_PORT:-8787}"
echo
echo "  9yards NIDS  →  http://${NIDS_HOST}:${NIDS_PORT}/"
echo "  health       →  http://${NIDS_HOST}:${NIDS_PORT}/api/health"
echo "  demo data is labeled DEMO. Live capture is off by default."
echo
exec python -m nids
