#!/usr/bin/env bash
# Replay a pcap into a throwaway data dir then serve it.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PCAP="${1:-}"
if [[ -z "$PCAP" ]]; then
  echo "usage: $0 /path/to/file.pcap" >&2
  exit 1
fi
export NIDS_AUTODEMO=0
cd "$ROOT"
# shellcheck disable=SC1091
source .venv/bin/activate
python - <<PY
from pathlib import Path
from nids.config import load_settings
from nids.db import Store
from nids.engine import Engine
s = load_settings()
store = Store(s.db_path)
eng = Engine(s, store)
print(eng.ingest_pcap_file("$PCAP", replace=True))
PY
echo "Ingested $PCAP. Start with ./start.sh (NIDS_AUTODEMO=0 if you do not want demo overwrite)."
