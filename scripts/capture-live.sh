#!/usr/bin/env bash
# Start the dashboard with a live tap (requires wireshark group / dumpcap caps).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export NIDS_LIVE=1
export NIDS_IFACE="${1:-any}"
export NIDS_AUTODEMO=0
echo "Live iface=$NIDS_IFACE  bind=127.0.0.1:8787"
exec "$ROOT/start.sh"
