#!/bin/bash
set -euo pipefail

INTERVAL="${CHECK_INTERVAL:-3600}"

echo "[entrypoint] Security metrics collector starting (interval=${INTERVAL}s)"

# Run immediately on startup, then loop
while true; do
    /usr/local/bin/security-updates-metrics.sh || echo "[entrypoint] Check failed, will retry next cycle" >&2
    sleep "${INTERVAL}"
done
