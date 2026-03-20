#!/bin/bash
# security-updates-metrics.sh
#
# Collects pending security update metrics for Prometheus via the
# node_exporter textfile collector.
#
# Designed to run inside a container with the host's apt/dpkg state
# bind-mounted read-only. See the accompanying docker-compose.yml.
#
# Metrics emitted:
#   node_security_updates_total            – all upgradable packages
#   node_security_updates_security         – from the -security pocket
#   node_security_updates_by_priority      – gauge per CVE priority bucket
#   node_security_updates_reboot_required  – 1 if reboot-required exists
#   node_security_updates_last_check       – unix timestamp of this run
#   node_security_updates_check_duration   – seconds this script took
#
# Dependencies: apt, curl, jq

set -euo pipefail

START_TIME=$(date +%s)

# ── Configuration ─────────────────────────────────────────────────────
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/node_exporter/textfile_collector}"
PROM_FILE="${TEXTFILE_DIR}/security_updates.prom"
CACHE_DIR="${CACHE_DIR:-/var/cache/security-updates-metrics}"
PRIORITY_CACHE="${CACHE_DIR}/pkg_priorities.cache"
PRIORITY_CACHE_MAX_AGE="${PRIORITY_CACHE_MAX_AGE:-86400}"

API_BASE="https://ubuntu.com/security/cves.json"
API_TIMEOUT="${API_TIMEOUT:-10}"

mkdir -p "${TEXTFILE_DIR}" "${CACHE_DIR}"

# Detect the host codename from the mounted /etc/apt sources, not the
# container's own OS. The container image may differ from the host.
if [ -f /etc/apt/sources.list ]; then
    CODENAME=$(grep -oP '(?<=\/)\w+-security' /etc/apt/sources.list 2>/dev/null | head -1 | sed 's/-security//' || echo "")
fi
if [ -z "${CODENAME:-}" ]; then
    CODENAME=$(lsb_release -cs 2>/dev/null || echo "jammy")
fi

# ── Helpers ───────────────────────────────────────────────────────────
log() { echo "[$(date -Iseconds)] $*" >&2; }

prom_write() {
    local name="$1" help="$2" type="$3"
    shift 3
    echo "# HELP ${name} ${help}"
    echo "# TYPE ${name} ${type}"
    for line in "$@"; do
        echo "${name}${line}"
    done
}

priority_rank() {
    case "$1" in
        critical)   echo 5 ;;
        high)       echo 4 ;;
        medium)     echo 3 ;;
        low)        echo 2 ;;
        negligible) echo 1 ;;
        *)          echo 0 ;;
    esac
}

# ── 1. Collect upgradable packages ────────────────────────────────────
# We do NOT run apt-get update. The host's apt-daily.timer keeps the
# cache fresh; we just read it via the bind mounts.
mapfile -t UPGRADABLE < <(apt list --upgradable 2>/dev/null | grep -v "^Listing" | grep -v "^$")

TOTAL=${#UPGRADABLE[@]}

SECURITY_PKGS=()
for line in "${UPGRADABLE[@]}"; do
    if [[ "$line" == *-security* ]]; then
        SECURITY_PKGS+=("$line")
    fi
done
SECURITY=${#SECURITY_PKGS[@]}

# ── 2. Priority bucketing via Ubuntu CVE API ──────────────────────────
declare -A PRIORITY_COUNTS=(
    [critical]=0 [high]=0 [medium]=0 [low]=0 [negligible]=0 [unknown]=0
)

# Expire stale cache
if [ -f "$PRIORITY_CACHE" ]; then
    cache_age=$(( $(date +%s) - $(stat -c %Y "$PRIORITY_CACHE") ))
    if [ "$cache_age" -ge "$PRIORITY_CACHE_MAX_AGE" ]; then
        log "Priority cache expired (${cache_age}s old), clearing"
        rm -f "$PRIORITY_CACHE"
    fi
fi
[ -f "$PRIORITY_CACHE" ] || touch "$PRIORITY_CACHE"

lookup_priority() {
    local pkg="$1"

    # Check cache
    local cached
    cached=$(grep "^${pkg}=" "$PRIORITY_CACHE" 2>/dev/null | tail -1 | cut -d= -f2)
    if [ -n "$cached" ]; then
        echo "$cached"
        return
    fi

    # Query Canonical's public CVE API
    local url="${API_BASE}?package=${pkg}&version=${CODENAME}&status=released&limit=10"
    local response
    response=$(curl -sf --max-time "$API_TIMEOUT" "$url" 2>/dev/null || echo "")

    local highest="unknown"
    local highest_rank=0

    if [ -n "$response" ] && echo "$response" | jq -e '.cves' &>/dev/null; then
        while IFS= read -r p; do
            local rank
            rank=$(priority_rank "$p")
            if [ "$rank" -gt "$highest_rank" ]; then
                highest="$p"
                highest_rank=$rank
            fi
        done < <(echo "$response" | jq -r '.cves[].priority // empty' 2>/dev/null)
    fi

    echo "${pkg}=${highest}" >> "$PRIORITY_CACHE"
    echo "$highest"
}

if [ "$SECURITY" -gt 0 ]; then
    for line in "${SECURITY_PKGS[@]}"; do
        pkg_name="${line%%/*}"
        priority=$(lookup_priority "$pkg_name")
        PRIORITY_COUNTS[$priority]=$(( ${PRIORITY_COUNTS[$priority]} + 1 ))
    done
fi

# ── 3. Reboot check ──────────────────────────────────────────────────
REBOOT_REQUIRED=0
[ -f /var/run/reboot-required ] && REBOOT_REQUIRED=1

# ── 4. Write .prom file atomically ───────────────────────────────────
END_TIME=$(date +%s)
DURATION=$(( END_TIME - START_TIME ))

TMPFILE=$(mktemp "${TEXTFILE_DIR}/.security_updates.prom.XXXXXX")
trap 'rm -f "${TMPFILE}"' EXIT

{
    prom_write "node_security_updates_total" \
        "Total number of pending package updates." "gauge" \
        " ${TOTAL}"

    prom_write "node_security_updates_security" \
        "Number of pending updates from the -security pocket." "gauge" \
        " ${SECURITY}"

    echo "# HELP node_security_updates_by_priority Pending security updates by Ubuntu CVE priority."
    echo "# TYPE node_security_updates_by_priority gauge"
    for p in critical high medium low negligible unknown; do
        echo "node_security_updates_by_priority{priority=\"${p}\"} ${PRIORITY_COUNTS[$p]}"
    done

    prom_write "node_security_updates_reboot_required" \
        "Whether a system reboot is required (0 or 1)." "gauge" \
        " ${REBOOT_REQUIRED}"

    prom_write "node_security_updates_last_check" \
        "Unix timestamp of the last security update check." "gauge" \
        " ${END_TIME}"

    prom_write "node_security_updates_check_duration_seconds" \
        "How long the security check script took to run." "gauge" \
        " ${DURATION}"

} > "${TMPFILE}"

mv "${TMPFILE}" "${PROM_FILE}"
trap - EXIT

log "OK: total=${TOTAL} security=${SECURITY} crit=${PRIORITY_COUNTS[critical]} high=${PRIORITY_COUNTS[high]} med=${PRIORITY_COUNTS[medium]} low=${PRIORITY_COUNTS[low]} reboot=${REBOOT_REQUIRED} duration=${DURATION}s"
