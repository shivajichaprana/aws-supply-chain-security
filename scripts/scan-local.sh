#!/usr/bin/env bash
###############################################################################
# scan-local.sh
#
# Locally scan a container image with Trivy AND Grype, mirroring (as closely
# as possible) the findings that AWS Inspector v2 would surface once the
# image lands in ECR.
#
# This script is intentionally hermetic — it does not push the image, does
# not require AWS credentials, and produces machine-readable JSON output
# alongside a human-readable severity summary.
#
# USAGE:
#   ./scripts/scan-local.sh <image-ref> [--severity HIGH,CRITICAL] [--out-dir DIR]
#
# Examples:
#   ./scripts/scan-local.sh nginx:1.27
#   ./scripts/scan-local.sh ghcr.io/example/api:sha-abc123 --severity CRITICAL
#   ./scripts/scan-local.sh local-build:latest --out-dir ./scan-results
###############################################################################

set -euo pipefail

# ---------- pretty printing ---------------------------------------------------
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
  C_RED=$(tput setaf 1)
  C_YEL=$(tput setaf 3)
  C_GRN=$(tput setaf 2)
  C_BLU=$(tput setaf 4)
  C_BLD=$(tput bold)
  C_RST=$(tput sgr0)
else
  C_RED=""; C_YEL=""; C_GRN=""; C_BLU=""; C_BLD=""; C_RST=""
fi

log()  { echo "${C_BLU}[scan-local]${C_RST} $*" >&2; }
warn() { echo "${C_YEL}[scan-local]${C_RST} $*" >&2; }
err()  { echo "${C_RED}[scan-local]${C_RST} $*" >&2; }

usage() {
  cat <<USAGE >&2
Usage: $0 <image-ref> [--severity SEV[,SEV...]] [--out-dir DIR] [--fail-on SEV]

Arguments:
  <image-ref>            Image reference to scan (registry/name:tag or local)

Options:
  --severity SEVS        Comma-separated severities to report (default: HIGH,CRITICAL)
  --out-dir DIR          Directory to write JSON results (default: ./scan-results)
  --fail-on SEV          Exit non-zero if any finding at this severity is present
                         (default: CRITICAL; use "NONE" to never fail)
  -h, --help             Show this help

Requires: trivy, grype, jq (all must be on PATH).
USAGE
  exit "${1:-0}"
}

# ---------- argument parsing --------------------------------------------------
IMAGE=""
SEVERITY="HIGH,CRITICAL"
OUT_DIR="./scan-results"
FAIL_ON="CRITICAL"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)         usage 0 ;;
    --severity)        SEVERITY="${2:?severity required}"; shift 2 ;;
    --out-dir)         OUT_DIR="${2:?out-dir required}";   shift 2 ;;
    --fail-on)         FAIL_ON="${2:?fail-on required}";   shift 2 ;;
    -*)                err "Unknown flag: $1"; usage 1 ;;
    *)
      if [[ -z "$IMAGE" ]]; then
        IMAGE="$1"
        shift
      else
        err "Unexpected positional argument: $1"
        usage 1
      fi
      ;;
  esac
done

[[ -z "$IMAGE" ]] && { err "Image reference is required."; usage 1; }

# ---------- pre-flight --------------------------------------------------------
require() {
  command -v "$1" >/dev/null 2>&1 || { err "Required tool not on PATH: $1"; exit 127; }
}
require trivy
require grype
require jq

mkdir -p "$OUT_DIR"
# Sanitize image ref into a filename-safe slug.
SLUG="$(echo "$IMAGE" | tr '/:@' '___')"
TRIVY_JSON="${OUT_DIR}/trivy-${SLUG}.json"
GRYPE_JSON="${OUT_DIR}/grype-${SLUG}.json"

cleanup() {
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    warn "scan-local exited with code $rc — partial outputs in $OUT_DIR"
  fi
}
trap cleanup EXIT

# ---------- run scanners ------------------------------------------------------
log "Scanning ${C_BLD}${IMAGE}${C_RST} with Trivy (severity=${SEVERITY})"
trivy image \
  --severity "$SEVERITY" \
  --format json \
  --output "$TRIVY_JSON" \
  --quiet \
  --no-progress \
  "$IMAGE"

log "Scanning ${C_BLD}${IMAGE}${C_RST} with Grype"
grype "$IMAGE" -o json --quiet > "$GRYPE_JSON"

# ---------- summarise ---------------------------------------------------------
log "Aggregating findings..."

trivy_summary=$(jq -r '
  [ .Results[]?.Vulnerabilities[]?.Severity ]
  | group_by(.) | map({severity: .[0], count: length})
  | sort_by(.severity)
' "$TRIVY_JSON")

grype_summary=$(jq -r '
  [ .matches[]?.vulnerability.severity ]
  | group_by(.) | map({severity: .[0], count: length})
  | sort_by(.severity)
' "$GRYPE_JSON")

echo
echo "${C_BLD}===== scan-local report for ${IMAGE} =====${C_RST}"
echo "Trivy:  $TRIVY_JSON"
echo "${trivy_summary}"
echo
echo "Grype:  $GRYPE_JSON"
echo "${grype_summary}"
echo "${C_BLD}==========================================${C_RST}"

# ---------- gating ------------------------------------------------------------
if [[ "$FAIL_ON" != "NONE" ]]; then
  trivy_hits=$(jq --arg s "$FAIL_ON" '[ .Results[]?.Vulnerabilities[]? | select(.Severity == $s) ] | length' "$TRIVY_JSON")
  grype_hits=$(jq --arg s "$FAIL_ON" '[ .matches[]? | select(.vulnerability.severity == ($s | ascii_downcase) or .vulnerability.severity == $s) ] | length' "$GRYPE_JSON")
  total=$((trivy_hits + grype_hits))

  if [[ "$total" -gt 0 ]]; then
    err "${C_RED}FAIL${C_RST}: ${total} findings at severity ${FAIL_ON} (Trivy=${trivy_hits}, Grype=${grype_hits})"
    exit 2
  fi
  log "${C_GRN}PASS${C_RST}: no findings at severity ${FAIL_ON}"
fi

trap - EXIT
