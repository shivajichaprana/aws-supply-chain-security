#!/usr/bin/env bash
# =============================================================================
# generate-sbom.sh — local Syft wrapper for SBOM generation
# =============================================================================
#
# Wraps `syft` with sane defaults for this project:
#   * Defaults to SPDX-JSON output (the format required by the CodeBuild
#     buildspec's Cosign attestation step).
#   * Auto-detects whether the target is a local directory, an OCI image
#     reference, or an OCI archive.
#   * Optionally signs the SBOM with cosign if --sign is passed.
#
# Usage:
#   generate-sbom.sh [-o OUTPUT] [-f FORMAT] [-s] TARGET
#
#   TARGET    Image reference (123456789012.dkr.ecr.us-east-1.amazonaws.com/api:abc),
#             local path (./.), or OCI archive (oci-archive:image.tar).
#
#   -o OUTPUT Output file path. Default: sbom-<sanitized-target>.<ext>
#   -f FORMAT One of: spdx-json | spdx-tag-value | cyclonedx-json | cyclonedx-xml |
#             syft-json | syft-table. Default: spdx-json.
#   -s        Also sign the SBOM with cosign (requires COSIGN_KMS_KEY_URI in env).
#   -h        Show help.
#
# Exit codes:
#   0  SBOM generated (and optionally signed) successfully
#   1  Bad arguments
#   2  Missing dependency (syft, jq, cosign when -s)
#   3  Syft failed
#   4  Cosign signing failed
# =============================================================================

set -euo pipefail

# ---- pretty output ----------------------------------------------------------
if command -v tput >/dev/null 2>&1 && [[ -t 1 ]]; then
  C_RED="$(tput setaf 1)"
  C_GRN="$(tput setaf 2)"
  C_YLW="$(tput setaf 3)"
  C_BLU="$(tput setaf 4)"
  C_RST="$(tput sgr0)"
else
  C_RED=""; C_GRN=""; C_YLW=""; C_BLU=""; C_RST=""
fi

log()  { printf '%s[sbom]%s %s\n'   "$C_BLU" "$C_RST" "$*"; }
ok()   { printf '%s[ ok ]%s %s\n'   "$C_GRN" "$C_RST" "$*"; }
warn() { printf '%s[warn]%s %s\n'   "$C_YLW" "$C_RST" "$*" >&2; }
err()  { printf '%s[err ]%s %s\n'   "$C_RED" "$C_RST" "$*" >&2; }

# ---- usage ------------------------------------------------------------------
usage() {
  sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
}

# ---- defaults ---------------------------------------------------------------
FORMAT="spdx-json"
OUTPUT=""
SIGN="false"

# ---- arg parsing ------------------------------------------------------------
while getopts "o:f:sh" opt; do
  case "$opt" in
    o) OUTPUT="$OPTARG" ;;
    f) FORMAT="$OPTARG" ;;
    s) SIGN="true" ;;
    h) usage; exit 0 ;;
    *) usage >&2; exit 1 ;;
  esac
done
shift $((OPTIND - 1))

if [[ $# -ne 1 ]]; then
  err "exactly one TARGET argument is required"
  usage >&2
  exit 1
fi
TARGET="$1"

# ---- dependency checks ------------------------------------------------------
need() {
  command -v "$1" >/dev/null 2>&1 || { err "missing required tool: $1"; exit 2; }
}
need syft
need jq
[[ "$SIGN" == "true" ]] && need cosign

# ---- format -> extension ----------------------------------------------------
case "$FORMAT" in
  spdx-json)        EXT="spdx.json" ;;
  spdx-tag-value)   EXT="spdx" ;;
  cyclonedx-json)   EXT="cdx.json" ;;
  cyclonedx-xml)    EXT="cdx.xml" ;;
  syft-json)        EXT="syft.json" ;;
  syft-table)       EXT="txt" ;;
  *)
    err "unsupported format: $FORMAT"
    err "use one of: spdx-json, spdx-tag-value, cyclonedx-json, cyclonedx-xml, syft-json, syft-table"
    exit 1
    ;;
esac

# ---- derive default output --------------------------------------------------
if [[ -z "$OUTPUT" ]]; then
  SANITIZED="$(printf '%s' "$TARGET" | tr '/:@' '___' | tr -cd 'A-Za-z0-9._-')"
  OUTPUT="sbom-${SANITIZED}.${EXT}"
fi

# ---- temp + cleanup ---------------------------------------------------------
TMP_DIR="$(mktemp -d -t sbom.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

# ---- run syft ---------------------------------------------------------------
log "Generating SBOM"
log "  target : $TARGET"
log "  format : $FORMAT"
log "  output : $OUTPUT"

# Syft auto-detects scheme (image vs dir vs oci-archive). We pass the target
# verbatim so users may use any scheme prefix they like.
if ! syft "$TARGET" --output "${FORMAT}=${OUTPUT}" --quiet; then
  err "syft failed to generate SBOM"
  exit 3
fi

# ---- post-validate ----------------------------------------------------------
SIZE_BYTES="$(wc -c < "$OUTPUT" | tr -d ' ')"
if [[ "$SIZE_BYTES" -lt 64 ]]; then
  err "SBOM output suspiciously small ($SIZE_BYTES bytes) — aborting"
  exit 3
fi

# Quick sanity check for SPDX outputs.
if [[ "$FORMAT" == "spdx-json" ]]; then
  if ! jq -e '.SPDXID and .packages' "$OUTPUT" >/dev/null 2>&1; then
    warn "SBOM JSON missing SPDXID/packages keys — output may be malformed"
  else
    PKG_COUNT="$(jq '.packages | length' "$OUTPUT")"
    ok "SPDX SBOM contains $PKG_COUNT packages"
  fi
fi

ok "SBOM written: $OUTPUT ($SIZE_BYTES bytes)"

# ---- optional sign ---------------------------------------------------------
if [[ "$SIGN" == "true" ]]; then
  if [[ -z "${COSIGN_KMS_KEY_URI:-}" ]]; then
    err "--sign requested but COSIGN_KMS_KEY_URI is not set"
    err "  example: export COSIGN_KMS_KEY_URI=awskms:///alias/aws-supply-chain-security-cosign"
    exit 4
  fi
  log "Signing SBOM with cosign (key: $COSIGN_KMS_KEY_URI)"
  if ! cosign sign-blob --yes --key "$COSIGN_KMS_KEY_URI" \
        --output-signature "${OUTPUT}.sig" \
        "$OUTPUT"; then
    err "cosign sign-blob failed"
    exit 4
  fi
  ok "Signature written: ${OUTPUT}.sig"
fi
