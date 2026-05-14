#!/usr/bin/env bash
# =============================================================================
# scripts/verify-admission.sh
# =============================================================================
#
# Integration test for the Gatekeeper admission policies in
# policies/gatekeeper/. Performs a four-phase smoke test against a live cluster:
#
#   Phase 1 -- Apply ConstraintTemplates + Constraints.
#   Phase 2 -- Attempt to deploy a pod WITHOUT the cosign / inspector
#              annotations. Expect: REJECTED by Gatekeeper.
#   Phase 3 -- Attempt to deploy a pod WITH a signed annotation but a
#              CRITICAL CVE annotation. Expect: REJECTED.
#   Phase 4 -- Attempt to deploy a pod WITH a clean signed + scan annotation.
#              Expect: ADMITTED.
#
# Prerequisites:
#   - kubectl pointed at a cluster where Gatekeeper is installed.
#   - The current kubectl context must have permission to apply
#     ConstraintTemplates and create pods.
#   - The test runs in its own namespace `gk-admission-test` which is
#     created and torn down by this script.
#
# Exit codes:
#   0  -- all four phases behaved as expected.
#   1  -- one or more phases failed (see log).
#   2  -- prerequisite check failed (kubectl/cluster/gatekeeper missing).
#
# Usage:
#   ./scripts/verify-admission.sh [--keep] [--namespace NAME]
#
# Options:
#   --keep             Leave the test namespace and resources in place after
#                      the run (useful for debugging Gatekeeper events).
#   --namespace NAME   Override the default test namespace.
# =============================================================================

set -euo pipefail

# ---------- Constants ----------
NAMESPACE="gk-admission-test"
KEEP="false"
TEST_REGISTRY="123456789012.dkr.ecr.us-east-1.amazonaws.com"
IMAGE_UNSIGNED="docker.io/library/nginx:1.27"
IMAGE_SIGNED="${TEST_REGISTRY}/sample-app:1.0.0"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLICY_DIR="${ROOT_DIR}/policies/gatekeeper"
TMP_DIR="$(mktemp -d)"
trap 'cleanup' EXIT

# ---------- Colors (skip in non-TTY environments) ----------
if [[ -t 1 ]]; then
  RED="$(tput setaf 1)"
  GREEN="$(tput setaf 2)"
  YELLOW="$(tput setaf 3)"
  BLUE="$(tput setaf 4)"
  BOLD="$(tput bold)"
  RESET="$(tput sgr0)"
else
  RED="" GREEN="" YELLOW="" BLUE="" BOLD="" RESET=""
fi

log()    { printf "%s[%s]%s %s\n" "${BLUE}"  "$(date +%H:%M:%S)" "${RESET}" "$*"; }
ok()     { printf "%s[ OK ]%s %s\n"       "${GREEN}" "${RESET}" "$*"; }
warn()   { printf "%s[WARN]%s %s\n"       "${YELLOW}" "${RESET}" "$*"; }
fail()   { printf "%s[FAIL]%s %s\n"       "${RED}"   "${RESET}" "$*"; }
bold()   { printf "%s%s%s\n"               "${BOLD}"  "$*" "${RESET}"; }

usage() {
  cat <<USAGE
Usage: $(basename "$0") [--keep] [--namespace NAME]

  --keep             Leave the test namespace in place after the run
  --namespace NAME   Override the default test namespace
                     (default: ${NAMESPACE})

This script runs four phases of admission tests against a cluster with
Gatekeeper installed. Exit code 0 means all phases passed.
USAGE
}

cleanup() {
  rm -rf "${TMP_DIR}"
  if [[ "${KEEP}" == "true" ]]; then
    warn "Keeping namespace ${NAMESPACE} for debugging (--keep was set)"
    return 0
  fi
  log "Cleaning up test namespace ${NAMESPACE}"
  kubectl delete namespace "${NAMESPACE}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kubectl delete -f "${POLICY_DIR}/constraints.yaml" --ignore-not-found >/dev/null 2>&1 || true
}

# ---------- Arg parse ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep)
      KEEP="true"; shift ;;
    --namespace)
      NAMESPACE="${2:?missing value for --namespace}"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      fail "Unknown argument: $1"; usage; exit 2 ;;
  esac
done

# ---------- Pre-flight ----------
pre_flight() {
  bold "Pre-flight checks"

  command -v kubectl >/dev/null 2>&1 \
    || { fail "kubectl not on PATH"; exit 2; }

  kubectl cluster-info >/dev/null 2>&1 \
    || { fail "kubectl cannot reach a cluster"; exit 2; }

  kubectl get crd constrainttemplates.templates.gatekeeper.sh >/dev/null 2>&1 \
    || { fail "Gatekeeper CRDs not found on cluster -- install Gatekeeper first"; exit 2; }

  [[ -f "${POLICY_DIR}/constraints.yaml" ]] \
    || { fail "Missing ${POLICY_DIR}/constraints.yaml"; exit 2; }

  ok "kubectl present, cluster reachable, Gatekeeper CRDs present"
}

# ---------- Apply constraints ----------
phase1_apply() {
  bold "Phase 1 -- Applying ConstraintTemplates + Constraints"

  kubectl apply -f "${POLICY_DIR}/constraints.yaml"

  # Gatekeeper needs a moment to register the CRDs from the ConstraintTemplates
  # before Constraint resources of those kinds can be applied. Re-apply once
  # to handle this race deterministically.
  sleep 5
  kubectl apply -f "${POLICY_DIR}/constraints.yaml"

  # Make sure the namespace exists before we try to deploy.
  kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
  # Take this namespace OUT of the exclusion list of either constraint -- the
  # default constraints exclude a few system namespaces but include ours.

  ok "Constraints applied; test namespace ${NAMESPACE} ready"
}

# ---------- Generate test manifests ----------
write_pod_manifest() {
  local name="$1" image="$2" signed="$3" findings="$4" out="$5"

  local annotations=""
  if [[ -n "${signed}" ]]; then
    annotations+="    cosign.sigstore.dev/signed: \"${signed}\"\n"
  fi
  if [[ -n "${findings}" ]]; then
    annotations+="    inspector.aws/findings: \"${findings}\"\n"
  fi

  cat > "${out}" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${name}
  namespace: ${NAMESPACE}
  annotations:
$(echo -e "${annotations}")
spec:
  restartPolicy: Never
  containers:
    - name: app
      image: ${image}
      command: ["sleep", "60"]
EOF
}

# ---------- Phase runners ----------
expect_deny() {
  local manifest="$1" reason="$2"
  if kubectl apply -f "${manifest}" >"${TMP_DIR}/out" 2>&1; then
    fail "Expected DENY but admission ALLOWED. Manifest: ${manifest}"
    cat "${TMP_DIR}/out" | sed 's/^/    /'
    return 1
  fi
  if ! grep -q -i -E "denied|violation|admission webhook" "${TMP_DIR}/out"; then
    warn "Resource was rejected but error did not mention Gatekeeper -- check output:"
    cat "${TMP_DIR}/out" | sed 's/^/    /'
  fi
  ok "Denied as expected (${reason})"
}

expect_admit() {
  local manifest="$1" reason="$2"
  if ! kubectl apply -f "${manifest}" >"${TMP_DIR}/out" 2>&1; then
    fail "Expected ADMIT but admission DENIED. Reason: ${reason}"
    cat "${TMP_DIR}/out" | sed 's/^/    /'
    return 1
  fi
  ok "Admitted as expected (${reason})"
}

phase2_unsigned() {
  bold "Phase 2 -- Unsigned image must be DENIED"
  local manifest="${TMP_DIR}/pod-unsigned.yaml"
  # No signed annotation, no inspector annotation -- both constraints should fire.
  write_pod_manifest "pod-unsigned" "${IMAGE_UNSIGNED}" "" "" "${manifest}"
  expect_deny "${manifest}" "no cosign annotation, no inspector annotation"
}

phase3_critical_cve() {
  bold "Phase 3 -- Signed image with CRITICAL CVE must be DENIED"
  local manifest="${TMP_DIR}/pod-critical-cve.yaml"
  write_pod_manifest \
    "pod-critical-cve" \
    "${IMAGE_SIGNED}" \
    "true" \
    "critical=1,high=0,medium=2,low=5" \
    "${manifest}"
  expect_deny "${manifest}" "1 CRITICAL Inspector finding"
}

phase4_clean() {
  bold "Phase 4 -- Clean signed image must be ADMITTED"
  local manifest="${TMP_DIR}/pod-clean.yaml"
  write_pod_manifest \
    "pod-clean" \
    "${IMAGE_SIGNED}" \
    "true" \
    "critical=0,high=0,medium=3,low=2" \
    "${manifest}"
  expect_admit "${manifest}" "signed, no critical findings"
}

# ---------- Main ----------
main() {
  pre_flight
  phase1_apply

  local rc=0
  phase2_unsigned     || rc=1
  phase3_critical_cve || rc=1
  phase4_clean        || rc=1

  echo
  if [[ "${rc}" -eq 0 ]]; then
    bold "${GREEN}All admission phases behaved as expected.${RESET}"
  else
    bold "${RED}One or more admission phases failed -- see log above.${RESET}"
  fi
  return "${rc}"
}

main "$@"
