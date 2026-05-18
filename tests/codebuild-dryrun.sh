#!/usr/bin/env bash
# =============================================================================
# codebuild-dryrun.sh
# =============================================================================
#
# Exercises the shell logic from pipelines/buildspec.yml LOCALLY, without
# requiring docker, AWS credentials, or network access. Catches:
#
#   * obvious bash syntax errors
#   * unset variable references
#   * broken phase ordering / missing exported variables
#   * regressions in the tag / digest derivation logic
#
# Strategy:
#
#   1. Parse pipelines/buildspec.yml with python+PyYAML, extract every
#      command from every phase.
#   2. Stub out the commands that need real infrastructure or root --
#      docker, aws cli, curl, syft, cosign, trivy, jq, chmod, apt-get --
#      with no-op wrappers that print a "stubbed:" prefix and exit 0.
#   3. Source the resulting concatenated phase script under
#      `set -uo pipefail`; failure to expand a referenced variable will
#      bubble up as an "unbound variable" error.
#
# This is NOT a security or functional test of the pipeline. It is a
# fast smoke test that any change to the buildspec passes basic shell
# hygiene before being pushed to CodeBuild.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILDSPEC="${REPO_ROOT}/pipelines/buildspec.yml"

if [[ ! -f "${BUILDSPEC}" ]]; then
  echo "FAIL: buildspec not found at ${BUILDSPEC}" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "FAIL: python3 is required for the dry-run" >&2
  exit 1
fi

if ! python3 -c 'import yaml' 2>/dev/null; then
  echo "INFO: PyYAML not present, installing..."
  pip3 install --quiet --user PyYAML
fi

# ---------------------------------------------------------------------------
# 1. Build a sandbox dir of stub binaries on PATH.
# ---------------------------------------------------------------------------
STUB_DIR="$(mktemp -d -t codebuild-dryrun.XXXXXX)"
PHASE_SCRIPT="$(mktemp -t codebuild-phases.XXXXXX.sh)"
trap 'rm -rf "${STUB_DIR}" "${PHASE_SCRIPT}"' EXIT

# Helper: chmod stub that always succeeds. The buildspec calls
# `chmod +x /usr/local/bin/cosign` after curl-downloading the binary; in the
# sandbox we cannot write to /usr/local/bin so chmod targets a missing file.
# Treat chmod as a no-op here -- this script is about shell-hygiene, not
# filesystem semantics.
cat > "${STUB_DIR}/chmod" <<'STUB'
#!/usr/bin/env bash
# Permissive stub: print the args, always succeed.
echo "stubbed: chmod $*" >&2
exit 0
STUB
chmod +x "${STUB_DIR}/chmod"

# Helper: write a stub for each tool. The curl stub redirects
# `-o /usr/local/bin/<x>` writes into ${STUB_DIR}/<x> so subsequent
# invocations of <x> still resolve to our stub (since STUB_DIR is on PATH).
for cmd in docker aws syft cosign trivy curl jq apt-get; do
  cat > "${STUB_DIR}/${cmd}" <<STUB
#!/usr/bin/env bash
echo "stubbed: ${cmd} \$*" >&2
case "${cmd}" in
  docker)
    if [[ "\${1:-}" == "inspect" ]]; then
      # Return a fake digest reference for awk '\$F@ {print \$2}' parsing.
      echo "registry.example.invalid/repo@sha256:0000000000000000000000000000000000000000000000000000000000000000"
      exit 0
    fi
    ;;
  aws)
    if [[ "\${1:-}" == "ecr" && "\${2:-}" == "get-login-password" ]]; then
      echo "fake-token"
      exit 0
    fi
    if [[ "\${1:-}" == "kms" && "\${2:-}" == "describe-key" ]]; then
      echo "00000000-0000-0000-0000-000000000000"
      exit 0
    fi
    ;;
  syft)
    if [[ "\${1:-}" == "version" ]]; then
      echo "syft 1.10.0 (stub)"
      exit 0
    fi
    # When invoked as 'syft <image> --output spdx-json=...': emit placeholder SBOM.
    out_path=""
    for arg in "\$@"; do
      if [[ "\$arg" == spdx-json=* ]]; then
        out_path="\${arg#spdx-json=}"
      fi
    done
    if [[ -n "\${out_path}" ]]; then
      printf '{"spdxVersion":"SPDX-2.3","name":"stub"}\n' > "\${out_path}"
    fi
    exit 0
    ;;
  cosign)
    if [[ "\${1:-}" == "version" ]]; then
      echo "cosign 2.4.0 (stub)"
      exit 0
    fi
    exit 0
    ;;
  trivy)
    if [[ "\${1:-}" == "--version" ]]; then
      echo "trivy 0.55.2 (stub)"
      exit 0
    fi
    # Emit a placeholder JSON / XML report so the post_build phase parses cleanly.
    out_arg=""
    while [[ \$# -gt 0 ]]; do
      case "\$1" in
        --output) out_arg="\$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    if [[ -n "\${out_arg}" ]]; then
      if [[ "\${out_arg}" == *.json ]]; then
        printf '{"Results":[]}\n' > "\${out_arg}"
      else
        printf '<testsuite tests="0" failures="0"/>\n' > "\${out_arg}"
      fi
    fi
    exit 0
    ;;
  curl)
    # Redirect /usr/local/bin/<name> writes into STUB_DIR/<name> so subsequent
    # invocations resolve to our stub.
    out_path=""
    while [[ \$# -gt 0 ]]; do
      case "\$1" in
        -o) out_path="\$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    if [[ -n "\${out_path}" ]]; then
      if [[ "\${out_path}" == /usr/local/bin/* ]]; then
        tool_name="\$(basename "\${out_path}")"
        out_path="${STUB_DIR}/\${tool_name}"
      fi
      mkdir -p "\$(dirname "\${out_path}")"
      printf '#!/bin/sh\nexit 0\n' > "\${out_path}"
      chmod +x "\${out_path}" 2>/dev/null || true
    fi
    exit 0
    ;;
  jq)
    # The buildspec uses jq to count vulns from trivy-report.json. Our stub
    # report is {"Results":[]} -> length 0.
    echo 0
    exit 0
    ;;
  apt-get)
    exit 0
    ;;
esac
exit 0
STUB
  chmod +x "${STUB_DIR}/${cmd}"
done

# Make the stubs win over real binaries (path-wise) but keep coreutils available.
export PATH="${STUB_DIR}:${PATH}"

# ---------------------------------------------------------------------------
# 2. Required env vars (mirror what the CodeBuild project supplies).
# ---------------------------------------------------------------------------
export AWS_REGION="us-east-1"
export ECR_REGISTRY="123456789012.dkr.ecr.us-east-1.amazonaws.com"
export ECR_REPOSITORY="platform/dryrun-app"
export COSIGN_KMS_KEY_ALIAS="alias/cosign-signing"
export CODEBUILD_RESOLVED_SOURCE_VERSION="abc123def456abc123de"
export CODEBUILD_SOURCE_REPO_URL="https://github.com/example-org/example-repo.git"
export FAIL_ON_HIGH_CVE="true"

# ---------------------------------------------------------------------------
# 3. Extract every phase's commands into a single shell script.
# ---------------------------------------------------------------------------
python3 - "${BUILDSPEC}" "${PHASE_SCRIPT}" <<'PYTHON'
import json
import sys
import yaml

with open(sys.argv[1]) as fh:
    spec = yaml.safe_load(fh)

with open(sys.argv[2], "w") as out:
    out.write("#!/usr/bin/env bash\n")
    # We DELIBERATELY do not enable -e here; the buildspec phases set their
    # own -euo pipefail. Re-enabling at the top would mask the case where a
    # phase forgets to.
    out.write("set -uo pipefail\n")

    # Pre-declare exported variables so unbound checks work even before the
    # phase that defines them runs.
    for var in spec.get("env", {}).get("exported-variables", []) or []:
        out.write(f'{var}=""\n')

    # Materialise env.variables -- always-quote with JSON so no escaping
    # surprises (yaml.dump can mangle values with trailing dots or numbers).
    for k, v in (spec.get("env", {}).get("variables", {}) or {}).items():
        out.write(f"export {k}={json.dumps(str(v))}\n")

    phase_order = ["install", "pre_build", "build", "post_build"]
    for phase in phase_order:
        block = spec.get("phases", {}).get(phase)
        if not block:
            continue
        out.write(f"\necho '====> phase: {phase}'\n")
        for cmd in block.get("commands", []) or []:
            out.write(cmd.rstrip("\n") + "\n")
PYTHON

# ---------------------------------------------------------------------------
# 4. Run.
# ---------------------------------------------------------------------------
echo "==> Running ${PHASE_SCRIPT} (with stubbed binaries on PATH)"
if bash "${PHASE_SCRIPT}"; then
  echo "==> codebuild-dryrun.sh PASSED"
else
  rc=$?
  echo "==> FAIL: dry-run exited with code ${rc}" >&2
  echo "==> First 60 lines of generated script:" >&2
  sed -n '1,60p' "${PHASE_SCRIPT}" >&2
  exit "${rc}"
fi
