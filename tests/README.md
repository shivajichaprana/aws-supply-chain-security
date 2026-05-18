# tests

Automated tests for the supply-chain-security stack. Everything here is run
on every PR by `.github/workflows/supply-chain-ci.yml`.

## Layout

| Path | Purpose |
|---|---|
| `gatekeeper/*.rego` | OPA unit tests for the Gatekeeper admission policies in `policies/gatekeeper/`. |
| `check_template_drift.py` | Detects drift between the standalone `.rego` files and the Rego embedded inside `policies/gatekeeper/constraints.yaml`. |
| `codebuild-dryrun.sh` | Smoke-runs the shell logic from `pipelines/buildspec.yml` with stubbed `docker`, `aws`, `syft`, `cosign`, and `trivy` so syntax / unset-variable errors surface in CI. |

## Run locally

```bash
# Install OPA (single static binary)
curl -fsSL -o /usr/local/bin/opa \
  https://github.com/open-policy-agent/opa/releases/download/v0.65.0/opa_linux_amd64_static
chmod +x /usr/local/bin/opa

# Rego unit tests + coverage
opa test --verbose --coverage --format=json policies/gatekeeper tests/gatekeeper | jq .

# ConstraintTemplate drift check
python3 tests/check_template_drift.py

# Buildspec dry-run
bash tests/codebuild-dryrun.sh
```

## Conventions

Rego tests live in package `<policy_name>_test` and import the policy by its
`data.<policy_name>` path. Each test function is named
`test_<scenario>_<allow|deny>` and asserts on both the violation count AND a
substring of the violation message so refactors that change wording without
changing intent are caught.
