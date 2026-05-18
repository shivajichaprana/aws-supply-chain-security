# Contributing

Thank you for considering a contribution. This repo is small, opinionated,
and intentionally narrow in scope — it covers container supply-chain
security on AWS and nothing else. Contributions that broaden the scope
will be deferred; contributions that deepen a single control are welcome.

## Quick map of what lives where

| You want to...                              | Edit                                                |
|---------------------------------------------|-----------------------------------------------------|
| Tighten an admission rule                   | `policies/gatekeeper/*.rego` + tests                |
| Add a new admission rule                    | See [Adding a new admission policy](#adding-a-new-admission-policy) |
| Tweak the CodeBuild pipeline                | `pipelines/buildspec.yml` + dry-run test            |
| Add a Terraform resource                    | `terraform/<area>.tf` + a corresponding test        |
| Update docs                                 | `docs/` (architecture / SLSA / runbook)             |
| Add an external integration                 | Discuss in an issue first — scope-creep risk        |

## Development workflow

1. Fork & branch from `main`. Branch names: `feat/<area>-<short>`,
   `fix/<area>-<short>`, `docs/<area>-<short>`.
2. Make your change. Keep commits small and focused — one logical change per
   commit, using [Conventional Commits](https://www.conventionalcommits.org).
3. Run the local checks:
   ```bash
   make fmt        # terraform fmt, opa fmt
   make lint       # tflint, yamllint, shellcheck
   make test       # opa test on Gatekeeper policies + drift check
   make scan       # trivy config scan on the repo
   ```
4. Open a PR. The supply-chain-ci workflow runs the same commands the
   `make` targets do, plus a few extra (Checkov, kubeconform).
5. Address review. We squash-merge.

## Adding a new admission policy

The repo's invariant is that every admission rule has **three** linked
artefacts:

1. A standalone `.rego` file in `policies/gatekeeper/` (long-comments-OK,
   the source of truth for review).
2. An inline copy of the same Rego embedded in
   `policies/gatekeeper/constraints.yaml` as a `ConstraintTemplate` (this
   is what Gatekeeper actually loads).
3. A `_test.rego` file in `tests/gatekeeper/` covering both passing and
   failing inputs.

The CI workflow runs `tests/check-constraints-drift.sh` to confirm the
inline Rego matches the standalone file. If they drift, CI fails.

### Step-by-step

```bash
# 1. Author the policy as a standalone .rego file. Heavy comments OK.
$EDITOR policies/gatekeeper/my-new-policy.rego

# 2. Write tests first; aim for 5+ test cases including edge cases.
$EDITOR tests/gatekeeper/my_new_policy_test.rego

# 3. Confirm tests pass against the standalone .rego.
opa test -v policies/gatekeeper tests/gatekeeper

# 4. Embed the Rego in constraints.yaml as a new ConstraintTemplate
#    (also create the matching Constraint binding).
$EDITOR policies/gatekeeper/constraints.yaml

# 5. Add the new kind to KIND_TO_FILE in the drift check.
$EDITOR tests/check-constraints-drift.sh
bash tests/check-constraints-drift.sh

# 6. Document in docs/ if the new control changes the architecture.
$EDITOR docs/architecture.md
```

A good policy:

- Has a clear English-language one-liner describing what it blocks.
- Has a unit test that **fails** when the policy is commented out — this
  proves the test is doing something.
- Fails closed on missing data (default-deny on absent annotation, default-
  empty parameter lists, etc.).
- Has at least one parameter so it can be tuned per-namespace without a
  code change.

## Commit-message style

Conventional Commits, lowercase subject, no full stop:

```
feat(<scope>): short imperative summary

Longer body if needed. Wrap at 72 characters. Reference issues:

Fixes #123
```

Allowed types: `feat`, `fix`, `docs`, `test`, `ci`, `refactor`, `chore`,
`build`, `style`, `perf`.

## What we will *not* merge

- Bypasses or escape hatches in the admission policies. The policies are
  designed to be all-or-nothing; tunables live in the constraint parameters.
- New external dependencies in the CodeBuild buildspec without a clear
  threat-model story (any new binary pulled into the build is a new
  supply-chain risk).
- Code generation tools (boto3 stubs, etc.) — keep the repo human-readable.
- Personal information of any kind — see `LICENSE` for the legal copyright
  notice, which is the one place a name appears.

## Security disclosures

Please do not file public issues for vulnerabilities. Open a
[GitHub Security Advisory](https://github.com/shivajichaprana/aws-supply-chain-security/security/advisories/new)
and we will coordinate disclosure.

## License

By contributing you agree your contribution is licensed under the same
MIT license that covers the rest of the repo.
