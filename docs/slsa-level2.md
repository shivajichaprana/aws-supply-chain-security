# SLSA Build Level 2 mapping

This document maps every [SLSA v1.0 Build Level 2](https://slsa.dev/spec/v1.0/levels)
requirement to a specific control implemented by this stack, so an auditor
can walk the list once and tick every box.

## Quick verdict

| SLSA requirement                                  | Status   | Where                                                           |
|---------------------------------------------------|----------|-----------------------------------------------------------------|
| Source: identified                                | **Met**  | git SHA + branch baked into image at build time                 |
| Source: version-controlled                        | **Met**  | GitHub                                                          |
| Build: hosted                                     | **Met**  | CodeBuild (AWS-managed)                                         |
| Build: scripted                                   | **Met**  | `pipelines/buildspec.yml`                                       |
| Build: parameterless                              | **Met**  | All inputs are env vars defined on the CodeBuild project        |
| Build: isolation                                  | **Met**  | Each CodeBuild build runs in a fresh ephemeral container        |
| Provenance: exists                                | **Met**  | Cosign signature + KMS attestation cover the image digest       |
| Provenance: authenticated                         | **Met**  | KMS-backed Cosign key, key policy denies sign outside CodeBuild |
| Provenance: service-generated                     | **Met**  | Generated inside CodeBuild, never on the developer's laptop     |
| Provenance: non-falsifiable                       | **Met**  | KMS signing requires `kms:Sign` and is logged in CloudTrail     |
| Provenance: distributed                           | **Met**  | Pushed as an OCI artifact attached to the image digest in ECR   |
| Hermetic / Reproducible (L3 only)                 | Future   | Not required for L2; tracked as roadmap                         |

## Detailed walkthrough

### Source — identified, version-controlled, verifiable history

- The CodeBuild project pulls source from a specific GitHub commit SHA, not a
  branch tip. The buildspec's `pre_build` phase runs
  `git rev-parse --short=12 HEAD` and exports `IMAGE_TAG = <12-char SHA>`.
- The Dockerfile copies the SHA into `/etc/build-info.txt` so any running
  container can be traced back to its commit.
- GitHub branch protection on `main` requires PR review + supply-chain-ci
  to pass before merge. There is no force-push allowance.

### Build — hosted, scripted, parameterless, isolated

- **Hosted**: every build runs on AWS CodeBuild, not a self-hosted runner.
  The IAM role that the build assumes is provisioned in `terraform/codebuild.tf`
  and is scoped to ECR push, KMS sign, and SSM read only — no IAM admin.
- **Scripted**: every command lives in `pipelines/buildspec.yml`. There are
  no out-of-band shell scripts running on the worker. The file is reviewed
  via PR.
- **Parameterless**: CodeBuild receives no per-build inputs other than the
  source revision. All other configuration (region, registry, KMS alias,
  Trivy severity) is wired into the project as environment variables in
  Terraform; a per-build override would be visible in CloudTrail as a
  `StartBuild` parameter and would fail review.
- **Isolated**: CodeBuild starts a fresh container per build by default. The
  buildspec does not cache between builds (no `cache:` block) so a malicious
  cache poisoning attack cannot taint a future build.

### Provenance — exists, authenticated, service-generated, non-falsifiable, distributed

- **Exists**: Cosign signs the image digest at the end of every build. The
  signature is attached to ECR as an OCI artifact (Sigstore Cosign 2.x
  default). The SBOM (Syft, SPDX-JSON) is attached separately.
- **Authenticated**: The signing key is an AWS KMS asymmetric key
  (`ECC_NIST_P256`, usage `SIGN_VERIFY`). The KMS key policy restricts
  `kms:Sign` to the CodeBuild role's principal ARN and an explicit
  break-glass administrator. Every `Sign` call is recorded in CloudTrail.
- **Service-generated**: The signing operation happens inside CodeBuild,
  not on a developer's laptop. There is no path for a developer-laptop key
  to produce a signature accepted by the admission policy because the
  Gatekeeper constraint pins `approvedRegistries` to the production ECR.
- **Non-falsifiable**: An attacker would have to (a) obtain `kms:Sign`
  against the asymmetric private key — which never leaves KMS — or
  (b) replace the image at the registry layer, which is blocked by ECR
  tag immutability and would be visible in CloudTrail.
- **Distributed**: The signature lives next to the image in ECR. The SBOM
  too. A consumer can `oras pull` both without needing a separate
  artifact store.

### Why this is Build Level 2 (and not yet 3)

SLSA Build Level 3 additionally requires:

1. The build platform itself prevents tenant influence over the build (this
   is true of CodeBuild but only when the project is exclusively used for
   this purpose — multi-tenant projects need extra IAM partitioning).
2. Provenance is **hermetic**: the build must declare all inputs and the
   builder must enforce that those inputs are the only ones used. The
   current Dockerfile pulls from public package repositories at build time,
   which is the textbook L2 → L3 gap. Closing the gap requires pinning a
   private package mirror or a base image with all dependencies vendored.
3. Provenance is **reproducible**: bit-for-bit identical output across
   builds. This requires removing build-time timestamps and randomised
   layer ordering — feasible but not trivial.

These three gaps are tracked in the repo's [issue tracker](../../issues)
under the `slsa-l3` label.

## Auditor checklist

If you are auditing this repo against SLSA L2, run through this list:

- [ ] `terraform/codebuild.tf` — CodeBuild project source is `GITHUB` with
      `report_build_status = true` and `auth = "PERSONAL_ACCESS_TOKEN"`.
- [ ] `terraform/codebuild.tf` — Build env vars match what the buildspec
      expects; there is no `parameter_override` path open.
- [ ] `terraform/signer.tf` — Signing profile and KMS key policies allow only
      the CodeBuild role to sign.
- [ ] `pipelines/buildspec.yml` — All gates run under `set -euo pipefail`.
      No `|| true` after a security check.
- [ ] `policies/gatekeeper/constraints.yaml` — `approvedRegistries` lists
      only the production ECR registries.
- [ ] ECR repository policy — Tag immutability is `IMMUTABLE`.
- [ ] CloudTrail — `kms:Sign` events show only the CodeBuild role as
      `userIdentity.arn` over the most recent 30 days.
- [ ] Security Hub — AWS FSBP control `EC2.7` (default EBS encryption) and
      `KMS.4` (CMK rotation) are PASSED for the account.

Each unchecked box represents a regression to triage before re-asserting L2
status.
