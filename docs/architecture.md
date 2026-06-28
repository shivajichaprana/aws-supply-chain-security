# Architecture

This document explains the design of the aws-supply-chain-security stack,
the trade-offs behind it, and the failure modes you should expect.

The complementary docs are:

- [SLSA Level 2 mapping](slsa-level2.md) — how the stack satisfies the SLSA
  Build L2 requirements, control by control.
- [Runbook](runbook.md) — the routine operating procedures (blocked
  admission, finding triage, key rotation, vault unseal).

## 1. Goals and non-goals

### Goals

1. Every container image that runs in production is **provenance-stamped**,
   **scanned**, **signed**, and **policy-verified** before admission.
2. The chain of trust is **rooted in AWS-managed primitives** (KMS, Signer,
   Inspector, ECR) — no out-of-band key custody.
3. Every gate produces a Security Hub finding, so a single Security Hub
   query gives the SOC a unified view across pipelines.
4. The stack is **reversible**: every component can be re-run against a new
   image without re-architecting; the keys and policies are stable.

### Non-goals

1. **Runtime threat detection** is out of scope — that is handled by
   GuardDuty + a separate EDR. This stack only covers build-time and
   admission-time controls.
2. **Multi-tenant isolation inside the same ECR registry** is out of scope —
   tenants are expected to have distinct ECR repositories and IAM principals.
3. **Replay protection of older signed images** is delegated to ECR's tag
   immutability + Cosign verify-time policy; there is no separate Rekor
   transparency log integration in this revision.

## 2. Component map

```
┌────────────────────────────────────────────────────────────────────────────┐
│                          Build-time (CodeBuild)                            │
│                                                                            │
│   1. checkout  ──▶  2. build  ──▶  3. SBOM (Syft) ──▶  4. sign (Cosign+KMS) │
│                                                          │                 │
│                                                          ▼                 │
│                                              5. Trivy CVE gate (HIGH/CRIT) │
│                                                          │                 │
│                                                          ▼                 │
│                                                  6. docker push  ──▶  ECR  │
└────────────────────────────────────────────────────────────────────────────┘
                                                          │
                                                          ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                          Registry hardening (ECR)                          │
│   - Immutable tags                                                         │
│   - KMS-encrypted layers                                                   │
│   - Scan-on-push (Inspector v2 enhanced scanning)                          │
│   - Lifecycle policy: keep last N tagged + last 7 days untagged            │
└────────────────────────────────────────────────────────────────────────────┘
                                                          │
                            ┌─────────────────────────────┴────────────────┐
                            ▼                                              ▼
┌──────────────────────────────────────────┐  ┌────────────────────────────────────┐
│           Aggregation (Security Hub)     │  │           Admission (EKS)          │
│   - AWS FSBP standard enabled            │  │   Gatekeeper Constraints:          │
│   - Inspector v2 integration enabled     │  │   - K8sRequireSignedImages         │
│   - EventBridge rule → Lambda → Slack    │  │   - K8sBlockHighCVE                │
└──────────────────────────────────────────┘  │   Annotations checked:             │
                                              │   - cosign.sigstore.dev/signed     │
                                              │   - inspector.aws/findings         │
                                              └────────────────────────────────────┘
```

## 3. Build phase, gate by gate

### 3.1 Build

`docker build` runs inside CodeBuild with `DOCKER_BUILDKIT=1` and three
build-args injected from the buildspec environment: `GIT_SHA`,
`GIT_BRANCH`, `BUILD_TIME`. The Dockerfile is required to copy these into
`/etc/build-info.txt` so any subsequent forensic step can correlate a
running container back to the exact source revision.

### 3.2 SBOM (Syft)

Syft emits SPDX-JSON. The SBOM is **not** sidecar metadata; it is pushed to
ECR as an OCI artifact attached to the image digest using
`oras attach`. This means deleting the image automatically orphans the
SBOM — there is no separate retention story.

### 3.3 Sign (Cosign + AWS KMS)

The signing key is an asymmetric KMS key (`SIGN_VERIFY`, `ECC_NIST_P256`).
The KMS key policy allows only the CodeBuild role to sign; only the Signer
profile role to verify; and only break-glass admins to read the key.

The signed image is then published to ECR with the original tag plus a
`-signed` suffix variant for auditors who want to grep for explicitly
verified tags.

### 3.4 Trivy gate

Trivy runs locally in CodeBuild after sign but before push. The threshold
is `HIGH,CRITICAL` and `FAIL_ON_HIGH_CVE=true`. The reason for running
Trivy in addition to Inspector v2 (which scans on push) is to provide a
**pre-push** gate — Inspector findings only become visible after the image
is in ECR, which is too late if you want to keep the registry clean.

### 3.5 Push

`docker push` happens last. ECR is configured with `IMMUTABLE` tag policy
so a re-push of an existing tag is a hard error.

## 4. Admission phase, gate by gate

### 4.1 K8sRequireSignedImages

Every container — init, main, side-car, ephemeral — must (a) come from an
approved registry prefix and (b) ride on a pod (or pod-template) carrying
`cosign.sigstore.dev/signed="true"`. The annotation is stamped by the
GitOps tool after `cosign verify` succeeds during manifest rendering.

A prefix-confusion attack (where an attacker registers a domain that
shares a prefix with an approved registry) is mitigated by appending a
trailing slash before the prefix comparison. The unit test
`test_pod_prefix_confusion_attack_fails` locks this behaviour in.

### 4.2 K8sBlockHighCVE

CodeBuild's post-push step queries Inspector v2 for findings against the
image digest and stamps the deployment with
`inspector.aws/findings=critical=N,high=N,medium=N,low=N`. The Gatekeeper
constraint fails closed if the annotation is missing (so an image that was
never scanned cannot deploy) and denies admission whenever the critical
count exceeds the configured threshold (default zero).

The "high" threshold is opt-in (`highThreshold=-1` disables it). The
rollout recommendation is: enforce critical=0 globally for at least one
sprint, then opt in to high≤5 per namespace as teams stabilise.

## 5. Aggregation

Security Hub is enabled with AWS FSBP as the baseline standard and
Inspector v2 as an integration. An EventBridge rule fires on every
`Security Hub Findings - Imported` event with severity ≥ HIGH, invoking
the `findings-forwarder` Lambda which POSTs a formatted block to Slack.

The Lambda is deliberately minimal: it does not deduplicate (we want every
finding visible) and it does not auto-close (a human triages each finding).
Future revisions may add a "first finding only per CVE per repo" rate
limiter, but only after the SOC has agreed to the trade-off.

## 6. Failure modes and recovery

| Failure                                                          | Detection                                                    | Recovery                                          |
|------------------------------------------------------------------|--------------------------------------------------------------|---------------------------------------------------|
| Trivy gate fails on a new HIGH CVE                               | CodeBuild build log + Slack notification from EventBridge    | Patch base image, re-run pipeline                 |
| Inspector finds a new CRITICAL in an already-deployed image      | Slack finding + Gatekeeper will start blocking new deploys   | Roll forward; existing pods continue running      |
| KMS key disabled / re-keyed                                      | CodeBuild fails at the sign step with a clear error          | Re-enable key or update the alias used by CB      |
| Gatekeeper Config admission down                                 | Existing Pods continue; new Pods queue (fail-open per K8s)   | Investigate Gatekeeper deployment; rollback        |
| ECR push race (someone tries to re-push an existing tag)         | `RepositoryAlreadyExistsException`                           | New tag — never reuse a published immutable tag    |
| Slack webhook compromised                                        | n/a (alerts stop arriving)                                   | Rotate webhook; rotate the SSM parameter alias    |

## 7. Cost notes

The dominant costs in this stack are Inspector v2 (per-image scan) and
CodeBuild (per-build-minute). Rough monthly back-of-envelope, assuming
50 images pushed per day with a 10-minute build each:

- CodeBuild: 50 × 10 × 30 = 15 000 min/month × $0.005/min ≈ **$75/mo**
- Inspector v2 enhanced scanning: 50 × 30 = 1 500 scans/month × $0.09 ≈ **$135/mo**
- ECR storage: ~50 GB at $0.10/GB ≈ **$5/mo**
- KMS, Signer, Security Hub, EventBridge: aggregate **< $5/mo**

Total: about **$220 / month** for a small platform team — see the
inline notes in `terraform/inspector.tf` for how to disable enhanced
scanning per-repository if cost becomes a concern.
