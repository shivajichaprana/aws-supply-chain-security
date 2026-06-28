# Runbook

Operating procedures for the routine care and feeding of the
aws-supply-chain-security stack. Each section names the symptom you would
see, the alert that fires, and the exact steps to take. Keep this open in
a tab during on-call.

## 1. Gatekeeper blocked an admission

### Symptom

A developer reports their deploy is stuck. `kubectl rollout status` shows
`waiting for rollout to finish` indefinitely. `kubectl get events -n <ns>`
shows admission webhook denials referring to `K8sRequireSignedImages` or
`K8sBlockHighCVE`.

### Diagnose

```bash
# Find the most recent denials in the cluster.
kubectl get events -A --field-selector reason=FailedCreate \
    --sort-by='.lastTimestamp' | tail -20

# Inspect the constraint status.
kubectl get K8sRequireSignedImages require-signed-images -o yaml | yq '.status'
kubectl get K8sBlockHighCVE       block-high-cve         -o yaml | yq '.status'

# Look at the offending pod manifest.
kubectl get -n <ns> deploy <name> -o yaml | yq '.spec.template.metadata.annotations'
```

### Triage tree

1. **Missing `cosign.sigstore.dev/signed` annotation?**
   The GitOps tool (Argo / Flux) is not stamping it. Confirm the
   `cosign verify` step in the rendering pipeline succeeded. If yes, the
   manifest patch is broken — fix and re-sync. If no, the image is not
   actually signed.

2. **Missing `inspector.aws/findings` annotation?**
   CodeBuild's post-push step did not query Inspector — most often because
   the image was pushed manually outside CodeBuild. The remediation is to
   re-build through CodeBuild; do NOT add the annotation by hand.

3. **`critical=N` with N > 0?**
   The image has new CRITICAL findings. Either:
   - Patch the base image and rebuild (preferred), or
   - Mark the CVE as accepted in Inspector v2 (only for FPs, with an
     explicit sign-off in the audit log).

4. **`image is not from an approved registry`?**
   The pod is pulling from an unexpected registry. Verify
   `policies/gatekeeper/constraints.yaml` lists every region your ECR is
   in. Do not add public registries (`docker.io`, `gcr.io`) to bypass.

### Recovery

For a legitimate emergency where the denied deploy must go through, the
escape hatch is to temporarily flip the constraint's `enforcementAction`
from `deny` to `dryrun`. This requires two on-call approvals and an
explicit change ticket:

```bash
kubectl patch K8sRequireSignedImages require-signed-images \
    --type=merge -p '{"spec":{"enforcementAction":"dryrun"}}'
```

Set a reminder to revert within 4 hours. The CI workflow detects the
deviation on the next PR by snapshotting the live cluster (planned for
v1.1).

---

## 2. Inspector v2 surfaced a new CRITICAL CVE

### Symptom

A Slack notification fires from the `findings-forwarder` Lambda. Severity
is CRITICAL and the affected resource is an image already in ECR.

### Diagnose

```bash
# Pull the finding from Security Hub for the full context.
aws securityhub get-findings \
  --filters '{"Title":[{"Value":"<title from Slack>","Comparison":"PREFIX"}]}' \
  --max-items 1

# Identify deployed pods using the affected image.
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name} {.spec.containers[*].image}{"\n"}{end}' \
    | grep <image-digest>
```

### Decide

| Situation                                                     | Action                                                              |
|---------------------------------------------------------------|---------------------------------------------------------------------|
| CVE has a patched upstream version                            | Bump base image, rebuild, re-deploy. Existing pods keep running.    |
| No patch yet, but workaround exists (e.g. disable a feature)  | Open a tracking issue. Pin the existing pods (immutable tag).       |
| No patch and no workaround                                    | Escalate to the security lead. Consider rotating to a different base. |
| Confirmed false positive                                      | Suppress in Inspector via "Mark as Suppressed" with justification.  |

### Recovery

There is no immediate eviction of running pods on a new CVE — only **new**
admissions are blocked. This is intentional: a hot rollback that drains
the cluster is more dangerous than an extra few hours of exposure on an
image that has already passed previous gates.

---

## 3. Cosign signing failure inside CodeBuild

### Symptom

CodeBuild build fails at the `cosign sign` step. Build log shows
`signing failed: AccessDeniedException: User: arn:aws:sts::...:assumed-role/...
is not authorized to perform: kms:Sign`.

### Diagnose

```bash
# Check the KMS key policy effective for the CodeBuild role.
KEY_ID=$(aws kms describe-key --key-id alias/cosign-signing --query KeyMetadata.KeyId --output text)
aws kms get-key-policy --key-id "$KEY_ID" --policy-name default | jq .
```

### Likely causes

1. KMS key policy was edited to remove the CodeBuild role principal.
2. CodeBuild role's IAM policy lost `kms:Sign` permission.
3. KMS key was disabled or pending deletion.
4. KMS key was re-aliased and CodeBuild still references the old alias.

### Recovery

Restore the KMS key policy and the CodeBuild IAM policy from the
Terraform-managed state:

```bash
cd terraform
terraform plan -target=aws_kms_key.cosign_signing \
               -target=aws_kms_key_policy.cosign_signing \
               -target=aws_iam_role_policy.codebuild_kms
terraform apply -target=...
```

Re-run the CodeBuild build manually with `aws codebuild start-build
--project-name supply-chain-build`.

---

## 4. Rotate the Cosign KMS key

Cosign keys should be rotated **annually** or immediately after any
suspected exposure. Rotation does not invalidate previously-signed images
because the previous public key remains verifiable.

### Steps

1. Create a new KMS key alongside the old one with a date-suffixed alias
   (`alias/cosign-signing-2027`).
2. Update `terraform/codebuild.tf` to reference the new alias.
3. Run a canary build and verify the resulting image's signature using
   the new key.
4. Update the Gatekeeper-side verification config (if you maintain a
   public-key allow-list) to include the new public key alongside the
   old one. Both keys remain trusted during the cut-over window.
5. After 90 days (longer than the longest image-deploy half-life), remove
   the old public key from the allow-list and schedule the old KMS key
   for deletion.

---

## 5. Slack webhook compromised or rate-limited

### Symptom

`findings-forwarder` Lambda logs show repeated `429 Too Many Requests`
from Slack, or worse, the webhook URL has been leaked.

### Recovery

1. Rotate the webhook from the Slack admin console. **Do this first.**
2. Update the SSM parameter the Lambda reads:
   ```bash
   aws ssm put-parameter --name /supply-chain/slack-webhook \
       --type SecureString --overwrite --value 'https://hooks.slack.com/...'
   ```
3. Confirm by tailing the Lambda log group; the next CloudWatch event will
   exercise it.
4. If rate-limited, increase the channel's webhook limit or split delivery
   across multiple channels (severity-based routing).

---

## 6. Disaster: ECR repository deleted

Tag immutability does not protect against repository deletion. If
`aws ecr delete-repository --force` is run against a production
repository, every image is gone.

### Recovery

1. Stop further deploys (set both Gatekeeper constraints to `deny` if not
   already).
2. From your image registry mirror (if you keep one — recommended), or
   from a CodeBuild rebuild of the last good tag, restore the most
   recent images.
3. Investigate the IAM policy that allowed the delete; tighten it so the
   action requires a second principal's approval (`aws_organizations_policy`
   or SCP with `ecr:DeleteRepository` denied on the prod OU).
4. Postmortem; file the deletion event ID for legal-discovery purposes.

---

## On-call quick reference

| Issue                            | First command to run                                          |
|----------------------------------|---------------------------------------------------------------|
| Admission denied                 | `kubectl get events -A --field-selector reason=FailedCreate`  |
| New CRITICAL finding             | `aws securityhub get-findings --max-items 1`                  |
| Signing failure                  | `aws kms describe-key --key-id alias/cosign-signing`          |
| Slack alerts silent              | Tail `/aws/lambda/findings-forwarder` log group               |
| ECR push 403                     | `aws ecr describe-repositories --repository-names <name>`     |
