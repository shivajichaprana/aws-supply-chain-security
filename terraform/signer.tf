###############################################################################
# AWS Signer signing profile.
#
# Why both Cosign AND AWS Signer?
#
# Cosign (KMS-backed in codebuild.tf) signs OCI image manifests so that EKS
# admission controllers (Gatekeeper / Kyverno) can refuse unsigned images at
# deploy-time. That covers the container path.
#
# AWS Signer covers the AWS-native artifact paths that Cosign does not:
#
#   * Lambda code-signing — Lambda functions can be configured with a
#     `code_signing_config` that requires every published version's deployment
#     package to carry a Signer signature; without this, malicious code pushed
#     into S3 could be promoted into Lambda.
#   * IoT firmware OTA jobs — Signer signatures are mandatory for FreeRTOS /
#     Greengrass OTA delivery.
#   * Notation (CNCF) — recent versions of AWS Signer also support a
#     "Notation-OCI-SHA384-ECDSA" platform that can sign OCI artifacts, useful
#     when standardizing on Notation rather than Cosign in the future.
#
# We provision two profiles:
#
#   1. `aws_signer_signing_profile.container` — Notation-OCI profile usable by
#      future Notation-based admission flows.
#   2. `aws_signer_signing_profile.lambda` — AWSLambda-SHA384-ECDSA profile,
#      attachable to Lambda code-signing configs in downstream stacks.
#
# Both profiles live for two years, then auto-revoke; this protects against
# long-lived key compromise.
###############################################################################

# ---------------------------------------------------------------------------
# Container image signing profile (Notation-compatible).
# ---------------------------------------------------------------------------
resource "aws_signer_signing_profile" "container" {
  name_prefix = "${replace(var.project_tag, "-", "")}_oci_"
  platform_id = "Notation-OCI-SHA384-ECDSA"

  signature_validity_period {
    type  = "YEARS"
    value = 2
  }

  tags = {
    Name    = "${var.project_tag}-container-signer"
    Purpose = "oci-image-signing"
  }
}

# ---------------------------------------------------------------------------
# Lambda code-signing profile.
#
# Downstream Lambda functions reference this profile via:
#
#   resource "aws_lambda_code_signing_config" "this" {
#     allowed_publishers {
#       signing_profile_version_arns = [
#         aws_signer_signing_profile.lambda.version_arn,
#       ]
#     }
#     policies { untrusted_artifact_on_deployment = "Enforce" }
#   }
#
# `Enforce` (vs `Warn`) means Lambda *refuses* deployments lacking a valid
# signature — the strict mode required for production.
# ---------------------------------------------------------------------------
resource "aws_signer_signing_profile" "lambda" {
  name_prefix = "${replace(var.project_tag, "-", "")}_lambda_"
  platform_id = "AWSLambda-SHA384-ECDSA"

  signature_validity_period {
    type  = "YEARS"
    value = 2
  }

  tags = {
    Name    = "${var.project_tag}-lambda-signer"
    Purpose = "lambda-code-signing"
  }
}

# ---------------------------------------------------------------------------
# Re-attach Signer permissions to the CodeBuild role created in codebuild.tf.
# Kept in this file (not codebuild.tf) so each Terraform file owns the
# resources that conceptually belong to it: codebuild.tf knows nothing about
# signer, signer.tf knows it needs to grant the build pipeline access.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "codebuild_signer" {
  statement {
    sid    = "SignerInvoke"
    effect = "Allow"
    actions = [
      "signer:StartSigningJob",
      "signer:GetSigningProfile",
      "signer:DescribeSigningJob",
      "signer:ListSigningJobs",
      "signer:GetRevocationStatus",
    ]
    resources = [
      aws_signer_signing_profile.container.arn,
      aws_signer_signing_profile.lambda.arn,
    ]
  }

  # PutSigningProfile / RevokeSigningProfile remain admin-only; the build role
  # can only consume profiles, not modify them.
}

resource "aws_iam_role_policy" "codebuild_signer" {
  name   = "${var.project_tag}-codebuild-signer"
  role   = aws_iam_role.codebuild.id
  policy = data.aws_iam_policy_document.codebuild_signer.json
}

# ---------------------------------------------------------------------------
# Outputs.
# ---------------------------------------------------------------------------
output "container_signing_profile_arn" {
  description = "ARN of the Notation-OCI container image signing profile."
  value       = aws_signer_signing_profile.container.arn
}

output "container_signing_profile_version_arn" {
  description = "Version ARN — pass this to admission controllers / Notation policies."
  value       = aws_signer_signing_profile.container.version_arn
}

output "lambda_signing_profile_arn" {
  description = "ARN of the AWS Lambda code-signing profile."
  value       = aws_signer_signing_profile.lambda.arn
}

output "lambda_signing_profile_version_arn" {
  description = "Version ARN suitable for aws_lambda_code_signing_config."
  value       = aws_signer_signing_profile.lambda.version_arn
}
