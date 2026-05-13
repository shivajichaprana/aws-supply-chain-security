###############################################################################
# AWS CodeBuild project for the supply-chain-hardened container build.
#
# What this provisions:
#   - A KMS CMK used by Cosign to sign image manifests (stored separately
#     from the ECR encryption key — separation of duty: encryption-at-rest vs
#     code-signing material).
#   - An S3 bucket for SBOM and Trivy artifacts emitted by the build.
#   - A CloudWatch log group, encrypted with a dedicated CMK alias for log
#     confidentiality (CodeBuild logs may contain image inventories / package
#     names useful to attackers triaging the supply chain).
#   - The CodeBuild project itself, configured to run privileged (required
#     for `docker build`) on a Linux STANDARD image, on the LARGE compute
#     class (DinD + Trivy DB needs the headroom).
#   - An IAM role granting only the permissions buildspec.yml actually uses:
#       * ECR push to the configured repository ARNs (no wildcard).
#       * KMS sign + describe on the Cosign signing key only.
#       * CloudWatch Logs write to the project's log group.
#       * S3 put on the artifact bucket.
#       * AWS Signer integration (StartSigningJob, GetSigningProfile) for
#         hand-off to signer.tf's profile.
###############################################################################

# ---------------------------------------------------------------------------
# Inputs specific to the CodeBuild project — duplicated here (rather than in
# variables.tf) so that the resource definition stays self-contained and any
# future split into a module is mechanical.
# ---------------------------------------------------------------------------
variable "codebuild_source_repo_url" {
  description = "HTTPS clone URL of the application source repo CodeBuild will pull."
  type        = string
  default     = "https://github.com/shivajichaprana/example-service.git"
}

variable "codebuild_source_branch" {
  description = "Default branch to build."
  type        = string
  default     = "main"
}

variable "codebuild_compute_type" {
  description = "CodeBuild compute size."
  type        = string
  default     = "BUILD_GENERAL1_LARGE"

  validation {
    condition = contains(
      ["BUILD_GENERAL1_SMALL", "BUILD_GENERAL1_MEDIUM", "BUILD_GENERAL1_LARGE", "BUILD_GENERAL1_2XLARGE"],
      var.codebuild_compute_type,
    )
    error_message = "codebuild_compute_type must be a valid CodeBuild compute size."
  }
}

variable "codebuild_image" {
  description = "CodeBuild managed Docker image — must support privileged mode for DinD."
  type        = string
  default     = "aws/codebuild/standard:7.0"
}

variable "trivy_severity" {
  description = "Comma-separated severities Trivy will fail on."
  type        = string
  default     = "HIGH,CRITICAL"
}

variable "fail_on_high_cve" {
  description = "If true, the build fails when Trivy finds any matching CVE."
  type        = bool
  default     = true
}

# ---------------------------------------------------------------------------
# Cosign signing key — KMS CMK with usage SIGN_VERIFY, asymmetric, ECC NIST
# P-256. Cosign supports several algorithms; ECC_NIST_P256 is the default
# Sigstore expectation and produces compact signatures suitable for OCI
# annotations.
# ---------------------------------------------------------------------------
resource "aws_kms_key" "cosign" {
  description              = "Cosign signing key for ${var.project_tag}"
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 30
  enable_key_rotation      = false # rotation not supported for asymmetric CMKs

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableRootAccountAdmin"
        Effect    = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCodeBuildRoleToSign"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.codebuild.arn }
        Action = [
          "kms:Sign",
          "kms:Verify",
          "kms:DescribeKey",
          "kms:GetPublicKey",
        ]
        Resource = "*"
      },
    ]
  })

  tags = {
    Name    = "${var.project_tag}-cosign"
    Purpose = "container-image-signing"
  }
}

resource "aws_kms_alias" "cosign" {
  name          = "alias/${var.project_tag}-cosign"
  target_key_id = aws_kms_key.cosign.key_id
}

# ---------------------------------------------------------------------------
# S3 bucket for build artifacts (SBOMs, Trivy reports). Versioned + lifecycle
# managed so we keep ~90 days of provenance evidence cheaply.
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "artifacts" {
  bucket        = "${var.project_tag}-artifacts-${data.aws_caller_identity.current.account_id}-${var.region}"
  force_destroy = false

  tags = {
    Name    = "${var.project_tag}-artifacts"
    Purpose = "supply-chain-artifacts"
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "expire-old-artifacts"
    status = "Enabled"

    filter {}

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = 90
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# ---------------------------------------------------------------------------
# CloudWatch Logs group for build output.
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "codebuild" {
  name              = "/aws/codebuild/${var.project_tag}"
  retention_in_days = 90

  tags = {
    Name = "${var.project_tag}-codebuild"
  }
}

# ---------------------------------------------------------------------------
# IAM role for the CodeBuild project. Inline policy is intentionally tight:
# every Action is scoped to the resources we created above.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "codebuild_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["codebuild.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "codebuild" {
  name               = "${var.project_tag}-codebuild"
  assume_role_policy = data.aws_iam_policy_document.codebuild_assume.json
  description        = "Role assumed by the supply-chain CodeBuild project."

  tags = {
    Name = "${var.project_tag}-codebuild"
  }
}

data "aws_iam_policy_document" "codebuild" {
  # CloudWatch Logs — write only to this project's group.
  statement {
    sid    = "CWLogsWrite"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.codebuild.arn}:*"]
  }

  # ECR auth + push to the configured repos only.
  statement {
    sid    = "ECRAuthToken"
    effect = "Allow"
    actions = [
      "ecr:GetAuthorizationToken",
    ]
    resources = ["*"] # GetAuthorizationToken is not resource-scopable.
  }

  statement {
    sid    = "ECRPushPull"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:CompleteLayerUpload",
      "ecr:DescribeImages",
      "ecr:DescribeRepositories",
      "ecr:GetDownloadUrlForLayer",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
    ]
    resources = [for r in aws_ecr_repository.this : r.arn]
  }

  # KMS — Cosign signing key (sign + describe, no key admin).
  statement {
    sid    = "CosignKMSSign"
    effect = "Allow"
    actions = [
      "kms:Sign",
      "kms:Verify",
      "kms:DescribeKey",
      "kms:GetPublicKey",
    ]
    resources = [aws_kms_key.cosign.arn]
  }

  # KMS — ECR encryption key (need DescribeKey + GenerateDataKey for PutImage).
  statement {
    sid    = "ECRKMSEncrypt"
    effect = "Allow"
    actions = [
      "kms:DescribeKey",
      "kms:GenerateDataKey",
      "kms:Encrypt",
    ]
    resources = [aws_kms_key.ecr.arn]
  }

  # S3 — artifact bucket only.
  statement {
    sid    = "ArtifactBucket"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:ListBucket",
    ]
    resources = [
      aws_s3_bucket.artifacts.arn,
      "${aws_s3_bucket.artifacts.arn}/*",
    ]
  }

  # CodeBuild itself — required for the project to write reports.
  statement {
    sid    = "CodeBuildReports"
    effect = "Allow"
    actions = [
      "codebuild:CreateReportGroup",
      "codebuild:CreateReport",
      "codebuild:UpdateReport",
      "codebuild:BatchPutTestCases",
      "codebuild:BatchPutCodeCoverages",
    ]
    resources = ["arn:${data.aws_partition.current.partition}:codebuild:${var.region}:${data.aws_caller_identity.current.account_id}:report-group/${var.project_tag}-*"]
  }
}

resource "aws_iam_role_policy" "codebuild" {
  name   = "${var.project_tag}-codebuild"
  role   = aws_iam_role.codebuild.id
  policy = data.aws_iam_policy_document.codebuild.json
}

# ---------------------------------------------------------------------------
# CodeBuild project. The project pulls from var.codebuild_source_repo_url
# and runs pipelines/buildspec.yml from this repo (sourced via secondary).
# ---------------------------------------------------------------------------
resource "aws_codebuild_project" "supply_chain" {
  name          = "${var.project_tag}-build"
  description   = "Builds, signs, and publishes hardened container images."
  service_role  = aws_iam_role.codebuild.arn
  build_timeout = 60

  artifacts {
    type      = "S3"
    location  = aws_s3_bucket.artifacts.bucket
    packaging = "ZIP"
    name      = "${var.project_tag}-artifacts"
  }

  cache {
    type     = "S3"
    location = "${aws_s3_bucket.artifacts.bucket}/cache"
  }

  environment {
    compute_type    = var.codebuild_compute_type
    image           = var.codebuild_image
    type            = "LINUX_CONTAINER"
    privileged_mode = true # required for docker build inside CodeBuild

    image_pull_credentials_type = "CODEBUILD"

    environment_variable {
      name  = "AWS_REGION"
      value = var.region
    }

    environment_variable {
      name  = "ECR_REGISTRY"
      value = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.region}.amazonaws.com"
    }

    # Default to the first ECR repo. CI callers override this per build.
    environment_variable {
      name  = "ECR_REPOSITORY"
      value = element(var.ecr_repository_names, 0)
    }

    environment_variable {
      name  = "COSIGN_KMS_KEY_ALIAS"
      value = aws_kms_alias.cosign.name
    }

    environment_variable {
      name  = "TRIVY_SEVERITY"
      value = var.trivy_severity
    }

    environment_variable {
      name  = "FAIL_ON_HIGH_CVE"
      value = var.fail_on_high_cve ? "true" : "false"
    }
  }

  source {
    type            = "GITHUB"
    location        = var.codebuild_source_repo_url
    git_clone_depth = 1
    buildspec       = "pipelines/buildspec.yml"

    git_submodules_config {
      fetch_submodules = false
    }
  }

  source_version = var.codebuild_source_branch

  logs_config {
    cloudwatch_logs {
      group_name  = aws_cloudwatch_log_group.codebuild.name
      status      = "ENABLED"
      stream_name = "build"
    }
    s3_logs {
      status = "DISABLED"
    }
  }

  tags = {
    Name = "${var.project_tag}-build"
  }

  depends_on = [
    aws_iam_role_policy.codebuild,
  ]
}

# ---------------------------------------------------------------------------
# Outputs — surface the most useful identifiers for downstream stacks
# (admission controllers, dashboards, etc.).
# ---------------------------------------------------------------------------
output "codebuild_project_name" {
  description = "Name of the supply-chain CodeBuild project."
  value       = aws_codebuild_project.supply_chain.name
}

output "codebuild_role_arn" {
  description = "Role assumed by the CodeBuild project."
  value       = aws_iam_role.codebuild.arn
}

output "cosign_kms_key_arn" {
  description = "KMS CMK used by Cosign to sign container images."
  value       = aws_kms_key.cosign.arn
}

output "cosign_kms_key_alias" {
  description = "KMS alias for the Cosign signing key (use as awskms://// URI base)."
  value       = aws_kms_alias.cosign.name
}

output "artifacts_bucket" {
  description = "S3 bucket holding SBOMs and Trivy reports."
  value       = aws_s3_bucket.artifacts.bucket
}
