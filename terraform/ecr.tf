###############################################################################
# Amazon ECR private repositories.
#
# Design choices:
#   - One KMS CMK encrypts every repository at rest (AES_256 fallback unsupported
#     once a CMK is specified, so we use AWS_KMS encryption explicitly).
#   - Tag mutability is IMMUTABLE — once a tag points to a digest, it cannot be
#     overwritten. This blocks the entire "re-tag and re-push" class of supply-
#     chain attacks.
#   - Scan-on-push is enabled on the repository AND Inspector v2 enhanced
#     scanning is configured account-wide (see inspector.tf). Inspector v2
#     deprecates the legacy basic scan; we still keep image_scanning_configuration
#     on for backwards-compatibility / clarity.
#   - Lifecycle policy keeps the last N tagged images and purges untagged
#     images after the configured retention window. This caps storage costs
#     without losing forensic history of recent releases.
#   - A registry-level pull-through-cache rule is intentionally NOT created here.
#     Pull-through caches mirror upstream registries (e.g. public.ecr.aws) into
#     ECR; they're useful but expand the supply-chain surface area and so are
#     opt-in for downstream consumers, not baked into the baseline.
###############################################################################

locals {
  # Convert ["platform/api", "platform/worker"] into a keyed map so for_each
  # produces stable, addressable resources keyed by repo name.
  ecr_repositories = { for name in var.ecr_repository_names : name => name }
}

# ---------------------------------------------------------------------------
# KMS CMK that encrypts every ECR repository.
# ---------------------------------------------------------------------------
resource "aws_kms_key" "ecr" {
  description             = "CMK for ECR image encryption (${var.project_tag})"
  deletion_window_in_days = 30
  enable_key_rotation     = true

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
        Sid       = "AllowECRServiceUse"
        Effect    = "Allow"
        Principal = { Service = "ecr.amazonaws.com" }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:ReEncrypt*",
        ]
        Resource = "*"
      },
    ]
  })

  tags = {
    Name = "${var.project_tag}-ecr"
  }
}

resource "aws_kms_alias" "ecr" {
  name          = "alias/${var.project_tag}-ecr"
  target_key_id = aws_kms_key.ecr.key_id
}

# ---------------------------------------------------------------------------
# ECR repositories.
# ---------------------------------------------------------------------------
resource "aws_ecr_repository" "this" {
  for_each = local.ecr_repositories

  name                 = each.value
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    # Inspector v2 takes precedence once enabled at the account level, but we
    # leave scan_on_push = true for visibility and basic-scan fallback.
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ecr.arn
  }

  # We force_delete = false on purpose: an accidental `terraform destroy`
  # should NOT purge production images. Operators must empty the repo manually.
  force_delete = false

  tags = {
    Name      = each.value
    ImageType = "container"
  }
}

# ---------------------------------------------------------------------------
# Lifecycle policy:
#   - rule 1: keep only the last N tagged images per tag prefix
#   - rule 2: delete untagged images older than untagged_retention_days
# ---------------------------------------------------------------------------
resource "aws_ecr_lifecycle_policy" "this" {
  for_each = aws_ecr_repository.this

  repository = each.value.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last ${var.ecr_image_retention_count} tagged images"
        selection = {
          tagStatus     = "tagged"
          tagPatternList = ["*"]
          countType     = "imageCountMoreThan"
          countNumber   = var.ecr_image_retention_count
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Purge untagged images after ${var.ecr_untagged_retention_days} days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = var.ecr_untagged_retention_days
        }
        action = { type = "expire" }
      },
    ]
  })
}

# ---------------------------------------------------------------------------
# Registry-level scanning configuration:
#   - puts every repository created in this account onto enhanced scanning
#   - "continuous_scan" re-evaluates findings as the CVE database changes,
#     not only at push time
#
# This block is account-scoped and idempotent — applying it from multiple
# stacks in the same account is safe but discouraged. Keep the registry
# scanning configuration centralised here.
# ---------------------------------------------------------------------------
resource "aws_ecr_registry_scanning_configuration" "this" {
  scan_type = "ENHANCED"

  rule {
    scan_frequency = "CONTINUOUS_SCAN"
    repository_filter {
      filter      = "*"
      filter_type = "WILDCARD"
    }
  }

  # Keep this depends_on so registry-level config only attempts to apply
  # AFTER Inspector v2 enablement (Inspector backs enhanced scanning).
  depends_on = [aws_inspector2_enabler.this]
}

# ---------------------------------------------------------------------------
# Optional repository policy template: restricts pull to a configurable list
# of principals. We attach a single conservative policy that allows the
# account itself only — extend in downstream stacks for cross-account pulls.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "ecr_pull" {
  statement {
    sid    = "AllowAccountPull"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    actions = [
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "ecr:BatchCheckLayerAvailability",
      "ecr:DescribeImages",
      "ecr:DescribeRepositories",
      "ecr:GetRepositoryPolicy",
      "ecr:ListImages",
    ]
  }
}

resource "aws_ecr_repository_policy" "this" {
  for_each = aws_ecr_repository.this

  repository = each.value.name
  policy     = data.aws_iam_policy_document.ecr_pull.json
}
