variable "region" {
  description = "AWS region for the supply-chain stack."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]+$", var.region))
    error_message = "region must be a valid AWS region identifier (e.g. us-east-1)."
  }
}

variable "environment" {
  description = "Environment name (dev/staging/prod)."
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "project_tag" {
  description = "Project tag applied to every taggable resource."
  type        = string
  default     = "aws-supply-chain-security"
}

variable "ecr_repository_names" {
  description = "List of ECR repository names to create."
  type        = list(string)
  default = [
    "platform/api",
    "platform/worker",
    "platform/web",
  ]

  validation {
    condition     = length(var.ecr_repository_names) > 0
    error_message = "At least one ECR repository name must be provided."
  }
}

variable "ecr_image_retention_count" {
  description = "Number of most-recent tagged images to retain in each ECR repository."
  type        = number
  default     = 30

  validation {
    condition     = var.ecr_image_retention_count >= 5 && var.ecr_image_retention_count <= 200
    error_message = "ecr_image_retention_count must be between 5 and 200."
  }
}

variable "ecr_untagged_retention_days" {
  description = "Days to retain untagged ECR images before purge."
  type        = number
  default     = 7
}

variable "enable_inspector_ec2" {
  description = "Whether to also enable Inspector v2 scanning for EC2 (in addition to ECR)."
  type        = bool
  default     = false
}

variable "enable_inspector_lambda" {
  description = "Whether to also enable Inspector v2 scanning for Lambda."
  type        = bool
  default     = false
}

# ---------------------------------------------------------------------------
# Security Hub — standards toggles.
# Day 52: see security-hub.tf.
# ---------------------------------------------------------------------------
variable "enable_cis_standard" {
  description = "Subscribe Security Hub to the CIS AWS Foundations Benchmark v1.4.0 standard."
  type        = bool
  default     = false
}

variable "enable_nist_standard" {
  description = "Subscribe Security Hub to the NIST 800-53 Rev 5 standard."
  type        = bool
  default     = false
}

variable "enable_pci_standard" {
  description = "Subscribe Security Hub to the PCI-DSS v3.2.1 standard."
  type        = bool
  default     = false
}

# ---------------------------------------------------------------------------
# Security Hub — product integrations.
# Inspector is always-on (see security-hub.tf); the rest are opt-in.
# ---------------------------------------------------------------------------
variable "enable_guardduty_integration" {
  description = "Subscribe to the GuardDuty -> Security Hub product integration."
  type        = bool
  default     = false
}

variable "enable_macie_integration" {
  description = "Subscribe to the Macie -> Security Hub product integration."
  type        = bool
  default     = false
}

variable "enable_access_analyzer_integration" {
  description = "Subscribe to the IAM Access Analyzer -> Security Hub product integration."
  type        = bool
  default     = false
}

variable "enable_config_integration" {
  description = "Subscribe to the AWS Config -> Security Hub product integration."
  type        = bool
  default     = false
}

variable "enable_health_integration" {
  description = "Subscribe to the AWS Health -> Security Hub product integration."
  type        = bool
  default     = false
}

variable "enable_finding_aggregation" {
  description = "Enable Security Hub cross-region finding aggregation (all regions to this region)."
  type        = bool
  default     = false
}


# ---------------------------------------------------------------------------
# EventBridge findings forwarder (Day 52).
# ---------------------------------------------------------------------------
variable "finding_severity_threshold" {
  description = "Minimum Security Hub finding severity that triggers a notification (LOW|MEDIUM|HIGH|CRITICAL)."
  type        = string
  default     = "HIGH"

  validation {
    condition     = contains(["LOW", "MEDIUM", "HIGH", "CRITICAL"], var.finding_severity_threshold)
    error_message = "finding_severity_threshold must be one of: LOW, MEDIUM, HIGH, CRITICAL."
  }
}

variable "slack_webhook_secret_name" {
  description = "Name of the Secrets Manager secret containing the Slack incoming-webhook URL (key: webhook_url). When null the Slack Lambda is not deployed and findings are still pushed to SNS."
  type        = string
  default     = null
}

variable "notification_email" {
  description = "Optional email subscribed directly to the SNS topic for findings (in addition to the Slack Lambda)."
  type        = string
  default     = null

  validation {
    condition     = var.notification_email == null || can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.notification_email))
    error_message = "notification_email must be a valid email address or null."
  }
}

variable "lambda_log_retention_days" {
  description = "CloudWatch Logs retention (days) for the Slack forwarder Lambda."
  type        = number
  default     = 30

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.lambda_log_retention_days)
    error_message = "lambda_log_retention_days must be one of the values supported by CloudWatch Logs."
  }
}
