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

