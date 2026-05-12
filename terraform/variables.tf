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
