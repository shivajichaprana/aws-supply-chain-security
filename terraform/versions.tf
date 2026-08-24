terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }

    # data.archive_file in findings-forwarder.tf comes from this provider.
    # tflint flags it when it is used but not declared.
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = var.project_tag
      Environment = var.environment
      ManagedBy   = "terraform"
      Repository  = "aws-supply-chain-security"
    }
  }
}

# Useful data sources reused across the stack.
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}
