terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
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
