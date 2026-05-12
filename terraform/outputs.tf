output "ecr_repository_urls" {
  description = "Map of repository name -> ECR repository URL."
  value       = { for k, r in aws_ecr_repository.this : k => r.repository_url }
}

output "ecr_repository_arns" {
  description = "Map of repository name -> ECR repository ARN."
  value       = { for k, r in aws_ecr_repository.this : k => r.arn }
}

output "ecr_kms_key_arn" {
  description = "KMS key ARN used to encrypt ECR images at rest."
  value       = aws_kms_key.ecr.arn
}

output "inspector_account_id" {
  description = "Account where Inspector v2 has been enabled."
  value       = data.aws_caller_identity.current.account_id
}

output "inspector_enabled_resources" {
  description = "Resource types Inspector v2 has been enabled for."
  value       = local.inspector_resource_types
}
