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

# ---------------------------------------------------------------------------
# Security Hub outputs (Day 52).
# ---------------------------------------------------------------------------
output "security_hub_account_arn" {
  description = "ARN of the enabled Security Hub account resource."
  value       = aws_securityhub_account.this.arn
}

output "security_hub_standards_enabled" {
  description = "List of Security Hub standards ARNs subscribed."
  value       = local.standards_to_enable
}

output "security_hub_products_enabled" {
  description = "List of Security Hub product integration ARNs subscribed."
  value       = local.products_to_enable
}

output "security_hub_insight_arns" {
  description = "ARNs of the saved Security Hub Insights for triage."
  value = {
    open_critical_container = aws_securityhub_insight.open_critical_container_findings.arn
    ecr_misconfigurations   = aws_securityhub_insight.ecr_misconfigurations.arn
  }
}
