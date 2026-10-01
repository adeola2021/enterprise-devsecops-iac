output "github_oidc_provider_arn" {
  description = "Existing GitHub Actions OIDC provider used for workload identity federation."
  value       = data.aws_iam_openid_connect_provider.github.arn
}

output "drift_remediation_role_name" {
  description = "IAM role used by the Phase 3 GitHub Actions remediation workflow."
  value       = aws_iam_role.drift_remediation.name
}

output "drift_remediation_role_arn" {
  description = "ARN of the Phase 3 drift-remediation IAM role."
  value       = aws_iam_role.drift_remediation.arn
}
