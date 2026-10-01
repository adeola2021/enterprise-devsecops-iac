variable "aws_region" {
  description = "AWS region used by the Phase 3 drift-remediation workload."
  type        = string
  default     = "us-east-1"
}

variable "github_oidc_subject" {
  description = "Immutable GitHub OIDC subject restricted to the enterprise-devsecops-iac main branch."
  type        = string
  default     = "repo:adeola2021@117751150/enterprise-devsecops-iac@1337933865:ref:refs/heads/main"
}

variable "terraform_state_bucket_arn" {
  description = "ARN of the S3 bucket containing the Terraform drift-demo state."
  type        = string
  default     = "arn:aws:s3:::enterprise-devsecops-tfstate-011122914928"
}

variable "drift_parameter_arn" {
  description = "ARN of the SSM parameter approved for automatic Phase 3 remediation."
  type        = string
  default     = "arn:aws:ssm:us-east-1:011122914928:parameter/enterprise-devsecops/drift-demo"
}
