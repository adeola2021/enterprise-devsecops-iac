# ============================================================
# PHASE 2 - ORGANIZATIONAL POLICY VARIABLES
# ============================================================

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "dev"

  validation {
    condition = contains(
      ["dev", "development", "staging", "production"],
      var.environment
    )

    error_message = "Environment must be dev, development, staging, or production."
  }
}

variable "owner" {
  description = "Resource owner"
  type        = string
  default     = "DevSecOps"
}

variable "cost_center" {
  description = "Cost center responsible for the infrastructure"
  type        = string
  default     = "IT-SEC-001"
}

# ============================================================
# EC2 POLICY-AS-CODE VARIABLE
# ============================================================

variable "instance_type" {
  description = "EC2 instance type"

  type    = string
  default = "t3.medium"
}

# ============================================================
# NETWORK VARIABLES
# ============================================================

variable "vpc_id" {
  description = "VPC ID for the application security group"
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID for the application EC2 instance"
  type        = string
}

# ============================================================
# EC2 AMI
# ============================================================

variable "application_ami" {
  description = "AMI ID for the application EC2 instance"
  type        = string
}

# ============================================================
# DATABASE
# ============================================================

variable "db_password" {
  description = "Database administrator password"
  type        = string
  sensitive   = true
}

variable "postgres_parameter_family" {
  description = "PostgreSQL RDS parameter group family"
  type        = string
  default     = "postgres16"
}
