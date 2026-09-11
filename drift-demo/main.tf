terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {}
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_ssm_parameter" "drift_demo" {
  name  = "/enterprise-devsecops/drift-demo"
  type  = "String"
  value = "COMPLIANT"

  tags = {
    Environment = "dev"
    Owner       = "DevSecOps"
    CostCenter  = "IT-SEC-001"
    Purpose     = "Terraform Drift Detection Demo"
  }
}
