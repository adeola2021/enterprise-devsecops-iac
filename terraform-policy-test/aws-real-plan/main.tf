terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.100.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
}

resource "aws_s3_bucket" "insecure" {
  bucket = "enterprise-devsecops-phase4-insecure-test"

  tags = {
    Environment = "dev"
    Owner       = "SecurityTeam"
    CostCenter  = "Security"
    Project     = "Enterprise-DevSecOps"
  }
}

resource "aws_security_group" "insecure" {
  name        = "phase4-insecure-security-group"
  description = "Negative policy test"

  ingress {
    from_port   = 20
    to_port     = 25
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Environment = "dev"
    Owner       = "SecurityTeam"
    CostCenter  = "Security"
    Project     = "Enterprise-DevSecOps"
  }
}
