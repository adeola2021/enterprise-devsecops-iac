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

locals {
  mandatory_tags = {
    Environment = "dev"
    Owner       = "SecurityTeam"
    CostCenter  = "Security"
    Project     = "Enterprise-DevSecOps"
  }
}

resource "aws_kms_key" "secure" {
  description         = "KMS key for positive policy test"
  enable_key_rotation = true
  tags                = local.mandatory_tags
}

resource "aws_s3_bucket" "secure" {
  bucket = "enterprise-devsecops-phase4-secure-test"
  tags   = local.mandatory_tags
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure" {
  bucket = aws_s3_bucket.secure.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.secure.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "secure" {
  bucket = aws_s3_bucket.secure.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_security_group" "secure" {
  name        = "phase4-secure-security-group"
  description = "Positive policy test"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.mandatory_tags
}
