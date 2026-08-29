terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "enterprise_data" {
  bucket = "enterprise-devsecops-demo-data"

  tags = {
    Name        = "Enterprise Data"
    Environment = "dev"
  }
}

resource "aws_s3_bucket_public_access_block" "enterprise_data" {
  bucket = aws_s3_bucket.enterprise_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "enterprise_data" {
  bucket = aws_s3_bucket.enterprise_data.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "enterprise_data" {
  bucket = aws_s3_bucket.enterprise_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }

    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "enterprise_data" {
  bucket = aws_s3_bucket.enterprise_data.id

  rule {
    id     = "enterprise-data-lifecycle"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

resource "aws_s3_bucket_logging" "enterprise_data" {
  bucket = aws_s3_bucket.enterprise_data.id

  target_bucket = aws_s3_bucket.enterprise_data.id
  target_prefix = "logs/"
}

resource "aws_security_group" "application" {
  name        = "enterprise-application-sg"
  description = "Application security group"
  vpc_id      = "vpc-12345678"

  ingress {
    description = "Allow HTTPS from trusted network"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    description = "Allow outbound HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "enterprise_database" {
  identifier        = "enterprise-devsecops-db"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  username = "admin"

  password = var.db_password

  storage_encrypted = true

  multi_az = true

  deletion_protection = true

  skip_final_snapshot = false

  backup_retention_period = 7

  copy_tags_to_snapshot = true

  auto_minor_version_upgrade = true

  performance_insights_enabled = true

  enabled_cloudwatch_logs_exports = [
    "postgresql"
  ]

  iam_database_authentication_enabled = true

  monitoring_interval = 60

  tags = {
    Name        = "Enterprise Database"
    Environment = "dev"
  }
}

variable "db_password" {
  description = "Database administrator password"
  type        = string
  sensitive   = true
}
