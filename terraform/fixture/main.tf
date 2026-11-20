terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

# Mock credentials so `terraform plan` works offline. Fixture only.
provider "aws" {
  region                      = "us-east-1"
  access_key                  = "mock"
  secret_key                  = "mock"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

# VIOLATION 1: no server-side encryption (no SSE resource at all)
resource "aws_s3_bucket" "logs" {
  bucket = "segun-demo-logs-bucket"
}

# VIOLATION 2: SSH and RDP open to the world (443 must be left alone)
resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "demo"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "app" {
  name = "demo-app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

# VIOLATION 3a: wildcard IAM, heredoc form (visible to Conftest on raw HCL)
resource "aws_iam_role_policy" "god_mode_heredoc" {
  name   = "god-mode-heredoc"
  role   = aws_iam_role.app.id
  policy = <<POLICY
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
POLICY
}

# VIOLATION 3b: wildcard IAM, jsonencode form (only visible on the plan-JSON path)
resource "aws_iam_role_policy" "god_mode" {
  name = "god-mode"
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}
