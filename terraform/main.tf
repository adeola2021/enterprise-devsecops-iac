terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# ============================================================
# PROVIDERS
# ============================================================

provider "aws" {
  region = "us-east-1"
}

provider "aws" {
  alias  = "replica"
  region = "us-west-2"
}

# ============================================================
# DATA
# ============================================================

data "aws_caller_identity" "current" {}

# ============================================================
# LOCAL ORGANIZATIONAL TAGS
# ============================================================

locals {
  mandatory_tags = {
    Environment = var.environment
    Owner       = var.owner
    CostCenter  = var.cost_center
  }

  primary_tags = merge(
    local.mandatory_tags,
    {
      Name = "Enterprise DevSecOps"
    }
  )
}

# ============================================================
# KMS
# ============================================================

resource "aws_kms_key" "enterprise" {
  description             = "Enterprise DevSecOps encryption key"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "EnableRootPermissions"
        Effect = "Allow"

        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }

        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })

  tags = merge(
    local.mandatory_tags,
    {
      Name = "Enterprise DevSecOps KMS Key"
    }
  )
}

resource "aws_kms_alias" "enterprise" {
  name          = "alias/enterprise-devsecops"
  target_key_id = aws_kms_key.enterprise.key_id
}

# ============================================================
# S3 - PRIMARY BUCKET
# ============================================================

resource "aws_s3_bucket" "enterprise_data" {
  bucket = "enterprise-devsecops-demo-data"

  tags = merge(
    local.mandatory_tags,
    {
      Name = "Enterprise Data"
    }
  )
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
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.enterprise.arn
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

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# ============================================================
# S3 - REPLICA BUCKET
# ============================================================
resource "aws_s3_bucket" "replica_access_logs" {
  provider = aws.replica

  bucket = "enterprise-devsecops-replica-access-logs"

  tags = merge(
    local.mandatory_tags,
    {
      Name = "Enterprise Replica Access Logs"
    }
  )
}
resource "aws_s3_bucket" "enterprise_replica" {
  provider = aws.replica

  bucket = "enterprise-devsecops-demo-data-replica"

  tags = merge(
    local.mandatory_tags,
    {
      Name = "Enterprise Data Replica"
    }
  )
}
resource "aws_kms_key" "replica_access_logs" {
  provider = aws.replica

  description             = "KMS key for enterprise replica S3 access logs"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = merge(
    local.mandatory_tags,
    {
      Name = "Enterprise Replica Access Logs KMS Key"
    }
  )
}

data "aws_iam_policy_document" "replica_access_logs_kms_policy" {
  statement {
    sid    = "EnableRootPermissions"
    effect = "Allow"

    principals {
      type = "AWS"
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.replica.account_id}:root"
      ]
    }

    actions   = ["kms:*"]
    resources = [aws_kms_key.replica_access_logs.arn]
  }
}

resource "aws_kms_key_policy" "replica_access_logs" {
  provider = aws.replica

  key_id = aws_kms_key.replica_access_logs.id
  policy = data.aws_iam_policy_document.replica_access_logs_kms_policy.json
}

resource "aws_s3_bucket_public_access_block" "replica_access_logs" {
  provider = aws.replica

  bucket = aws_s3_bucket.replica_access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "replica_access_logs" {
  provider = aws.replica

  bucket = aws_s3_bucket.replica_access_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "replica_access_logs" {
  provider = aws.replica

  bucket = aws_s3_bucket.replica_access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.replica_access_logs.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "replica_access_logs" {
  provider = aws.replica

  bucket = aws_s3_bucket.replica_access_logs.id

  rule {
    id     = "replica-access-logs-lifecycle"
    status = "Enabled"

    filter {
      prefix = ""
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    expiration {
      days = 90
    }
  }
}

resource "aws_s3_bucket_logging" "enterprise_replica" {
  provider = aws.replica

  bucket        = aws_s3_bucket.enterprise_replica.id
  target_bucket = aws_s3_bucket.replica_access_logs.id
  target_prefix = "replica/"
}

resource "aws_kms_key" "enterprise_replica" {
  provider = aws.replica

  description             = "KMS key for enterprise replica S3 bucket"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = merge(
    local.mandatory_tags,
    {
      Name = "Enterprise Replica KMS Key"
    }
  )
}

data "aws_caller_identity" "replica" {
  provider = aws.replica
}

data "aws_iam_policy_document" "enterprise_replica_kms_policy" {
  statement {
    sid    = "EnableRootPermissions"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.replica.account_id}:root"
      ]
    }

    actions = [
      "kms:*"
    ]

    resources = [
      aws_kms_key.enterprise_replica.arn
    ]
  }
}

resource "aws_kms_key_policy" "enterprise_replica" {
  provider = aws.replica

  key_id = aws_kms_key.enterprise_replica.id
  policy = data.aws_iam_policy_document.enterprise_replica_kms_policy.json
}
resource "aws_s3_bucket_server_side_encryption_configuration" "enterprise_replica" {
  provider = aws.replica

  bucket = aws_s3_bucket.enterprise_replica.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.enterprise_replica.arn
    }

    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "enterprise_replica" {
  provider = aws.replica

  bucket = aws_s3_bucket.enterprise_replica.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "enterprise_replica" {
  provider = aws.replica

  bucket = aws_s3_bucket.enterprise_replica.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "enterprise_replica" {
  provider = aws.replica

  bucket = aws_s3_bucket.enterprise_replica.id

  rule {
    id     = "replica-lifecycle"
    status = "Enabled"

    filter {
      prefix = ""
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# ============================================================
# S3 - ACCESS LOGGING BUCKET
# ============================================================

resource "aws_s3_bucket" "access_logs" {
  bucket = "enterprise-devsecops-access-logs"

  tags = merge(
    local.mandatory_tags,
    {
      Name = "Enterprise Access Logs"
    }
  )
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.enterprise.arn
    }

    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    id     = "access-logs-lifecycle"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    expiration {
      days = 365
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.access_logs
  ]
}

# ============================================================
# S3 SERVER ACCESS LOGGING
# ============================================================

resource "aws_s3_bucket_logging" "enterprise_data" {
  bucket = aws_s3_bucket.enterprise_data.id

  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "enterprise-data/"
}

# NOTE:
# Cross-region S3 server access logging from the replica bucket
# to the primary-region access log bucket is intentionally omitted.
#
# The replica bucket remains protected with encryption, versioning,
# public-access blocking, and lifecycle controls.

# ============================================================
# IAM - S3 REPLICATION
# ============================================================

resource "aws_iam_role" "s3_replication" {
  name = "enterprise-devsecops-s3-replication-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Principal = {
          Service = "s3.amazonaws.com"
        }

        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(
    local.mandatory_tags,
    {
      Name = "S3 Replication Role"
    }
  )
}

resource "aws_iam_role_policy" "s3_replication" {
  name = "enterprise-devsecops-s3-replication-policy"
  role = aws_iam_role.s3_replication.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Action = [
          "s3:GetReplicationConfiguration",
          "s3:ListBucket"
        ]

        Resource = aws_s3_bucket.enterprise_data.arn
      },

      {
        Effect = "Allow"

        Action = [
          "s3:GetObjectVersionForReplication",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging"
        ]

        Resource = "${aws_s3_bucket.enterprise_data.arn}/*"
      },

      {
        Effect = "Allow"

        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicateTags"
        ]

        Resource = "${aws_s3_bucket.enterprise_replica.arn}/*"
      }
    ]
  })
}

resource "aws_s3_bucket_replication_configuration" "enterprise_data" {
  bucket = aws_s3_bucket.enterprise_data.id
  role   = aws_iam_role.s3_replication.arn

  depends_on = [
    aws_s3_bucket_versioning.enterprise_data,
    aws_s3_bucket_versioning.enterprise_replica
  ]

  rule {
    id     = "enterprise-cross-region-replication"
    status = "Enabled"

    filter {}

    destination {
      bucket = aws_s3_bucket.enterprise_replica.arn
    }
  }
}

# ============================================================
# S3 EVENT NOTIFICATION
# ============================================================

resource "aws_sqs_queue" "enterprise_events" {
  name              = "enterprise-devsecops-events"
  kms_master_key_id = aws_kms_key.enterprise.arn

  tags = merge(
    local.mandatory_tags,
    {
      Name = "Enterprise S3 Events Queue"
    }
  )
}

data "aws_iam_policy_document" "s3_sqs_policy" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    actions = [
      "sqs:SendMessage"
    ]

    resources = [
      aws_sqs_queue.enterprise_events.arn
    ]

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"

      values = [
        aws_s3_bucket.enterprise_data.arn
      ]
    }
  }
}

resource "aws_sqs_queue_policy" "enterprise_events" {
  queue_url = aws_sqs_queue.enterprise_events.id
  policy    = data.aws_iam_policy_document.s3_sqs_policy.json
}

resource "aws_s3_bucket_notification" "enterprise_data" {
  bucket = aws_s3_bucket.enterprise_data.id

  queue {
    queue_arn = aws_sqs_queue.enterprise_events.arn

    events = [
      "s3:ObjectCreated:*"
    ]
  }

  depends_on = [
    aws_sqs_queue_policy.enterprise_events
  ]
}

# ============================================================
# SECURITY GROUP
# ============================================================

resource "aws_security_group" "application" {
  name        = "enterprise-application-sg"
  description = "Enterprise application security group"

  vpc_id = var.vpc_id

  ingress {
    description = "Allow HTTPS from trusted network"

    from_port = 443
    to_port   = 443
    protocol  = "tcp"

    cidr_blocks = [
      "10.0.0.0/8"
    ]
  }

  egress {
    description = "Allow outbound HTTPS"

    from_port = 443
    to_port   = 443
    protocol  = "tcp"

    cidr_blocks = [
      "0.0.0.0/0"
    ]
  }

  tags = merge(
    local.mandatory_tags,
    {
      Name = "Enterprise Application Security Group"
    }
  )
}

# ============================================================
# IAM - APPLICATION EC2 ROLE
# ============================================================

resource "aws_iam_role" "application" {
  name = "enterprise-devsecops-application-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Principal = {
          Service = "ec2.amazonaws.com"
        }

        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(
    local.mandatory_tags,
    {
      Name = "Application EC2 IAM Role"
    }
  )
}

resource "aws_iam_instance_profile" "application" {
  name = "enterprise-devsecops-application-profile"
  role = aws_iam_role.application.name
}

# ============================================================
# EC2 APPLICATION INSTANCE
# ============================================================

resource "aws_instance" "application" {
  ami           = var.application_ami
  instance_type = var.instance_type
  subnet_id     = var.subnet_id

  vpc_security_group_ids = [
    aws_security_group.application.id
  ]

  ebs_optimized = true
  monitoring    = true

  iam_instance_profile = aws_iam_instance_profile.application.name

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    encrypted = true
  }

  tags = merge(
    local.mandatory_tags,
    {
      Name = "Enterprise Application EC2"
    }
  )
}

# ============================================================
# RDS PARAMETER GROUP
# ============================================================

resource "aws_db_parameter_group" "enterprise_postgres" {
  name   = "enterprise-devsecops-postgres"
  family = var.postgres_parameter_family

  parameter {
    name  = "log_statement"
    value = "all"
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  tags = merge(
    local.mandatory_tags,
    {
      Name = "Enterprise PostgreSQL Parameter Group"
    }
  )
}

# ============================================================
# RDS POSTGRESQL
# ============================================================

resource "aws_db_instance" "enterprise_database" {
  identifier = "enterprise-devsecops-db"

  engine         = "postgres"
  instance_class = "db.t3.micro"

  allocated_storage = 20

  username = "admin"
  password = var.db_password

  storage_encrypted = true

  multi_az = true

  deletion_protection = true

  skip_final_snapshot = false

  final_snapshot_identifier = "enterprise-devsecops-final-snapshot"

  backup_retention_period = 7

  copy_tags_to_snapshot = true

  auto_minor_version_upgrade = true

  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.enterprise.arn

  enabled_cloudwatch_logs_exports = [
    "postgresql"
  ]

  parameter_group_name = aws_db_parameter_group.enterprise_postgres.name

  iam_database_authentication_enabled = true

  monitoring_interval = 60

  tags = merge(
    local.mandatory_tags,
    {
      Name = "Enterprise PostgreSQL Database"
    }
  )
}
