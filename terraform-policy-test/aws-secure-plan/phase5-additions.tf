# PHASE 5 OFFLINE SECURITY TEST FIXTURE
# This configuration is not deployment-ready.
# AWS account IDs, IAM role ARNs, and bucket names are examples.
# Validate KMS administration, S3 log delivery permissions,
# and AWS account-specific settings before any deployment.
#
data "aws_iam_policy_document" "kms" {
  statement {
    sid    = "KeyAdministration"
    effect = "Allow"

    actions = [
      "kms:DescribeKey",
      "kms:EnableKeyRotation",
      "kms:GetKeyPolicy",
      "kms:PutKeyPolicy"
    ]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:role/Phase5KMSAdministrator"]
    }

    resources = [aws_kms_key.secure.arn]
  }

  statement {
    sid    = "KeyUsage"
    effect = "Allow"

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey"
    ]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:role/Phase5S3ServiceRole"]
    }

    resources = [aws_kms_key.secure.arn]
  }
}

resource "aws_kms_key_policy" "secure" {
  key_id = aws_kms_key.secure.id
  policy = data.aws_iam_policy_document.kms.json
}

resource "aws_s3_bucket" "access_logs" {
  #checkov:skip=CKV_AWS_145:S3 server access logging destination uses SSE-S3 for AWS compatibility.
  bucket = "enterprise-devsecops-phase5-access-logs"
  tags   = local.mandatory_tags
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_logging" "secure" {
  bucket        = aws_s3_bucket.secure.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "access-logs/"
}

resource "aws_vpc" "secure" {
  cidr_block           = "10.50.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = local.mandatory_tags
}

resource "aws_subnet" "secure" {
  vpc_id                  = aws_vpc.secure.id
  cidr_block              = "10.50.1.0/24"
  map_public_ip_on_launch = false

  tags = local.mandatory_tags
}

resource "aws_network_interface" "secure" {
  subnet_id       = aws_subnet.secure.id
  security_groups = [aws_security_group.secure.id]

  tags = local.mandatory_tags
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    id     = "log-retention"
    status = "Enabled"

    filter {}

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.access_logs]
}

resource "aws_default_security_group" "secure" {
  vpc_id = aws_vpc.secure.id

  ingress = []
  egress  = []

  tags = local.mandatory_tags
}

resource "aws_flow_log" "secure" {
  vpc_id               = aws_vpc.secure.id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = aws_s3_bucket.access_logs.arn

  tags = local.mandatory_tags
}

data "aws_iam_policy_document" "access_logs" {
  statement {
    sid    = "AllowS3ServerAccessLogging"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }

    actions = ["s3:PutObject"]

    resources = [
      "${aws_s3_bucket.access_logs.arn}/access-logs/*"
    ]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = ["123456789012"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.secure.arn]
    }
  }

  statement {
    sid    = "AllowVPCFlowLogsBucketAccess"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    actions = [
      "s3:GetBucketAcl",
      "s3:ListBucket"
    ]

    resources = [aws_s3_bucket.access_logs.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = ["123456789012"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:logs:us-east-1:123456789012:*"]
    }
  }

  statement {
    sid    = "AllowVPCFlowLogsDelivery"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    actions = ["s3:PutObject"]

    resources = [
      "${aws_s3_bucket.access_logs.arn}/AWSLogs/123456789012/*"
    ]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = ["123456789012"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:logs:us-east-1:123456789012:*"]
    }
  }

}

resource "aws_s3_bucket_policy" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  policy = data.aws_iam_policy_document.access_logs.json
}
