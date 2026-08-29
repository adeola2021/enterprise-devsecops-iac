# Checkov Contextual Exceptions

## Purpose

The following Checkov controls were intentionally excluded after architectural
review. They were not disabled because the controls are ineffective; they are
not applicable to the intended function of the affected resources.

## CKV2_AWS_62 — S3 Event Notifications

Affected resources:

- aws_s3_bucket.enterprise_replica
- aws_s3_bucket.access_logs

Rationale:

The enterprise replica bucket is the destination of the S3 cross-region
replication configuration. The access-logs bucket is a centralized logging
destination. Neither bucket requires an additional S3 event notification
workflow for its intended function.

Adding notifications solely to satisfy a static analysis rule could introduce
unnecessary event processing and operational complexity.

## CKV_AWS_144 — S3 Cross-Region Replication

Affected resource:

- aws_s3_bucket.access_logs

Rationale:

The access-logs bucket is the centralized logging destination. Cross-region
replication of this bucket represents an additional disaster-recovery or
regulatory requirement rather than a mandatory baseline security control.

Replication of the access-log destination should therefore be implemented only
if the organization's business continuity, disaster recovery, or regulatory
requirements require it.

## Compensating Controls

The Terraform configuration implements:

- S3 public access blocking
- S3 versioning
- S3 encryption using AWS KMS
- S3 lifecycle management
- S3 access logging
- S3 cross-region replication for enterprise data
- S3 event notifications for enterprise data
- KMS key rotation
- KMS key policy
- RDS encryption
- RDS Performance Insights encryption
- PostgreSQL query logging
- EC2 EBS encryption
- EC2 IMDSv2
- EC2 detailed monitoring
- IAM role association
- encrypted SQS
- Terraform validation
- Checkov static security analysis

## Validation

Terraform validation must return:

Success! The configuration is valid.

The final Checkov scan must report:

Failed: 0
Parsing Errors: 0
