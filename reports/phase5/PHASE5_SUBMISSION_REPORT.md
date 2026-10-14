# Phase 5 — Production Security Hardening

## 1. Objective

Strengthen Terraform infrastructure security through remediation
of IaC findings, OPA policy enforcement, blocking Checkov controls,
and threat-to-control traceability.

## 2. Terraform Security Hardening

The secure AWS test fixture includes:

- S3 server-side encryption using AWS KMS.
- S3 public access restrictions.
- S3 bucket versioning and lifecycle configuration.
- S3 server access logging.
- VPC Flow Logs configuration.
- Security group restrictions.
- KMS key policy configuration.
- Default security group restrictions.

The S3 access logging destination uses SSE-S3 with a documented
Checkov exception. OPA permits this only when the required
logging-destination configuration and associated controls exist.

## 3. Checkov Validation

Critical blocking controls:

- CKV_AWS_24 — Public SSH exposure.
- CKV_AWS_145 — S3 KMS encryption.

Local validation:

- Main Terraform module: 5 passed, 0 failed.
- Secure AWS fixture: 2 passed, 0 failed, 1 skipped.
- Negative tests: Both critical vulnerabilities detected and blocked.

The GitHub Actions workflow includes positive and negative
security-gate tests.

## 4. OPA Policy Validation

All four existing regression tests passed:

1. Genuine AWS secure plan.
2. Genuine AWS insecure plan.
3. Phase 2 compliant fixture.
4. Phase 2 insecure fixture.

An additional negative test confirmed that removing the S3
logging relationship restores KMS enforcement.

## 5. Threat Modeling

PyTM identified 214 potential threats:

- Very High: 20
- High: 72
- Medium: 104
- Low: 14
- Very Low: 4

The threat-to-control matrix contains all 214 findings.

Twenty findings have predefined proposed controls.
The remaining 194 require individual assessment.

These are potential threats, not confirmed exploited vulnerabilities.
Control implementation and effectiveness remain subject to verification.

## 6. Deployment Limitations

The secure AWS fixture is intended for offline validation.

Before real AWS deployment:

- Replace placeholder account IDs and IAM roles.
- Review KMS key administration and recovery permissions.
- Validate S3 log delivery permissions and destination configuration.
- Confirm S3 bucket names are available.
- Verify service-specific permissions using actual AWS resources.
- Perform deployment testing in an authorized non-production account.

No successful AWS deployment is claimed.

## 7. Outstanding Activities

- Verify the Phase 5 workflow on GitHub Actions.
- Review final changes and security exceptions.
- Complete threat triage and assign control owners.
- Validate production-specific AWS permissions before deployment.

## 8. Conclusion

Phase 5 local security tests demonstrate functioning Terraform
policy checks, critical Checkov enforcement, negative security
tests, and an initial threat-to-control register.

Remote CI verification and production deployment validation
remain outstanding.
