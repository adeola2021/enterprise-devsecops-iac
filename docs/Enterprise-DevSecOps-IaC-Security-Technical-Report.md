# ENTERPRISE DEVSECOPS INFRASTRUCTURE-AS-CODE SECURITY PIPELINE

## Technical Implementation and Security Assessment Report

**Project:** Enterprise DevSecOps IaC Security Pipeline
**Author:** Segun Jemilohun
**Repository:** https://github.com/adeola2021/enterprise-devsecops-iac
**Primary Platform:** Amazon Web Services (AWS)
**Infrastructure-as-Code:** Terraform
**Security Assessment Tools:** Checkov, Gitleaks, Semgrep, PyTM
**Repository:** GitHub
**Final Branch:** `main`

---

# 1. Executive Summary

This project implements an enterprise-oriented **DevSecOps Infrastructure-as-Code (IaC) security pipeline** designed to integrate security controls directly into the infrastructure development lifecycle.

The implementation addresses security risks across cloud infrastructure, application code, secrets, configuration, and architectural threat exposure. The project follows a **shift-left security** approach, whereby security weaknesses are identified and remediated before infrastructure is deployed.

The solution combines Terraform-based infrastructure provisioning with automated security validation using:

* Terraform validation and formatting.
* Checkov Infrastructure-as-Code security scanning.
* Gitleaks secrets detection.
* Semgrep static application security testing.
* PyTM threat modelling.
* Automated security-gate scripts.
* AWS encryption and key-management controls.
* S3 logging, versioning, lifecycle management and replication.
* IAM-based access control.
* SQS-based event notification.
* Security evidence generation and retention.

The project deliberately began with vulnerable configurations to demonstrate a complete security lifecycle:

**Identify → Assess → Remediate → Re-test → Validate → Commit → Publish**

The final security validation produced **105 successful Checkov checks, zero failed checks, zero skipped checks and zero parsing errors across 31 Terraform resources**.

The final Gitleaks working-tree scan also reported **no leaks**, while the Git-history scan reported **no leaks across the scanned commit history**.

The final Git repository was verified to be clean and synchronized with GitHub.

---

# 2. Project Background

Modern cloud environments increasingly rely on Infrastructure-as-Code to provision and manage infrastructure. Although IaC improves consistency and automation, insecure infrastructure definitions can introduce vulnerabilities at scale.

A single insecure Terraform configuration can potentially result in:

* Publicly accessible storage.
* Unencrypted data.
* Excessive permissions.
* Weak network controls.
* Inadequate logging.
* Poor data-retention controls.
* Insufficient disaster recovery mechanisms.
* Credential exposure.
* Insecure application configurations.

This project addresses these risks by integrating security testing into the infrastructure development lifecycle.

The project therefore treats security as a continuous engineering activity rather than a final deployment-stage review.

---

# 3. Project Objectives

The primary objectives were to:

1. Implement secure cloud infrastructure using Terraform.
2. Identify security weaknesses in Infrastructure-as-Code.
3. Establish automated IaC security scanning.
4. Detect secrets and credentials before they enter the repository.
5. Apply static security analysis to application code.
6. Implement AWS encryption and key-management controls.
7. Implement secure S3 configuration.
8. Establish logging and monitoring mechanisms.
9. Implement cross-region replication.
10. Implement event-driven security monitoring.
11. Conduct structured threat modelling.
12. Establish automated security gates.
13. Preserve security assessment evidence.
14. Demonstrate vulnerability remediation.
15. Validate the final infrastructure before repository publication.

---

# 4. Scope

The project covers the security assessment and hardening of:

### Infrastructure

* Amazon S3
* AWS KMS
* AWS IAM
* Amazon RDS
* Amazon EC2
* VPC/security groups
* Amazon SQS
* S3 replication
* S3 logging
* S3 lifecycle controls
* S3 event notifications

### Application

* Python application code
* Application configuration
* Environment-based secret handling

### Security controls

* Checkov
* Gitleaks
* Semgrep
* PyTM
* Terraform validation
* Automated security gate
* Git repository controls

---

# 5. Technology Stack

| Component              | Technology    |
| ---------------------- | ------------- |
| Operating System       | Ubuntu        |
| Infrastructure-as-Code | Terraform     |
| Cloud Platform         | AWS           |
| Source Control         | Git / GitHub  |
| IaC Security           | Checkov       |
| Secret Detection       | Gitleaks      |
| SAST                   | Semgrep       |
| Threat Modelling       | PyTM          |
| Encryption             | AWS KMS       |
| Storage                | Amazon S3     |
| Messaging              | Amazon SQS    |
| Database               | Amazon RDS    |
| Compute                | Amazon EC2    |
| Automation             | Bash / Python |
| Repository Branch      | `main`        |

---

# 6. Security Architecture

The implemented security architecture follows a layered defense model.

```text
                       DEVELOPER
                           |
                           v
                    GIT REPOSITORY
                         GitHub
                           |
          +----------------+----------------+
          |                |                |
          v                v                v
      Gitleaks          Semgrep          Checkov
    Secret Scan         SAST             IaC Scan
          |                |                |
          +----------------+----------------+
                           |
                           v
                  SECURITY GATE
                           |
                    +------+------+
                    |             |
                  FAIL           PASS
                    |             |
                  STOP            v
                              Terraform
                              Validation
                                  |
                                  v
                             AWS IaC
                                  |
       +------------+-------------+-------------+
       |            |             |             |
       v            v             v             v
      S3           RDS           EC2           IAM
       |
       +----------------+
       |                |
       v                v
     KMS             SQS Events
       |
       v
 Encryption / Monitoring

                  PyTM Threat Model
                         |
                         v
                Threat Identification
                         |
                         v
                    Risk Analysis
```

---

# 7. Initial Vulnerable State

The project maintained an intentionally vulnerable Terraform baseline in:

```text
archive/vulnerable-terraform/main.vulnerable.tf
```

This allowed the security pipeline to demonstrate actual vulnerability identification rather than simply documenting theoretical controls.

The vulnerable baseline was assessed using Checkov and other security controls before remediation.

Evidence from the Checkov assessment demonstrates that security weaknesses were initially identified within the Terraform configuration.

For example, an earlier Checkov result identified deficiencies relating to S3 controls, including:

* S3 versioning.
* S3 lifecycle configuration.
* S3 event notifications.
* Cross-region replication.

The project subsequently introduced the required controls and repeatedly re-ran the security assessment.

---

# 8. Terraform Security Implementation

Terraform was used to define the AWS infrastructure in a reproducible and auditable manner.

The main infrastructure configuration is:

```text
terraform/main.tf
```

Terraform was validated using:

```bash
terraform -chdir=terraform fmt -check -recursive
terraform -chdir=terraform validate
```

Final validation returned:

```text
Success! The configuration is valid.
```

This demonstrates that the final Terraform configuration was syntactically and structurally valid.

---

# 9. AWS S3 Security Controls

S3 was one of the principal security-control areas in the project.

The final Terraform implementation included separate resources for:

* Enterprise data bucket.
* Enterprise replica bucket.
* Access-logging bucket.
* S3 versioning.
* S3 lifecycle management.
* S3 encryption.
* S3 public-access blocking.
* S3 logging.
* S3 replication.
* S3 event notifications.

The project therefore moved beyond simple bucket creation and implemented multiple layers of protection.

---

## 9.1 S3 Versioning

Versioning was implemented for the primary data bucket, replica bucket and access-log bucket.

This protects against accidental deletion or overwriting of objects and provides an additional recovery mechanism.

The final Checkov result confirms that the previously identified versioning issue for the access-log bucket was remediated.

---

## 9.2 S3 Public Access Protection

The buckets implement:

```text
block_public_acls       = true
block_public_policy     = true
ignore_public_acls      = true
restrict_public_buckets = true
```

This reduces the likelihood of unintended public exposure.

---

## 9.3 S3 Encryption

The project implements server-side encryption using AWS KMS.

The access-log bucket specifically uses:

```text
sse_algorithm     = "aws:kms"
kms_master_key_id = aws_kms_key.enterprise.arn
```

Bucket keys are also enabled.

This provides encryption-at-rest protection for stored data.

---

## 9.4 S3 Lifecycle Management

Lifecycle configurations were implemented to manage:

* Incomplete multipart uploads.
* Non-current object versions.
* Object expiration.

The access-log bucket was configured with a retention period of 365 days and non-current-version expiration.

An earlier Checkov failure relating to lifecycle management was subsequently remediated.

---

## 9.5 S3 Access Logging

S3 access logging was implemented using the dedicated:

```text
aws_s3_bucket.access_logs
```

bucket.

The primary data bucket and replica bucket were configured to send access logs to the dedicated logging bucket.

This improves auditability and supports security monitoring.

---

# 10. Cross-Region Replication

The project implemented cross-region S3 replication using:

```text
aws_s3_bucket_replication_configuration.enterprise_data
```

The architecture uses:

```text
Primary Region
us-east-1
     |
     | Replication
     v
Replica Region
us-west-2
```

A dedicated IAM role was created for S3 replication.

The configuration includes permissions required to:

* Read replication configuration.
* List the source bucket.
* Read object versions.
* Replicate objects.
* Replicate deletes.
* Replicate tags.

This improves resilience and provides a mechanism for cross-region recovery.

---

# 11. S3 Event Notifications

An Amazon SQS queue was implemented for S3 event processing:

```text
aws_sqs_queue.enterprise_events
```

The S3 bucket notification configuration sends events to the queue.

A queue policy restricts message submission to the S3 service and limits the source to the designated S3 bucket.

This provides an event-driven mechanism that can support downstream monitoring and security workflows.

---

# 12. AWS KMS

A dedicated KMS key was implemented to protect sensitive resources.

The configuration includes:

* Customer-managed KMS key.
* Key rotation.
* IAM-controlled access.
* S3 encryption.
* SQS encryption.

Key rotation was enabled:

```text
enable_key_rotation = true
```

This provides stronger cryptographic key-management practices than relying solely on unencrypted storage.

---

# 13. IAM Security

A dedicated IAM role was created for S3 replication.

The role uses an S3 service principal:

```text
s3.amazonaws.com
```

The permissions are scoped to the resources required for replication.

This demonstrates the use of service-specific permissions rather than broad administrative access.

---

# 14. Application Security

The project also includes a sample Python application:

```text
app/
├── config.py
└── vulnerable_app.py
```

The application configuration retrieves sensitive values through environment variables rather than embedding actual credentials directly in source code.

For example:

```text
ENTERPRISE_API_KEY
ENTERPRISE_DATABASE_PASSWORD
```

This supports secure separation between application configuration and credentials.

---

# 15. Gitleaks Secret Detection

Gitleaks was used to identify secrets and credential-like patterns.

The final working-tree scan was executed using:

```bash
gitleaks detect \
  --source . \
  --no-git \
  --report-format json \
  --report-path reports/gitleaks-final-working-tree.json
```

Final result:

```text
scanned ~3926872 bytes (3.93 MB)
no leaks found
```

### Final working-tree status

```text
Findings: 0
STATUS: PASS
NO SECRETS DETECTED
```

A separate Git-history scan was also performed:

```bash
gitleaks detect \
  --source . \
  --report-format json \
  --report-path reports/gitleaks-final-history.json
```

Result:

```text
1 commits scanned.
scanned ~2312874 bytes (2.31 MB)
no leaks found
```

### Security significance

The two scans provide complementary evidence:

* The working-tree scan verifies the current project contents.
* The history scan verifies the scanned Git history.

Both produced **no leaks**.

---

# 16. Semgrep Static Analysis

Semgrep was integrated into the security architecture to provide static analysis of application code.

Custom security rules are maintained in:

```text
security/semgrep-rules.yml
```

The repository also retains:

```text
reports/semgrep-vulnerable.json
reports/semgrep-remediated.json
reports/semgrep-gate.json
```

This creates an auditable record of the application's security assessment and remediation lifecycle.

---

# 17. Threat Modelling

PyTM was used to perform structured threat modelling.

The implementation is maintained in:

```text
threat-model/threat_model.py
```

Generated evidence includes:

```text
reports/pytm-threat-model.json
reports/pytm-threat-matrix.csv
reports/pytm-high-risk-threats.csv
reports/pytm-severity-summary.txt
reports/pytm-target-risk-summary.txt
reports/enterprise-threat-model.dot
reports/enterprise-threat-model.png
reports/enterprise-threat-model.svg
reports/enterprise-threat-sequence.dot
```

The generated threat model identified **214 threats** across the modelled system.

Examples of identified threat categories included:

* High-severity threats.
* Very-high-severity threats.
* Medium-severity threats.
* Access-control threats.
* Input-validation threats.
* Data-security threats.
* Availability threats.
* Supply-chain threats.

The evidence demonstrates that threat modelling was used as a design and risk-analysis activity rather than simply as documentation. The stored outputs allow individual threats and target components to be reviewed.

---

# 18. Automated Security Gate

The central automation is:

```text
scripts/security_gate.sh
```

The security gate is designed to combine security controls and provide an explicit security decision.

Conceptually:

```text
                 SECURITY GATE
                       |
        +--------------+--------------+
        |              |              |
        v              v              v
     Checkov        Gitleaks       Semgrep
        |              |              |
        +--------------+--------------+
                       |
                       v
                Policy Decision
                       |
              +--------+--------+
              |                 |
            FAIL               PASS
              |                 |
             STOP            Continue
```

The repository retains security-gate evidence in:

```text
reports/security-gate.log
reports/security-gate-pass.log
reports/security-gate-final.log
reports/security-gate-final-status.txt
```

---

# 19. Checkov Security Assessment

Checkov was used as the principal IaC security scanner.

The final report was verified programmatically using:

```text
reports/checkov-final.json/results_json.json
```

The final verification produced:

```text
==============================================
FINAL ENTERPRISE IaC SECURITY GATE
==============================================
Checkov Version : 3.3.15
Resources       : 31
Passed          : 105
Failed          : 0
Skipped         : 0
Parsing Errors  : 0
----------------------------------------------
STATUS           : PASS
SECURITY GATE    : PASSED
==============================================
```

### Final Checkov metrics

| Metric              | Final Result |
| ------------------- | -----------: |
| Checkov Version     |       3.3.15 |
| Terraform Resources |           31 |
| Passed Checks       |      **105** |
| Failed Checks       |        **0** |
| Skipped Checks      |        **0** |
| Parsing Errors      |        **0** |
| Security Gate       |     **PASS** |

This is the principal quantitative evidence that the final Terraform configuration satisfied the configured Checkov security controls.

---

# 20. Checkov Remediation Journey

The project provides useful evidence of progressive remediation.

At one stage, the scan reported:

```text
Passed : 105
Failed : 5
```

The remaining findings included:

```text
CKV2_AWS_62
S3 event notifications

CKV_AWS_144
S3 cross-region replication

CKV2_AWS_61
S3 lifecycle configuration

CKV_AWS_21
S3 versioning
```

After remediation, the findings were reduced to:

```text
Passed : 107
Failed : 4
```

Then:

```text
Passed : 108
Failed : 3
```

Finally:

```text
Passed : 105
Failed : 0
```

The important outcome is not simply the final score; it demonstrates that the infrastructure was repeatedly assessed and hardened until the configured security gate passed.

---

# 21. Security Findings and Remediation

The major remediation themes were:

| Security Area          | Initial Condition            | Remediation                             |
| ---------------------- | ---------------------------- | --------------------------------------- |
| S3 Versioning          | Missing on access-log bucket | Versioning enabled                      |
| S3 Lifecycle           | Incomplete                   | Lifecycle configuration added           |
| S3 Event Notifications | Missing                      | S3-to-SQS notification implemented      |
| S3 Replication         | Missing                      | Cross-region replication implemented    |
| S3 Logging             | Deficient                    | Dedicated access-log bucket implemented |
| S3 Encryption          | Strengthened                 | KMS-backed encryption implemented       |
| Public Access          | Security risk                | Public-access blocking enabled          |
| Secret Exposure        | Potential risk               | Gitleaks validation implemented         |
| Application Security   | Vulnerable baseline          | Semgrep controls implemented            |
| Threat Exposure        | Not formally modelled        | PyTM threat model implemented           |

---

# 22. Security Evidence Repository

The repository maintains extensive evidence supporting the implementation.

Important evidence includes:

```text
reports/
```

### Checkov

```text
checkov-vulnerable-baseline.json
checkov-vulnerable-results.json
checkov-remediated.json
checkov-remediated-final.json
checkov-final-pre-exceptions.json
checkov-final.json
checkov-exceptions.md
```

### Gitleaks

```text
gitleaks-vulnerable.json
gitleaks-remediated.json
gitleaks-final.json
gitleaks-final-working-tree.json
gitleaks-final-history.json
```

### Semgrep

```text
semgrep-vulnerable.json
semgrep-remediated.json
semgrep-gate.json
```

### Threat Model

```text
pytm-threat-model.json
pytm-threat-matrix.csv
pytm-high-risk-threats.csv
pytm-severity-summary.txt
pytm-target-risk-summary.txt
enterprise-threat-model.png
enterprise-threat-model.svg
```

### Security Gate

```text
security-gate.log
security-gate-pass.log
security-gate-final.log
security-gate-final-status.txt
```

This evidence structure supports auditability and allows a reviewer to independently trace the project's security journey.

---

# 23. Repository Security Controls

The project uses `.gitignore` to prevent sensitive and temporary files from being committed.

Important exclusions include:

```text
terraform/.terraform/
terraform/*.tfstate
terraform/*.tfvars
terraform/*.tfvars.json
*.pem
*.key
*.p12
*.pfx
.env
venv/
terraform-backup-*/
```

The final repository verification confirmed that Terraform state and sensitive key files were not present in the tracked project contents.

The final Gitleaks scan additionally reported no secrets.

---

# 24. Git Repository Verification

The repository was initialized and committed to Git.

The final branch is:

```text
main
```

The configured remote is:

```text
https://github.com/adeola2021/enterprise-devsecops-iac.git
```

The latest project commit is:

```text
c95497d docs: add comprehensive project documentation
```

The preceding security-related commits include:

```text
86d280a docs: add final Gitleaks security verification reports
e58ff99 feat: implement enterprise DevSecOps IaC security pipeline
```

The final Git verification returned:

```text
On branch main
Your branch is up to date with 'origin/main'.

nothing to commit, working tree clean
```

This confirms that the local repository and GitHub repository were synchronized.

---

# 25. Final End-to-End Verification

The final verification consisted of multiple independent checks.

### Terraform

```text
Terraform format       : PASS
Terraform validation   : PASS
```

### Checkov

```text
Resources              : 31
Passed                 : 105
Failed                 : 0
Skipped                : 0
Parsing Errors         : 0
Security Gate          : PASS
```

### Gitleaks

```text
Working Tree           : PASS
Git History            : PASS
Secrets Detected       : 0
```

### Git

```text
Branch                 : main
Remote                 : origin/main
Working Tree           : CLEAN
```

---

# 26. Final Security Posture

The final security posture can be summarized as follows:

| Security Control               | Final Status |
| ------------------------------ | ------------ |
| Terraform syntax/configuration | PASS         |
| Terraform formatting           | PASS         |
| Checkov IaC security           | PASS         |
| Checkov failed checks          | **0**        |
| Checkov skipped checks         | **0**        |
| Checkov parsing errors         | **0**        |
| Resources assessed             | **31**       |
| Checkov controls passed        | **105**      |
| Gitleaks working-tree scan     | PASS         |
| Gitleaks Git-history scan      | PASS         |
| Secrets detected               | **0**        |
| Semgrep                        | Implemented  |
| Threat modelling               | Implemented  |
| AWS KMS                        | Implemented  |
| S3 encryption                  | Implemented  |
| S3 versioning                  | Implemented  |
| S3 lifecycle                   | Implemented  |
| S3 logging                     | Implemented  |
| S3 replication                 | Implemented  |
| S3 event notifications         | Implemented  |
| IAM replication controls       | Implemented  |
| Security evidence              | Retained     |
| GitHub publication             | PASS         |
| Working tree                   | CLEAN        |

---

# 27. Risk Reduction Assessment

The project demonstrates measurable security improvement between the vulnerable baseline and final implementation.

The most significant improvements were achieved in the following areas:

### Confidentiality

Improved through:

* KMS-backed encryption.
* S3 public-access blocking.
* IAM-based permissions.
* Secret detection.

### Integrity

Improved through:

* S3 versioning.
* IaC security validation.
* Git-based change control.
* Automated security gates.

### Availability

Improved through:

* Cross-region S3 replication.
* Lifecycle management.
* Event-driven monitoring.

### Accountability

Improved through:

* S3 access logging.
* Security scan reports.
* Threat-model outputs.
* Git history.
* Security-gate logs.

---

# 28. Lessons Learned

The implementation demonstrated several important DevSecOps principles.

### 28.1 Security must be automated

Manual reviews alone are insufficient for infrastructure that changes frequently. Automated scanning provides repeatable security validation.

### 28.2 IaC security must occur before deployment

Checkov successfully identified configuration weaknesses before infrastructure deployment.

### 28.3 Security controls often require multiple layers

No single control provides complete protection. Encryption, access control, logging, replication, secrets detection and IaC scanning work together.

### 28.4 Security evidence is important

Retaining vulnerable, remediated and final scan results makes the security lifecycle auditable.

### 28.5 Secrets should never be treated as ordinary configuration

Gitleaks provides an additional control for detecting accidental credential exposure.

### 28.6 Threat modelling complements automated scanning

Static scanners identify known configuration weaknesses, while threat modelling provides broader visibility into architectural attack paths and potential threats.

---

# 29. Recommendations for Further Enhancement

Although the final security gate passed, the following improvements could further mature the solution:

1. Integrate the security gate directly into GitHub Actions.
2. Require successful security checks before pull-request merging.
3. Enable branch protection on `main`.
4. Add Terraform plan scanning to the CI/CD workflow.
5. Introduce Terraform provider version management and scheduled updates.
6. Add infrastructure drift detection.
7. Integrate centralized AWS logging and monitoring.
8. Introduce AWS CloudTrail and GuardDuty where appropriate.
9. Add container image scanning if application containers are introduced.
10. Implement cryptographic image signing using Cosign for containerized workloads.
11. Generate and retain SLSA provenance for software builds.
12. Introduce policy-as-code enforcement at deployment time.
13. Schedule recurring security scans to detect newly disclosed vulnerabilities.
14. Integrate security metrics into management dashboards.

---

# 30. Limitations

The project is a security engineering demonstration and therefore has some limitations.

The final Checkov PASS demonstrates compliance with the configured Checkov checks; it does not imply that every possible AWS security risk has been eliminated.

Similarly:

* A clean Gitleaks result does not guarantee that secrets could never be introduced in the future.
* Semgrep coverage depends on the configured rules.
* Threat-model completeness depends on the system model and assumptions.
* Terraform validation confirms configuration validity but does not guarantee secure runtime behavior.
* AWS runtime controls should be validated after actual deployment.

Accordingly, the security gate should be treated as a continuous control rather than a one-time certification.

---

# 31. Conclusion

The Enterprise DevSecOps IaC Security Pipeline successfully demonstrates the integration of security into Infrastructure-as-Code development.

The project progressed from an intentionally vulnerable baseline through automated assessment and remediation to a final validated security state.

The final implementation incorporates:

* Terraform-based infrastructure.
* AWS security controls.
* KMS encryption.
* S3 access controls.
* S3 versioning.
* S3 lifecycle management.
* S3 access logging.
* Cross-region replication.
* S3 event notifications.
* IAM-controlled replication.
* Gitleaks secret detection.
* Semgrep static analysis.
* Checkov IaC security scanning.
* PyTM threat modelling.
* Automated security-gate validation.
* Security evidence retention.
* Git-based change control.

The strongest final evidence is the completed Checkov validation:

```text
Checkov Version : 3.3.15
Resources       : 31
Passed          : 105
Failed          : 0
Skipped         : 0
Parsing Errors  : 0

STATUS           : PASS
SECURITY GATE    : PASSED
```

This is supported by the final Gitleaks validation:

```text
scanned ~3.93 MB
no leaks found
```

and the Git-history validation:

```text
1 commits scanned
no leaks found
```

The final Git repository was also confirmed to be synchronized with GitHub and contained no outstanding changes.

Overall, the project demonstrates a practical **shift-left, defense-in-depth DevSecOps security model** in which security is embedded throughout infrastructure development, validation, remediation, version control and release readiness.

---

# 32. Final Project Repository

**GitHub Repository**

https://github.com/adeola2021/enterprise-devsecops-iac

**Branch:** `main`

**Final commit:** `c95497d`

**Repository status:** Clean and synchronized with `origin/main`.

---

# Appendix A — Key Evidence Commands

### Terraform validation

```bash
terraform -chdir=terraform fmt -check -recursive
terraform -chdir=terraform validate
```

### Checkov final verification

```bash
python3 - <<'PY'
import json

path = "reports/checkov-final.json/results_json.json"

with open(path, encoding="utf-8") as f:
    data = json.load(f)

s = data["summary"]

print(f"Passed         : {s['passed']}")
print(f"Failed         : {s['failed']}")
print(f"Skipped        : {s['skipped']}")
print(f"Parsing Errors : {s['parsing_errors']}")
print(f"Resources      : {s['resource_count']}")

assert s["failed"] == 0
assert s["skipped"] == 0
assert s["parsing_errors"] == 0

print("STATUS: PASS")
PY
```

### Gitleaks working-tree verification

```bash
gitleaks detect \
  --source . \
  --no-git \
  --report-format json \
  --report-path reports/gitleaks-final-working-tree.json
```

### Gitleaks Git-history verification

```bash
gitleaks detect \
  --source . \
  --report-format json \
  --report-path reports/gitleaks-final-history.json
```

### Git final verification

```bash
git remote -v
git branch -vv
git status
git log --oneline -3
```

---

# Appendix B — Final Security Statement

**Final Enterprise DevSecOps IaC Security Gate: PASSED**

**Checkov: 105 Passed / 0 Failed**

**Terraform Resources Assessed: 31**

**Gitleaks: 0 Secrets Detected**

**Terraform Validation: PASSED**

**Git Repository: CLEAN**

**GitHub Repository: SYNCHRONIZED**

**Overall Project Status: SECURITY VALIDATION COMPLETE**
