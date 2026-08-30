# Enterprise DevSecOps Infrastructure-as-Code Security Pipeline

## Technical Security Assessment, Remediation and Validation Report

**Repository:** `adeola2021/enterprise-devsecops-iac`
**Platform:** GitHub
**Primary Branch:** `main`
**Assessment Status:** COMPLETED
**Final Security Gate:** PASSED
**Report Date:** 30 August 2026

---

# 1. Executive Summary

This project implements an enterprise-oriented DevSecOps Infrastructure-as-Code (IaC) security pipeline designed to identify, remediate and continuously validate security risks before cloud infrastructure and application components are deployed.

The implementation combines Infrastructure-as-Code security, application static analysis, secret detection, threat modelling, preventive AWS security controls and automated security gates.

The project demonstrates a defense-in-depth security approach across:

* Terraform Infrastructure-as-Code
* AWS cloud security controls
* Application source code
* Secret and credential detection
* Static Application Security Testing (SAST)
* Threat modelling
* Security policy enforcement
* Automated security validation
* Security evidence and audit reporting

The final validation demonstrates that the remediated Terraform configuration satisfies the implemented Checkov security requirements.

Final Checkov verification recorded:

| Metric             |     Result |
| ------------------ | ---------: |
| Checkov Version    |     3.3.15 |
| Resources Assessed |         31 |
| Passed Checks      |        105 |
| Failed Checks      |          0 |
| Skipped Checks     |          0 |
| Parsing Errors     |          0 |
| Security Gate      | **PASSED** |

Gitleaks also completed successfully against both the working tree and Git history, with no secrets detected.

The repository is available at:

**GitHub:** https://github.com/adeola2021/enterprise-devsecops-iac

---

# 2. Project Background

Modern cloud environments increasingly depend on Infrastructure-as-Code to provision networking, compute, storage, databases and security services.

Although IaC improves consistency and automation, insecure Terraform configurations can introduce significant risks such as:

* Publicly accessible cloud resources
* Inadequate encryption
* Missing access controls
* Weak logging
* Missing backup or replication controls
* Inadequate lifecycle management
* Hard-coded credentials
* Insecure application configurations
* Excessive IAM permissions
* Poor visibility of security threats

The objective of this project was therefore to demonstrate how security controls can be integrated directly into the infrastructure development lifecycle rather than relying exclusively on post-deployment security reviews.

---

# 3. Project Objectives

The project objectives were to:

1. Secure AWS Infrastructure-as-Code using Terraform.
2. Identify insecure infrastructure configurations before deployment.
3. Detect hard-coded credentials and sensitive information.
4. Perform static analysis of application source code.
5. Implement preventive cloud security controls.
6. Apply encryption and secure data-storage controls.
7. Implement S3 versioning, lifecycle management and replication.
8. Implement logging and event notification mechanisms.
9. Apply appropriate IAM controls.
10. Perform structured threat modelling.
11. Establish automated security gates.
12. Preserve security assessment and remediation evidence.
13. Validate the final infrastructure configuration.
14. Demonstrate a repeatable DevSecOps security workflow.

---

# 4. Scope

The assessment covered the following project components:

```text
Enterprise DevSecOps Repository
│
├── Terraform Infrastructure
│   ├── AWS S3
│   ├── AWS KMS
│   ├── AWS IAM
│   ├── AWS SQS
│   ├── AWS EC2
│   ├── AWS RDS
│   ├── Security Groups
│   └── Supporting resources
│
├── Application
│   ├── Python application
│   └── Configuration management
│
├── Security Controls
│   ├── Checkov
│   ├── Gitleaks
│   ├── Semgrep
│   └── PyTM
│
├── Security Automation
│   └── security_gate.sh
│
├── Threat Model
│   ├── Threat matrix
│   ├── High-risk threats
│   ├── Severity summary
│   └── Architecture diagrams
│
└── Security Evidence
    ├── Vulnerable baseline
    ├── Remediation evidence
    └── Final validation
```

---

# 5. Security Architecture

The solution follows a defense-in-depth model.

```text
                    ┌──────────────────────┐
                    │      Developer       │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   Git Repository     │
                    │      GitHub          │
                    └──────────┬───────────┘
                               │
             ┌─────────────────┼──────────────────┐
             │                 │                  │
             ▼                 ▼                  ▼
       ┌──────────┐      ┌──────────┐      ┌──────────┐
       │ Semgrep  │      │ Gitleaks │      │ Checkov  │
       │   SAST   │      │  Secrets │      │   IaC    │
       └────┬─────┘      └────┬─────┘      └────┬─────┘
            │                 │                  │
            └─────────────────┼──────────────────┘
                              ▼
                    ┌──────────────────────┐
                    │ Automated Security   │
                    │       Gate           │
                    └──────────┬───────────┘
                               │
                         PASS / FAIL
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Terraform Validation │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ AWS Infrastructure   │
                    │ Security Controls    │
                    └──────────────────────┘
```

Threat modelling provides an additional security layer by identifying architectural threats before implementation.

---

# 6. Technology Stack

| Technology | Security Purpose                     |
| ---------- | ------------------------------------ |
| Terraform  | Infrastructure-as-Code               |
| AWS        | Cloud infrastructure                 |
| Checkov    | IaC security scanning                |
| Gitleaks   | Secret detection                     |
| Semgrep    | Static application security analysis |
| PyTM       | Threat modelling                     |
| Python     | Application and automation           |
| Git        | Version control                      |
| GitHub     | Source-code repository               |
| Bash       | Security automation                  |
| KMS        | Encryption key management            |
| S3         | Secure object storage                |
| SQS        | Event notification integration       |
| IAM        | Identity and access management       |

---

# 7. Initial Security Assessment

The project maintained a vulnerable baseline to demonstrate the effectiveness of the security controls.

The baseline assessment identified multiple security weaknesses across the infrastructure.

Examples of controls subsequently addressed included:

* S3 event notifications
* S3 replication
* S3 versioning
* S3 lifecycle management
* Encryption
* Access logging
* Public access restrictions
* IAM permissions
* Infrastructure configuration weaknesses
* Secret-management concerns

Historical vulnerable configurations and assessment outputs have been retained in the repository as evidence.

The vulnerable configuration is maintained separately under:

```text
archive/vulnerable-terraform/
```

This separation prevents the historical demonstration configuration from being confused with the final remediated Terraform implementation.

---

# 8. Infrastructure Security Controls

## 8.1 S3 Data Protection

The final Terraform implementation applies multiple controls to S3 resources.

These include:

* Versioning
* Server-side encryption
* KMS encryption
* Bucket public-access blocking
* Lifecycle management
* Access logging
* Cross-region replication
* Event notifications

These controls collectively improve:

* Confidentiality
* Integrity
* Availability
* Recoverability
* Auditability

---

## 8.2 S3 Versioning

S3 versioning was enabled for applicable buckets.

Versioning protects against accidental deletion and overwriting of objects and provides additional recovery capability.

---

## 8.3 S3 Lifecycle Management

Lifecycle configurations were implemented to control object retention and non-current versions.

This supports:

* Storage management
* Data retention governance
* Reduction of unnecessary storage
* Management of historical object versions

---

## 8.4 Cross-Region Replication

Cross-region replication was implemented between the primary enterprise data bucket and the replica bucket.

This provides an additional resilience mechanism for data recovery and regional failure scenarios.

The replication configuration uses a dedicated IAM role rather than unrestricted permissions.

---

## 8.5 Encryption

AWS KMS was incorporated into the infrastructure for encryption-related controls.

Encryption was applied to relevant storage and messaging resources.

The project also enables KMS key rotation.

---

## 8.6 S3 Public Access Protection

S3 public-access-block configurations were implemented to reduce the risk of unintended public exposure.

The controls include:

```text
block_public_acls       = true
block_public_policy     = true
ignore_public_acls      = true
restrict_public_buckets = true
```

---

## 8.7 S3 Access Logging

Access logging was configured for relevant S3 buckets.

Logs are directed to a dedicated access-log bucket, improving auditability and security monitoring.

---

## 8.8 S3 Event Notifications

S3 event notifications were implemented using Amazon SQS.

This provides an event-driven mechanism for monitoring relevant bucket activity.

The implementation includes an SQS queue policy restricting message submission to the expected S3 source.

---

# 9. Identity and Access Management

The infrastructure implements dedicated IAM permissions for S3 replication.

The replication role is assumed by the S3 service and is granted permissions required for replication activities.

The implementation avoids granting broad administrative privileges to the replication process.

This supports the principle of least privilege.

---

# 10. Secret Management

Secret exposure was specifically assessed using Gitleaks.

Sensitive values are not intended to be committed directly into the repository.

Terraform variables are used for sensitive configuration such as database credentials.

The repository also contains:

```text
terraform/terraform.tfvars.example
```

rather than requiring actual secret values to be committed.

The `.gitignore` configuration excludes sensitive Terraform and credential-related files including:

```text
*.tfvars
*.tfstate
*.pem
*.key
*.p12
*.pfx
.env
```

---

# 11. Gitleaks Security Validation

Gitleaks was executed against the working tree.

Final working-tree verification produced:

```text
scanned ~3926872 bytes (3.93 MB)
no leaks found
```

A separate Git-history scan was also performed.

The history verification reported:

```text
1 commits scanned.
scanned ~2312874 bytes (2.31 MB)
no leaks found
```

Final status:

**GITLEAKS: PASS**

This provides evidence that no secrets were detected in the current working tree or Git history assessed by the scan.

---

# 12. Static Application Security Testing

Semgrep was incorporated into the security workflow to identify security weaknesses within application source code.

Security rules are maintained under:

```text
security/semgrep-rules.yml
```

Semgrep evidence is retained within:

```text
reports/
```

This establishes application-level security analysis alongside the infrastructure security assessment.

---

# 13. Infrastructure Security Assessment with Checkov

Checkov was used to evaluate the Terraform infrastructure against security best practices.

The project used Checkov version:

```text
3.3.15
```

The final assessment covered:

```text
31 resources
```

Final results:

| Checkov Metric | Final Result |
| -------------- | -----------: |
| Passed         |          105 |
| Failed         |            0 |
| Skipped        |            0 |
| Parsing Errors |            0 |
| Resources      |           31 |

Final security status:

```text
STATUS: PASS
SECURITY GATE: PASSED
```

---

# 14. Checkov Remediation Progression

The remediation process was iterative.

The project initially contained multiple failed security checks.

The findings were progressively addressed through Terraform changes.

Examples included:

* S3 event notifications
* S3 lifecycle configuration
* S3 versioning
* Cross-region replication
* Security configuration improvements

The final verification demonstrates that the previously identified Checkov findings were remediated to the configured acceptance criteria.

The final state therefore changed from an infrastructure configuration with security findings to:

```text
105 Passed
0 Failed
0 Skipped
0 Parsing Errors
```

---

# 15. Security Exceptions

Checkov exception documentation has been retained in:

```text
reports/checkov-exceptions.md
```

The final result nevertheless reports zero failed checks and zero skipped checks.

This distinction is important because the repository preserves both the assessment history and the final security state.

---

# 16. Terraform Validation

Terraform formatting was validated using:

```bash
terraform -chdir=terraform fmt -check -recursive
```

Terraform configuration validation was performed using:

```bash
terraform -chdir=terraform validate
```

The final validation returned:

```text
Success! The configuration is valid.
```

This confirms that the Terraform configuration is syntactically and structurally valid according to Terraform's validation process.

---

# 17. Security Automation

The project includes:

```text
scripts/security_gate.sh
```

The security gate provides an automated mechanism for integrating multiple security checks into a repeatable workflow.

The pipeline is designed around the principle:

```text
Source Code
     │
     ▼
Security Scanning
     │
     ├── Gitleaks
     ├── Semgrep
     └── Checkov
     │
     ▼
Security Gate
     │
     ├── PASS → Continue
     │
     └── FAIL → Block / Remediate
```

This approach helps prevent insecure configurations from progressing without security review.

---

# 18. Threat Modelling

PyTM was used to model the application's security threats and attack surfaces.

Threat-model evidence is retained under:

```text
reports/
```

including:

```text
pytm-high-risk-threats.csv
pytm-severity-summary.txt
pytm-target-risk-summary.txt
pytm-threat-matrix.csv
pytm-threat-model.json
enterprise-threat-model.dot
enterprise-threat-model.png
enterprise-threat-model.svg
enterprise-threat-sequence.dot
```

The threat model provides architectural context for understanding:

* Threat actors
* Trust boundaries
* Attack surfaces
* High-risk threats
* Potential attack paths
* Security control requirements

---

# 19. Security Evidence Repository

The project retains evidence from the complete security lifecycle.

Important evidence categories include:

### Vulnerable Baseline

```text
reports/checkov-vulnerable-baseline.json
reports/checkov-vulnerable-results.json
reports/gitleaks-vulnerable.json
reports/semgrep-vulnerable.json
```

### Remediation Evidence

```text
reports/checkov-remediated.json/
reports/checkov-remediated-main.json/
reports/checkov-remediated-final.json/
reports/gitleaks-remediated.json
reports/semgrep-remediated.json
```

### Final Verification

```text
reports/checkov-final.json/
reports/gitleaks-final.json
reports/gitleaks-final-working-tree.json
reports/gitleaks-final-history.json
reports/security-gate-final.log
reports/security-gate-final-status.txt
```

This provides an auditable progression from vulnerable baseline through remediation to final validation.

---

# 20. Final Security Gate

The final security gate was independently verified using the Checkov report.

The verification script enforced:

```text
failed == 0
skipped == 0
parsing_errors == 0
```

The resulting output was:

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

This represents the final security acceptance state of the project.

---

# 21. Final Repository Verification

The final repository was verified using Git.

Repository:

```text
https://github.com/adeola2021/enterprise-devsecops-iac
```

Remote:

```text
origin  https://github.com/adeola2021/enterprise-devsecops-iac.git
```

Branch:

```text
main
```

The branch tracks:

```text
origin/main
```

Final repository state:

```text
On branch main
Your branch is up to date with 'origin/main'.

nothing to commit, working tree clean
```

This confirms that the final implementation and security evidence were committed and pushed successfully.

---

# 22. Final Validation Summary

| Security Domain   | Control                    | Result      |
| ----------------- | -------------------------- | ----------- |
| IaC               | Terraform formatting       | PASS        |
| IaC               | Terraform validation       | PASS        |
| IaC               | Checkov                    | PASS        |
| IaC               | Checkov failed checks      | 0           |
| IaC               | Checkov skipped checks     | 0           |
| IaC               | Checkov parsing errors     | 0           |
| Secrets           | Gitleaks working tree      | PASS        |
| Secrets           | Gitleaks Git history       | PASS        |
| Application       | Semgrep                    | Implemented |
| Threat Management | PyTM                       | Implemented |
| Storage           | S3 encryption              | Implemented |
| Storage           | S3 versioning              | Implemented |
| Storage           | S3 lifecycle               | Implemented |
| Storage           | S3 replication             | Implemented |
| Storage           | S3 access logging          | Implemented |
| Monitoring        | S3 event notifications     | Implemented |
| IAM               | Dedicated replication role | Implemented |
| Repository        | Git status                 | Clean       |
| Repository        | GitHub synchronization     | PASS        |
| Security Gate     | Final                      | **PASSED**  |

---

# 23. Security Improvement Outcome

The project demonstrates a measurable improvement between the vulnerable baseline and the final infrastructure state.

The most significant outcome is the reduction of final Checkov findings to:

```text
0 failed checks
```

while maintaining:

```text
105 passed checks
31 resources assessed
0 skipped checks
0 parsing errors
```

In addition, Gitleaks identified no secrets in the final working tree or scanned Git history.

The result is a substantially stronger infrastructure security posture compared with the initial vulnerable configuration.

---

# 24. Key Security Principles Demonstrated

The project demonstrates practical implementation of the following security principles:

### Shift Left

Security checks are performed before infrastructure deployment.

### Defense in Depth

Multiple independent security mechanisms are used rather than relying on one security scanner.

### Least Privilege

IAM permissions are scoped to required activities.

### Secure by Default

Public access restrictions, encryption and security validation are integrated into infrastructure configuration.

### Continuous Validation

Security checks can be repeated whenever infrastructure changes.

### Evidence-Based Security

Assessment results and remediation evidence are retained in the repository.

### Separation of Historical and Production Configuration

Vulnerable demonstration configurations are separated from the final remediated implementation.

---

# 25. Lessons Learned

Several important lessons were demonstrated during the implementation.

1. IaC security scanning should occur before deployment.
2. Security controls should be encoded directly into Terraform where possible.
3. Security findings often require iterative remediation.
4. Automated security gates reduce reliance on manual security reviews.
5. Secret detection should cover both the working tree and Git history.
6. Historical security evidence is valuable for demonstrating remediation.
7. Threat modelling provides important architectural context beyond automated scanners.
8. Security controls should address confidentiality, integrity and availability together.
9. Repository hygiene is an important component of DevSecOps.
10. Final validation should be independently repeatable.

---

# 26. Recommendations

For continued improvement of the project, the following controls are recommended:

1. Integrate the security gate into GitHub Actions.
2. Require security-gate success before merging pull requests.
3. Store sensitive production values in AWS Secrets Manager or an equivalent secure secret-management platform.
4. Implement remote Terraform state using encrypted S3 storage with state locking.
5. Introduce dependency scanning for application packages.
6. Add container image scanning if containerized workloads are introduced.
7. Enable continuous AWS security monitoring.
8. Integrate AWS CloudTrail and centralized security logging.
9. Periodically review IAM permissions.
10. Schedule recurring Checkov, Gitleaks and Semgrep scans.
11. Periodically update Terraform and provider versions.
12. Maintain threat models as the architecture evolves.
13. Protect the `main` branch using GitHub branch protection rules.
14. Require pull-request review before production changes.
15. Maintain security evidence for audit and compliance purposes.

---

# 27. Conclusion

The Enterprise DevSecOps IaC Security Pipeline successfully demonstrates how Infrastructure-as-Code security can be incorporated into an enterprise development lifecycle.

The final implementation combines:

* Terraform security controls
* AWS security configuration
* Checkov IaC scanning
* Gitleaks secret detection
* Semgrep application analysis
* PyTM threat modelling
* Automated security gates
* Security evidence management
* Git-based change control

The final security validation achieved:

```text
31 Resources
105 Passed
0 Failed
0 Skipped
0 Parsing Errors
```

Gitleaks additionally reported:

```text
NO LEAKS FOUND
```

Terraform validation reported:

```text
Success! The configuration is valid.
```

The final security gate therefore achieved:

```text
STATUS        : PASS
SECURITY GATE : PASSED
```

The implementation provides a strong foundation for extending the project into a fully automated CI/CD security pipeline with mandatory pull-request security gates, continuous cloud security monitoring and policy-as-code enforcement.

---

# 28. Repository

The complete project, implementation, security evidence and supporting documentation are available at:

**https://github.com/adeola2021/enterprise-devsecops-iac**

Repository structure:

```text
enterprise-devsecops-iac/
│
├── README.md
├── docs/
│   └── Enterprise-DevSecOps-IaC-Security-Technical-Report.md
├── app/
├── archive/
├── reports/
├── scripts/
├── security/
├── terraform/
└── threat-model/
```

---

# Appendix A — Final Security Evidence

## Checkov

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

## Gitleaks

```text
Working Tree:
no leaks found

Git History:
1 commits scanned.
no leaks found
```

## Terraform

```text
Success! The configuration is valid.
```

## Git

```text
On branch main
Your branch is up to date with 'origin/main'.

nothing to commit, working tree clean
```

---

# Appendix B — Primary Evidence Files

The following repository files provide supporting evidence for the assessment:

```text
reports/checkov-final.json/results_json.json
reports/gitleaks-final.json
reports/gitleaks-final-working-tree.json
reports/gitleaks-final-history.json
reports/security-gate-final.log
reports/security-gate-final-status.txt
reports/semgrep-gate.json
reports/pytm-threat-matrix.csv
reports/pytm-high-risk-threats.csv
reports/pytm-severity-summary.txt
reports/enterprise-threat-model.png
reports/enterprise-threat-model.svg
```

---

**End of Report**
