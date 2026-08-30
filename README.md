# Enterprise DevSecOps IaC Security Pipeline

## Overview

This project implements an enterprise-grade **DevSecOps Infrastructure-as-Code (IaC) security pipeline** designed to identify, prevent, and continuously validate security risks across Terraform infrastructure, application code, secrets, and threat models.

The project demonstrates a defense-in-depth approach to cloud infrastructure security by integrating **Terraform, Checkov, Gitleaks, Semgrep, PyTM, AWS security controls, and automated security gates** into a reproducible security workflow.

The objective is to shift security left by detecting vulnerabilities and insecure configurations before infrastructure is deployed.

---

## Project Objectives

The project was developed to demonstrate the ability to:

* Secure Infrastructure-as-Code using Terraform.
* Detect insecure AWS configurations before deployment.
* Identify hard-coded credentials and secrets.
* Perform static application security analysis.
* Apply preventive security controls to cloud resources.
* Implement encryption, access control, logging, lifecycle management, replication, and event monitoring.
* Perform structured threat modelling.
* Establish automated security gates.
* Maintain security evidence and remediation reports.
* Validate that the final infrastructure meets defined security requirements.
* Integrate security controls into the software development lifecycle.

---

## Security Architecture

The project follows a layered security model:

```text
                         ┌──────────────────────────┐
                         │       Developer          │
                         └────────────┬─────────────┘
                                      │
                                      ▼
                         ┌──────────────────────────┐
                         │     Git Repository       │
                         │        GitHub            │
                         └────────────┬─────────────┘
                                      │
                    ┌─────────────────┼─────────────────┐
                    │                 │                 │
                    ▼                 ▼                 ▼
             ┌────────────┐   ┌────────────┐   ┌────────────┐
             │  Gitleaks  │   │  Semgrep   │   │   Checkov  │
             │   Secrets  │   │ Application│   │    IaC     │
             │   Scan     │   │   SAST     │   │   Scan     │
             └─────┬──────┘   └─────┬──────┘   └─────┬──────┘
                   │                │                 │
                   └────────────────┼─────────────────┘
                                    │
                                    ▼
                         ┌──────────────────────────┐
                         │    Security Gate         │
                         │     PASS / FAIL          │
                         └────────────┬─────────────┘
                                      │
                                      ▼
                         ┌──────────────────────────┐
                         │       Terraform           │
                         │       Validation          │
                         └────────────┬─────────────┘
                                      │
                                      ▼
                         ┌──────────────────────────┐
                         │       AWS Resources       │
                         │ S3 | IAM | RDS | EC2 |    │
                         │ KMS | SQS | VPC           │
                         └──────────────────────────┘

                         ┌──────────────────────────┐
                         │       PyTM Threat         │
                         │         Modelling         │
                         └──────────────────────────┘
```

---

## Key Security Controls

### 1. Infrastructure-as-Code Security

Terraform is used to define the cloud infrastructure in a repeatable and auditable manner.

The infrastructure includes security controls for:

* AWS S3
* AWS KMS
* AWS IAM
* AWS RDS
* AWS EC2
* AWS VPC/security groups
* S3 replication
* S3 access logging
* S3 lifecycle management
* S3 event notifications
* Amazon SQS

Terraform validation is performed before security scanning and deployment.

---

### 2. AWS S3 Security

The S3 implementation incorporates multiple layers of protection, including:

* S3 versioning.
* Public access blocking.
* Server-side encryption.
* AWS KMS encryption.
* Bucket keys.
* Lifecycle configuration.
* Non-current object version expiration.
* Incomplete multipart upload cleanup.
* S3 access logging.
* Cross-region replication.
* Event notifications.
* SQS integration.

The design provides improved confidentiality, integrity, availability, monitoring, and recovery capabilities.

---

### 3. Encryption and Key Management

AWS KMS is used to protect sensitive infrastructure resources.

The project implements:

* Customer-managed KMS key.
* KMS key rotation.
* KMS-backed S3 encryption.
* KMS-backed SQS encryption.
* Controlled IAM access to protected resources.

---

### 4. Secrets Detection

**Gitleaks** is used to detect accidentally committed secrets and credentials.

The final verification included both:

#### Working-tree scan

```bash
gitleaks detect \
  --source . \
  --no-git \
  --report-format json \
  --report-path reports/gitleaks-final-working-tree.json
```

Result:

```text
scanned ~3911401 bytes
no leaks found
```

#### Git-history scan

```bash
gitleaks detect \
  --source . \
  --report-format json \
  --report-path reports/gitleaks-final-history.json
```

Result:

```text
1 commits scanned
no leaks found
```

### Final Gitleaks Result

**STATUS: PASS**

**NO SECRETS DETECTED**

---

## 5. Checkov IaC Security Scanning

Checkov is used to evaluate Terraform infrastructure against security and compliance policies.

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

### Final Checkov Result

| Metric          |   Result |
| --------------- | -------: |
| Checkov Version |   3.3.15 |
| Resources       |       31 |
| Passed Checks   |  **105** |
| Failed Checks   |    **0** |
| Skipped Checks  |    **0** |
| Parsing Errors  |    **0** |
| Security Gate   | **PASS** |

The project demonstrates remediation of previously identified S3 security deficiencies, including:

* S3 versioning.
* S3 lifecycle configuration.
* Cross-region replication.
* Event notifications.
* Access logging.

---

## 6. Semgrep Static Analysis

Semgrep is incorporated to identify insecure application-code patterns.

Security rules are maintained in:

```text
security/semgrep-rules.yml
```

Security scan evidence is maintained under:

```text
reports/
```

The vulnerable and remediated scan results are retained to demonstrate the security improvement achieved during remediation.

---

## 7. Threat Modelling

The project uses **PyTM** to perform structured threat modelling.

Threat-model outputs include:

```text
threat-model/threat_model.py
```

and generated evidence including:

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

The threat model provides visibility into:

* High-risk threats.
* Threat severity.
* Attack paths.
* Security boundaries.
* Target risks.
* Mitigation requirements.

---

## 8. Automated Security Gate

The central security automation is implemented in:

```text
scripts/security_gate.sh
```

The security gate brings multiple security controls together to provide a repeatable PASS/FAIL decision.

The pipeline incorporates:

```text
Terraform
   │
   ├── Format validation
   ├── Configuration validation
   │
   ▼
Checkov
   │
   ▼
Semgrep
   │
   ▼
Gitleaks
   │
   ▼
Threat-model evidence
   │
   ▼
Security Gate
   │
   ├── PASS → Continue
   │
   └── FAIL → Stop / Remediate
```

This approach prevents known security issues from progressing unnoticed toward deployment.

---

## Vulnerability-to-Remediation Approach

The project intentionally maintains vulnerable baseline configurations to demonstrate the complete security lifecycle.

```text
Vulnerable Configuration
          │
          ▼
     Security Scan
          │
          ▼
     Findings Identified
          │
          ▼
       Remediation
          │
          ▼
     Security Rescan
          │
          ▼
    Security Gate PASS
```

Evidence from both vulnerable and remediated states is retained in the `reports/` directory.

This provides an auditable demonstration that security controls were not simply configured but were also tested and validated.

---

## Repository Structure

```text
enterprise-devsecops-iac/
│
├── .checkov.yaml
├── .gitignore
│
├── app/
│   ├── config.py
│   └── vulnerable_app.py
│
├── archive/
│   └── vulnerable-terraform/
│       └── main.vulnerable.tf
│
├── reports/
│   ├── Checkov reports
│   ├── Gitleaks reports
│   ├── Semgrep reports
│   ├── Security-gate evidence
│   ├── PyTM threat-model outputs
│   └── Threat-model diagrams
│
├── scripts/
│   └── security_gate.sh
│
├── security/
│   ├── gitleaks.toml
│   └── semgrep-rules.yml
│
├── terraform/
│   ├── main.tf
│   ├── main.tf.before-final-remediation
│   ├── terraform.tfvars.example
│   └── .terraform.lock.hcl
│
└── threat-model/
    └── threat_model.py
```

---

## Reproducing the Security Validation

### 1. Clone the repository

```bash
git clone https://github.com/adeola2021/enterprise-devsecops-iac.git
cd enterprise-devsecops-iac
```

### 2. Create a Python virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Initialize Terraform

```bash
terraform -chdir=terraform init
```

### 4. Format Terraform

```bash
terraform -chdir=terraform fmt -recursive
```

### 5. Validate Terraform

```bash
terraform -chdir=terraform validate
```

Expected result:

```text
Success! The configuration is valid.
```

### 6. Run Checkov

```bash
checkov -d terraform --framework terraform
```

### 7. Run Gitleaks

```bash
gitleaks detect \
  --source . \
  --no-git
```

For Git-history verification:

```bash
gitleaks detect \
  --source .
```

### 8. Run the security gate

```bash
./scripts/security_gate.sh
```

---

## Security Evidence

The repository deliberately retains security evidence to support auditability and technical review.

Important evidence includes:

| Evidence                         | Purpose                           |
| -------------------------------- | --------------------------------- |
| `checkov-vulnerable-*`           | Vulnerable baseline               |
| `checkov-remediated-*`           | Remediation verification          |
| `checkov-final-*`                | Final IaC security verification   |
| `gitleaks-vulnerable.*`          | Initial secret-detection evidence |
| `gitleaks-remediated.json`       | Remediation evidence              |
| `gitleaks-final.json`            | Final secret scan                 |
| `semgrep-vulnerable.json`        | Initial SAST results              |
| `semgrep-remediated.json`        | Remediated SAST results           |
| `security-gate-final.log`        | Final security-gate evidence      |
| `security-gate-final-status.txt` | Final PASS/FAIL status            |
| `pytm-threat-matrix.csv`         | Threat analysis                   |
| `pytm-high-risk-threats.csv`     | High-risk threats                 |
| `enterprise-threat-model.png`    | Threat-model visualization        |

---

## Final Security Validation

The final project validation achieved the following:

```text
Terraform Format        : PASS
Terraform Validation    : PASS

Checkov
  Passed                : 105
  Failed                : 0
  Skipped               : 0
  Parsing Errors        : 0
  Resources             : 31
  Security Gate         : PASS

Gitleaks
  Working Tree          : PASS
  Git History           : PASS
  Secrets Detected      : 0

Git
  Branch                : main
  Remote                : origin/main
  Working Tree          : CLEAN
```

### Final Security Status

**PASS — Enterprise IaC Security Gate**

The final infrastructure configuration passed the implemented IaC security controls with **zero failed Checkov checks and zero detected secrets**.

---

## Security Principles Demonstrated

This project demonstrates practical implementation of:

* **Shift-left security**
* **Infrastructure-as-Code security**
* **Defense in depth**
* **Least privilege**
* **Secure-by-default configuration**
* **Secrets management**
* **Encryption at rest**
* **Continuous security validation**
* **Threat modelling**
* **Security automation**
* **Preventive security controls**
* **Security evidence and auditability**
* **Reproducible infrastructure security**

---

## Project Outcome

The project demonstrates an end-to-end DevSecOps security lifecycle in which insecure infrastructure is:

1. Identified.
2. Scanned.
3. Analysed.
4. Remediated.
5. Re-scanned.
6. Validated.
7. Passed through an automated security gate.
8. Committed to Git.
9. Verified for secrets.
10. Published to GitHub.

The resulting implementation provides a practical foundation for integrating security into enterprise cloud infrastructure development and deployment processes.

---

## Repository

**GitHub:**
https://github.com/adeola2021/enterprise-devsecops-iac

---

## Author

**Enterprise DevSecOps IaC Security Project**

Built as a practical demonstration of cloud security, Infrastructure-as-Code security, DevSecOps automation, application security, secrets detection, and threat modelling.


