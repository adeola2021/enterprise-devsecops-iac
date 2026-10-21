#!/usr/bin/env python3

import csv
import json
from pathlib import Path

source = Path("reports/pytm-threat-model.json")
destination = Path("reports/phase5/threat-control-matrix.csv")

data = json.loads(source.read_text())
findings = data.get("findings", [])

metadata_fields = [
    "Control Owner", "Implementation Status", "Verification Status",
    "Control Classification", "OPA Policy Reference",
    "AWS Security Hub Control Reference", "Control Coverage Assessment",
    "Required Remediation Action", "Supporting API Gateway Boundary Control",
]
existing_metadata = {}

if destination.exists():
    with destination.open(newline="", encoding="utf-8-sig") as old_file:
        for old_row in csv.DictReader(old_file):
            existing_metadata[str(old_row.get("Finding ID", ""))] = {
                field: old_row.get(field, "") for field in metadata_fields
            }

control_mapping = {
    "INP05": (
        "Parameterized SQL queries; input validation; least-privilege DB access",
        "Application security / Semgrep / DAST",
        "Review query implementation and perform SQL injection testing",
    ),
    "HA01": (
        "Canonical path validation; restrict filesystem access",
        "Application security / Semgrep / DAST",
        "Perform path traversal tests and review filesystem permissions",
    ),
    "AC06": (
        "Validate uploaded files; malware scanning; isolated storage",
        "Application security / Malware scanning",
        "Test malicious file upload handling and storage restrictions",
    ),
    "SC02": (
        "Context-aware output encoding; content security policy",
        "Application security / Semgrep / DAST",
        "Perform XSS testing and inspect output encoding",
    ),
    "AC17": (
        "Secure session management; token rotation and expiration",
        "Authentication security / DAST",
        "Test session fixation, hijacking and token invalidation",
    ),
    "AA03": (
        'Protect trusted credentials and authentication tokens; enforce token validation, expiry, revocation, and secure session handling',
        'Semgrep / authentication tests / secret scanning',
        'Credential-handling code review, token validation tests, and secret-scanning results',
    ),

    "AA04": (
        'Enforce authentication, authorization, and input validation on the server; do not rely solely on client-side checks',
        'API security tests / Semgrep / DAST',
        'Negative authorization tests, server-side validation tests, and code review',
    ),

    "AC16": (
        'Generate session identifiers with cryptographically secure randomness; use adequate entropy, protect identifiers, and rotate sessions appropriately',
        'Semgrep / session-management tests / DAST',
        'Session generation code review and session prediction, rotation, and invalidation test results',
    ),

    "CR03": (
        'Enforce password policy, authentication rate limiting, and monitoring for repeated failed login attempts',
        'Authentication tests / DAST / configuration review',
        'Password-policy evidence, rate-limit test results, and failed-login monitoring configuration',
    ),

    "CR06": (
        'Encrypt sensitive communications with correctly configured TLS and authenticate and authorize communication channels',
        'TLS scanner / API security tests / configuration review',
        'TLS configuration and certificate-validation results, service communication tests, and authorization evidence',
    ),

    "INP03": (
        'Disable server-side includes where unnecessary and sanitize untrusted input to prevent interpretation as server directives',
        'Semgrep / DAST / web-server configuration review',
        'SSI configuration evidence, injection test results, and input-validation code review',
    ),

    "INP08": (
        'Use safe formatting functions and validate untrusted values before formatting, processing, or logging them',
        'Semgrep / SAST / code review',
        'Static-analysis results and review of formatting functions and untrusted input handling',
    ),

    "INP09": (
        'Use safe parameterized LDAP query construction, validate input, and prevent detailed directory errors from being exposed',
        'Semgrep / LDAP injection tests / DAST',
        'LDAP query implementation review, injection test results, and error-handling test results',
    ),

    "INP11": (
        'Canonicalize and validate file paths, use allowlisted or indirect file identifiers, and restrict filesystem permissions',
        'Semgrep / DAST',
        'Relative path traversal tests, code review, and filesystem permission evidence',
    ),

    "INP16": (
        'Disable remote file inclusion and allow only approved local files for application include operations',
        'Semgrep / PHP configuration review / DAST',
        'PHP configuration evidence, include-path code review, and file-inclusion test results',
    ),

    "INP22": (
        'Use a secure XML parser and enforce document size, attribute-count, and processing-resource limits',
        'SAST / XML parser configuration review / security tests',
        'Parser configuration, malformed XML test results, and resource-limit test evidence',
    ),

    "INP28": (
        'Validate and canonicalize URI values, reject unsafe schemes, and apply context-aware output encoding',
        'Semgrep / DAST / URI validation tests',
        'URI validation code review, alternate-input test results, and XSS test evidence',
    ),

    "INP34": (
        'Validate SOAP message structure and array sizes and enforce request-size and parser resource limits',
        'SOAP security tests / SAST / parser configuration review',
        'SOAP schema validation results, malformed-message tests, and resource-limit evidence',
    ),

    "INP37": (
        'Reject ambiguous or malformed HTTP requests and align request parsing and framing behavior across gateways, proxies, and backends',
        'HTTP request-smuggling tests / DAST / gateway configuration review',
        'Request-smuggling test results and gateway/backend parsing configuration review',
    ),

    "SC03": (
        'Sanitize untrusted content, encode output appropriately, and prevent unsafe nested script execution or unsafe remote-content proxying',
        'Semgrep / DAST / CSP review',
        'Nested-script and XSS test results, output-encoding review, and relevant security-header evidence',
    ),

    "SC04": (
        'Canonicalize input encoding, validate untrusted content, and apply context-aware output encoding to prevent alternate-syntax XSS',
        'Semgrep / DAST / XSS security tests',
        'Alternate-encoding XSS test results and input/output validation review',
    ),

    "SC05": (
        'Repeat security-critical client-side checks on the server and verify client application integrity where applicable',
        'API authorization tests / code review / integrity checks',
        'Tests bypassing client-side controls, server-side authorization results, and applicable client-integrity evidence',
    ),
    "DE04": (
        "Require PostgreSQL CloudWatch log export and statement, connection, "
        "and disconnection logging in the Terraform plan",
        "OPA / policy/phase5-database-logging.rego / "
        "tests/phase5/verify_database_logging.py",
        "Passing policy tests; separately verify deployed logging, access "
        "controls, retention, and tamper protection",
    ),

    "AA01": (
        "Enforce authentication on protected endpoints and reject invalid or missing credentials",
        "API integration tests",
        "Tests showing unauthenticated and invalid-credential requests are rejected",
    ),
    "AA02": (
        "Validate authenticated identity and trusted issuer, audience, and claims",
        "Authentication integration tests",
        "Tests showing forged identities and invalid tokens are rejected",
    ),
    "AC01": (
        "Enforce server-side authorization and least-privilege permissions",
        "Authorization tests and IAM review",
        "Negative access tests and evidence of scoped permissions",
    ),
    "AC05": (
        "Validate request integrity and encode untrusted content appropriately",
        "API security tests",
        "Tests showing manipulated request content is safely rejected or handled",
    ),
    "AC07": (
        "Apply deny-by-default authorization and review access-control configuration",
        "Authorization tests and configuration review",
        "Evidence of denied unauthorized actions and reviewed access rules",
    ),
    "AC08": (
        "Restrict modification of configuration and service metadata to authorized identities",
        "Configuration and access-control tests",
        "Unauthorized configuration changes are denied and authorized changes are logged",
    ),
    "AC09": (
        "Enforce server-side business rules, quotas, and permitted operation boundaries",
        "API negative and abuse-case tests",
        "Tests showing prohibited operations and excessive requests are rejected",
    ),
    "AC11": (
        "Use secure session handling, token validation, expiration, and rotation where applicable",
        "Session security tests",
        "Tests showing tampered, expired, and invalid session credentials are rejected",
    ),
    "CR05": (
        "Use approved cryptographic algorithms and adequate key sizes; protect keys and limit authentication attempts",
        "TLS and cryptographic configuration review",
        "Evidence of approved algorithms, key configuration, and relevant abuse tests",
    ),
    "CR08": (
        "Enforce secure protocol configuration and consistent request validation",
        "TLS configuration and protocol security tests",
        "Evidence of secure protocol settings and rejection of malformed or invalid requests",
    ),
    "DE01": (
        "Encrypt sensitive traffic in transit and validate peer certificates",
        "TLS configuration and integration tests",
        "Evidence of encrypted connections and rejection of invalid certificates",
    ),
    "DE02": (
        "Canonicalize input consistently and validate it after decoding",
        "Input validation and API security tests",
        "Tests showing double-encoded or ambiguous inputs cannot bypass validation",
    ),
    "DE03": (
        "Require encrypted transport and prevent sensitive data exposure over untrusted channels",
        "TLS configuration and traffic inspection",
        "Evidence that sensitive traffic uses approved encryption and is not exposed in plaintext",
    ),
    "DO01": (
        "Apply rate limits, request throttling, and abuse monitoring at relevant service boundaries",
        "Load and API abuse tests",
        "Evidence that excessive requests are limited and service health is maintained",
    ),
    "DO02": (
        "Set request-size limits, timeouts, concurrency limits, and resource quotas",
        "Resource-exhaustion and load tests",
        "Tests showing excessive payloads and resource use are bounded",
    ),
    "DS01": (
        "Restrict sensitive data access and prevent unauthorized extraction",
        "Data-access and API authorization tests",
        "Tests showing unauthorized data access and bulk extraction are blocked",
    ),
    "DS03": (
        "Reduce unnecessary public exposure of system and service information",
        "External exposure and configuration review",
        "Evidence that unnecessary public metadata and services are restricted",
    ),
    "DS04": (
        "Return generic error responses and safely encode any dynamic error-page content",
        "Error-handling and XSS tests",
        "Tests showing errors do not expose sensitive details or execute injected content",
    ),
    "HA03": (
        "Minimize technology fingerprints in responses and remove unnecessary identifying headers",
        "HTTP header and response review",
        "Evidence that unnecessary version and technology details are not exposed",
    ),
    "INP10": (
        "Use parameterized operations and validate inputs against explicit schemas",
        "Injection and API validation tests",
        "Tests showing crafted parameters cannot alter query or command behavior",
    ),
    "INP14": (
        "Validate input server-side and enforce integrity and business constraints",
        "API negative and data-integrity tests",
        "Tests showing unauthorized or malformed data changes are rejected",
    ),
    "INP17": (
        "Set correct content types and enforce safe MIME handling and browser protections",
        "HTTP header and XSS tests",
        "Evidence of correct content types and safe handling of mismatched MIME types",
    ),
    "INP18": (
        "Use generic client-facing errors and restrict sensitive diagnostic details in logs and responses",
        "Error-handling and information-disclosure tests",
        "Tests showing malformed requests do not disclose stack traces or sensitive internals",
    ),
    "INP19": (
        "Disable unsafe XML external entity processing and apply XML parser resource limits",
        "XML parser security tests",
        "Tests showing external entity resolution and XML expansion attacks are blocked",
    ),
    "INP21": (
        "Disable unnecessary DTD processing and external entity resolution in XML parsers",
        "XML parser security tests",
        "Tests showing malicious DTD and external entity payloads are rejected",
    ),
    "INP29": (
        "Apply context-aware output encoding and robust input validation against XSS variants",
        "XSS and web application security tests",
        "Tests showing doubled-character and encoded XSS payloads do not execute",
    ),
    "INP36": (
        "Reject ambiguous HTTP message framing and ensure intermediaries parse requests consistently",
        "HTTP request-smuggling security tests",
        "Tests showing conflicting content-length and transfer-encoding requests are rejected safely",
    ),
}

columns = [
    "Finding ID",
    "Threat ID",
    "Threat Description",
    "Affected Component",
    "Severity",
    "PyTM Recommended Mitigation",
    "Proposed Control",
    "Proposed Verification Tool",
    "Required Verification Evidence",
    "Control Owner",
    "Implementation Status",
    "Verification Status",
    "Control Classification",
    "OPA Policy Reference",
    "AWS Security Hub Control Reference",
    "Control Coverage Assessment",
    "Required Remediation Action",
    "Supporting API Gateway Boundary Control",
]

rows = []

for index, finding in enumerate(findings, 1):
    threat_id = str(finding.get("threat_id", ""))

    control, tool, evidence = control_mapping.get(
        threat_id,
        (
            "Requires individual threat assessment",
            "To be determined",
            "Threat-specific verification evidence required",
        ),
    )

    rows.append({
        "Finding ID": finding.get("id") or f"PYTM-{index:03d}",
        "Threat ID": threat_id,
        "Threat Description": finding.get("description", ""),
        "Affected Component": finding.get("target", ""),
        "Severity": finding.get("severity", ""),
        "PyTM Recommended Mitigation": finding.get("mitigations", ""),
        "Proposed Control": control,
        "Proposed Verification Tool": tool,
        "Required Verification Evidence": evidence,
        "Control Owner": "To be assigned",
        "Implementation Status": "Not verified",
        "Verification Status": "Pending",
    })

    finding_id = str(rows[-1]["Finding ID"])
    rows[-1].update(existing_metadata.get(finding_id, {}))

    # Fill missing metadata conservatively; preserve existing documented values.
    row = rows[-1]
    control_text = str(row.get("Proposed Control", "")).strip()
    evidence_text = str(row.get("Required Verification Evidence", "")).strip()

    if threat_id.startswith(("AA", "AC", "CR", "HA", "INP", "SC")):
        classification = "Application security"
    elif threat_id.startswith("DE"):
        classification = "Data protection and security"
    elif threat_id.startswith("DO"):
        classification = "Availability and resilience"
    elif threat_id.startswith("DS"):
        classification = "Data security"
    else:
        classification = "Threat-specific security control"

    defaults = {
        "Control Classification": classification,
        "OPA Policy Reference": (
            "No direct applicable OPA rule verified; assess policy scope"
        ),
        "AWS Security Hub Control Reference": (
            "Not mapped to a verified applicable Security Hub control"
        ),
        "Control Coverage Assessment": (
            "Not verified: compare this proposed control with the threat, "
            "existing policy scope, and test evidence. No implementation "
            "or effectiveness is implied."
        ),
        "Required Remediation Action": (
            f"Assess and implement the proposed control: {control_text}. "
            f"Collect verification evidence: {evidence_text}"
        ),
        "Supporting API Gateway Boundary Control": (
            "Not mapped: determine applicability and verify boundary coverage"
        ),
    }

    for field, value in defaults.items():
        if not str(row.get(field, "") or "").strip():
            row[field] = value

    # Reusable threat-level metadata. These describe policy scope and
    # verification needs; they do not assert application-control effectiveness.
    targeted_mappings = {
        "INP05": {
            "OPA Policy Reference": (
                "No direct OPA rule for SQL injection; existing infrastructure "
                "policies do not validate application SQL queries"
            ),
            "Control Coverage Assessment": (
                "No direct mitigation by existing OPA IaC rules. Verify "
                "parameterized queries, input validation, and least-privilege "
                "database access using application-level tests."
            ),
            "Supporting API Gateway Boundary Control": (
                "API Gateway route-authorization policy is defense in depth "
                "only; it does not detect or prevent SQL injection."
            ),
        },
        "AA01": {
            "OPA Policy Reference": (
                "policy/phase5-api-gateway.rego (partial infrastructure coverage: "
                "blocks API Gateway methods/routes with authorization NONE or omitted)"
            ),
            "Control Coverage Assessment": (
                "Partial infrastructure coverage verified by policy tests. "
                "This does not establish that credentials, token claims, or "
                "application authentication flows are secure."
            ),
            "Supporting API Gateway Boundary Control": (
                "The policy checks missing API Gateway route authorization. "
                "Test invalid credentials, token validation, and authentication "
                "flows separately."
            ),
        },
        "AA03": {
            "OPA Policy Reference": (
                "No direct OPA rule verified for credential protection, token "
                "validation, expiry, or revocation"
            ),
            "Control Coverage Assessment": (
                "No direct coverage by the existing API Gateway OPA rule. "
                "Verify credential handling, token validation, expiry, "
                "revocation, and session security with application tests."
            ),
            "Supporting API Gateway Boundary Control": (
                "API Gateway route-authorization checks are defense in depth; "
                "they do not validate token integrity, claims, expiry, revocation, "
                "or credential storage."
            ),
        },
        "AA04": {
            "OPA Policy Reference": (
                "policy/phase5-api-gateway.rego (partial route-authorization "
                "coverage only; no direct rule verified for server-side input validation)"
            ),
            "Control Coverage Assessment": (
                "Partial coverage for missing API Gateway authorization only. "
                "Server-side authorization behavior and input validation still "
                "require application-level tests and code review."
            ),
            "Supporting API Gateway Boundary Control": (
                "The policy blocks methods/routes configured without authorization; "
                "it does not prove that client-side checks are repeated on the "
                "server or that input is validated."
            ),
        },
        "AC17": {
            "OPA Policy Reference": (
                "No direct OPA rule verified for session hijacking, token rotation, "
                "session expiry, or invalidation"
            ),
            "Control Coverage Assessment": (
                "No direct mitigation by existing OPA IaC rules. Verify session "
                "fixation/hijacking defenses, token rotation, expiry, and "
                "invalidation through authentication security tests."
            ),
            "Supporting API Gateway Boundary Control": (
                "API Gateway route authorization is defense in depth only; it "
                "does not enforce secure session lifecycle or token invalidation."
            ),
        },
        "CR06": {
            "OPA Policy Reference": (
                "No direct OPA rule verified for TLS configuration or "
                "communication-channel certificate validation"
            ),
            "Control Coverage Assessment": (
                "No direct TLS or communication-channel protection verified "
                "by the existing OPA rules. Verify TLS versions and cipher "
                "configuration, certificate validation, and service-to-service "
                "authentication for each affected communication path."
            ),
            "Supporting API Gateway Boundary Control": (
                "Assess API Gateway TLS and integration settings where applicable; "
                "this does not establish TLS protection for every backend or "
                "service-to-service communication path."
            ),
        },
        "HA01": {
            "OPA Policy Reference": (
                "No direct OPA rule verified for application filesystem path traversal"
            ),
            "Control Coverage Assessment": (
                "No direct mitigation by the existing OPA IaC rules has been "
                "verified for application path traversal. Validate canonicalized "
                "paths, restrict filesystem access, and test traversal payloads."
            ),
            "Supporting API Gateway Boundary Control": (
                "API Gateway authorization may restrict access to endpoints but "
                "does not validate filesystem paths processed by the application."
            ),
        },
        "AC06": {
            "OPA Policy Reference": (
                "policy/terraform.rego; policy/phase4.rego; "
                "policy/s3-association.rego (supporting S3 configuration only)"
            ),
            "Control Coverage Assessment": (
                "Partial supporting infrastructure coverage only: existing S3 "
                "rules check selected storage protections, not file-content "
                "validation, malware detection, upload authorization, or safe "
                "file processing. Verify these controls separately."
            ),
            "Supporting API Gateway Boundary Control": (
                "Endpoint authorization may restrict upload access but does not "
                "scan uploaded content or prove that files are safely processed."
            ),
        },
        "AC16": {
            "OPA Policy Reference": (
                "No direct OPA rule verified for cryptographically secure session-ID "
                "generation, entropy, or session rotation"
            ),
            "Control Coverage Assessment": (
                "No direct mitigation by existing OPA IaC rules has been verified. "
                "Review session-ID generation and storage, assess entropy, and test "
                "prediction resistance, rotation, and invalidation."
            ),
            "Supporting API Gateway Boundary Control": (
                "Route authorization does not establish session-ID randomness, "
                "entropy, or secure session lifecycle management."
            ),
        },
        "CR03": {
            "OPA Policy Reference": (
                "No direct OPA rule verified for password policy, login rate "
                "limiting, or failed-authentication monitoring"
            ),
            "Control Coverage Assessment": (
                "No direct coverage by the existing OPA rules has been verified. "
                "Inspect password-policy enforcement, test authentication throttling, "
                "and verify monitoring and alerting for repeated failed logins."
            ),
            "Supporting API Gateway Boundary Control": (
                "API Gateway route authorization is not evidence of password-policy "
                "enforcement or effective login throttling and monitoring."
            ),
        },
        "INP03": {
            "OPA Policy Reference": (
                "No direct OPA rule verified for server-side include injection "
                "or application input sanitization"
            ),
            "Control Coverage Assessment": (
                "No direct mitigation by existing OPA IaC rules has been verified. "
                "Review server-side include configuration and input handling; "
                "test whether untrusted input can be interpreted as directives."
            ),
            "Supporting API Gateway Boundary Control": (
                "Route authorization does not establish safe handling of "
                "server-side include directives or untrusted input."
            ),
        },
        "INP08": {
            "OPA Policy Reference": (
                "No direct OPA rule verified for unsafe application string formatting"
            ),
            "Control Coverage Assessment": (
                "No direct application-level mitigation has been verified. Review "
                "formatting and logging code paths, use safe formatting functions, "
                "and test handling of attacker-controlled values."
            ),
            "Supporting API Gateway Boundary Control": (
                "Route authorization does not verify safe formatting or processing "
                "of untrusted values inside application code."
            ),
        },
        "INP09": {
            "OPA Policy Reference": (
                "No direct OPA rule verified for LDAP query construction or "
                "application LDAP injection defenses"
            ),
            "Control Coverage Assessment": (
                "No direct mitigation by existing OPA IaC rules has been verified. "
                "Review LDAP query construction, validate untrusted input, and test "
                "injection payloads and directory error handling."
            ),
            "Supporting API Gateway Boundary Control": (
                "Route authorization does not prove that LDAP queries are safely "
                "constructed or directory errors are handled securely."
            ),
        },
        "INP11": {
            "OPA Policy Reference": (
                "No direct OPA rule verified for application file-path "
                "canonicalization or traversal defenses"
            ),
            "Control Coverage Assessment": (
                "No direct application-level path-traversal mitigation has been "
                "verified. Review canonicalization, allowlisting, indirect file "
                "identifiers, and filesystem permissions; test traversal variants."
            ),
            "Supporting API Gateway Boundary Control": (
                "Route authorization does not validate filesystem paths used "
                "by backend application code."
            ),
        },
        "INP16": {
            "OPA Policy Reference": (
                "No direct OPA rule verified for remote file inclusion or "
                "application include-path restrictions"
            ),
            "Control Coverage Assessment": (
                "No direct mitigation by existing OPA IaC rules has been verified. "
                "Review include operations and relevant runtime configuration; "
                "test that remote and unapproved file inclusion is rejected."
            ),
            "Supporting API Gateway Boundary Control": (
                "Route authorization does not establish safe application "
                "file-inclusion behavior."
            ),
        },
        "INP22": {
            "OPA Policy Reference": (
                "No direct OPA rule verified for XML parser hardening or "
                "XML-processing resource limits"
            ),
            "Control Coverage Assessment": (
                "No direct application-level XML parser mitigation has been "
                "verified. Inspect parser settings and resource limits, and test "
                "malformed XML, external entities, and oversized documents as applicable."
            ),
            "Supporting API Gateway Boundary Control": (
                "Route authorization alone does not establish secure XML parsing "
                "or protection against XML processing exhaustion."
            ),
        },
        "INP28": {
            "OPA Policy Reference": (
                "No direct OPA rule verified for application URI validation, "
                "scheme restrictions, or context-aware output encoding"
            ),
            "Control Coverage Assessment": (
                "No direct application-level URI handling mitigation has been "
                "verified. Review URI canonicalization and scheme allowlists, "
                "then test alternate encodings and context-specific output handling."
            ),
            "Supporting API Gateway Boundary Control": (
                "Route authorization does not prove safe URI parsing or output encoding."
            ),
        },
        "INP34": {
            "OPA Policy Reference": (
                "No direct OPA rule verified for SOAP message validation or "
                "SOAP parser resource limits"
            ),
            "Control Coverage Assessment": (
                "No direct application-level SOAP mitigation has been verified. "
                "Review schema validation, array and request-size limits, and parser "
                "resource controls; test malformed and oversized messages."
            ),
            "Supporting API Gateway Boundary Control": (
                "Route authorization does not establish safe SOAP parsing or "
                "message-structure validation."
            ),
        },
        "INP37": {
            "OPA Policy Reference": (
                "No direct OPA rule verified for HTTP request-smuggling defenses "
                "or consistent gateway/backend request parsing"
            ),
            "Control Coverage Assessment": (
                "No direct request-smuggling mitigation has been verified in the "
                "existing OPA rules. Test ambiguous HTTP framing and review parsing "
                "consistency across gateways, proxies, and backends."
            ),
            "Supporting API Gateway Boundary Control": (
                "API Gateway authorization checks do not prove consistent HTTP "
                "message-framing behavior across the request path."
            ),
        },
        "SC02": {
            "OPA Policy Reference": (
                "No direct OPA rule verified for application output encoding "
                "or Content Security Policy enforcement"
            ),
            "Control Coverage Assessment": (
                "No direct XSS mitigation by existing OPA IaC rules has been "
                "verified. Review context-aware output encoding and CSP, and "
                "perform application-level XSS testing."
            ),
            "Supporting API Gateway Boundary Control": (
                "Route authorization does not prevent XSS caused by unsafe "
                "application output or establish that CSP is correctly enforced."
            ),
        },
        "SC03": {
            "OPA Policy Reference": (
                "No direct OPA rule verified for nested-script handling, "
                "unsafe remote-content proxying, or application output encoding"
            ),
            "Control Coverage Assessment": (
                "No direct application-level mitigation has been verified. Review "
                "content sanitization, output encoding, script execution controls, "
                "and remote-content handling; test relevant attack cases."
            ),
            "Supporting API Gateway Boundary Control": (
                "Route authorization does not establish safe nested-script handling "
                "or safe processing of remote content."
            ),
        },
        "SC04": {
            "OPA Policy Reference": (
                "No direct OPA rule verified for alternate-encoding XSS defenses "
                "or application input/output canonicalization"
            ),
            "Control Coverage Assessment": (
                "No direct application-level mitigation has been verified. Test "
                "alternate and encoded payloads and review canonicalization, input "
                "validation, and context-aware output encoding."
            ),
            "Supporting API Gateway Boundary Control": (
                "Route authorization does not establish correct input canonicalization "
                "or context-aware output encoding."
            ),
        },
        "SC05": {
            "OPA Policy Reference": (
                "policy/phase5-api-gateway.rego provides partial route-authorization "
                "checks only; no direct rule verified for client-control bypass"
            ),
            "Control Coverage Assessment": (
                "Partial infrastructure coverage only where API Gateway methods or "
                "routes lack authorization. Verify that security-critical checks "
                "are repeated server-side and cannot be bypassed by modifying the client."
            ),
            "Supporting API Gateway Boundary Control": (
                "API Gateway authorization can be one defense in depth, but does not "
                "prove server-side business-rule enforcement or client integrity."
            ),
        },
    }


    # PHASE5_GENERIC_COVERAGE_REFINEMENT_V1
    # Threat-specific assessments; these do not assert control effectiveness.
    targeted_mappings.update({
        "AA02": {
            "OPA Policy Reference": "Partial infrastructure check: policy/phase5-api-gateway.rego flags REST methods and V2 routes with authorization NONE or omitted. It does not validate token signatures, issuer, audience, claims, or trusted identity-provider configuration.",
            "Control Coverage Assessment": "Partial: API Gateway authorization configuration is checked, but principal spoofing defenses and token/identity trust validation are not directly verified by the existing OPA rules.",
            "Required Remediation Action": "Verify API authentication configuration and identity-provider trust. Test forged identities, invalid signatures, untrusted issuers, incorrect audiences, and manipulated claims; retain test results and configuration evidence."
        },
        "AC01": {
            "OPA Policy Reference": "No direct rule verified for application-level privilege enforcement or least-privilege authorization. Existing API Gateway policy checks only missing or NONE route/method authorization; review IAM permissions separately.",
            "Control Coverage Assessment": "No direct verification of server-side business/object authorization or least-privilege access. API Gateway authorization configuration alone does not prove users can access only permitted resources.",
            "Required Remediation Action": "Review IAM and application permissions; implement server-side authorization on every sensitive operation. Test horizontal and vertical privilege escalation and retain denied-access results and permission-review evidence."
        },
        "AC05": {
            "OPA Policy Reference": "No direct OPA rule verified for application request-integrity validation or context-aware content encoding.",
            "Control Coverage Assessment": "Not directly covered by existing infrastructure policies. Content spoofing protections depend on application validation, safe rendering, and appropriate response handling.",
            "Required Remediation Action": "Validate untrusted request content server-side and apply context-aware output encoding. Test manipulated headers, parameters, and content in relevant contexts; retain results showing unsafe content is rejected or rendered inert."
        },
        "AC07": {
            "OPA Policy Reference": "No direct rule verified for application deny-by-default access-control configuration. API Gateway policy checks only whether supported methods/routes omit authorization or use NONE.",
            "Control Coverage Assessment": "Partial at most: API Gateway authorization configuration is checked, but the completeness and correctness of application access-control rules are not established.",
            "Required Remediation Action": "Document access-control rules and enforce deny-by-default behavior. Test unauthenticated, unauthorized, and out-of-scope actions and retain reviewed access rules and negative-test results."
        },
        "AC08": {
            "OPA Policy Reference": "No direct rule verified for authorized modification of application registry, configuration, or service metadata.",
            "Control Coverage Assessment": "Not directly covered by existing OPA rules. Infrastructure tagging, encryption, and public-access checks do not establish who may modify application or service metadata.",
            "Required Remediation Action": "Restrict metadata and configuration changes to approved identities and roles. Test unauthorized changes, verify audit logging for authorized changes, and retain access-review and log evidence."
        },
        "AC09": {
            "OPA Policy Reference": "No direct rule verified for application business-rule enforcement, operation quotas, or abuse-case restrictions.",
            "Control Coverage Assessment": "Not directly covered. API Gateway authorization checks do not establish that permitted users are prevented from abusing valid functionality or exceeding business limits.",
            "Required Remediation Action": "Enforce server-side business rules, operation boundaries, and appropriate quotas. Test prohibited actions and excessive requests; retain results demonstrating rejection or throttling."
        },
        "AC11": {
            "OPA Policy Reference": "No direct rule verified for session credential integrity, token tampering detection, expiration, or rotation.",
            "Control Coverage Assessment": "Not directly covered by existing infrastructure policies. API Gateway route authorization configuration does not prove session credentials are validated and lifecycle controls are effective.",
            "Required Remediation Action": "Verify session/token validation, expiration, rotation where applicable, and invalidation. Test tampered, expired, revoked, and malformed credentials and retain the results."
        },
        "CR05": {
            "OPA Policy Reference": "No direct rule verified for transport cryptographic algorithm strength or resistance to credential/key brute-force attacks. Existing storage-encryption rules do not establish TLS configuration or authentication-attempt controls.",
            "Control Coverage Assessment": "Not directly covered for transport cryptography or brute-force resistance. Storage encryption and region checks are not evidence that approved transport algorithms, key sizes, and attempt limits are configured.",
            "Required Remediation Action": "Review approved cryptographic protocols, algorithms, key sizes, and key protection; apply appropriate authentication-attempt limits where relevant. Retain configuration evidence and applicable cryptographic and abuse-test results."
        },
        "CR08": {
            "OPA Policy Reference": "No direct rule verified for secure TLS/protocol configuration or consistent request parsing across intermediaries.",
            "Control Coverage Assessment": "Not directly covered. Existing infrastructure rules do not establish secure transport protocol settings or consistent gateway-to-backend message interpretation.",
            "Required Remediation Action": "Review transport and protocol settings and test malformed or ambiguous requests across gateway and backend components. Retain configuration evidence and protocol-security test results."
        },
        "DE01": {
            "OPA Policy Reference": "No direct rule verified for TLS enforcement or peer-certificate validation. Existing encryption checks primarily address selected storage resources, not network transport.",
            "Control Coverage Assessment": "Not directly covered for traffic interception. Storage encryption does not prove data in transit is encrypted or invalid peer certificates are rejected.",
            "Required Remediation Action": "Verify TLS enforcement and certificate-chain, hostname, and trust validation for relevant connections. Test invalid and untrusted certificates and retain configuration and integration-test evidence."
        },
        "DE02": {
            "OPA Policy Reference": "No direct OPA rule verified for application input canonicalization or double-decoding defenses.",
            "Control Coverage Assessment": "Not directly covered. Existing IaC policies do not validate application decoding order or prevent encoded input from bypassing validation.",
            "Required Remediation Action": "Define consistent decoding and canonicalization rules and validate input after the intended decoding step. Test double-encoded and ambiguous inputs and retain results showing validation cannot be bypassed."
        },
        "DE03": {
            "OPA Policy Reference": "No direct rule verified for transport encryption and prevention of sensitive-data exposure over untrusted channels.",
            "Control Coverage Assessment": "Not directly covered for sniffing attacks. Existing storage-encryption rules do not prove that application traffic is encrypted in transit or that sensitive data is excluded from exposed channels.",
            "Required Remediation Action": "Verify encryption for relevant network paths and inspect for sensitive data transmitted in plaintext. Retain TLS configuration evidence and traffic-inspection or integration-test results."
        },
        "DO01": {
            "OPA Policy Reference": "No direct rule verified for application rate limiting, request throttling, or abuse monitoring.",
            "Control Coverage Assessment": "Not directly covered. API Gateway authorization checks do not establish rate limits or resilience to flooding; service-specific throttling and monitoring require separate verification.",
            "Required Remediation Action": "Configure appropriate rate limits, throttling, and abuse monitoring at relevant service boundaries. Run controlled load and abuse tests and retain evidence of throttling, alerting, and service health."
        },
        "DO02": {
            "OPA Policy Reference": "No direct rule verified for application request-size limits, timeouts, concurrency bounds, or resource quotas.",
            "Control Coverage Assessment": "Not directly covered. Existing IaC policy checks do not establish that oversized requests or excessive resource consumption are bounded.",
            "Required Remediation Action": "Set appropriate payload-size limits, timeouts, concurrency limits, and quotas. Run controlled resource-exhaustion tests and retain evidence that excessive inputs and workloads are bounded."
        },
        "DS01": {
            "OPA Policy Reference": "No direct rule verified for application data-extraction prevention or authorization against bulk data access. S3 public-access-block checks cover a specific storage configuration, not all data-access paths.",
            "Control Coverage Assessment": "Partial storage configuration protection may exist, but unauthorized data retrieval and bulk extraction are not directly verified by the current policies.",
            "Required Remediation Action": "Review data-access permissions and bulk-export paths, enforce server-side authorization and least privilege, and test unauthorized reads and extraction attempts. Retain access-review and negative-test evidence."
        },
        "DS03": {
            "OPA Policy Reference": "Existing rules check selected exposure risks, including public SSH/RDP and S3 public-access-block settings. No direct rule verified for minimizing application or service fingerprinting information.",
            "Control Coverage Assessment": "Partial infrastructure exposure checks do not prevent technology fingerprinting through HTTP headers, error messages, banners, or publicly disclosed metadata.",
            "Required Remediation Action": "Review externally visible services, headers, banners, and metadata; remove unnecessary version and technology details. Retain external-scan and response-review evidence."
        },
        "DS04": {
            "OPA Policy Reference": "No direct OPA rule verified for application error-page content, error disclosure, or context-aware encoding of dynamic error messages.",
            "Control Coverage Assessment": "Not directly covered. Existing IaC policies do not establish that error responses conceal sensitive details or safely handle attacker-controlled content.",
            "Required Remediation Action": "Use generic client-facing errors, protect diagnostic logs, and safely encode dynamic error content. Test malformed requests and XSS payloads against error paths; retain response and test evidence."
        },
        "HA03": {
            "OPA Policy Reference": "No direct rule verified for reducing HTTP response technology fingerprints or removing unnecessary identifying headers.",
            "Control Coverage Assessment": "Not directly covered. Infrastructure tagging, encryption, and network exposure rules do not establish that application responses conceal unnecessary technology/version information.",
            "Required Remediation Action": "Review public response headers, banners, and error pages; remove unnecessary identifying details. Retain representative response captures and external-review results."
        },
        "INP10": {
            "OPA Policy Reference": "No direct OPA rule verified for application parameter injection prevention or parameterized query/command construction.",
            "Control Coverage Assessment": "Not directly covered. Existing Terraform policies do not inspect application query construction or validate parameters against application schemas.",
            "Required Remediation Action": "Use parameterized database/command operations and explicit server-side input schemas. Test injection payloads against relevant parameters and retain evidence that inputs cannot alter query or command behavior."
        },
        "INP14": {
            "OPA Policy Reference": "No direct rule verified for application input integrity, server-side data validation, or business-constraint enforcement.",
            "Control Coverage Assessment": "Not directly covered. Infrastructure policy checks do not establish that manipulated or unauthorized application data changes are rejected.",
            "Required Remediation Action": "Validate input server-side and enforce authorization, integrity, and business constraints. Test malformed and unauthorized changes and retain API negative-test and data-integrity evidence."
        },
        "INP17": {
            "OPA Policy Reference": "No direct rule verified for application response Content-Type correctness, MIME-sniffing protections, or browser-side content handling.",
            "Control Coverage Assessment": "Not directly covered. Existing OPA IaC rules do not establish safe MIME handling or prevent executable content from being interpreted under an unintended content type.",
            "Required Remediation Action": "Set correct response content types and appropriate browser protections, including X-Content-Type-Options where applicable. Test mismatched MIME types and retain response-header and XSS-test evidence."
        },
        "INP18": {
            "OPA Policy Reference": "No direct rule verified for suppressing sensitive application diagnostics, stack traces, or internal mapping details in client-facing errors.",
            "Control Coverage Assessment": "Not directly covered. Existing infrastructure policies do not establish that malformed requests and failures avoid disclosing sensitive implementation details.",
            "Required Remediation Action": "Return generic client-facing errors and restrict sensitive diagnostic details in responses and logs. Test malformed requests and retain evidence that stack traces, secrets, and internal details are not exposed."
        },
        "INP19": {
            "OPA Policy Reference": "No direct rule verified for XML parser external-entity processing or XML expansion/resource limits.",
            "Control Coverage Assessment": "Not directly covered. Terraform IaC policies do not inspect application XML parser configuration or establish defenses against XXE and XML expansion attacks.",
            "Required Remediation Action": "Disable unsafe external-entity processing and set appropriate XML parser resource limits. Test external-entity and expansion payloads in a controlled environment and retain parser configuration and test results."
        },
        "INP21": {
            "OPA Policy Reference": "No direct rule verified for XML DTD processing or external entity resolution settings.",
            "Control Coverage Assessment": "Not directly covered. Existing infrastructure policies do not verify application XML parser behavior for malicious DTDs or external entities.",
            "Required Remediation Action": "Disable unnecessary DTD processing and external entity resolution. Test malicious DTD and entity payloads and retain parser configuration and security-test evidence."
        },
        "INP29": {
            "OPA Policy Reference": "No direct rule verified for application context-aware output encoding or XSS payload variants involving doubled characters.",
            "Control Coverage Assessment": "Not directly covered. Existing OPA IaC rules do not inspect application rendering or establish that encoded and alternate XSS payloads remain inert.",
            "Required Remediation Action": "Apply context-aware output encoding and validate inputs appropriately. Test doubled-character, encoded, and context-specific XSS payloads and retain results showing injected scripts do not execute."
        },
        "INP36": {
            "OPA Policy Reference": "No direct rule verified for HTTP message-framing consistency or request-smuggling defenses across intermediaries.",
            "Control Coverage Assessment": "Not directly covered. Existing Terraform policy checks do not establish that gateways, proxies, and backends interpret HTTP message boundaries consistently.",
            "Required Remediation Action": "Review gateway/proxy/backend HTTP parsing and reject ambiguous message framing safely. Run controlled request-smuggling tests and retain configuration and test evidence demonstrating inconsistent framing is rejected."
        },
    })

    row = rows[-1]
    targeted = targeted_mappings.get(threat_id)
    if targeted:
        row.update(targeted)

    if threat_id == "DE04":
        rows[-1].update({
            "Control Owner": "To be assigned",
            "Implementation Status": "Policy and tests implemented; deployment not verified",
            "Verification Status": "Unit tests passed; CI and deployment verification pending",
            "Control Classification": "Preventive IaC configuration check",
            "OPA Policy Reference": "policy/phase5-database-logging.rego",
            "AWS Security Hub Control Reference": "Not yet mapped; confirm applicable AWS controls",
            "Control Coverage Assessment": (
                "Partial: validates planned PostgreSQL log export and logging "
                "parameters only; does not verify deployed settings, least-privilege "
                "access, retention, immutability, or resistance to privileged deletion."
            ),
            "Required Remediation Action": (
                "Verify deployed RDS and CloudWatch configuration; enforce "
                "least-privilege access; configure and test retention and tamper "
                "protection; assess log-deletion alerting."
            ),
            "Supporting API Gateway Boundary Control": "Not applicable",
        })

with destination.open("w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(file, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)

print(f"Generated: {destination}")
print(f"Total threat records: {len(rows)}")

assert len(rows) == len(findings)
