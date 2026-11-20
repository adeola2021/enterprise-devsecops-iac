package cloud_security

import rego.v1

# ---------- helpers ----------
as_array(x) := x if is_array(x)
as_array(x) := [x] if not is_array(x)

managed contains rc if {
	some rc in input.resource_changes
	not "delete" in rc.change.actions
}

# ---------- Rule 1: S3 encryption ----------
# Provider >= 4: standalone SSE resource referencing the bucket.
# References live in `configuration`, because bucket.id is unknown at plan time.
bucket_has_sse_resource(addr) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_server_side_encryption_configuration"
	some ref in r.expressions.bucket.references
	ref == addr
}

# Legacy inline block
bucket_has_inline_sse(rc) if {
	count(rc.change.after.server_side_encryption_configuration) > 0
}

deny contains msg if {
	some rc in managed
	rc.type == "aws_s3_bucket"
	not bucket_has_sse_resource(rc.address)
	not bucket_has_inline_sse(rc)
	msg := sprintf("[S3_ENCRYPTION] %s: S3 bucket has no server-side encryption configuration", [rc.address])
}

# ---------- Rule 2: SG hardening (22 / 3389 from 0.0.0.0/0) ----------
admin_ports := {22, 3389}

open_cidr(rule) if {
	some c in rule.cidr_blocks
	c == "0.0.0.0/0"
}

open_cidr(rule) if {
	some c in rule.ipv6_cidr_blocks
	c == "::/0"
}

exposes_admin(rule) if {
	some p in admin_ports
	rule.from_port <= p
	p <= rule.to_port
}

exposes_admin(rule) if rule.protocol == "-1"

deny contains msg if {
	some rc in managed
	rc.type == "aws_security_group"
	some rule in rc.change.after.ingress
	open_cidr(rule)
	exposes_admin(rule)
	msg := sprintf("[SG_OPEN_ADMIN] %s: ingress %v-%v open to the internet", [rc.address, rule.from_port, rule.to_port])
}

deny contains msg if {
	some rc in managed
	rc.type == "aws_security_group_rule"
	rc.change.after.type == "ingress"
	open_cidr(rc.change.after)
	exposes_admin(rc.change.after)
	msg := sprintf("[SG_OPEN_ADMIN] %s: ingress %v-%v open to the internet", [rc.address, rc.change.after.from_port, rc.change.after.to_port])
}

# ---------- Rule 3: IAM least privilege ----------
iam_policy_types := {
	"aws_iam_role_policy", "aws_iam_user_policy",
	"aws_iam_group_policy", "aws_iam_policy",
}

# `warn` flags without blocking, because it needs human remediation.
warn contains msg if {
	some rc in managed
	rc.type in iam_policy_types
	doc := json.unmarshal(rc.change.after.policy)
	some stmt in as_array(doc.Statement)
	stmt.Effect == "Allow"
	"*" in as_array(stmt.Action)
	"*" in as_array(stmt.Resource)
	msg := sprintf("[IAM_WILDCARD] %s: Allow Action:* on Resource:* (needs manual least-privilege rewrite)", [rc.address])
}
