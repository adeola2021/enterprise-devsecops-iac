package cloud_security_hcl

import rego.v1

# Raw-HCL companion to cloud_security (plan-JSON). Conftest wraps each
# resource body in a one-element array; unwrap it.
as_list(x) := x if is_array(x)

as_list(x) := [x] if not is_array(x)

body(x) := x[0] if is_array(x)

body(x) := x if not is_array(x)

resources(rtype) := {name: body(raw) |
	some name, raw in object.get(input, ["resource", rtype], {})
}

admin_ports := {22, 3389}

has_inline_sse(b) if b.server_side_encryption_configuration

has_separate_sse(name) if {
	some _, sse in resources("aws_s3_bucket_server_side_encryption_configuration")
	contains(sse.bucket, sprintf("aws_s3_bucket.%s.", [name]))
}

deny contains msg if {
	some name, b in resources("aws_s3_bucket")
	not has_inline_sse(b)
	not has_separate_sse(name)
	msg := sprintf("[S3_ENCRYPTION] aws_s3_bucket.%s: S3 bucket has no server-side encryption configuration", [name])
}

exposes_admin(rule) if {
	some p in admin_ports
	to_number(rule.from_port) <= p
	p <= to_number(rule.to_port)
}

open_cidr(rule) if "0.0.0.0/0" in as_list(rule.cidr_blocks)

open_cidr(rule) if "::/0" in as_list(rule.ipv6_cidr_blocks)

deny contains msg if {
	some name, sg in resources("aws_security_group")
	some rule in as_list(sg.ingress)
	exposes_admin(rule)
	open_cidr(rule)
	msg := sprintf("[SG_OPEN_ADMIN] aws_security_group.%s: ingress %v-%v open to the internet", [name, rule.from_port, rule.to_port])
}

deny contains msg if {
	some name, rule in resources("aws_security_group_rule")
	rule.type == "ingress"
	exposes_admin(rule)
	open_cidr(rule)
	msg := sprintf("[SG_OPEN_ADMIN] aws_security_group_rule.%s: ingress %v-%v open to the internet", [name, rule.from_port, rule.to_port])
}

iam_policy_types := {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}

is_wild(x) if "*" in as_list(x)

# warn, not deny: needs a human to rewrite (same as the plan-JSON policy)
warn contains msg if {
	some t in iam_policy_types
	some name, r in resources(t)
	is_string(r.policy)
	json.is_valid(r.policy)
	doc := json.unmarshal(r.policy)
	some st in as_list(doc.Statement)
	st.Effect == "Allow"
	is_wild(st.Action)
	is_wild(st.Resource)
	msg := sprintf("[IAM_WILDCARD] %s.%s: Allow Action:* on Resource:* (needs manual least-privilege rewrite)", [t, name])
}
