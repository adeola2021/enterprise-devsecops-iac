package cloud_security_hcl_test

import rego.v1

import data.cloud_security_hcl

# Inputs mirror the real `conftest parse` shape (resource bodies are 1-element arrays).

test_unencrypted_bucket_denied if {
	r := cloud_security_hcl.deny with input as {"resource": {"aws_s3_bucket": {"b": [{"bucket": "x"}]}}}
	count(r) == 1
}

test_bucket_with_sse_resource_passes if {
	r := cloud_security_hcl.deny with input as {"resource": {
		"aws_s3_bucket": {"b": [{"bucket": "x"}]},
		"aws_s3_bucket_server_side_encryption_configuration": {"s": [{"bucket": "${aws_s3_bucket.b.id}"}]},
	}}
	count(r) == 0
}

test_ssh_open_denied if {
	r := cloud_security_hcl.deny with input as {"resource": {"aws_security_group": {"w": [{"ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]}]}}}
	count(r) == 1
}

test_rdp_open_denied if {
	r := cloud_security_hcl.deny with input as {"resource": {"aws_security_group": {"w": [{"ingress": [{"from_port": 3389, "to_port": 3389, "cidr_blocks": ["0.0.0.0/0"]}]}]}}}
	count(r) == 1
}

test_https_open_allowed if {
	r := cloud_security_hcl.deny with input as {"resource": {"aws_security_group": {"w": [{"ingress": [{"from_port": 443, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"]}]}]}}}
	count(r) == 0
}

test_iam_wildcard_warns if {
	r := cloud_security_hcl.warn with input as {"resource": {"aws_iam_role_policy": {"p": [{"policy": `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`}]}}}
	count(r) == 1
}

test_iam_scoped_ok if {
	r := cloud_security_hcl.warn with input as {"resource": {"aws_iam_role_policy": {"p": [{"policy": `{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::b/*"]}]}`}]}}}
	count(r) == 0
}
