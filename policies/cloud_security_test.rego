package cloud_security_test

import rego.v1

import data.cloud_security

bare_bucket := {
	"resource_changes": [{"address": "aws_s3_bucket.b", "type": "aws_s3_bucket", "change": {"actions": ["create"], "after": {}}}],
	"configuration": {"root_module": {"resources": []}},
}

test_unencrypted_bucket_denied if {
	count(cloud_security.deny) == 1 with input as bare_bucket
}

test_bucket_with_sse_resource_passes if {
	inp := object.union(bare_bucket, {"configuration": {"root_module": {"resources": [{
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"expressions": {"bucket": {"references": ["aws_s3_bucket.b.id", "aws_s3_bucket.b"]}},
	}]}}})
	count(cloud_security.deny) == 0 with input as inp
}

test_ssh_open_denied if {
	inp := {"resource_changes": [{"address": "aws_security_group.s", "type": "aws_security_group", "change": {"actions": ["create"], "after": {"ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": []}]}}}]}
	count(cloud_security.deny) == 1 with input as inp
}

test_https_open_allowed if {
	inp := {"resource_changes": [{"address": "aws_security_group.s", "type": "aws_security_group", "change": {"actions": ["create"], "after": {"ingress": [{"from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": []}]}}}]}
	count(cloud_security.deny) == 0 with input as inp
}
