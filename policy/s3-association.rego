package main

# Find a configured managed resource by its full Terraform address.
s3_config_resource(address) := resource if {
	root := input.configuration.root_module
	walk(root, [_, resource])
	is_object(resource)
	resource.address == address
	resource.mode == "managed"
}

# An associated resource explicitly references the bucket.
s3_reference_matches(config_resource, bucket_address) if {
	refs := config_resource.expressions.bucket.references
	refs[_] == bucket_address
}

s3_reference_matches(config_resource, bucket_address) if {
	refs := config_resource.expressions.bucket.references
	refs[_] == sprintf("%s.id", [bucket_address])
}

# Prefer configuration references where available.
s3_resource_matches_bucket(resource, bucket) if {
	config := s3_config_resource(resource.address)
	s3_reference_matches(config, bucket.address)
}

# Support fixtures containing resolved bucket names.
# Do not use this fallback if the configuration explicitly
# references a different Terraform resource.
s3_resource_matches_bucket(resource, bucket) if {
	not s3_config_resource(resource.address)

	bucket_name := bucket.values.bucket
	is_string(bucket_name)
	bucket_name != ""

	resource.values.bucket == bucket_name
}

# Resolve customer-managed KMS references in genuine plans.
s3_has_customer_kms_reference(resource) if {
	config := s3_config_resource(resource.address)

	rule := config.expressions.rule[_]
	setting := rule.apply_server_side_encryption_by_default[_]

	refs := setting.kms_master_key_id.references
	ref := refs[_]

	startswith(ref, "aws_kms_key.")
}

# Support resolved KMS identifiers in existing fixtures.
s3_has_customer_kms_reference(resource) if {
	rule := resource.values.rule[_]
	setting := rule.apply_server_side_encryption_by_default[_]

	key := setting.kms_master_key_id
	is_string(key)
	key != ""
}

# ==========================================================
# PHASE 5: S3 SERVER ACCESS LOGGING DESTINATION EXCEPTION
# ==========================================================

# Match a Terraform configuration reference to a resource
# using its complete address, rather than its name.

phase5_config_references(config_resource, attribute, address) if {
	refs := config_resource.expressions[attribute].references
	refs[_] == address
}

phase5_config_references(config_resource, attribute, address) if {
	refs := config_resource.expressions[attribute].references
	refs[_] == sprintf("%s.id", [address])
}

# The bucket must be the destination of S3 server access logging.

phase5_is_logging_destination(bucket) if {
	logging := input.planned_values.root_module.resources[_]
	logging.type == "aws_s3_bucket_logging"

	config := s3_config_resource(logging.address)
	phase5_config_references(
		config,
		"target_bucket",
		bucket.address,
	)
}

# The destination must explicitly use SSE-S3.

phase5_has_sse_s3(bucket) if {
	encryption := input.planned_values.root_module.resources[_]
	encryption.type == "aws_s3_bucket_server_side_encryption_configuration"

	s3_resource_matches_bucket(encryption, bucket)

	rule := encryption.values.rule[_]
	setting := rule.apply_server_side_encryption_by_default[_]

	setting.sse_algorithm == "AES256"
}

# Confirm that a bucket policy is attached.

phase5_has_bucket_policy(bucket) if {
	policy := input.planned_values.root_module.resources[_]
	policy.type == "aws_s3_bucket_policy"

	s3_resource_matches_bucket(policy, bucket)
}

# Confirm versioning is enabled.

phase5_has_versioning(bucket) if {
	versioning := input.planned_values.root_module.resources[_]
	versioning.type == "aws_s3_bucket_versioning"

	s3_resource_matches_bucket(versioning, bucket)

	config := versioning.values.versioning_configuration[_]
	config.status == "Enabled"
}

# Confirm a lifecycle rule is enabled.

phase5_has_lifecycle(bucket) if {
	lifecycle := input.planned_values.root_module.resources[_]
	lifecycle.type == "aws_s3_bucket_lifecycle_configuration"

	s3_resource_matches_bucket(lifecycle, bucket)

	rule := lifecycle.values.rule[_]
	rule.status == "Enabled"
}

# All requirements must be satisfied.

phase5_approved_logging_destination(bucket) if {
	phase5_is_logging_destination(bucket)
	phase5_has_sse_s3(bucket)
	phase4_s3_has_public_access_block(bucket)
	phase5_has_bucket_policy(bucket)
	phase5_has_versioning(bucket)
	phase5_has_lifecycle(bucket)
}
