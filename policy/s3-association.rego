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
