package main

required_tags := {
	"Environment",
	"Owner",
	"CostCenter",
}

allowed_nonprod_instance_types := {
	"t3.micro",
	"t3.small",
	"t3.medium",
}

sensitive_ports := {
	22,
	3389,
}

# Mandatory tags
deny contains msg if {
	resource := input.planned_values.root_module.resources[_]

	taggable_resource_types := {
		"aws_instance",
		"aws_security_group",
		"aws_s3_bucket",
		"aws_kms_key",
		"aws_sqs_queue",
		"aws_db_instance",
		"aws_db_parameter_group",
	}

	taggable_resource_types[resource.type]

	tags := object.get(resource.values, "tags", {})

	missing := required_tags - object.keys(tags)

	count(missing) > 0

	msg := sprintf(
		"Resource %s is missing mandatory tags: %v",
		[resource.address, missing],
	)
}

# EC2 instance size restriction
deny contains msg if {
	resource := input.planned_values.root_module.resources[_]

	resource.type == "aws_instance"

	tags := object.get(resource.values, "tags", {})

	environment := object.get(tags, "Environment", "")

	environment != "production"

	instance_type := resource.values.instance_type

	not allowed_nonprod_instance_types[instance_type]

	msg := sprintf(
		"EC2 instance %s uses prohibited instance type %s in non-production environment %s",
		[resource.address, instance_type, environment],
	)
}

# Restrict public SSH and RDP access
deny contains msg if {
	resource := input.planned_values.root_module.resources[_]

	resource.type == "aws_security_group"

	ingress := resource.values.ingress[_]

	sensitive_ports[ingress.from_port]

	"0.0.0.0/0" == ingress.cidr_blocks[_]

	msg := sprintf(
		"Security Group %s allows public access to sensitive port %v",
		[resource.address, ingress.from_port],
	)
}

# ==========================================================
# PHASE 2 ADVANCED POLICY CONTROLS
# ==========================================================

allowed_aws_regions := {
	"us-east-1",
	"eu-west-1",
}

# ----------------------------------------------------------
# Require customer-managed KMS encryption for EBS volumes
# ----------------------------------------------------------
deny contains msg if {
	resource := input.planned_values.root_module.resources[_]

	resource.type == "aws_ebs_volume"

	encrypted := object.get(resource.values, "encrypted", false)
	kms_key_id := object.get(resource.values, "kms_key_id", "")

	encrypted != true

	msg := sprintf(
		"EBS volume %s must be encrypted",
		[resource.address],
	)
}

deny contains msg if {
	resource := input.planned_values.root_module.resources[_]

	resource.type == "aws_ebs_volume"

	encrypted := object.get(resource.values, "encrypted", false)
	kms_key_id := object.get(resource.values, "kms_key_id", "")

	encrypted == true
	kms_key_id == ""

	msg := sprintf(
		"EBS volume %s must use a customer-managed KMS key",
		[resource.address],
	)
}

# ----------------------------------------------------------
# Require customer-managed KMS encryption for EC2 root EBS
# ----------------------------------------------------------
deny contains msg if {
	resource := input.planned_values.root_module.resources[_]

	resource.type == "aws_instance"

	root_block := resource.values.root_block_device[_]

	encrypted := object.get(root_block, "encrypted", false)
	kms_key_id := object.get(root_block, "kms_key_id", "")

	encrypted != true

	msg := sprintf(
		"EC2 instance %s root EBS volume must be encrypted",
		[resource.address],
	)
}

deny contains msg if {
	resource := input.planned_values.root_module.resources[_]

	resource.type == "aws_instance"

	root_block := resource.values.root_block_device[_]

	encrypted := object.get(root_block, "encrypted", false)
	kms_key_id := object.get(root_block, "kms_key_id", "")

	encrypted == true
	kms_key_id == ""

	msg := sprintf(
		"EC2 instance %s root EBS volume must use a customer-managed KMS key",
		[resource.address],
	)
}

# ----------------------------------------------------------
# Require KMS encryption configuration for S3 buckets
# ----------------------------------------------------------
deny contains msg if {
	resource := input.planned_values.root_module.resources[_]

	resource.type == "aws_s3_bucket"

	bucket_address := resource.address

	not s3_bucket_has_kms_encryption(bucket_address)

	msg := sprintf(
		"S3 bucket %s must have server-side encryption configured with a customer-managed KMS key",
		[bucket_address],
	)
}

s3_bucket_has_kms_encryption(bucket_address) if {
	encryption := input.planned_values.root_module.resources[_]

	encryption.type == "aws_s3_bucket_server_side_encryption_configuration"

	encryption.values.bucket != null

	contains(encryption.address, trim_prefix(bucket_address, "aws_s3_bucket."))

	rule := encryption.values.rule[_]
	default_encryption := rule.apply_server_side_encryption_by_default[_]

	default_encryption.sse_algorithm == "aws:kms"
	default_encryption.kms_master_key_id != null
	default_encryption.kms_master_key_id != ""
}

# ----------------------------------------------------------
# Require S3 Public Access Block
# ----------------------------------------------------------
deny contains msg if {
	resource := input.planned_values.root_module.resources[_]

	resource.type == "aws_s3_bucket"

	bucket_address := resource.address

	not s3_bucket_has_public_access_block(bucket_address)

	msg := sprintf(
		"S3 bucket %s must have an aws_s3_bucket_public_access_block resource",
		[bucket_address],
	)
}

s3_bucket_has_public_access_block(bucket_address) if {
	block := input.planned_values.root_module.resources[_]

	block.type == "aws_s3_bucket_public_access_block"

	contains(block.address, trim_prefix(bucket_address, "aws_s3_bucket."))

	block.values.block_public_acls == true
	block.values.ignore_public_acls == true
	block.values.block_public_policy == true
	block.values.restrict_public_buckets == true
}

# ----------------------------------------------------------
# Restrict AWS provider regions
# ----------------------------------------------------------
deny contains msg if {
	configuration := input.configuration.provider_config

	provider_name := object.keys(configuration)[_]
	provider := configuration[provider_name]

	startswith(provider_name, "aws")

	region := provider.expressions.region.constant_value

	not allowed_aws_regions[region]

	msg := sprintf(
		"AWS provider %s uses prohibited region %s. Allowed regions are us-east-1 and eu-west-1",
		[provider_name, region],
	)
}
