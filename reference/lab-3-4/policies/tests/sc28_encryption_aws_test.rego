package compliance.sc28_aws_test

import data.compliance.sc28_aws
import rego.v1

# Fixtures mirror real `terraform show -json` shape: configuration.* holds
# references (resolvable at plan time), planned_values.* holds values.
kms_encrypted := {"configuration": {"root_module": {"resources": [
	{"type": "aws_s3_bucket", "name": "primary", "expressions": {}},
	{
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"name": "primary",
		"expressions": {
			"bucket": {"references": ["aws_s3_bucket.primary.id", "aws_s3_bucket.primary"]},
			"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": {"constant_value": "aws:kms"}}]}],
		},
	},
]}}}

aes_only := {"configuration": {"root_module": {"resources": [
	{"type": "aws_s3_bucket", "name": "primary", "expressions": {}},
	{
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"name": "primary",
		"expressions": {
			"bucket": {"references": ["aws_s3_bucket.primary.id", "aws_s3_bucket.primary"]},
			"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": {"constant_value": "AES256"}}]}],
		},
	},
]}}}

no_encryption := {"configuration": {"root_module": {"resources": [
	{"type": "aws_s3_bucket", "name": "primary", "expressions": {}},
]}}}

test_cmk_encrypted_passes if {
	count(sc28_aws.deny) == 0 with input as kms_encrypted
}

test_missing_encryption_fails if {
	some msg in sc28_aws.deny with input as no_encryption
	contains(msg, "SC-28")
	contains(msg, "no aws_s3_bucket_server_side_encryption_configuration")
}

# The distinct-message requirement: AES256 is present-but-weak, which is a
# different finding from absent, with a different fix.
test_aes256_fails_with_distinct_message if {
	some msg in sc28_aws.deny with input as aes_only
	contains(msg, "SC-28")
	contains(msg, "not a customer-managed key")
}
