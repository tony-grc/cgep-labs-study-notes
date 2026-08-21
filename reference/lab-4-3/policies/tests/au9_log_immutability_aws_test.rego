package compliance.au9_aws_test

import data.compliance.au9_aws
import rego.v1

# Compliant: the log bucket named as the logging target is itself versioned.
versioned_target := {"configuration": {"root_module": {"resources": [
	{
		"type": "aws_s3_bucket_logging",
		"name": "primary",
		"expressions": {
			"bucket": {"references": ["aws_s3_bucket.primary.id"]},
			"target_bucket": {"references": ["aws_s3_bucket.log.id", "aws_s3_bucket.log"]},
		},
	},
	{
		"type": "aws_s3_bucket_versioning",
		"name": "log",
		"expressions": {"bucket": {"references": ["aws_s3_bucket.log.id", "aws_s3_bucket.log"]}},
	},
]}}}

# The common shape of the mistake: primary versioned, log bucket not.
v1_shape := {"configuration": {"root_module": {"resources": [
	{
		"type": "aws_s3_bucket_logging",
		"name": "primary",
		"expressions": {
			"bucket": {"references": ["aws_s3_bucket.primary.id"]},
			"target_bucket": {"references": ["aws_s3_bucket.log.id", "aws_s3_bucket.log"]},
		},
	},
	{
		"type": "aws_s3_bucket_versioning",
		"name": "primary",
		"expressions": {"bucket": {"references": ["aws_s3_bucket.primary.id", "aws_s3_bucket.primary"]}},
	},
]}}}

test_versioned_log_target_passes if {
	count(au9_aws.deny) == 0 with input as versioned_target
}

test_v1_unversioned_log_bucket_fails if {
	some msg in au9_aws.deny with input as v1_shape
	contains(msg, "AU-9")
	contains(msg, "aws_s3_bucket.log")
}
