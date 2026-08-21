package compliance.ac3_aws_test

import rego.v1
import data.compliance.ac3_aws

cfg := {"root_module": {"resources": [
	{"type": "aws_s3_bucket", "name": "primary", "expressions": {}},
	{
		"type": "aws_s3_bucket_public_access_block",
		"name": "primary",
		"expressions": {"bucket": {"references": ["aws_s3_bucket.primary.id", "aws_s3_bucket.primary"]}},
	},
]}}

all_four := {
	"configuration": cfg,
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_public_access_block.primary",
		"type": "aws_s3_bucket_public_access_block",
		"values": {
			"block_public_acls": true,
			"block_public_policy": true,
			"ignore_public_acls": true,
			"restrict_public_buckets": true,
		},
	}]}},
}

# Three of four. This is the case the lab insists on: two axes (ACL vs
# policy) by two states (new vs existing), so one gap leaves a door open.
three_of_four := {
	"configuration": cfg,
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_public_access_block.primary",
		"type": "aws_s3_bucket_public_access_block",
		"values": {
			"block_public_acls": true,
			"block_public_policy": true,
			"ignore_public_acls": true,
			"restrict_public_buckets": false,
		},
	}]}},
}

no_pab := {"configuration": {"root_module": {"resources": [
	{"type": "aws_s3_bucket", "name": "primary", "expressions": {}},
]}}}

test_all_four_true_passes if {
	count(ac3_aws.deny) == 0 with input as all_four
}

test_three_of_four_fails if {
	some msg in ac3_aws.deny with input as three_of_four
	contains(msg, "AC-3")
}

test_missing_pab_fails if {
	some msg in ac3_aws.deny with input as no_pab
	contains(msg, "AC-3")
}
