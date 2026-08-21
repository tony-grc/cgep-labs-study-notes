package compliance.cm6_aws_test

import rego.v1
import data.compliance.cm6_aws

tagged := {"planned_values": {"root_module": {"resources": [{
	"address": "aws_s3_bucket.primary",
	"type": "aws_s3_bucket",
	"values": {"tags_all": {
		"Project": "cgep-lab",
		"Environment": "dev",
		"ManagedBy": "terraform",
		"ComplianceScope": "cge-p-lab",
	}},
}]}}}

partial := {"planned_values": {"root_module": {"resources": [{
	"address": "aws_s3_bucket.primary",
	"type": "aws_s3_bucket",
	"values": {"tags_all": {"Project": "cgep-lab"}},
}]}}}

# Lab 2.3 v2 creates a CMK. An untagged key sits outside boundary enumeration.
untagged_kms := {"planned_values": {"root_module": {"resources": [{
	"address": "aws_kms_key.bucket",
	"type": "aws_kms_key",
	"values": {},
}]}}}

not_taggable := {"planned_values": {"root_module": {"resources": [{
	"address": "random_id.bucket_suffix",
	"type": "random_id",
	"values": {},
}]}}}

test_fully_tagged_passes if {
	count(cm6_aws.deny) == 0 with input as tagged
}

test_partial_tags_fail if {
	some msg in cm6_aws.deny with input as partial
	contains(msg, "CM-6")
}

test_untagged_kms_key_fails if {
	some msg in cm6_aws.deny with input as untagged_kms
	contains(msg, "aws_kms_key.bucket")
}

# Constrains taggable_type, so the mutation cannot survive by OR-ing the
# alternative definitions. Same trap as the GCP variant in Lab 3.3.
test_non_taggable_type_ignored if {
	count(cm6_aws.deny) == 0 with input as not_taggable
}
