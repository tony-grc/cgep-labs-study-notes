# METADATA
# title: SC-28 - Encryption at Rest (AWS S3, customer-managed key)
# description: "Every aws_s3_bucket must have a server-side encryption configuration using aws:kms with a customer-managed key."
# authors:
#   - CGE-P
# custom:
#   control_id: SC-28
#   framework: nist-800-53-rev5
#   severity: high
#   remediation: "Add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm = aws:kms, kms_master_key_id referencing your aws_kms_key, and bucket_key_enabled = true."
package compliance.sc28_aws

import rego.v1

# Two separate rules, not one compound condition. A missing configuration and
# a weak configuration are different findings with different remediations;
# merging them produces a message that is wrong half the time.
deny contains msg if {
	some bucket in bucket_addresses
	not has_encryption(bucket)
	msg := sprintf(
		"[SC-28] %s: no aws_s3_bucket_server_side_encryption_configuration references this bucket. Remediation: add one.",
		[bucket],
	)
}

deny contains msg if {
	some bucket in bucket_addresses
	has_encryption(bucket)
	not has_kms_encryption(bucket)
	msg := sprintf(
		"[SC-28] %s: encrypted with SSE-S3 (AES256), not a customer-managed key. Remediation: sse_algorithm = aws:kms with kms_master_key_id.",
		[bucket],
	)
}

bucket_addresses contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

sse_configs contains r if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_server_side_encryption_configuration"
}

has_encryption(bucket_addr) if {
	some r in sse_configs
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
}

has_kms_encryption(bucket_addr) if {
	some r in sse_configs
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	r.expressions.rule[_].apply_server_side_encryption_by_default[_].sse_algorithm.constant_value == "aws:kms"
}

# At plan time the bucket name is "(known after apply)" because the random_id
# suffix does not exist yet, so planned_values.bucket is null. Match on the
# configuration references instead: strings like "aws_s3_bucket.primary.id"
# that Terraform resolves at apply.
references_bucket(ref, addr) if ref == addr

references_bucket(ref, addr) if ref == sprintf("%s.id", [addr])

references_bucket(ref, addr) if ref == sprintf("%s.bucket", [addr])

references_bucket(ref, addr) if ref == sprintf("%s.arn", [addr])
