# METADATA
# title: AC-3 - Access Enforcement (AWS S3 public access block)
# description: "Every aws_s3_bucket must have an aws_s3_bucket_public_access_block with all four flags true."
# authors:
#   - CGE-P
# custom:
#   control_id: AC-3
#   framework: nist-800-53-rev5
#   severity: critical
#   remediation: "Add aws_s3_bucket_public_access_block with all four flags set to true. Three is not enough."
package compliance.ac3_aws

import rego.v1

deny contains msg if {
	some bucket in bucket_addresses
	not has_complete_pab(bucket)
	msg := sprintf(
		"[AC-3] %s: missing or incomplete aws_s3_bucket_public_access_block. All four flags must be true.",
		[bucket],
	)
}

bucket_addresses contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

# The four flags are two axes crossed: ACL vs policy, and new vs existing.
# Leave one off and you have either an existing public grant still live or
# an open door for a new one.
has_complete_pab(bucket_addr) if {
	addr := pab_for(bucket_addr)
	v := pab_planned_values(addr)
	v.block_public_acls == true
	v.block_public_policy == true
	v.ignore_public_acls == true
	v.restrict_public_buckets == true
}

pab_for(bucket_addr) := addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_public_access_block"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	addr := sprintf("aws_s3_bucket_public_access_block.%s", [r.name])
}

pab_planned_values(addr) := values if {
	some r in input.planned_values.root_module.resources
	r.address == addr
	values := r.values
}

references_bucket(ref, addr) if ref == addr

references_bucket(ref, addr) if ref == sprintf("%s.id", [addr])

references_bucket(ref, addr) if ref == sprintf("%s.bucket", [addr])
