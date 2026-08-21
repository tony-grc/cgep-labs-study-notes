# METADATA
# title: SC-28 - Encryption at Rest (GCS)
# description: "Every google_storage_bucket must encrypt at rest with a customer-managed encryption key (CMEK)."
# authors:
#   - CGE-P
# custom:
#   control_id: SC-28
#   framework: nist-800-53-rev5
#   severity: high
#   remediation: "Add an encryption { default_kms_key_name = ... } block referencing a google_kms_crypto_key you control."
package compliance.sc28

import rego.v1

deny contains msg if {
	some resource in all_buckets
	not has_cmek(resource)
	msg := sprintf(
		"[SC-28] %s: missing customer-managed encryption key. Remediation: add encryption { default_kms_key_name = ... }.",
		[resource.address],
	)
}

all_buckets contains r if {
	some r in input.planned_values.root_module.resources
	r.type == "google_storage_bucket"
}

all_buckets contains r if {
	some child in input.planned_values.root_module.child_modules
	some r in child.resources
	r.type == "google_storage_bucket"
}

# At plan time the KMS key ID is "(known after apply)" and the plan JSON
# omits unknown values entirely. Requiring a populated string would fail
# every compliant configuration. Accept a non-empty block; fail only when
# it is missing or explicitly empty.
has_cmek(resource) if {
	count(resource.values.encryption) > 0
	not empty_kms_key(resource.values.encryption[0])
}

empty_kms_key(enc) if enc.default_kms_key_name == ""

empty_kms_key(enc) if enc.default_kms_key_name == null
