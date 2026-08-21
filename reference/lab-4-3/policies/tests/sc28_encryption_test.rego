package compliance.sc28_test

import data.compliance.sc28
import rego.v1

compliant := {"planned_values": {"root_module": {"resources": [{
	"address": "google_storage_bucket.good",
	"type": "google_storage_bucket",
	"values": {
		"name": "good",
		"encryption": [{"default_kms_key_name": "projects/x/locations/us/keyRings/r/cryptoKeys/k"}],
	},
}]}}}

noncompliant := {"planned_values": {"root_module": {"resources": [{
	"address": "google_storage_bucket.bad",
	"type": "google_storage_bucket",
	"values": {"name": "bad", "encryption": []},
}]}}}

empty_key := {"planned_values": {"root_module": {"resources": [{
	"address": "google_storage_bucket.empty",
	"type": "google_storage_bucket",
	"values": {"name": "empty", "encryption": [{"default_kms_key_name": ""}]},
}]}}}

test_compliant_passes if {
	count(sc28.deny) == 0 with input as compliant
}

test_missing_encryption_fails if {
	some msg in sc28.deny with input as noncompliant
	contains(msg, "SC-28")
	contains(msg, "google_storage_bucket.bad")
}

test_empty_key_fails if {
	some msg in sc28.deny with input as empty_key
	contains(msg, "SC-28")
}
