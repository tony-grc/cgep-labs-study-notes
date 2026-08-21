package compliance.au9_test

import data.compliance.au9
import rego.v1

compliant := {"planned_values": {"root_module": {"resources": [
	{
		"address": "google_storage_bucket.app",
		"type": "google_storage_bucket",
		"values": {"name": "app", "logging": [{"log_bucket": "logs"}], "versioning": []},
	},
	{
		"address": "google_storage_bucket.logs",
		"type": "google_storage_bucket",
		"values": {"name": "logs", "logging": [], "versioning": [{"enabled": true}]},
	},
]}}}

noncompliant := {"planned_values": {"root_module": {"resources": [
	{
		"address": "google_storage_bucket.app",
		"type": "google_storage_bucket",
		"values": {"name": "app", "logging": [{"log_bucket": "logs"}], "versioning": []},
	},
	{
		"address": "google_storage_bucket.logs",
		"type": "google_storage_bucket",
		"values": {"name": "logs", "logging": [], "versioning": [{"enabled": false}]},
	},
]}}}

test_versioned_log_target_passes if {
	count(au9.deny) == 0 with input as compliant
}

# The mechanical form of a quiet mistake: an architecture that promises
# versioning on both buckets, and code that versions only one.
test_unversioned_log_target_fails if {
	some msg in au9.deny with input as noncompliant
	contains(msg, "AU-9")
	contains(msg, "google_storage_bucket.logs")
}
