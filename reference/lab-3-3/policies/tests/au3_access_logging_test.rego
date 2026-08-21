package compliance.au3_test

import data.compliance.au3
import rego.v1

compliant := {"planned_values": {"root_module": {"resources": [
	{
		"address": "google_storage_bucket.app",
		"type": "google_storage_bucket",
		"values": {"name": "app", "logging": [{"log_bucket": "logs"}]},
	},
	{
		"address": "google_storage_bucket.logs",
		"type": "google_storage_bucket",
		"values": {"name": "logs", "logging": []},
	},
]}}}

noncompliant := {"planned_values": {"root_module": {"resources": [{
	"address": "google_storage_bucket.naked",
	"type": "google_storage_bucket",
	"values": {"name": "naked", "logging": []},
}]}}}

test_logged_bucket_passes if {
	count(au3.deny) == 0 with input as compliant
}

test_unlogged_bucket_fails if {
	some msg in au3.deny with input as noncompliant
	contains(msg, "AU-3")
	contains(msg, "google_storage_bucket.naked")
}

# The log sink itself must not be flagged for lacking a log sink.
test_log_sink_is_exempt if {
	not sink_flagged with input as compliant
}

sink_flagged if {
	some msg in au3.deny
	contains(msg, "google_storage_bucket.logs")
}
