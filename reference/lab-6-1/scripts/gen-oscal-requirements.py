#!/usr/bin/env python3
"""Build OSCAL implemented-requirements from the Lab 3.3 policy catalog.

Each Rego policy declares its control_id in a # METADATA block. That is the
single source of truth; this script projects it into OSCAL so the mapping is
authored once and never retyped. Anywhere a mapping is typed twice is a
place it can drift.

Usage: gen-oscal-requirements.py <policy-catalog.json> <evidence-uri>
"""
import json
import pathlib
import sys
import uuid

catalog_path = pathlib.Path(sys.argv[1])
evidence_uri = sys.argv[2]

# Controls satisfied by means OTHER than a Rego policy, plus any whose status
# is not a plain "implemented". Every entry is a claim you must defend aloud.
# Keeping this small and explicit is the discipline.
EXTRA = {
    "sc-8":  ("implemented", "aws_s3_bucket_policy denies s3:* when aws:SecureTransport is false, on both buckets."),
    "sc-12": ("implemented", "aws_kms_key.bucket with enable_key_rotation = true."),
    "sc-13": ("implemented", "SSE-KMS with a customer-managed key, bucket keys enabled."),
    "ac-6":  ("implemented", "aws_s3_bucket_ownership_controls = BucketOwnerEnforced; ACLs disabled."),
    "au-11": ("implemented", "aws_s3_bucket_lifecycle_configuration expires access logs at 90 days."),
    "cm-8":  ("implemented", "Provider default_tags applies ComplianceScope to every taggable resource."),
    "cp-9":  ("implemented", "aws_s3_bucket_versioning on the primary bucket."),
    "si-7":  ("implemented", "Versioning preserves prior object states for integrity comparison."),
    # Honest downgrades. Lab 5.2 authored the Athena queries; nothing schedules them.
    "au-6":  ("partial", "Athena review queries authored in Lab 5.2. Scheduled review and a named reviewer are not yet in place."),
}

TERRAFORM_RESOURCE = {
    "sc-8":  "aws_s3_bucket_policy.primary",
    "sc-12": "aws_kms_key.bucket",
    "sc-13": "aws_s3_bucket_server_side_encryption_configuration.primary",
    "sc-28": "aws_s3_bucket_server_side_encryption_configuration.primary",
    "ac-3":  "aws_s3_bucket_public_access_block.primary",
    "ac-6":  "aws_s3_bucket_ownership_controls.primary",
    "au-3":  "aws_s3_bucket_logging.primary",
    "au-9":  "aws_s3_bucket_versioning.log",
    "au-11": "aws_s3_bucket_lifecycle_configuration.log",
    "cp-9":  "aws_s3_bucket_versioning.primary",
    "si-7":  "aws_s3_bucket_versioning.primary",
    "cm-6":  "provider.aws.default_tags",
    "cm-8":  "provider.aws.default_tags",
}

reqs, seen = [], set()


def add(control_id, description, status, policy_pkg=None):
    if control_id in seen:
        return
    seen.add(control_id)
    props = [{"name": "implementation-status", "value": status}]
    if control_id in TERRAFORM_RESOURCE:
        props.append({"name": "terraform-resource", "value": TERRAFORM_RESOURCE[control_id]})
    if policy_pkg:
        props.append({"name": "enforced-by-policy", "value": policy_pkg})
    reqs.append({
        "uuid": str(uuid.uuid4()),
        "control-id": control_id,
        "description": description,
        "props": props,
        "links": [{
            "rel": "evidence",
            "href": evidence_uri,
            "text": "Signed pipeline bundle containing terraform plan.json.",
        }],
    })


for p in json.loads(catalog_path.read_text()):
    cid = (p.get("control") or "").lower()
    if not cid:
        continue
    add(cid,
        f"{p['title']} Enforced in the pipeline by Rego policy {p['package']}, "
        f"severity {p['severity']}. Remediation: {p.get('remediation', 'see policy')}",
        "implemented",
        p["package"])

for cid, (status, desc) in EXTRA.items():
    add(cid, desc, status)

json.dump(sorted(reqs, key=lambda r: r["control-id"]), sys.stdout, indent=2)
