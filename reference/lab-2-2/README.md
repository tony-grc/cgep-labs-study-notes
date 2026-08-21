# Lab 2.2 reference: remote state backend

Bootstrap workspace that creates the S3 + KMS state backend every other
lab uses. Guide: [`docs/02_02_remote_state_backend.md`](../../docs/02_02_remote_state_backend.md).

```bash
export AWS_PROFILE=cgep   # the credential_process profile from Lab 0.1
terraform init
terraform apply
terraform output -raw backend_block   # paste into the other labs
```

**This workspace keeps LOCAL state on purpose.** It is the bootstrap: you
cannot store the state of the bucket that stores state inside itself. Its
state describes a bucket, a key, an alias and five configuration
resources, none of which carry a secret attribute. Verify that claim
rather than trusting it:

```bash
terraform state pull | jq '[.resources[].instances[].attributes | keys] | flatten | unique'
```

If you ever add a resource here with a secret attribute, that reasoning
stops holding and the local-state decision has to be revisited.

Ten resources. Expect the lifecycle configuration to take 40 to 60 seconds;
everything else is quick. **Do not destroy this until the end of the course**, after
every other workspace is gone; deleting the state bucket while resources
still exist strands them.
