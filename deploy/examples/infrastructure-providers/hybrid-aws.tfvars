# Overlay in deploy/staging for a deployment that elects the two opt-ins in
# hybrid-openbao.values.yaml. Supply the installation's existing tfvars first.
evidence_encryption           = "provider-managed"
audit_export_queue_encryption = "provider-managed"
