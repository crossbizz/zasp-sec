# Accepted feature checkpoint39248419

This checkpoint preceded the focused manual-requester correction. Its exact patch is retained in checkpoint-39248419.patch. See final-manifest.md for the review candidate; task-only.patch now contains that final candidate.

HEAD: `8733b16f8d939d38a8157dd2519e57fc6f630542`.

Live release58 fingerprint: `39248419d0b55e7904f39b8f01d6aff748aeacd5fca1eed683e533a4a6396b4f`.

The task-only patch is relative to the preserved inherited bytes, not to HEAD. Nine created files were absent at entry. Only production_audit_exports.go and production_compliance.go modify inherited content; their full before bytes and SHA256 values are in before-manifest.md. No index, commit or remote mutation was performed.

Frozen SHA256 values:

```text
2fd3eaaa311ee27432021a9d8285db393d6387bb8bb69e8f9cb95e83c5e97080  services/platform/migrations/security_agent_exports_release.go
47d7492e68eb3d9db13a0cb15fb24e6c447cab397c87b7b8f143fce0c7468a2f  services/platform/migrations/production_security_agent_exports.go
87a38c5cf59e10f4cbd0d05d7a5e90f8237029f2865e24db8b98a21bf0038f0c  services/platform/migrations/sql/0058_production_security_agent_exports.up.sql
20d2706de4f746ae978fa1f663eb9e9e53c585a437fce3324d23dfd910ad2c15  services/platform/migrations/sql/0058_production_security_agent_exports.down.sql
0cfd0a60483eb0c9144bc879b4fcbff6ed6d6320b4c0b81b6218ea4bc6571acc  services/platform/migrations/sql/fragments/security_agent_export_sources.sql
8c25bfe0d7729c16d4130c7070587446655130e855a8650b09bce4f34c7abf21  services/platform/migrations/sql/fragments/security_agent_export_jobs.sql
e4740e384e821293d264435967bbce83dee6b9ad13ec97c060066b2905be022e  services/platform/migrations/sql/fragments/security_agent_export_links.sql
6ea9952d1e853e6197beb398ef36b8b8d241b399a149c1a1e2227ffccfad7147  services/platform/apiserver/security_agent_export_postgres_test.go
e0cb3d18b28bc5c861a1595f0246ea80a950aa8d1533a41484dd664c9554583c  services/platform/apiserver/security_agent_export_release_postgres_test.go
5e5ba19c9833ba91339bdc70c072792de126fa24bdebebd157d8721cb898bbbc  services/platform/migrations/production_audit_exports.go
f937b291e4a5c06f03d0a13f3be2ba77ee2ec51ee9ce4e063b45ab2a8b4d78c8  services/platform/migrations/production_compliance.go
0717f1520a8464e336dd5278914f0d6684613bd16c0c742db642a1c91ee1605a  docs/internal/security-agent-export-20260919/database/task-only.patch
bb933859b4ba754f446e2cf4147371aea230eb3f1f244752446571d5caea1e04  services/platform/agentsec-worker/security_agent_export_render.go
0b541bee4e3639d54e85308d797abb59bdf5309aa694258442256eb7876cf2cf  services/platform/agentsec-worker/security_agent_export_render_test.go
```

The two renderer hashes match the accepted baseline. The renderer patch remains `8aec587fa84f33247586d9124b99becc70ac65d8a1c53a0343c89875cc893ecf`.

Validation: `git apply --reverse --check docs/internal/security-agent-export-20260919/database/task-only.patch` exited0 against the frozen files. This was a read-only patch check.
