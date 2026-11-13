{{- /*
The baseline schema (agentsec-migrate install-baseline) replaces the historical
migration chain for new installations. schema.install selects which one the
schema job runs. "baseline" is the default and the only form that works on
managed PostgreSQL; "chain" keeps the historical commands and needs a superuser.
See docs/operations/baseline-schema-install.md.
*/ -}}
{{- define "zasp.schema.baseline" -}}
{{- if eq (toString .Values.schema.install) "baseline" -}}true{{- end -}}
{{- end -}}

{{- define "zasp.schema.validate" -}}
{{- if not (has (toString .Values.schema.install) (list "baseline" "chain")) -}}{{ fail "schema.install must be baseline or chain" }}{{- end -}}
{{- if not (has (toString (.Values.postgres.transport | default "")) (list "" "tcp" "websocket")) -}}{{ fail "postgres.transport must be empty, tcp or websocket" }}{{- end -}}
{{- if not (kindIs "bool" .Values.schema.registerIdentityVerifiers) -}}{{ fail "schema.registerIdentityVerifiers must be boolean" }}{{- end -}}
{{- if include "zasp.schema.baseline" . -}}
{{- if not .Values.authorizationTemporal.profile -}}{{ fail "the baseline schema requires authorizationTemporal.profile (runtime services, worker keys and the permission projector)" }}{{- end -}}
{{- if ne (toString .Values.databasePrincipals.migration) "zasp_operator" -}}{{ fail "the baseline schema is installed and owned by the role zasp_operator; set databasePrincipals.migration to zasp_operator" }}{{- end -}}
{{- $approval := .Values.approvalMaintenance -}}
{{- if not (regexMatch "^[a-f0-9]{64}$" (toString $approval.profileChecksum)) -}}{{ fail "approvalMaintenance.profileChecksum is required on the baseline schema; agentsec-migrate approval-maintenance-checksum prints it" }}{{- end -}}
{{- range $name := list (toString $approval.dsnSecret) (toString $approval.key.secretName) -}}
{{- if not (regexMatch "^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$" $name) -}}{{ fail "approvalMaintenance.dsnSecret and approvalMaintenance.key.secretName must name existing Kubernetes Secrets on the baseline schema" }}{{- end -}}
{{- end -}}
{{- if eq (toString $approval.dsnSecret) (toString $approval.key.secretName) -}}{{ fail "approvalMaintenance.dsnSecret and approvalMaintenance.key.secretName must be separate Secrets" }}{{- end -}}
{{- else if .Values.schema.registerIdentityVerifiers -}}{{ fail "schema.registerIdentityVerifiers applies to the baseline schema only" }}{{- end -}}
{{- end -}}

{{- /*
verify-baseline succeeds only on an installed, intact baseline from this
release's artifact. On an empty database it fails, install-baseline runs in one
transaction, and the result is verified. On a database that holds anything
else install-baseline refuses, so the job fails without changing it. The four
registrations are repeated on every run. The identity verifiers need the first
Organization, so they are registered only when asked.
*/ -}}
{{- define "zasp.baseline.schemaCommand" -}}
export ZASP_POSTGRES_DSN="$(cat /var/run/secrets/zasp-migration/postgres-dsn)"; export ZASP_WORKFLOW_SIGNING_KEY="$(cat /var/run/secrets/zasp-migration/workflow-signing-key)"; if ! /app/agentsec-migrate verify-baseline; then /app/agentsec-migrate install-baseline; /app/agentsec-migrate verify-baseline; fi; /app/agentsec-migrate register-authorization-verifier; /app/agentsec-migrate register-worker-authorization-verifier; /app/agentsec-migrate register-compensation-authorization-verifier; /app/agentsec-migrate register-approval-maintenance-verifier{{ if .Values.schema.registerIdentityVerifiers }}; export ZASP_STYTCH_PROJECT_ID="$(cat /var/run/secrets/zasp-migration/stytch-project-id)"; export ZASP_STYTCH_ORGANIZATION_ID="$(cat /var/run/secrets/zasp-migration/stytch-organization-id)"; /app/agentsec-migrate register-identity-session-verifier; /app/agentsec-migrate register-identity-webhook-verifier{{ end }}
{{- end -}}

{{- /*
The approval-notification delivery key must be a regular file of exactly 32
bytes with mode 0400 that belongs to the process user. A Secret volume serves
symbolic links, so the key is copied into memory first, as the worker keys are.
*/ -}}
{{- define "zasp.approvalMaintenance.keyEnv" -}}
- { name: ZASP_APPROVAL_MAINTENANCE_KEY_FILE, value: /var/run/zasp-approval-maintenance/delivery.key }
{{- end -}}
{{- define "zasp.approvalMaintenance.keyInit" -}}
- name: materialize-approval-maintenance-key
  image: {{ .image | quote }}
  command: ["/bin/sh", "-ec"]
  args: ['umask 077; cp /approval-maintenance-source/seed /approval-maintenance/delivery.key; chmod 0400 /approval-maintenance/delivery.key']
  securityContext: { runAsNonRoot: true, runAsUser: {{ .uid }}, runAsGroup: {{ .uid }}, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: [ALL] } }
  resources: { requests: { cpu: 10m, memory: 16Mi }, limits: { cpu: 100m, memory: 32Mi } }
  volumeMounts:
    - { name: approval-maintenance-key-source, mountPath: /approval-maintenance-source, readOnly: true }
    - { name: approval-maintenance-key, mountPath: /approval-maintenance }
{{- end -}}
{{- define "zasp.approvalMaintenance.keyMount" -}}
- { name: approval-maintenance-key, mountPath: /var/run/zasp-approval-maintenance, readOnly: true }
{{- end -}}
{{- define "zasp.approvalMaintenance.keyVolumes" -}}
- name: approval-maintenance-key
  emptyDir: { medium: Memory, sizeLimit: 64Ki }
- name: approval-maintenance-key-source
  secret: { secretName: {{ .Values.approvalMaintenance.key.secretName | quote }}, defaultMode: 288, items: [{ key: seed, path: seed }] }
{{- end -}}

{{- /* The API signs approval notifications: it needs the key and its own login. */ -}}
{{- define "zasp.approvalMaintenance.apiEnv" -}}
{{- include "zasp.approvalMaintenance.keyEnv" . }}
- name: ZASP_APPROVAL_MAINTENANCE_POSTGRES_DSN
  valueFrom: { secretKeyRef: { name: {{ .Values.approvalMaintenance.dsnSecret | quote }}, key: postgres-dsn } }
{{- end -}}

{{- /*
Unset is TCP on the DSN's port. "websocket" carries PostgreSQL inside TLS on
port 443 of the DSN's host. Only the binaries that open PostgreSQL through the
platform connector read it.
*/ -}}
{{- define "zasp.postgres.transportEnv" -}}
{{- if .Values.postgres.transport -}}
- { name: ZASP_POSTGRES_TRANSPORT, value: {{ .Values.postgres.transport | quote }} }
{{- end -}}
{{- end -}}
