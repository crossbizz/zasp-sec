{{- define "zasp.auditExports.selectedPolicy" -}}
{{- $config := .Values.auditExports -}}
{{- $idPattern := "^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" -}}
{{- $current := required "auditExports.currentPolicyID is required" $config.currentPolicyID -}}
{{- if not (kindIs "string" $config.expectedCurrentPolicyID) -}}{{ fail "audit export predecessor must be an explicit string" }}{{- end -}}
{{- $prior := $config.expectedCurrentPolicyID | default "" -}}
{{- if or (not (regexMatch $idPattern $current)) (and (ne $prior "") (or (not (regexMatch $idPattern $prior)) (eq $prior $current))) -}}{{ fail "audit export policy selection is invalid" }}{{- end -}}
{{- $worker := required "auditExports.workerPrincipal is required" $config.workerPrincipal -}}
{{- $outbox := required "auditExports.outboxPrincipal is required" $config.outboxPrincipal -}}
{{- if eq $worker $outbox -}}{{ fail "audit export worker logins must be distinct" }}{{- end -}}
{{- range $principal := list $worker $outbox -}}
{{- if or (not (regexMatch "^[a-z][a-z0-9_]{2,62}$" $principal)) (has $principal (list "zasp_audit_export_worker" "zasp_audit_export_outbox")) (has $principal (values ($.Values.databasePrincipals | default dict))) -}}{{ fail "audit export login conflicts with existing authority" }}{{- end -}}
{{- end -}}
{{- if or (not (kindIs "slice" $config.policies)) (lt (len $config.policies) 1) (gt (len $config.policies) 64) -}}{{ fail "audit export history is invalid" }}{{- end -}}
{{- if gt (len (toJson $config.policies)) 131072 -}}{{ fail "audit export history exceeds the runtime limit" }}{{- end -}}
{{- $selected := dict -}}
{{- $seen := dict -}}
{{- $fields := list "schema" "policy_id" "bucket" "expected_bucket_owner" "kms_key_arn" "maximum_export_bytes" "maximum_retained_bytes" "maximum_inflight" "capture_timeout_seconds" | sortAlpha -}}
{{- range $policy := $config.policies -}}
{{- if or (not (kindIs "map" $policy)) (ne (toJson (keys $policy | sortAlpha)) (toJson $fields)) -}}{{ fail "audit export policy fields are invalid" }}{{- end -}}
{{- if or (ne $policy.schema "audit-export-policy-v1") (not (regexMatch $idPattern $policy.policy_id)) (hasKey $seen $policy.policy_id) (not (regexMatch "^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$" $policy.bucket)) (not (regexMatch "^[0-9]{12}$" $policy.expected_bucket_owner)) (not (regexMatch "^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" $policy.kms_key_arn)) -}}{{ fail "audit export policy identity is invalid" }}{{- end -}}
{{- $_ := set $seen $policy.policy_id true -}}
{{- range $key, $maximum := dict "maximum_export_bytes" 9007199254740991 "maximum_retained_bytes" 9007199254740991 "maximum_inflight" 2147483647 "capture_timeout_seconds" 120 -}}
{{- $wire := toJson (index $policy $key) -}}
{{- if or (not (regexMatch "^[0-9]+$" $wire)) (lt (float64 $wire) 1.0) (gt (float64 $wire) (float64 $maximum)) -}}{{ fail "audit export policy integer limit is invalid" }}{{- end -}}
{{- end -}}
{{- if eq $policy.policy_id $current -}}{{- $selected = $policy -}}{{- end -}}
{{- end -}}
{{- if eq (len $selected) 0 -}}{{ fail "selected audit export policy is absent from history" }}{{- end -}}
{{- toJson $selected -}}
{{- end -}}

{{- define "zasp.auditExports.migrationEnv" -}}
{{- if .Values.auditExports.enabled -}}
{{- $policy := include "zasp.auditExports.selectedPolicy" . | fromJson -}}
- { name: ZASP_AUDIT_EXPORT_WORKER_DB_PRINCIPAL, value: {{ .Values.auditExports.workerPrincipal | quote }} }
- { name: ZASP_AUDIT_EXPORT_OUTBOX_DB_PRINCIPAL, value: {{ .Values.auditExports.outboxPrincipal | quote }} }
- { name: ZASP_AUDIT_EXPORT_POLICY_ID, value: {{ $policy.policy_id | quote }} }
- { name: ZASP_AUDIT_EXPORT_EXPECTED_CURRENT_POLICY_ID, value: {{ .Values.auditExports.expectedCurrentPolicyID | default "" | quote }} }
- { name: ZASP_AUDIT_EXPORT_BUCKET, value: {{ $policy.bucket | quote }} }
- { name: ZASP_AUDIT_EXPORT_EXPECTED_BUCKET_OWNER, value: {{ $policy.expected_bucket_owner | quote }} }
- { name: ZASP_AUDIT_EXPORT_KMS_KEY_ARN, value: {{ $policy.kms_key_arn | quote }} }
- { name: ZASP_AUDIT_EXPORT_MAXIMUM_EXPORT_BYTES, value: {{ toJson $policy.maximum_export_bytes | quote }} }
- { name: ZASP_AUDIT_EXPORT_MAXIMUM_RETAINED_BYTES, value: {{ toJson $policy.maximum_retained_bytes | quote }} }
- { name: ZASP_AUDIT_EXPORT_MAXIMUM_INFLIGHT, value: {{ toJson $policy.maximum_inflight | quote }} }
- { name: ZASP_AUDIT_EXPORT_CAPTURE_TIMEOUT_SECONDS, value: {{ toJson $policy.capture_timeout_seconds | quote }} }
{{- end -}}
{{- end -}}

{{- define "zasp.auditExports.migrationCommand" -}}
{{- if .Values.auditExports.enabled -}}
{{- $_ := include "zasp.auditExports.selectedPolicy" . -}}
ZASP_POSTGRES_DSN="$(cat /var/run/secrets/zasp-migration/postgres-dsn)" && export ZASP_POSTGRES_DSN && /app/agentsec-migrate up-to-{{ .Values.schema.expectedVersion }} && /app/agentsec-migrate register-audit-export-api && /app/agentsec-migrate register-audit-export-workers && exec /app/agentsec-migrate configure-audit-exports
{{- end -}}
{{- end -}}
