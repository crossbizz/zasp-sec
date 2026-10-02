{{- define "zasp.attackLabReconciler.migrationCommand" -}}
{{- $base := printf "export ZASP_POSTGRES_DSN=\"$(cat /var/run/secrets/zasp-migration/postgres-dsn)\"; exec /app/agentsec-migrate up-to-%v" .Values.schema.expectedVersion -}}
{{- if .Values.complianceExports.enabled -}}
{{- $base = include "zasp.complianceExports.migrationCommand" . -}}
{{- else if .Values.auditExports.enabled -}}
{{- $base = include "zasp.auditExports.migrationCommand" . -}}
{{- end -}}
{{ replace "exec /app/agentsec-migrate" "/app/agentsec-migrate" $base }} && exec /app/agentsec-migrate register-security-agent-attack-lab-reconciler
{{- end -}}
