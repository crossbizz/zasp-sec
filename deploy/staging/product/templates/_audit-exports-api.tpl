{{- define "zasp.auditExports.apiValidate" -}}
{{- if .Values.auditExports.enabled -}}
{{- $config := .Values.auditExports -}}
{{- $role := required "auditExports.readerRoleArn is required" $config.readerRoleArn -}}
{{- if or (not (regexMatch "^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,128}$" $role)) (has $role (list $config.writerRoleArn $config.publisherRoleArn .Values.connectors.roleArn)) -}}{{ fail "audit export reader role must be valid and distinct" }}{{- end -}}
{{- $account := index (splitList ":" $role) 4 -}}
{{- if or (ne $config.queueURL (printf "https://sqs.%s.amazonaws.com/%s/agentsec-audit-exports" $config.awsRegion $account)) (ne .Values.secrets.region $config.awsRegion) -}}{{ fail "audit export reader and CSI must match queue account and region" }}{{- end -}}
{{- $secret := required "auditExports.cursorSecretArn is required" $config.cursorSecretArn -}}
{{- if or (not (regexMatch (printf "^arn:aws:secretsmanager:%s:%s:secret:[A-Za-z0-9/_+=.@-]{1,512}$" $config.awsRegion $account) $secret)) (has $secret (list $config.workerDSNSecretArn $config.outboxDSNSecretArn)) -}}{{ fail "audit export cursor secret must be distinct and scoped" }}{{- end -}}
{{- end -}}
{{- end -}}
{{- define "zasp.auditExports.apiEnv" -}}
{{- include "zasp.auditExports.apiValidate" . -}}
{{- if .Values.auditExports.enabled -}}
- { name: ZASP_AUDIT_EXPORT_POLICIES_JSON, value: {{ toJson .Values.auditExports.policies | quote }} }
- { name: ZASP_AUDIT_EXPORT_READER_ROLE_ARN, value: {{ .Values.auditExports.readerRoleArn | quote }} }
- { name: ZASP_AUDIT_EXPORT_WEB_IDENTITY_TOKEN_FILE, value: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" }
{{- end -}}
{{- end -}}
{{- define "zasp.auditExports.apiSecretObject" -}}
{{- include "zasp.auditExports.apiValidate" . -}}
{{- if .Values.auditExports.enabled -}}
- objectName: {{ .Values.auditExports.cursorSecretArn | quote }}
  objectType: secretsmanager
  objectAlias: audit-export-cursor-signing-key
{{- end -}}
{{- end -}}
{{- define "zasp.auditExports.apiSecretLoad" -}}
{{- include "zasp.auditExports.apiValidate" . -}}
{{- if .Values.auditExports.enabled -}}
export ZASP_AUDIT_EXPORT_CURSOR_SIGNING_KEY="$(cat /var/run/secrets/zasp/audit-export-cursor-signing-key)"
{{- end -}}
{{- end -}}
