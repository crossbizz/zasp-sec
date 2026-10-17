{{/* Explicit API consumer checksum only; supplementary SQL/native admission is external. */}}
{{- define "zasp.agentOwnershipWrite.validate" -}}
{{- $e := .Values.agentOwnershipWrite -}}
{{- if not (kindIs "map" $e) -}}{{ fail "agent ownership write profile must be object" }}{{- end -}}
{{- if ne (len (keys $e)) 1 -}}{{ fail "agent ownership write rejects unknown configuration" }}{{- end -}}
{{- if not (kindIs "string" $e.profileChecksum) -}}{{ fail "agent ownership write profile checksum must be string" }}{{- end -}}
{{- if $e.profileChecksum -}}
{{- if not (and (ne .Values.profile "customer_edge") .Values.runtimeServices.enabled (eq .Values.authorizationTemporal.profile "canonical61-temporal78-authorization79-80-worker-v1")) -}}{{ fail "agent ownership write requires current authorization and Temporal runtime" }}{{- end -}}
{{- if not (regexMatch "^[a-f0-9]{64}$" $e.profileChecksum) -}}{{ fail "agent ownership write requires explicit compiled recipe checksum" }}{{- end -}}
{{- end -}}
{{- end -}}
{{- define "zasp.agentOwnershipWrite.env" -}}
{{- if .Values.agentOwnershipWrite.profileChecksum }}
- { name: ZASP_AGENT_OWNERSHIP_WRITE_PROFILE_CHECKSUM, value: {{ .Values.agentOwnershipWrite.profileChecksum | quote }} }
{{- end -}}
{{- end -}}
