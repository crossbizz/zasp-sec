{{/* Explicit API consumer checksum only; supplementary SQL/native admission is external. */}}
{{- define "zasp.agentRead.validate" -}}
{{- $e := .Values.agentRead -}}
{{- if not (kindIs "map" $e) -}}{{ fail "agent read profile must be object" }}{{- end -}}
{{- if ne (len (keys $e)) 1 -}}{{ fail "agent read rejects unknown configuration" }}{{- end -}}
{{- if not (kindIs "string" $e.profileChecksum) -}}{{ fail "agent read profile checksum must be string" }}{{- end -}}
{{- if $e.profileChecksum -}}
{{- if not (and (ne .Values.profile "customer_edge") .Values.runtimeServices.enabled (eq .Values.authorizationTemporal.profile "canonical61-temporal78-authorization79-80-worker-v1")) -}}{{ fail "agent read requires current authorization and Temporal runtime" }}{{- end -}}
{{- if not (regexMatch "^[a-f0-9]{64}$" $e.profileChecksum) -}}{{ fail "agent read requires explicit compiled recipe checksum" }}{{- end -}}
{{- end -}}
{{- end -}}
{{- define "zasp.agentRead.env" -}}
{{- if .Values.agentRead.profileChecksum }}
- { name: ZASP_AGENT_READ_PROFILE_CHECKSUM, value: {{ .Values.agentRead.profileChecksum | quote }} }
{{- end -}}
{{- end -}}
