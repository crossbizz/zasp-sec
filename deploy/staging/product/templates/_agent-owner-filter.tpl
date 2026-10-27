{{/* Consumer opt-in only; never installs SQL or grants writer privileges. */}}
{{- define "zasp.agentOwnerFilter.validate" -}}
{{- $e := .Values.agentOwnerFilter -}}
{{- if not (kindIs "bool" $e.enabled) -}}{{ fail "agent owner filter enabled must be boolean" }}{{- end -}}
{{- if $e.enabled -}}
{{- if not (and (ne .Values.profile "customer_edge") .Values.runtimeServices.enabled (eq .Values.authorizationTemporal.profile "canonical61-temporal78-authorization79-80-worker-v1")) -}}{{ fail "agent owner filter requires current authorization and Temporal runtime" }}{{- end -}}
{{- if not (regexMatch "^[a-f0-9]{64}$" $e.profileChecksum) -}}{{ fail "agent owner filter requires explicit compiled recipe checksum" }}{{- end -}}
{{- else -}}
{{- if $e.profileChecksum -}}{{ fail "disabled agent owner filter rejects orphan checksum" }}{{- end -}}
{{- end -}}
{{- end -}}
{{- define "zasp.agentOwnerFilter.env" -}}
{{- if .Values.agentOwnerFilter.enabled }}
- { name: ZASP_AGENT_OWNER_FILTER_ENABLED, value: "true" }
- { name: ZASP_AGENT_OWNER_FILTER_CHECKSUM, value: {{ .Values.agentOwnerFilter.profileChecksum | quote }} }
{{- end -}}
{{- end -}}
