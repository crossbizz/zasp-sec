{{/* Consumer opt-in only; never installs SQL or grants writer privileges. */}}
{{- define "zasp.environmentClass.validate" -}}
{{- $e := .Values.environmentClass -}}
{{- if not (kindIs "bool" $e.enabled) -}}{{ fail "environment class enabled must be boolean" }}{{- end -}}
{{- if $e.enabled -}}
{{- if not (and (ne .Values.profile "customer_edge") .Values.runtimeServices.enabled (eq .Values.authorizationTemporal.profile "canonical61-temporal78-authorization79-80-worker-v1")) -}}{{ fail "environment class requires current authorization and Temporal runtime" }}{{- end -}}
{{- if not (regexMatch "^[a-f0-9]{64}$" $e.profileChecksum) -}}{{ fail "environment class requires explicit compiled recipe checksum" }}{{- end -}}
{{- else -}}
{{- if $e.profileChecksum -}}{{ fail "disabled environment class rejects orphan checksum" }}{{- end -}}
{{- end -}}
{{- end -}}
{{- define "zasp.environmentClass.env" -}}
{{- if .Values.environmentClass.enabled }}
- { name: ZASP_ENVIRONMENT_CLASS_ENABLED, value: "true" }
- { name: ZASP_ENVIRONMENT_CLASS_PROFILE_CHECKSUM, value: {{ .Values.environmentClass.profileChecksum | quote }} }
{{- end -}}
{{- end -}}
