{{/* Explicit current-profile consumers; no identity, credential or RBAC creation. */}}
{{- define "zasp.gatewayBootstrap.validate" -}}
{{- $c := .Values.gatewayBootstrap -}}
{{- if not (kindIs "map" $c) -}}{{ fail "gateway bootstrap must be object" }}{{- end -}}
{{- if not (and (eq (len (keys $c)) 2) (hasKey $c "enabled") (hasKey $c "profileChecksum") (kindIs "bool" $c.enabled) (kindIs "string" $c.profileChecksum)) -}}{{ fail "gateway bootstrap configuration rejected" }}{{- end -}}
{{- if $c.enabled -}}
{{- if not (and (ne .Values.profile "customer_edge") (kindIs "bool" .Values.runtimeServices.enabled) .Values.runtimeServices.enabled (eq .Values.authorizationTemporal.profile "canonical61-temporal78-authorization79-80-worker-v1") (regexMatch "^[a-f0-9]{64}$" $c.profileChecksum)) -}}{{ fail "gateway bootstrap requires installed compiled profile and current authorization runtime" }}{{- end -}}
{{- else if $c.profileChecksum -}}{{ fail "disabled gateway bootstrap requires empty checksum" }}{{- end -}}
{{- end -}}
{{- define "zasp.gatewayBootstrap.apiEnv" -}}
{{- if .Values.gatewayBootstrap.enabled }}
- { name: ZASP_GATEWAY_BOOTSTRAP_PROFILE_CHECKSUM, value: {{ .Values.gatewayBootstrap.profileChecksum | quote }} }
{{- end -}}
{{- end -}}
{{- define "zasp.gatewayBootstrap.enrollmentEnv" -}}
{{- if .Values.gatewayBootstrap.enabled }}
- { name: ZASP_GATEWAY_ENROLLMENT_ENABLED, value: "true" }
- { name: ZASP_GATEWAY_ENROLLMENT_PROFILE_CHECKSUM, value: {{ .Values.gatewayBootstrap.profileChecksum | quote }} }
{{- end -}}
{{- end -}}
