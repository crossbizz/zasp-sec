{{/* Explicit application consumers; never installation, coverage or policy readiness. */}}
{{- define "zasp.gatewayInstallation.validate" -}}
{{- $c := .Values.gatewayInstallation -}}
{{- if not (kindIs "map" $c) -}}{{ fail "gateway installation must be object" }}{{- end -}}
{{- if ne (len (keys $c)) 2 -}}{{ fail "gateway installation rejects unknown configuration" }}{{- end -}}
{{- if not (and (hasKey $c "enabled") (hasKey $c "profileChecksum") (kindIs "bool" $c.enabled) (kindIs "string" $c.profileChecksum)) -}}{{ fail "gateway installation configuration types rejected" }}{{- end -}}
{{- if $c.enabled -}}
{{- if not (and (ne .Values.profile "customer_edge") (kindIs "bool" .Values.runtimeServices.enabled) .Values.runtimeServices.enabled (eq .Values.authorizationTemporal.profile "canonical61-temporal78-authorization79-80-worker-v1") (regexMatch "^[a-f0-9]{64}$" $c.profileChecksum)) -}}{{ fail "gateway installation requires installed compiled profile and current authorization runtime" }}{{- end -}}
{{- else if $c.profileChecksum -}}{{ fail "disabled gateway installation requires empty checksum" }}{{- end -}}
{{- if not (kindIs "bool" .Values.runtimeGateway.installationACKEnabled) -}}{{ fail "gateway installation producer must be boolean" }}{{- end -}}
{{- if and .Values.runtimeGateway.installationACKEnabled (ne .Values.profile "customer_edge") -}}{{ fail "gateway installation producer requires customer edge" }}{{- end -}}
{{- end -}}
{{- define "zasp.gatewayInstallation.env" -}}
{{- if .Values.gatewayInstallation.enabled }}
- { name: ZASP_GATEWAY_INSTALLATION_ACK_ENABLED, value: "true" }
- { name: ZASP_GATEWAY_INSTALLATION_PROFILE_CHECKSUM, value: {{ .Values.gatewayInstallation.profileChecksum | quote }} }
{{- end -}}
{{- end -}}
