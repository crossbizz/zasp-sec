{{/* Explicit current-profile consumers; no identity, credential or RBAC creation. */}}
{{- define "zasp.agentDeviceAssociation.validate" -}}
{{- $c := .Values.agentDeviceAssociation -}}
{{- if not (kindIs "map" $c) -}}{{ fail "Agent device association must be object" }}{{- end -}}
{{- if not (and (eq (len (keys $c)) 2) (hasKey $c "enabled") (hasKey $c "profileChecksum") (kindIs "bool" $c.enabled) (kindIs "string" $c.profileChecksum)) -}}{{ fail "Agent device association configuration rejected" }}{{- end -}}
{{- if $c.enabled -}}
{{- if not (and (ne .Values.profile "customer_edge") (kindIs "bool" .Values.runtimeServices.enabled) .Values.runtimeServices.enabled (eq .Values.authorizationTemporal.profile "canonical61-temporal78-authorization79-80-worker-v1") (regexMatch "^[a-f0-9]{64}$" $c.profileChecksum)) -}}{{ fail "Agent device association requires installed compiled profile and current authorization runtime" }}{{- end -}}
{{- else if $c.profileChecksum -}}{{ fail "disabled Agent device association requires empty checksum" }}{{- end -}}
{{- end -}}
{{- define "zasp.agentDeviceAssociation.apiEnv" -}}
{{- if .Values.agentDeviceAssociation.enabled }}
- { name: ZASP_AGENT_DEVICE_ASSOCIATION_PROFILE_CHECKSUM, value: {{ .Values.agentDeviceAssociation.profileChecksum | quote }} }
{{- end -}}
{{- end -}}
{{- define "zasp.agentDeviceAssociation.controlEnv" -}}
{{- if .Values.agentDeviceAssociation.enabled }}
- { name: ZASP_AGENT_DEVICE_ASSOCIATION_ENABLED, value: "true" }
- { name: ZASP_AGENT_DEVICE_ASSOCIATION_PROFILE_CHECKSUM, value: {{ .Values.agentDeviceAssociation.profileChecksum | quote }} }
{{- end -}}
{{- end -}}
