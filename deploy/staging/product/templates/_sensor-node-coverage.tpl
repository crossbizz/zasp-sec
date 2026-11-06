{{/* API reader and event-ingest writer only; no installation or native admission inferred. */}}
{{- define "zasp.sensorNodeCoverage.validate" -}}
{{- $c := .Values.sensorNodeCoverage -}}
{{- if not (kindIs "map" $c) -}}{{ fail "sensor node coverage must be object" }}{{- end -}}
{{- if ne (len (keys $c)) 2 -}}{{ fail "sensor node coverage rejects unknown configuration" }}{{- end -}}
{{- if not (and (kindIs "bool" $c.enabled) (kindIs "string" $c.profileChecksum)) -}}{{ fail "sensor node coverage has invalid configuration types" }}{{- end -}}
{{- if $c.enabled -}}
{{- if not (and (ne .Values.profile "customer_edge") .Values.runtimeServices.enabled (eq .Values.authorizationTemporal.profile "canonical61-temporal78-authorization79-80-worker-v1") (regexMatch "^[a-f0-9]{64}$" $c.profileChecksum)) -}}{{ fail "sensor node coverage requires installed compiled profile and current authorization runtime" }}{{- end -}}
{{- else if $c.profileChecksum -}}{{ fail "sensor node coverage disabled requires empty checksum" }}{{- end -}}
{{- end -}}
{{- define "zasp.sensorNodeCoverage.env" -}}
{{- if .Values.sensorNodeCoverage.enabled }}
- { name: ZASP_SENSOR_NODE_COVERAGE_RETENTION_ENABLED, value: "true" }
- { name: ZASP_SENSOR_NODE_COVERAGE_PROFILE_CHECKSUM, value: {{ .Values.sensorNodeCoverage.profileChecksum | quote }} }
{{- end -}}
{{- end -}}
