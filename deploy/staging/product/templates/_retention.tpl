{{- define "zasp.retention.validate" -}}
{{- $r := .Values.retentionReferenceExpiry -}}
{{- if not (kindIs "bool" $r.enabled) -}}{{ fail "retention enabled must be boolean" }}{{- end -}}
{{- if $r.enabled -}}
{{- if not (and (ne .Values.profile "customer_edge") (eq .Values.runtime.sessionSearchPhase "precision-intake") (eq (toString .Values.schema.expectedVersion) "61") .Values.runtimeServices.enabled (eq .Values.authorizationTemporal.profile "canonical61-temporal78-authorization79-80-worker-v1")) -}}{{ fail "retention requires current authorization and Temporal runtime" }}{{- end -}}
{{- if not (regexMatch "^[a-f0-9]{64}$" $r.profileChecksum) -}}{{ fail "retention requires explicit compiled Audit checksum" }}{{- end -}}
{{- if not (regexMatch "^[a-z][a-z0-9._-]{1,127}$" $r.taskQueue) -}}{{ fail "retention requires dedicated task queue" }}{{- end -}}
{{- if not (and (eq $r.indexStageVersion "runtime-index-v2") (eq $r.sessionIndex "zasp-runtime-sessions-v2")) -}}{{ fail "retention requires explicit precise executor and physical index" }}{{- end -}}
{{- if has $r.taskQueue (list .Values.runtimeServices.taskQueue .Values.runtimeServices.discoveryTaskQueue) -}}{{ fail "retention queue must be distinct" }}{{- end -}}
{{- else -}}
{{- if or $r.profileChecksum $r.taskQueue $r.indexStageVersion $r.sessionIndex -}}{{ fail "disabled retention rejects orphan configuration" }}{{- end -}}
{{- end -}}
{{- end -}}
{{- define "zasp.retention.pin" -}}
{{- if .Values.retentionReferenceExpiry.enabled }}
- { name: ZASP_RETENTION_PROFILE_CHECKSUM, value: {{ .Values.retentionReferenceExpiry.profileChecksum | quote }} }
{{- end }}
{{- end -}}
