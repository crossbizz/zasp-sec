{{- define "zasp.sessionSearch.validate" -}}
{{- $phase := .Values.runtime.sessionSearchPhase -}}
{{- $schema := toString .Values.schema.expectedVersion -}}
{{- if not (or (and (eq $phase "compatibility") (has $schema (list "48" "49"))) (and (has $phase (list "backfill" "query")) (eq $schema "50")) (and (has $phase (list "precision-consumers" "precision-intake")) (eq $schema "51"))) -}}
{{- fail "session search phase and schema version are incompatible" -}}
{{- end -}}
{{- end -}}

{{- define "zasp.runtimeNames" -}}
{{- $names := list "agentsec-event-ingest" "agentsec-gateway-control" "agentsec-runtime-outbox" "agentsec-runtime-coordinator" "agentsec-runtime-archive" "agentsec-runtime-index" "agentsec-runtime-correlation" "agentsec-runtime-projection" "agentsec-runtime-complete" -}}
{{- if ne .Values.runtime.sessionSearchPhase "compatibility" -}}
{{- $names = append $names "agentsec-runtime-session-index-v2" -}}
{{- end -}}
{{- toJson $names -}}
{{- end -}}

{{- define "zasp.runtimeIndexNames" -}}
{{- $names := list "agentsec-runtime-index" -}}
{{- if ne .Values.runtime.sessionSearchPhase "compatibility" -}}
{{- $names = append $names "agentsec-runtime-session-index-v2" -}}
{{- end -}}
{{- toJson $names -}}
{{- end -}}
