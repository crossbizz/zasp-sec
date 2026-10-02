{{- define "zasp.sessionSearch.validate" -}}
{{- $phase := .Values.runtime.sessionSearchPhase -}}
{{- $schema := toString .Values.schema.expectedVersion -}}
{{- if .Values.authorizationTemporal.profile -}}
{{- if not (and (eq .Values.authorizationTemporal.profile "canonical61-temporal78-authorization79-80-worker-v1") (eq $schema "61") (eq $phase "precision-intake") (eq .Values.rollout.discoveryScheduleReplayPhase "active") .Values.runtimeServices.enabled) -}}
{{- fail "authorization temporal profile and schema are incompatible" -}}
{{- end -}}
{{- else -}}
{{- if not (or (and (eq $phase "compatibility") (has $schema (list "48" "49"))) (and (has $phase (list "backfill" "query")) (eq $schema "50")) (and (has $phase (list "precision-consumers" "precision-intake")) (has $schema (list "51" "52" "53" "54" "55" "56" "57" "58" "59" "60")))) -}}
{{- fail "session search phase and schema version are incompatible" -}}
{{- end -}}
{{- $rollout := .Values.rollout.discoveryScheduleReplayPhase -}}
{{- if not (or (and (has $schema (list "48" "49" "50" "51" "52" "53" "54" "55" "56" "57" "58")) (eq $rollout "steady")) (and (eq $schema "59") (eq $rollout "maintenance")) (and (eq $schema "60") (eq $rollout "active"))) -}}
{{- fail "discovery schedule replay phase and schema version are incompatible" -}}
{{- end -}}
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
