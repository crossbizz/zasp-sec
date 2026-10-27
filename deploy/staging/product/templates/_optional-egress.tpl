{{/* Shared API/planner policy selection. No installer or fleet activation. */}}
{{- define "zasp.optionalEgress.validate" -}}
{{- $e := .Values.optionalEgress -}}
{{- if not (kindIs "bool" $e.enabled) -}}{{ fail "optional egress enabled must be boolean" }}{{- end -}}
{{- if $e.enabled -}}
{{- if not (and (ne .Values.profile "customer_edge") .Values.runtimeServices.enabled (eq .Values.authorizationTemporal.profile "canonical61-temporal78-authorization79-80-worker-v1")) -}}{{ fail "optional egress requires current authorization and Temporal runtime" }}{{- end -}}
{{- if not (regexMatch "^[a-f0-9]{64}$" $e.profileChecksum) -}}{{ fail "optional egress requires explicit compiled recipe checksum" }}{{- end -}}
{{- if not .Values.network.securityAgentPlannerEgressCIDRs -}}{{ fail "optional egress requires approved OpenRouter CIDRs" }}{{- end -}}
{{- if not (regexMatch "^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$" $e.settlementDSNSecret) -}}{{ fail "optional egress requires captured-settlement DSN Secret" }}{{- end -}}
{{- $p := .Values.authorizationTemporal -}}
{{- if has $e.settlementDSNSecret (list "zasp-runtime-secrets" $p.executorDSNSecret $p.compensationDSNSecret $p.projectorDSNSecret $p.adapterDSNSecret) -}}{{ fail "optional egress settlement Secret must be distinct" }}{{- end -}}
{{- else -}}
{{- if or $e.profileChecksum $e.settlementDSNSecret -}}{{ fail "disabled optional egress rejects orphan configuration" }}{{- end -}}
{{- end -}}
{{- end -}}
{{- define "zasp.optionalEgress.env" -}}
{{- if .Values.optionalEgress.enabled }}
- { name: ZASP_OPTIONAL_EGRESS_ENABLED, value: "true" }
- { name: ZASP_OPTIONAL_EGRESS_PROFILE_CHECKSUM, value: {{ .Values.optionalEgress.profileChecksum | quote }} }
{{- end }}
{{- end -}}
{{- define "zasp.optionalEgress.apiEnv" -}}
{{- if .Values.optionalEgress.enabled }}
- name: ZASP_OPTIONAL_EGRESS_SETTLEMENT_POSTGRES_DSN
  valueFrom: { secretKeyRef: { name: {{ .Values.optionalEgress.settlementDSNSecret | quote }}, key: postgres-dsn } }
{{- end }}
{{- end -}}
