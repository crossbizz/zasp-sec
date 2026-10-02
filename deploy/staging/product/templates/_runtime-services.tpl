{{- define "zasp.runtimeServices.env" -}}
{{- if .Values.runtimeServices.enabled }}
- { name: ZASP_RUNTIME_SERVICES_ENABLED, value: "true" }
- { name: ZASP_RUNTIME_SERVICES_TIMEOUT, value: {{ .Values.runtimeServices.timeout | quote }} }
- { name: ZASP_TEMPORAL_ADDRESS, value: {{ required "runtimeServices.temporalAddress required" .Values.runtimeServices.temporalAddress | quote }} }
- { name: ZASP_TEMPORAL_NAMESPACE, value: {{ required "runtimeServices.namespace required" .Values.runtimeServices.namespace | quote }} }
- { name: ZASP_TEMPORAL_TASK_QUEUE, value: {{ required "runtimeServices.taskQueue required" .Values.runtimeServices.taskQueue | quote }} }
- { name: ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE, value: {{ required "runtimeServices.discoveryTaskQueue required" .Values.runtimeServices.discoveryTaskQueue | quote }} }
- { name: ZASP_OPENFGA_URL, value: {{ required "runtimeServices.openfgaURL required" .Values.runtimeServices.openfgaURL | quote }} }
- { name: ZASP_OPENFGA_STORE_ID, value: {{ required "runtimeServices.storeID required" .Values.runtimeServices.storeID | quote }} }
- { name: ZASP_OPENFGA_MODEL_ID, value: {{ required "runtimeServices.modelID required" .Values.runtimeServices.modelID | quote }} }
- { name: ZASP_TEMPORAL_TLS_CA_FILE, value: /var/run/secrets/runtime-services/temporal-ca.crt }
- { name: ZASP_TEMPORAL_TLS_CERT_FILE, value: /var/run/secrets/runtime-services/temporal-client.crt }
- { name: ZASP_TEMPORAL_TLS_KEY_FILE, value: /var/run/secrets/runtime-services/temporal-client.key }
- { name: ZASP_OPENFGA_TLS_CA_FILE, value: /var/run/secrets/runtime-services/openfga-ca.crt }
- { name: ZASP_OPENFGA_TOKEN_FILE, value: /var/run/secrets/runtime-services/openfga-token }
{{- end }}
{{- end }}
{{- define "zasp.runtimeServices.mount" -}}
{{- if .Values.runtimeServices.enabled }}
- { name: runtime-services, mountPath: /var/run/secrets/runtime-services, readOnly: true }
{{- end }}
{{- end }}
{{- define "zasp.runtimeServices.volume" -}}
{{- if .Values.runtimeServices.enabled }}
- name: runtime-services
  secret:
    secretName: {{ required "runtimeServices.clientSecret required" .Values.runtimeServices.clientSecret | quote }}
    defaultMode: 288
{{- end }}
{{- end }}
