{{/* Optional runtime wiring; no installation, registration, or activation hook. */}}
{{- define "zasp.maintenanceRuntime.validate" -}}
{{- $m := .Values.authorizationTemporal.maintenance -}}
{{- if $m -}}
{{- if not (and (eq .Values.authorizationTemporal.profile "canonical61-temporal78-authorization79-80-worker-v1") .Values.runtimeServices.enabled (eq $m.profile "registered-dual-maintenance-runtime-v1") (eq (len $m) 8)) -}}{{ fail "maintenance runtime profile rejected" }}{{- end -}}
{{- range $key := list "connectorProfileChecksum" "approvalProfileChecksum" "activationProfileChecksum" -}}
{{- if not (regexMatch "^[0-9a-f]{64}$" (toString (index $m $key))) -}}{{ fail "maintenance runtime checksum rejected" }}{{- end -}}
{{- end -}}
{{- $refs := list -}}
{{- range $key := list "connectorDSNSecret" "approvalDSNSecret" "connectorKeySecret" "approvalKeySecret" -}}
{{- $value := index $m $key -}}
{{- if not (regexMatch "^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$" (toString $value)) -}}{{ fail "maintenance runtime reference rejected" }}{{- end -}}
{{- $refs = append $refs $value -}}
{{- end -}}
{{- $p := .Values.authorizationTemporal -}}
{{- $refs = concat $refs (list $p.executorDSNSecret $p.compensationDSNSecret $p.projectorDSNSecret $p.adapterDSNSecret $p.forwardKey.secretName $p.compensationKey.secretName $p.pricingBindingsConfigMap $p.gatewayPolicyKeysConfigMap .Values.runtimeServices.clientSecret) -}}
{{- if ne (len $refs) (len (uniq $refs)) -}}{{ fail "maintenance runtime references must be distinct" }}{{- end -}}
{{- end -}}
{{- end -}}
{{- define "zasp.maintenanceRuntime.pins" -}}
{{- with .Values.authorizationTemporal.maintenance }}
- { name: ZASP_CONNECTOR_MAINTENANCE_PROFILE_CHECKSUM, value: {{ .connectorProfileChecksum | quote }} }
- { name: ZASP_APPROVAL_MAINTENANCE_PROFILE_CHECKSUM, value: {{ .approvalProfileChecksum | quote }} }
- { name: ZASP_APPROVAL_ACTIVATION_PROFILE_CHECKSUM, value: {{ .activationProfileChecksum | quote }} }
{{- end }}
{{- end -}}
{{- define "zasp.maintenanceRuntime.apiEnv" -}}
{{- with .Values.authorizationTemporal.maintenance }}
- name: ZASP_CONNECTOR_MAINTENANCE_POSTGRES_DSN
  valueFrom: { secretKeyRef: { name: {{ .connectorDSNSecret | quote }}, key: postgres-dsn } }
- name: ZASP_APPROVAL_MAINTENANCE_POSTGRES_DSN
  valueFrom: { secretKeyRef: { name: {{ .approvalDSNSecret | quote }}, key: postgres-dsn } }
- { name: ZASP_CONNECTOR_MAINTENANCE_KEY_FILE, value: /var/run/zasp-maintenance/connector.seed }
- { name: ZASP_APPROVAL_MAINTENANCE_KEY_FILE, value: /var/run/zasp-maintenance/approval.seed }
{{- end }}
{{- end -}}
{{- define "zasp.maintenanceRuntime.init" -}}
{{- if .Values.authorizationTemporal.maintenance }}
- name: materialize-maintenance-keys
  image: {{ .Values.global.productImages.agentsecApi | quote }}
  command: ["/bin/sh", "-ec"]
  args: ['umask 077; cp /connector/seed /keys/connector.seed; cp /approval/seed /keys/approval.seed; chmod 0400 /keys/connector.seed /keys/approval.seed']
  securityContext: { runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: [ALL] } }
  resources: { requests: { cpu: 10m, memory: 16Mi }, limits: { cpu: 100m, memory: 32Mi } }
  volumeMounts:
    - { name: connector-maintenance-source, mountPath: /connector, readOnly: true }
    - { name: approval-maintenance-source, mountPath: /approval, readOnly: true }
    - { name: maintenance-keys, mountPath: /keys }
{{- end }}
{{- end -}}
{{- define "zasp.maintenanceRuntime.mount" -}}
{{- if .Values.authorizationTemporal.maintenance }}
- { name: maintenance-keys, mountPath: /var/run/zasp-maintenance, readOnly: true }
{{- end }}
{{- end -}}
{{- define "zasp.maintenanceRuntime.volumes" -}}
{{- with .Values.authorizationTemporal.maintenance }}
- name: maintenance-keys
  emptyDir: { medium: Memory, sizeLimit: 64Ki }
- name: connector-maintenance-source
  secret: { secretName: {{ .connectorKeySecret | quote }}, defaultMode: 288, items: [{ key: seed, path: seed }] }
- name: approval-maintenance-source
  secret: { secretName: {{ .approvalKeySecret | quote }}, defaultMode: 288, items: [{ key: seed, path: seed }] }
{{- end }}
{{- end -}}
