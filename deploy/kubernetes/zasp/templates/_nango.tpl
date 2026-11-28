{{/* The database is on loopback in this evaluation pod. Both processes use the
dedicated nango database and the same durable credential encryption key. */}}
{{- define "zasp.nangoDatabaseEnv" -}}
- { name: NANGO_DATABASE_URL, value: "postgres://nango@127.0.0.1:5432/nango?sslmode=disable" }
- { name: RECORDS_DATABASE_URL, value: "postgres://nango@127.0.0.1:5432/nango?sslmode=disable" }
- { name: NANGO_DB_SCHEMA, value: "nango" }
- { name: RECORDS_DATABASE_SCHEMA, value: "nango_records" }
- { name: NANGO_DB_SSL, value: "false" }
- { name: RECORDS_DATABASE_SSL, value: "false" }
- { name: NANGO_CLOUD, value: "false" }
- { name: NANGO_ENTERPRISE, value: "false" }
- { name: NANGO_LOGS_ENABLED, value: "false" }
- { name: NANGO_TELEMETRY_SDK, value: "false" }
- name: NANGO_ENCRYPTION_KEY
  valueFrom: { secretKeyRef: { name: {{ include "zasp.nangoSecret" . }}, key: encryption-key } }
{{- end }}

{{- define "zasp.nangoContainerSecurity" -}}
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities: { drop: ["ALL"] }
volumeMounts:
  - { name: nango-tmp, mountPath: /tmp }
{{- end }}
