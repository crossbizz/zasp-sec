{{- define "nango.podSecurity" -}}
automountServiceAccountToken: false
enableServiceLinks: false
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  fsGroup: 1000
  seccompProfile: { type: RuntimeDefault }
{{- end }}
{{- define "nango.containerSecurity" -}}
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities: { drop: [ALL] }
{{- end }}
{{- define "nango.databaseEnv" -}}
- { name: NANGO_CLOUD, value: "false" }
- { name: NANGO_ENTERPRISE, value: "false" }
- { name: NANGO_LOGS_ENABLED, value: "false" }
- { name: NANGO_TELEMETRY_SDK, value: "false" }
- { name: NANGO_DB_SSL, value: "true" }
- { name: RECORDS_DATABASE_SSL, value: "true" }
- { name: NANGO_DB_SCHEMA, value: "nango" }
- { name: RECORDS_DATABASE_SCHEMA, value: "nango_records" }
- { name: NODE_EXTRA_CA_CERTS, value: /run/database-ca/ca.crt }
{{- end }}
{{- define "nango.dbEgress" -}}
- to:
    - namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: kube-system } }
      podSelector: { matchLabels: { k8s-app: kube-dns } }
  ports: [{ protocol: UDP, port: 53 }, { protocol: TCP, port: 53 }]
- to:
    {{- range .Values.databaseEgressCIDRs }}
    - ipBlock: { cidr: {{ . | quote }} }
    {{- end }}
  ports: [{ protocol: TCP, port: 5432 }]
{{- end }}
{{- define "nango.loadStorage" -}}
test -s /run/nango-storage/database-url && test -s /run/nango-storage/encryption-key || exit 64
NANGO_DATABASE_URL="$(cat /run/nango-storage/database-url)"
RECORDS_DATABASE_URL="$NANGO_DATABASE_URL"
NANGO_ENCRYPTION_KEY="$(cat /run/nango-storage/encryption-key)"
export NANGO_DATABASE_URL RECORDS_DATABASE_URL NANGO_ENCRYPTION_KEY
{{- end }}
{{- define "nango.dbCheck" -}}
node --input-type=module --eval 'let url; try { url = new URL(process.env.NANGO_DATABASE_URL); } catch {} if (!url || process.env.NANGO_DATABASE_URL !== process.env.RECORDS_DATABASE_URL || !["postgres:", "postgresql:"].includes(url.protocol) || !url.username || !url.password || !url.hostname || url.port !== "5432" || url.pathname.length < 2 || url.hash || String([...url.searchParams.keys()]) !== "sslmode" || url.searchParams.get("sslmode") !== "verify-full") process.exit(64);'
{{- end }}
