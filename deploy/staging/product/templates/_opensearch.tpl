{{- define "zasp.searchTLS.env" -}}
{{- if .Values.searchTLS.enabled -}}
{{- if or (ne .Values.projectionSearch.endpoint "https://opensearch.opensearch.svc.cluster.local:9200") (ne .Values.runtime.openSearchEndpoint .Values.projectionSearch.endpoint) -}}
{{- fail "mTLS search requires readers, writers and initializers to share the private OpenSearch service" -}}
{{- end }}
- { name: ZASP_OPENSEARCH_AUTH_MODE, value: mtls }
{{- end -}}
{{- end -}}

{{- define "zasp.searchTLS.mount" -}}
- {name: opensearch-client, mountPath: /var/run/secrets/zasp-opensearch, readOnly: true}
{{- end -}}

{{- define "zasp.searchTLS.volume" -}}
- name: opensearch-client
  secret:
    secretName: {{ printf "opensearch-%s-client" . | quote }}
    defaultMode: 288
    items:
      - {key: ca.crt, path: ca.crt}
      - {key: tls.crt, path: tls.crt}
      - {key: tls.key, path: tls.key}
{{- end -}}

{{- define "zasp.searchTLS.egress" -}}
{{- if .Values.searchTLS.enabled -}}
- to:
    - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: opensearch}}
      podSelector: {matchLabels: {app.kubernetes.io/name: opensearch}}
  ports: [{protocol: TCP, port: 9200}]
{{- else -}}
- to: [{ ipBlock: { cidr: {{ required "network.opensearchCIDR is required" .Values.network.opensearchCIDR | quote }} } }]
  ports: [{ protocol: TCP, port: 443 }]
{{- end -}}
{{- end -}}
