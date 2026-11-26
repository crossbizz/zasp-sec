{{- define "zasp.openbao.validateClients" -}}
{{- $c := .Values.openbaoClients -}}
{{- if not (kindIs "map" $c) -}}{{ fail "openbaoClients must be an object" }}{{- end -}}
{{- range $key, $value := $c -}}
  {{- if or (not (has $key (list "namespace" "connectorSecretsProvider" "recoverySigningProvider" "kvMount" "transitKey"))) (not (kindIs "string" $value)) -}}
    {{- fail "unsupported openbaoClients setting or value type" -}}
  {{- end -}}
{{- end -}}
{{- if not (has $c.connectorSecretsProvider (list "aws-secrets-manager" "openbao")) -}}{{ fail "invalid OpenBao connector secrets provider" }}{{- end -}}
{{- if not (has $c.recoverySigningProvider (list "aws-kms" "openbao")) -}}{{ fail "invalid OpenBao recovery signing provider" }}{{- end -}}
{{- $kv := eq $c.connectorSecretsProvider "openbao" -}}
{{- $sign := eq $c.recoverySigningProvider "openbao" -}}
{{- if $kv -}}
  {{- if or (not (regexMatch "^[a-zA-Z0-9_-][a-zA-Z0-9._-]{0,126}$" $c.kvMount)) (hasSuffix "." $c.kvMount) -}}{{ fail "invalid OpenBao KV mount" }}{{- end -}}
  {{- if ne .Values.connectors.secretPrefix (printf "%s/oauth" .Values.discovery.secretPrefix) -}}{{ fail "OpenBao connector and discovery secret roots must match" }}{{- end -}}
{{- else if $c.kvMount -}}
  {{- fail "OpenBao KV mount requires connectorSecretsProvider=openbao" -}}
{{- end -}}
{{- if and $sign (not $c.transitKey) -}}{{ fail "OpenBao Transit signing requires a key" }}{{- end -}}
{{- if $c.transitKey -}}
  {{- if or (not .Values.recovery.canaryEnabled) (not (regexMatch "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" $c.transitKey)) -}}{{ fail "OpenBao Transit requires enabled recovery and a lowercase UUIDv4 key" }}{{- end -}}
{{- end -}}
{{- if or $kv $c.transitKey -}}
  {{- if or (eq .Values.profile "customer_edge") (gt (len $c.namespace) 63) (eq $c.namespace .Release.Namespace) (not (regexMatch "^[a-z]([-a-z0-9]*[a-z0-9])?$" $c.namespace)) -}}{{ fail "OpenBao clients require a separate OpenBao Kubernetes namespace" }}{{- end -}}
{{- else if $c.namespace -}}{{ fail "OpenBao namespace requires at least one OpenBao client" }}{{- end -}}
{{- end -}}

{{- define "zasp.openbao.env" -}}
- { name: ZASP_OPENBAO_ADDR, value: {{ printf "https://openbao.%s.svc:8200" .root.Values.openbaoClients.namespace | quote }} }
- { name: ZASP_OPENBAO_CA_FILE, value: "/run/zasp-openbao/ca.crt" }
- { name: ZASP_OPENBAO_TOKEN_FILE, value: "/run/zasp-openbao/token" }
{{- if has .role (list "api" "discovery") }}
- { name: ZASP_CONNECTOR_SECRETS_PROVIDER, value: "openbao" }
- { name: ZASP_OPENBAO_KV_MOUNT, value: {{ .root.Values.openbaoClients.kvMount | quote }} }
{{- else }}
- { name: ZASP_RECOVERY_SIGNING_PROVIDER, value: {{ .root.Values.openbaoClients.recoverySigningProvider | quote }} }
- { name: ZASP_OPENBAO_TRANSIT_KEY, value: {{ .root.Values.openbaoClients.transitKey | quote }} }
{{- end }}
{{- end -}}

{{- define "zasp.openbao.init" -}}
- name: prepare-openbao-credentials
  image: {{ .image | quote }}
  imagePullPolicy: IfNotPresent
  command: ["/bin/sh", "-ec"]
  args:
    - |
      umask 077
      mkdir -p /staging/private
      chmod 700 /staging/private
      rm -f /staging/private/token /staging/private/ca.crt
      cp /source/token /staging/private/token
      cp /source/ca.crt /staging/private/ca.crt
      chmod 400 /staging/private/token /staging/private/ca.crt
  securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: [ALL] }, readOnlyRootFilesystem: true, runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532 }
  resources: { requests: { cpu: 5m, memory: 8Mi }, limits: { cpu: 50m, memory: 32Mi } }
  volumeMounts:
    - { name: openbao-source, mountPath: /source, readOnly: true }
    - { name: openbao-private, mountPath: /staging }
{{- end -}}

{{- define "zasp.openbao.mount" -}}
- { name: openbao-private, mountPath: /run/zasp-openbao, subPath: private, readOnly: true }
{{- end -}}

{{- define "zasp.openbao.volumes" -}}
- name: openbao-source
  projected:
    defaultMode: 288
    sources:
      - secret:
          name: {{ printf "zasp-openbao-%s" .role | quote }}
          items: [{ key: token, path: token }]
      - configMap:
          name: zasp-openbao-ca
          items: [{ key: ca.crt, path: ca.crt }]
- name: openbao-private
  emptyDir: { medium: Memory, sizeLimit: 2Mi }
{{- end -}}
