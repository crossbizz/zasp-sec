{{- define "zasp.name" -}}
{{- .Release.Name | trunc 52 | trimSuffix "-" -}}
{{- end -}}

{{- define "zasp.labels" -}}
app.kubernetes.io/name: zasp
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "zasp.selector" -}}
app.kubernetes.io/name: zasp
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* The public origin, validated the way the product validates it. */}}
{{- define "zasp.origin" -}}
{{- $origin := required "publicOrigin is required, for example https://zasp.example.test:8443" .Values.publicOrigin -}}
{{- if not (regexMatch "^https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$" $origin) -}}
{{- fail "publicOrigin must be https://<host>[:port], lower case, with no path" -}}
{{- end -}}
{{- $host := include "zasp.host" . -}}
{{- if or (eq $host "localhost") (hasSuffix ".localhost" $host) (hasSuffix ".local" $host) (regexMatch "^[0-9.]+$" $host) -}}
{{- fail "publicOrigin must not be localhost, *.localhost, *.local or an IP address: the connector sign-in callbacks refuse those hosts" -}}
{{- end -}}
{{- $origin -}}
{{- end -}}

{{- define "zasp.host" -}}
{{- regexReplaceAll ":[0-9]+$" (trimPrefix "https://" (.Values.publicOrigin | default "")) "" -}}
{{- end -}}

{{- define "zasp.secretName" -}}
{{- .Values.secrets.existingSecret | default (printf "%s-secrets" (include "zasp.name" .)) -}}
{{- end -}}

{{- define "zasp.nangoName" -}}{{ printf "%s-nango" (include "zasp.name" .) }}{{- end -}}
{{- define "zasp.nangoSecret" -}}{{ .Values.nango.existingSecret | default (include "zasp.nangoName" .) }}{{- end -}}
{{- define "zasp.nangoURL" -}}{{ printf "http://%s.%s.svc.cluster.local:3003" (include "zasp.nangoName" .) .Release.Namespace }}{{- end -}}

{{/*
One container that runs a process of files/entrypoint.sh.
Arguments: root, name, image, args (list).
*/}}
{{- define "zasp.process" -}}
- name: {{ .name }}
  image: {{ .image | quote }}
  imagePullPolicy: {{ .root.Values.images.pullPolicy }}
  command: ["/bin/sh", "/zasp/config/entrypoint.sh"]
  args: {{ toJson .args }}
  envFrom:
    - configMapRef: { name: {{ include "zasp.name" .root }}-settings }
  {{- $nangoClient := and .root.Values.nango.enabled (has .name (list "api" "worker-discovery")) }}
  {{- if $nangoClient }}
  env:
    - { name: ZASP_DISCOVERY_SAAS_COLLECTOR_VERSION, value: "collector_v1" }
    - { name: ZASP_NANGO_BASE_URL, value: {{ include "zasp.nangoURL" .root | quote }} }
    - { name: ZASP_NANGO_ENVIRONMENT, value: "prod" }
    - { name: ZASP_NANGO_SERVICE_SECRET_REFERENCE, value: "ref:nango/service-key-0001" }
  {{- end }}
  securityContext:
    allowPrivilegeEscalation: false
    capabilities: { drop: [ALL] }
  {{- with (index .root.Values.resources .name) }}
  resources: {{ toJson . }}
  {{- end }}
  volumeMounts:
    {{- if $nangoClient }}
    - { name: nango-client, mountPath: /var/run/secrets/zasp-nango, readOnly: true }
    {{- end }}
    - { name: config, mountPath: /zasp/config, readOnly: true }
    - { name: run, mountPath: /run/zasp }
    - { name: data, mountPath: /var/lib/zasp, subPath: state }
    - { name: identity-token, mountPath: /var/run/secrets/eks.amazonaws.com/serviceaccount, readOnly: true }
    - { name: security-agent, mountPath: /var/run/secrets/zasp-security-agent }
    - { name: security-agent-action, mountPath: /var/run/secrets/zasp-security-agent-action }
    - { name: policy-verifier, mountPath: /var/run/zasp-policy-verifier }
    - { name: neo4j-tls, mountPath: /zasp/neo4j-tls, readOnly: true }
{{- end -}}
