{{- define "zasp.workerKeys.env" -}}
- { name: ZASP_AUTHORIZATION_WORKER_KEY_FILE, value: /var/run/zasp-authority/forward.seed }
- { name: ZASP_AUTHORIZATION_COMPENSATION_KEY_FILE, value: /var/run/zasp-authority/compensation.seed }
{{- end -}}
{{- define "zasp.workerKeys.init" -}}
- name: materialize-worker-keys
  image: {{ .image | quote }}
  command: ["/bin/sh", "-ec"]
  args: ['umask 077; cp /forward/seed /keys/forward.seed; cp /compensation/seed /keys/compensation.seed; chmod 0400 /keys/forward.seed /keys/compensation.seed']
  securityContext: { runAsNonRoot: true, runAsUser: {{ .uid }}, runAsGroup: {{ .uid }}, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: [ALL] } }
  resources: { requests: { cpu: 10m, memory: 16Mi }, limits: { cpu: 100m, memory: 32Mi } }
  volumeMounts:
    - { name: forward-key-source, mountPath: /forward, readOnly: true }
    - { name: compensation-key-source, mountPath: /compensation, readOnly: true }
    - { name: worker-keys, mountPath: /keys }
{{- end -}}
{{- define "zasp.workerKeys.mount" -}}
- { name: worker-keys, mountPath: /var/run/zasp-authority, readOnly: true }
{{- end -}}
{{- define "zasp.workerKeys.volumes" -}}
- name: worker-keys
  emptyDir: { medium: Memory, sizeLimit: 64Ki }
- name: forward-key-source
  secret: { secretName: {{ .Values.authorizationTemporal.forwardKey.secretName | quote }}, defaultMode: 288, items: [{ key: seed, path: seed }] }
- name: compensation-key-source
  secret: { secretName: {{ .Values.authorizationTemporal.compensationKey.secretName | quote }}, defaultMode: 288, items: [{ key: seed, path: seed }] }
{{- end -}}
{{- define "zasp.authorizationTemporal.migrationCommand" -}}
export ZASP_POSTGRES_DSN="$(cat /var/run/secrets/zasp-migration/postgres-dsn)"; export ZASP_WORKFLOW_SIGNING_KEY="$(cat /var/run/secrets/zasp-migration/workflow-signing-key)"; export ZASP_STYTCH_PROJECT_ID="$(cat /var/run/secrets/zasp-migration/stytch-project-id)"; export ZASP_STYTCH_ORGANIZATION_ID="$(cat /var/run/secrets/zasp-migration/stytch-organization-id)"; /app/agentsec-migrate up-authorization-runtime-profile; /app/agentsec-migrate register-temporal-executor-principals; /app/agentsec-migrate register-authorization-verifier; /app/agentsec-migrate register-identity-session-verifier; /app/agentsec-migrate register-identity-webhook-verifier; /app/agentsec-migrate register-worker-authorization-verifier; /app/agentsec-migrate register-compensation-authorization-verifier
{{- end -}}
