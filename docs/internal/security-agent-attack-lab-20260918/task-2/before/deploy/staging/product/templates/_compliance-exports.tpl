{{- define "zasp.complianceExports.validate" -}}
{{- $c := .Values.complianceExports -}}
{{- if not (kindIs "map" $c) -}}{{ fail "complianceExports must be a map" }}{{- end -}}
{{- if not (kindIs "bool" $c.enabled) -}}{{ fail "complianceExports.enabled must be boolean" }}{{- end -}}
{{- if $c.enabled -}}
{{- $fields := list "enabled" "awsRegion" "bucket" "bucketOwner" "kmsKeyArn" "readerRoleArn" "writerRoleArn" "cleanupRoleArn" "workerDSNSecretArn" "cleanupDSNSecretArn" "workerPrincipal" "cleanupPrincipal" "databaseCIDRs" "stsCIDRs" "s3CIDRs" -}}
{{- if ne (toJson (keys $c | sortAlpha)) (toJson ($fields | sortAlpha)) -}}{{ fail "compliance export fields are closed" }}{{- end -}}
{{- if or (ne .Values.profile "control_plane") (ne (toString .Values.schema.expectedVersion) "56") (not (has .Values.runtime.sessionSearchPhase (list "precision-consumers" "precision-intake"))) -}}{{ fail "compliance exports require precision schema56" }}{{- end -}}
{{- if or (not .Values.monitoring.enabled) (ne .Values.monitoring.namespace "monitoring") (le (int .Values.global.terminationGracePeriodSeconds) 20) (gt (int .Values.global.terminationGracePeriodSeconds) 300) -}}{{ fail "compliance exports require monitoring and bounded grace" }}{{- end -}}
{{- range $field := $fields -}}
{{- if not (has $field (list "enabled" "databaseCIDRs" "stsCIDRs" "s3CIDRs")) -}}
{{- $value := index $c $field -}}
{{- if or (not (kindIs "string" $value)) (contains "\n" $value) (contains "\r" $value) -}}{{ fail "compliance authority must be plain strings" }}{{- end -}}
{{- end -}}
{{- end -}}
{{- $region := $c.awsRegion -}}{{- $account := $c.bucketOwner -}}
{{- if or (not (regexMatch "^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$" $region)) (not (regexMatch "^[0-9]{12}$" $account)) (eq $account "000000000000") (not (hasPrefix (printf "arn:aws:iam::%s:role/" $account) .Values.serviceAccounts.api.roleArn)) -}}{{ fail "compliance account/region mismatch" }}{{- end -}}
{{- if not (regexMatch "^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$" $c.bucket) -}}{{ fail "compliance bucket invalid" }}{{- end -}}
{{- if not (regexMatch (printf "^arn:aws:kms:%s:%s:key/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" $region $account) $c.kmsKeyArn) -}}{{ fail "compliance KMS authority mismatch" }}{{- end -}}
{{- $roles := list $c.readerRoleArn $c.writerRoleArn $c.cleanupRoleArn -}}
{{- if ne (len (uniq $roles)) 3 -}}{{ fail "compliance roles must be distinct" }}{{- end -}}
{{- range $role := $roles -}}{{- if not (regexMatch (printf "^arn:aws:iam::%s:role/[A-Za-z0-9+=,.@_/-]{1,128}$" $account) $role) -}}{{ fail "compliance role mismatch" }}{{- end -}}{{- end -}}
{{- if eq $c.workerDSNSecretArn $c.cleanupDSNSecretArn -}}{{ fail "compliance DSNs must be separate" }}{{- end -}}
{{- range $secret := list $c.workerDSNSecretArn $c.cleanupDSNSecretArn -}}{{- if not (regexMatch (printf "^arn:aws:secretsmanager:%s:%s:secret:[A-Za-z0-9/_+=.@-]{1,512}$" $region $account) $secret) -}}{{ fail "compliance DSN authority mismatch" }}{{- end -}}{{- end -}}
{{- if eq $c.workerPrincipal $c.cleanupPrincipal -}}{{ fail "compliance principals must be distinct" }}{{- end -}}
{{- range $principal := list $c.workerPrincipal $c.cleanupPrincipal -}}{{- if or (not (regexMatch "^[a-z][a-z0-9_]{2,62}$" $principal)) (hasPrefix "zasp_" $principal) -}}{{ fail "compliance principal invalid" }}{{- end -}}{{- end -}}
{{- $predecessors := omit .Values "complianceExports" | toJson -}}
{{- range $field := list "bucket" "readerRoleArn" "writerRoleArn" "cleanupRoleArn" "workerDSNSecretArn" "cleanupDSNSecretArn" "workerPrincipal" "cleanupPrincipal" -}}
{{- if contains (toJson (index $c $field)) $predecessors -}}{{ fail "compliance authority collides with predecessor" }}{{- end -}}
{{- end -}}
{{- if not (regexMatch "^[a-z0-9][a-z0-9./_-]*(:[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$" .Values.global.productImages.agentsecWorker) -}}{{ fail "compliance image must be pinned" }}{{- end -}}
{{- include "zasp.complianceExports.cidrs" . -}}
{{- else -}}
{{- if ne (len $c) 1 -}}{{ fail "disabled compliance exports cannot carry authority" }}{{- end -}}
{{- end -}}
{{- end -}}

{{- define "zasp.complianceExports.apiEnv" -}}
{{- $c := .Values.complianceExports -}}
- { name: ZASP_COMPLIANCE_EXPORT_BUCKET, value: {{ $c.bucket | quote }} }
- { name: ZASP_COMPLIANCE_EXPORT_BUCKET_OWNER, value: {{ $c.bucketOwner | quote }} }
- { name: ZASP_COMPLIANCE_EXPORT_KMS_KEY_ARN, value: {{ $c.kmsKeyArn | quote }} }
- { name: ZASP_COMPLIANCE_EXPORT_READER_ROLE_ARN, value: {{ $c.readerRoleArn | quote }} }
- { name: ZASP_COMPLIANCE_EXPORT_WEB_IDENTITY_TOKEN_FILE, value: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" }
{{- end -}}

{{- define "zasp.complianceExports.migrationCommand" -}}
ZASP_POSTGRES_DSN="$(cat /var/run/secrets/zasp-migration/postgres-dsn)" && export ZASP_POSTGRES_DSN && /app/agentsec-migrate up-to-56{{ if .Values.auditExports.enabled }} && /app/agentsec-migrate register-audit-export-api && /app/agentsec-migrate register-audit-export-workers && /app/agentsec-migrate configure-audit-exports{{ end }} && exec /app/agentsec-migrate register-compliance-workers
{{- end -}}

{{- define "zasp.complianceExports.cidrs" -}}
{{- $c := .Values.complianceExports -}}
{{- range $field := list "databaseCIDRs" "stsCIDRs" "s3CIDRs" -}}
{{- $cidrs := index $c $field -}}
{{- if or (not (kindIs "slice" $cidrs)) (lt (len $cidrs) 1) (gt (len $cidrs) 64) -}}{{ fail "compliance endpoint snapshots required" }}{{- end -}}
{{- $ranges := list -}}
{{- range $cidr := $cidrs -}}
{{- if not (kindIs "string" $cidr) -}}{{ fail "compliance CIDR must be string" }}{{- end -}}
{{- if not (regexMatch "^([0-9]{1,3}\\.){3}[0-9]{1,3}/(1[6-9]|2[0-9]|3[0-2])$" $cidr) -}}{{ fail "compliance CIDR must be bounded IPv4" }}{{- end -}}
{{- $parts := splitList "/" $cidr -}}
{{- $octets := splitList "." (index $parts 0) -}}
{{- $start := int64 0 -}}
{{- range $octet := $octets -}}
{{- if or (gt (int $octet) 255) (ne (toString (int $octet)) $octet) -}}{{ fail "compliance CIDR must be canonical" }}{{- end -}}
{{- $start = add (mul $start 256) (int $octet) -}}
{{- end -}}
{{- $first := int (index $octets 0) -}}
{{- if or (eq $first 0) (eq $first 127) (ge $first 224) (and (eq $first 169) (eq (index $octets 1) "254")) -}}{{ fail "compliance CIDR cannot be local/metadata/multicast" }}{{- end -}}
{{- $size := int64 1 -}}
{{- range until (int (sub 32 (int (index $parts 1)))) -}}{{- $size = mul $size 2 -}}{{- end -}}
{{- if ne (mod $start $size) 0 -}}{{ fail "compliance CIDR has host bits" }}{{- end -}}
{{- $end := sub (add $start $size) 1 -}}
{{- range $prior := $ranges -}}{{- if and (le $start $prior.end) (ge $end $prior.start) -}}{{ fail "compliance endpoint ranges overlap" }}{{- end -}}{{- end -}}
{{- $ranges = append $ranges (dict "start" $start "end" $end) -}}
{{- end -}}
{{- end }}
{{- end -}}
