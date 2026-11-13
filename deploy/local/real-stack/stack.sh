#!/usr/bin/env bash
# Runs the product API against real dependencies on one machine: PostgreSQL 18,
# the pinned Temporal and OpenFGA servers, and a real Stytch project.
# See README.md in this directory for what this does and does not establish.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
STATE="${ZASP_REAL_STACK_STATE:-${XDG_STATE_HOME:-$HOME/.local/state}/zasp-real-stack}"
BIN="$STATE/bin"
SECRETS="$STATE/secrets"
COMPOSE="$ROOT/deploy/local/temporal-openfga.compose.yaml"

# PostgreSQL 18 is the reference major (the production Neon project runs 18).
# The digest is the ECR Public mirror of the official image.
PG_IMAGE="${ZASP_REAL_STACK_PG_IMAGE:-public.ecr.aws/docker/library/postgres:18.3@sha256:7e32e9833a6fb1c92c32552794cb6ed569d51b445a54907d35fc112ef39684db}"
PG_CONTAINER="zasp-real-stack-pg"
PG_PORT="${ZASP_REAL_STACK_PG_PORT:-55434}"
# LocalStack stands in for AWS and a single OpenSearch node for the search
# domain. Both are development-only; production refuses the local endpoint.
LOCALSTACK_IMAGE="${ZASP_REAL_STACK_LOCALSTACK_IMAGE:-public.ecr.aws/localstack/localstack:4.7.0}"
OPENSEARCH_IMAGE="${ZASP_REAL_STACK_OPENSEARCH_IMAGE:-public.ecr.aws/opensearchproject/opensearch:3.8.0}"
LOCALSTACK_SERVICES="sts,iam,secretsmanager,kms,s3,sqs,ec2"
LOCAL_CLOUD="http://127.0.0.1:4566"
# The emulated customer AWS account an AWS integration connects to. The role
# must sit under a path: the API only assumes roles below an allowed prefix.
CUSTOMER_ROLE_PATH="/zasp-reference/"
CUSTOMER_ROLE_NAME="customer-read"
CUSTOMER_ROLE_ARN="arn:aws:iam::000000000000:role/zasp-reference/customer-read"
CUSTOMER_EXTERNAL_ID_NAME="localstack-dev-0001"
SEARCH_URL="http://127.0.0.1:4092"
TOKEN_FILE=/var/run/secrets/eks.amazonaws.com/serviceaccount/token
FGA_URL="http://127.0.0.1:8088"
FGA_TOKEN="${ZASP_LOCAL_OPENFGA_TOKEN:-local-openfga-smoke-only}"
# The public origin must be HTTPS and must not be localhost or an IP address:
# the connector OAuth callbacks refuse those hosts.
PUBLIC_ORIGIN="${ZASP_REAL_STACK_ORIGIN:-https://zasp.local-stack.test:8443}"
# The operator is not a superuser, exactly as on managed PostgreSQL. The
# cluster superuser is used only to create that role and its database.
OPERATOR="zasp_operator"
PG_SUPERUSER="postgres"
PG_DATABASE="zasp"

fail() { echo "real-stack: $*" >&2; exit 1; }
# An external PostgreSQL (for example a Neon development branch) replaces the
# local container when ZASP_REAL_STACK_DATABASE_HOST is set. The baseline must
# be installable or installed there, every zasp_svc_* login must share the
# password in ZASP_REAL_STACK_DATABASE_PASSWORD_FILE, and
# ZASP_REAL_STACK_OPERATOR_DSN_FILE must hold the zasp_operator DSN. Never
# point this at a production database: the stack writes development data.
EXTERNAL_HOST="${ZASP_REAL_STACK_DATABASE_HOST:-}"
dsn() {
  if [ -z "$EXTERNAL_HOST" ]; then
    echo "postgres://$1@127.0.0.1:$PG_PORT/$PG_DATABASE?sslmode=disable"
  elif [ "$1" = "$OPERATOR" ]; then
    cat "${ZASP_REAL_STACK_OPERATOR_DSN_FILE:?set ZASP_REAL_STACK_OPERATOR_DSN_FILE}"
  else
    echo "postgres://$1:$(cat "${ZASP_REAL_STACK_DATABASE_PASSWORD_FILE:?set ZASP_REAL_STACK_DATABASE_PASSWORD_FILE}")@$EXTERNAL_HOST/$PG_DATABASE?sslmode=require"
  fi
}

ROLES=(
  ZASP_DISCOVERY_API_DB_PRINCIPAL=zasp_svc_api
  ZASP_DISCOVERY_WORKER_DB_PRINCIPAL=zasp_svc_discovery
  ZASP_RUNTIME_INGEST_DB_PRINCIPAL=zasp_svc_ingest
  ZASP_RUNTIME_WORKER_DB_PRINCIPAL=zasp_svc_runtime
  ZASP_OUTBOX_WORKER_DB_PRINCIPAL=zasp_svc_outbox
  ZASP_RUNTIME_GATEWAY_DB_PRINCIPAL=zasp_svc_gateway
  ZASP_DISCOVERY_SCHEDULER_DB_PRINCIPAL=zasp_svc_scheduler
  ZASP_PROJECTION_RISK_DB_PRINCIPAL=zasp_svc_projection_risk
  ZASP_PROJECTION_GRAPH_DB_PRINCIPAL=zasp_svc_projection_graph
  ZASP_PROJECTION_SEARCH_DB_PRINCIPAL=zasp_svc_projection_search
  ZASP_RUNTIME_COORDINATOR_DB_PRINCIPAL=zasp_svc_coordinator
  ZASP_RUNTIME_ARCHIVE_DB_PRINCIPAL=zasp_svc_archive
  ZASP_RUNTIME_INDEX_DB_PRINCIPAL=zasp_svc_index
  ZASP_RUNTIME_CORRELATION_DB_PRINCIPAL=zasp_svc_correlation
  ZASP_RUNTIME_PROJECTION_DB_PRINCIPAL=zasp_svc_runtime_projection
  ZASP_GATEWAY_CONTROL_DB_PRINCIPAL=zasp_svc_gateway_control
  ZASP_SECURITY_AGENT_API_DB_PRINCIPAL=zasp_svc_security_agent_api
  ZASP_SECURITY_AGENT_WORKER_DB_PRINCIPAL=zasp_svc_security_agent_worker
  ZASP_SECURITY_AGENT_ACTION_DB_PRINCIPAL=zasp_svc_security_agent_action
  ZASP_POLICY_DEPLOYMENT_DB_PRINCIPAL=zasp_svc_policy_deployment
  ZASP_RED_TEAM_WORKER_DB_PRINCIPAL=zasp_svc_red_team_worker
  ZASP_RED_TEAM_OUTBOX_DB_PRINCIPAL=zasp_svc_red_team_outbox
  ZASP_RED_TEAM_ADAPTER_DB_PRINCIPAL=zasp_svc_red_team_adapter
  ZASP_ATTACK_LAB_CONTROLLER_DB_PRINCIPAL=zasp_svc_attack_lab_controller
  ZASP_ATTACK_LAB_OUTBOX_DB_PRINCIPAL=zasp_svc_attack_lab_outbox
  ZASP_ATTACK_LAB_PROXY_DB_PRINCIPAL=zasp_svc_attack_lab_proxy
  ZASP_RECOVERY_WORKER_DB_PRINCIPAL=zasp_svc_recovery
  ZASP_RECOVERY_OUTBOX_DB_PRINCIPAL=zasp_svc_recovery_outbox
  ZASP_TEMPORAL_EXECUTOR_DB_PRINCIPAL=zasp_svc_temporal_executor
  ZASP_TEMPORAL_COMPENSATION_DB_PRINCIPAL=zasp_svc_temporal_compensation
)

require_provider() {
  for name in STYTCH_PROJECT_ID STYTCH_SECRET STYTCH_PUBLIC_TOKEN; do
    [ -n "${!name:-}" ] || fail "$name is required (Stytch B2B project credentials)"
  done
}

# Exports the settings shared by the operator commands and the API.
load_environment() {
  [ -f "$SECRETS/keys.env" ] || fail "run '$0 up' first"
  set -a
  # shellcheck disable=SC1091
  . "$SECRETS/keys.env"
  [ ! -f "$STATE/fga.env" ] || . "$STATE/fga.env"
  [ ! -f "$STATE/organization.env" ] || . "$STATE/organization.env"
  set +a
  for assignment in "${ROLES[@]}"; do export "${assignment?}"; done
  export ZASP_MIGRATION_DB_PRINCIPAL="$OPERATOR" ZASP_MIGRATION_TIMEOUT=20m
  export ZASP_PUBLIC_ORIGIN="$PUBLIC_ORIGIN" ZASP_DEPLOYMENT_MODE=saas ZASP_ORGANIZATION_ID=
  export ZASP_STYTCH_BASE_URL="${ZASP_STYTCH_BASE_URL:-https://test.stytch.com}"
  export ZASP_STYTCH_PROJECT_ID="$STYTCH_PROJECT_ID" ZASP_STYTCH_SECRET="$STYTCH_SECRET" ZASP_STYTCH_PUBLIC_TOKEN="$STYTCH_PUBLIC_TOKEN"
  export ZASP_RUNTIME_SERVICES_ENABLED=true ZASP_ENVIRONMENT=test ZASP_RUNTIME_SERVICES_TIMEOUT=10s
  export ZASP_LOCAL_CLOUD_ENDPOINT="$LOCAL_CLOUD"
  export ZASP_TEMPORAL_ADDRESS=127.0.0.1:7233 ZASP_TEMPORAL_NAMESPACE=zasp-dev
  export ZASP_TEMPORAL_TASK_QUEUE=zasp-security-agent ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE=zasp-discovery
  export ZASP_OPENFGA_URL="$FGA_URL" ZASP_OPENFGA_TOKEN_FILE="$SECRETS/openfga.token"
  # Approval notifications are delivered through the approval-maintenance
  # profile. Every process that reads permissions names the profile it expects.
  ZASP_APPROVAL_MAINTENANCE_PROFILE_CHECKSUM="$("$BIN/agentsec-migrate" approval-maintenance-checksum)" || fail "agentsec-migrate is not built"
  export ZASP_APPROVAL_MAINTENANCE_PROFILE_CHECKSUM ZASP_APPROVAL_MAINTENANCE_KEY_FILE="$SECRETS/approval-delivery.key"
}

build_binaries() {
  mkdir -p "$BIN"
  go build -C "$ROOT/services/platform" -o "$BIN/" ./agentsec-api ./agentsec-worker ./agentsec-migrate ./cmd/zasp-bootstrap ./cmd/zasp-authorization-reconcile
}

start_database() {
  [ -z "$EXTERNAL_HOST" ] || return 0
  if docker inspect "$PG_CONTAINER" >/dev/null 2>&1; then
    docker start "$PG_CONTAINER" >/dev/null
  else
    # The baseline requires C (or C.UTF-8) collation.
    docker run -d --name "$PG_CONTAINER" -e POSTGRES_USER="$PG_SUPERUSER" -e POSTGRES_DB=postgres \
      -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_INITDB_ARGS="--no-locale --encoding=UTF8" \
      -p "127.0.0.1:$PG_PORT:5432" "$PG_IMAGE" -c max_connections=300 >/dev/null
  fi
  local super="postgres://$PG_SUPERUSER@127.0.0.1:$PG_PORT/postgres?sslmode=disable"
  for _ in $(seq 1 120); do
    if psql -X -Atc 'select 1' "$super" >/dev/null 2>&1; then break; fi
    sleep 0.5
  done
  psql -X -Atc 'select 1' "$super" >/dev/null || fail "product database did not start"
  if [ "$(psql -X -Atc "select count(*) from pg_roles where rolname='$OPERATOR'" "$super")" != "1" ]; then
    psql -X -q -v ON_ERROR_STOP=1 "$super" -c "CREATE ROLE $OPERATOR LOGIN CREATEROLE BYPASSRLS"
  fi
  if [ "$(psql -X -Atc "select count(*) from pg_database where datname='$PG_DATABASE'" "$super")" != "1" ]; then
    psql -X -q -v ON_ERROR_STOP=1 "$super" -c "CREATE DATABASE $PG_DATABASE OWNER $OPERATOR TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C'"
  fi
  [ "$(psql -X -Atc "select datcollate from pg_database where datname=current_database()" "$(dsn "$OPERATOR")")" = "C" ] || fail "product database collation is not C"
}

generate_keys() {
  mkdir -p "$SECRETS"
  chmod 700 "$STATE" "$SECRETS"
  # keys.env is written last and atomically, so an interrupted or failed
  # generation is repeated in full instead of leaving a partial key set.
  if [ ! -f "$SECRETS/keys.env" ]; then
    (
      umask 077
      set -o pipefail
      rm -f "$SECRETS/forward.seed" "$SECRETS/compensation.seed" "$SECRETS/openfga.token" "$SECRETS/keys.env.partial"
      signing="$(openssl rand -hex 32)"
      reveal="$(openssl rand 32 | basenc --base64url | tr -d '=\n')"
      webhook="$(openssl rand -base64 32 | tr -d '\n')"
      [ "${#signing}" -eq 64 ] && [ "${#reveal}" -eq 43 ] && [ "${#webhook}" -eq 44 ] || fail "key generation failed"
      openssl rand 64 > "$SECRETS/forward.seed"
      openssl rand 64 > "$SECRETS/compensation.seed"
      printf '%s' "$FGA_TOKEN" > "$SECRETS/openfga.token"
      chmod 0400 "$SECRETS/forward.seed" "$SECRETS/compensation.seed" "$SECRETS/openfga.token"
      printf 'ZASP_WORKFLOW_SIGNING_KEY=%s\nZASP_TOKEN_REVEAL_KEY=%s\nZASP_STYTCH_WEBHOOK_SECRET=whsec_%s\n' "$signing" "$reveal" "$webhook" > "$SECRETS/keys.env.partial"
      mv "$SECRETS/keys.env.partial" "$SECRETS/keys.env"
    )
  fi
  # The approval-notification delivery key: 32 bytes, readable by its owner only.
  if [ ! -f "$SECRETS/approval-delivery.key" ]; then
    (umask 077; openssl rand 32 > "$SECRETS/approval-delivery.key.partial" && chmod 0400 "$SECRETS/approval-delivery.key.partial" && mv "$SECRETS/approval-delivery.key.partial" "$SECRETS/approval-delivery.key") || fail "key generation failed"
  fi
}

publish_model() {
  [ -f "$STATE/fga.env" ] && return 0
  local store model
  store="$(curl -fsS -H "Authorization: Bearer $FGA_TOKEN" -H 'Content-Type: application/json' -d '{"name":"zasp-real-stack"}' "$FGA_URL/stores" | sed -E 's/.*"id":"([^"]+)".*/\1/')"
  model="$(curl -fsS -H "Authorization: Bearer $FGA_TOKEN" -H 'Content-Type: application/json' --data-binary "@$ROOT/services/platform/authorization/model.json" "$FGA_URL/stores/$store/authorization-models" | sed -E 's/.*"authorization_model_id":"([^"]+)".*/\1/')"
  [[ "$store" =~ ^[0-9A-Z]{26}$ && "$model" =~ ^[0-9A-Z]{26}$ ]] || fail "authorization store or model was not created"
  printf 'ZASP_OPENFGA_STORE_ID=%s\nZASP_OPENFGA_MODEL_ID=%s\n' "$store" "$model" > "$STATE/fga.env"
}

start_local_cloud() {
  # EC2 is needed by the AWS collector (regions and instances). The collector's
  # posture step only accepts access keys shaped like AWS ones (ASIA/AKIA), so
  # LocalStack must issue those instead of its own LSIA/LKIA prefixes. A
  # container created with other settings is replaced: LocalStack keeps no
  # state across restarts here, so nothing is lost.
  local settings="SERVICES=$LOCALSTACK_SERVICES PARITY_AWS_ACCESS_KEY_ID=1"
  if docker inspect zasp-real-stack-localstack >/dev/null 2>&1 &&
    [ "$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' zasp-real-stack-localstack | grep -E '^(SERVICES|PARITY_AWS_ACCESS_KEY_ID)=' | sort -r | tr '\n' ' ' | sed 's/ $//')" != "$settings" ]; then
    docker rm -f zasp-real-stack-localstack >/dev/null
  fi
  docker inspect zasp-real-stack-localstack >/dev/null 2>&1 && docker start zasp-real-stack-localstack >/dev/null ||
    docker run -d --name zasp-real-stack-localstack -p 127.0.0.1:4566:4566 -e SERVICES="$LOCALSTACK_SERVICES" -e PARITY_AWS_ACCESS_KEY_ID=1 "$LOCALSTACK_IMAGE" >/dev/null
  # Disk watermarks are disabled: a nearly full developer disk otherwise
  # blocks index creation with no useful error.
  docker inspect zasp-real-stack-opensearch >/dev/null 2>&1 && docker start zasp-real-stack-opensearch >/dev/null ||
    docker run -d --name zasp-real-stack-opensearch -p 127.0.0.1:4092:9200 -e discovery.type=single-node -e DISABLE_SECURITY_PLUGIN=true \
      -e DISABLE_INSTALL_DEMO_CONFIG=true -e cluster.routing.allocation.disk.threshold_enabled=false \
      -e OPENSEARCH_JAVA_OPTS="-Xms512m -Xmx512m" "$OPENSEARCH_IMAGE" >/dev/null
  for _ in $(seq 1 90); do
    if curl -fsS -m 3 "$LOCAL_CLOUD/_localstack/health" 2>/dev/null | grep -q '"sts"' && curl -fsS -m 3 "$SEARCH_URL/_cluster/health" >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  fail "LocalStack or OpenSearch did not start"
}

# The workload identity token is read from a fixed path and must look like a
# token. LocalStack accepts any; this one is not a credential.
write_identity_token() {
  [ -s "$TOKEN_FILE" ] && [ "$(wc -c < "$TOKEN_FILE")" -ge 64 ] && return 0
  mkdir -p "$(dirname "$TOKEN_FILE")" 2>/dev/null || fail "create $TOKEN_FILE (needs root) with at least 64 token characters"
  printf '%s.%s.%s' "$(printf '{"alg":"none","typ":"JWT"}' | basenc --base64url | tr -d '=\n')" \
    "$(printf '{"iss":"zasp-real-stack","sub":"system:serviceaccount:zasp:local","aud":"sts.amazonaws.com"}' | basenc --base64url | tr -d '=\n')" \
    "bG9jYWwtZGV2ZWxvcG1lbnQtb25seQ" > "$TOKEN_FILE" || fail "write $TOKEN_FILE"
}

# Runs the production search-schema job against the local search node.
init_search() {
  env -i PATH="$PATH" ZASP_WORKER_MODE=projection-search-init ZASP_ENVIRONMENT=test ZASP_LOCAL_CLOUD_ENDPOINT="$LOCAL_CLOUD" \
    ZASP_AWS_REGION=us-east-1 ZASP_PROJECTION_INIT_ROLE_ARN=arn:aws:iam::000000000000:role/zasp-real-stack-projection-init \
    ZASP_PROJECTION_INIT_WEB_IDENTITY_TOKEN_FILE="$TOKEN_FILE" ZASP_PROJECTION_INIT_TIMEOUT=30s \
    ZASP_OPENSEARCH_ENDPOINT="$SEARCH_URL" ZASP_OPENSEARCH_INDEX=zasp-inventory-v1 "$BIN/agentsec-worker" || fail "search schema initialization refused"
}

migrate() { ZASP_POSTGRES_DSN="$(dsn "$OPERATOR")" "$BIN/agentsec-migrate" "$1" || fail "agentsec-migrate $1 refused"; }

cmd_up() {
  mkdir -p "$STATE"
  docker compose -f "$COMPOSE" up -d
  start_local_cloud
  write_identity_token
  start_database
  generate_keys
  build_binaries
  publish_model
  init_search
  provision_local_cloud
  STYTCH_PROJECT_ID="${STYTCH_PROJECT_ID:-project-unset}" STYTCH_SECRET="${STYTCH_SECRET:-secret-unset}" STYTCH_PUBLIC_TOKEN="${STYTCH_PUBLIC_TOKEN:-public-token-unset}" load_environment
  # verify-baseline succeeds only on an installed, intact baseline.
  if ! ZASP_POSTGRES_DSN="$(dsn "$OPERATOR")" "$BIN/agentsec-migrate" verify-baseline >/dev/null 2>&1; then
    migrate install-baseline
    migrate verify-baseline >/dev/null
  fi
  export ZASP_AUTHORIZATION_WORKER_KEY_FILE="$SECRETS/forward.seed" ZASP_AUTHORIZATION_COMPENSATION_KEY_FILE="$SECRETS/compensation.seed"
  for command in register-authorization-verifier register-worker-authorization-verifier register-compensation-authorization-verifier register-approval-maintenance-verifier; do
    migrate "$command"
  done
  echo "real-stack: schema installed; next: $0 bootstrap <organization name> <domain> <admin email>"
}

cmd_bootstrap() {
  [ "$#" -eq 3 ] || fail "usage: $0 bootstrap <organization name> <domain> <admin email>"
  require_provider
  load_environment
  local result reference organization
  result="$(ZASP_POSTGRES_DSN="$(dsn "$OPERATOR")" "$BIN/zasp-bootstrap" -organization-name "$1" -domain "$2" -admin-email "$3")" || fail "bootstrap refused (see the stage above)"
  reference="$(sed -E 's/.*"organization_reference":"([^"]+)".*/\1/' <<<"$result")"
  organization="$(sed -E 's/.*"organization_id":"([^"]+)".*/\1/' <<<"$result")"
  # Product-started sign-in is bound to one provider Organization. The first
  # bootstrapped Organization becomes that binding for this stack.
  # The binding is recorded only after both verifiers are registered, so a
  # failed registration is retried on the next run.
  if [ ! -f "$STATE/organization.env" ]; then
    export ZASP_STYTCH_ORGANIZATION_ID="$reference"
    migrate register-identity-session-verifier
    migrate register-identity-webhook-verifier
    printf 'ZASP_STYTCH_ORGANIZATION_ID=%s\n' "$reference" > "$STATE/organization.env"
  fi
  # One projector pass applies the new Organization's permissions.
  ZASP_POSTGRES_DSN="$(dsn zasp_svc_outbox)" "$BIN/zasp-authorization-reconcile" -mode reconcile -organization "$organization" -limit 1 -timeout 1m >/dev/null || fail "permission projection was not applied"
  echo "$result"
}

cmd_api() {
  require_provider
  load_environment
  [ -n "${ZASP_STYTCH_ORGANIZATION_ID:-}" ] || fail "run '$0 bootstrap' first"
  [ -s "$TOKEN_FILE" ] || fail "run '$0 up' first"
  # Reference authorization reads the customer role and its external ID. They
  # are gone after a LocalStack restart; one lookup decides whether to recreate.
  docker exec zasp-real-stack-localstack awslocal --region us-east-1 iam get-role --role-name "$CUSTOMER_ROLE_NAME" >/dev/null 2>&1 || provision_local_cloud
  export HOSTNAME=agentsec-api-real-stack
  export ZASP_PRODUCT_LISTEN_ADDRESS=127.0.0.1:4000 ZASP_INTERNAL_LISTEN_ADDRESS=127.0.0.1:4081
  export ZASP_TRUSTED_PROXY_CIDRS=127.0.0.0/8 ZASP_REQUEST_RATE_PER_SECOND=1000 ZASP_REQUEST_BURST=2000 ZASP_COOKIE_SECURE=true
  export ZASP_PROVIDER_TIMEOUT=10s ZASP_REQUEST_TIMEOUT=15s ZASP_SHUTDOWN_TIMEOUT=5s ZASP_READINESS_INTERVAL=1s ZASP_READINESS_MAX_INTERVAL=10s
  export ZASP_DISCOVERY_PARSER_VERSION=inventory-parser-2026.08.20 ZASP_DISCOVERY_TOOL_VERSION=collector-tool-2026.08.20
  export ZASP_POSTGRES_DSN="$(dsn zasp_svc_api)" ZASP_SECURITY_AGENT_POSTGRES_DSN="$(dsn zasp_svc_security_agent_api)"
  export ZASP_APPROVAL_MAINTENANCE_POSTGRES_DSN="$(dsn zasp_svc_approval_maintenance)"
  export ZASP_STYTCH_AUTHORIZE_URL="$ZASP_STYTCH_BASE_URL/v1/b2b/public/oauth/${ZASP_REAL_STACK_OAUTH_PROVIDER:-google}/start"
  export ZASP_CONNECTOR_AWS_REGION=us-east-1 ZASP_CONNECTOR_ROLE_ARN=arn:aws:iam::000000000000:role/zasp-real-stack-api-connectors
  export ZASP_CONNECTOR_WEB_IDENTITY_TOKEN_FILE=/var/run/secrets/eks.amazonaws.com/serviceaccount/token
  export ZASP_CONNECTOR_KMS_KEY_ARN=arn:aws:kms:us-east-1:000000000000:key/11111111-1111-1111-1111-111111111111
  export ZASP_CONNECTOR_SECRET_PREFIX=zasp-real-stack/connectors/oauth
  export ZASP_POLICY_HISTORY_ENDPOINT="$SEARCH_URL" ZASP_POLICY_HISTORY_INDEX=zasp-runtime-events-v1
  # The customer role the AWS integration may assume: the LocalStack role that
  # provision_local_cloud creates. The external ID it needs is the secret
  # zasp-real-stack/connectors/aws/external-id/<name> (the prefix above without
  # its /oauth suffix), referenced as ref:aws/external-id/<name>.
  export ZASP_AWS_CUSTOMER_ROLE_PREFIXES='["arn:aws:iam::000000000000:role/zasp-reference/"]'
  export ZASP_AWS_CUSTOMER_ROLE_ARNS="[\"$CUSTOMER_ROLE_ARN\"]"
  export ZASP_KUBERNETES_EGRESS_CIDRS=203.0.113.0/24 ZASP_FINDING_TICKET_EGRESS_CIDRS=192.0.2.64/28
  export ZASP_GITHUB_CLIENT_ID=Iv1.1234567890abcdef ZASP_GITHUB_CLIENT_SECRET_REFERENCE=ref:github/client-secret
  export ZASP_GITHUB_APP_ID=123456 ZASP_GITHUB_PRIVATE_KEY_REFERENCE=ref:github/app-private-key
  export ZASP_OKTA_CLIENT_ID=0oa1234567890abcdef ZASP_OKTA_CLIENT_SECRET_REFERENCE=ref:okta/client-secret
  exec "$BIN/agentsec-api"
}

# Creates the AWS resources the API and the workers address, in LocalStack.
# Idempotent, and repeated in full after a LocalStack restart (LocalStack keeps
# no state). The account is LocalStack's fixed 000000000000.
provision_local_cloud() {
  local aws="docker exec zasp-real-stack-localstack awslocal --region us-east-1"
  # The discovery queue must redrive to its dead-letter queue after five receives.
  $aws sqs create-queue --queue-name agentsec-discovery-jobs-dlq >/dev/null || fail "discovery dead-letter queue was not created"
  $aws sqs create-queue --queue-name agentsec-discovery-jobs >/dev/null || fail "discovery queue was not created"
  $aws sqs set-queue-attributes --queue-url http://sqs.us-east-1.localhost.localstack.cloud:4566/000000000000/agentsec-discovery-jobs \
    --attributes '{"RedrivePolicy":"{\"deadLetterTargetArn\":\"arn:aws:sqs:us-east-1:000000000000:agentsec-discovery-jobs-dlq\",\"maxReceiveCount\":\"5\"}"}' || fail "discovery queue redrive policy was not set"
  $aws s3api head-bucket --bucket zasp-real-stack-evidence >/dev/null 2>&1 || $aws s3api create-bucket --bucket zasp-real-stack-evidence >/dev/null || fail "evidence bucket was not created"
  # The recorded key is gone after a LocalStack restart; a new one replaces it.
  local key_arn=""
  [ ! -f "$STATE/cloud.env" ] || key_arn="$(sed -nE 's/^ZASP_EVIDENCE_KMS_KEY_ARN=//p' "$STATE/cloud.env")"
  if [ -z "$key_arn" ] || ! $aws kms describe-key --key-id "$key_arn" >/dev/null 2>&1; then
    local key
    key="$($aws kms create-key --description zasp-real-stack-evidence --query KeyMetadata.KeyId --output text)" || fail "evidence key was not created"
    [[ "$key" =~ ^[0-9a-f-]{36}$ ]] || fail "evidence key was not created"
    key_arn="arn:aws:kms:us-east-1:000000000000:key/$key"
    printf 'ZASP_EVIDENCE_KMS_KEY_ARN=%s\n' "$key_arn" > "$STATE/cloud.env"
  fi
  # The discovery worker's readiness probe requires a versioned evidence
  # bucket whose default encryption is this customer-managed key.
  $aws s3api put-bucket-versioning --bucket zasp-real-stack-evidence --versioning-configuration Status=Enabled || fail "evidence bucket versioning was not set"
  $aws s3api put-bucket-encryption --bucket zasp-real-stack-evidence --server-side-encryption-configuration \
    "{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\",\"KMSMasterKeyID\":\"$key_arn\"},\"BucketKeyEnabled\":true}]}" || fail "evidence bucket encryption was not set"
  # Provider credentials the worker must be able to resolve. These values are
  # placeholders: no GitHub App or Okta application stands behind them.
  local name
  for name in zasp-real-stack/discovery/github/app-private-key zasp-real-stack/discovery/okta/client-secret; do
    $aws secretsmanager describe-secret --secret-id "$name" >/dev/null 2>&1 ||
      $aws secretsmanager create-secret --name "$name" --secret-string "real-stack-placeholder-not-a-credential" >/dev/null || fail "placeholder secret $name was not created"
  done
  provision_customer_account
}

# Creates one IAM role unless it exists. Arguments: path, name, trust policy.
ensure_role() {
  $aws iam get-role --role-name "$2" >/dev/null 2>&1 ||
    $aws iam create-role --path "$1" --role-name "$2" --assume-role-policy-document "$3" >/dev/null || fail "role $2 was not created"
}

# Creates one customer-managed policy unless it exists and attaches it to a
# role. Arguments: policy name, policy document, role name.
ensure_attached_policy() {
  local arn="arn:aws:iam::000000000000:policy/$1"
  $aws iam get-policy --policy-arn "$arn" >/dev/null 2>&1 ||
    $aws iam create-policy --policy-name "$1" --policy-document "$2" >/dev/null || fail "policy $1 was not created"
  $aws iam attach-role-policy --role-name "$3" --policy-arn "$arn" || fail "policy $1 was not attached to $3"
}

# The emulated customer side of an AWS integration: the read-only role the
# product assumes with an external ID, that external ID as the secret both the
# API and the discovery worker resolve from ref:aws/external-id/<name>, and a
# small fixture for a discovery run to find. LocalStack does not enforce IAM,
# so the trust and permission policies document intent; they are not tested.
provision_customer_account() {
  local aws="docker exec zasp-real-stack-localstack awslocal --region us-east-1"
  if [ ! -f "$SECRETS/aws-external-id" ]; then
    (umask 077; openssl rand -hex 24 > "$SECRETS/aws-external-id.partial" && mv "$SECRETS/aws-external-id.partial" "$SECRETS/aws-external-id") || fail "external ID was not generated"
  fi
  local external_id name
  external_id="$(tr -d '\n' < "$SECRETS/aws-external-id")"
  [ "${#external_id}" -eq 48 ] || fail "external ID is malformed"
  # The API reads below its connector prefix, the worker below its own.
  for name in "zasp-real-stack/connectors/aws/external-id/$CUSTOMER_EXTERNAL_ID_NAME" "zasp-real-stack/discovery/aws/external-id/$CUSTOMER_EXTERNAL_ID_NAME"; do
    if $aws secretsmanager describe-secret --secret-id "$name" >/dev/null 2>&1; then
      $aws secretsmanager put-secret-value --secret-id "$name" --secret-string "$external_id" >/dev/null || fail "external ID secret $name was not updated"
    else
      $aws secretsmanager create-secret --name "$name" --secret-string "$external_id" >/dev/null || fail "external ID secret $name was not created"
    fi
  done
  ensure_role "$CUSTOMER_ROLE_PATH" "$CUSTOMER_ROLE_NAME" "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":[\"arn:aws:iam::000000000000:role/zasp-real-stack-api-connectors\",\"arn:aws:iam::000000000000:role/zasp-real-stack-discovery\"]},\"Action\":\"sts:AssumeRole\",\"Condition\":{\"StringEquals\":{\"sts:ExternalId\":\"$external_id\"}}}]}"
  ensure_attached_policy zasp-customer-read-inventory '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:ListRoles","iam:ListAttachedRolePolicies","iam:GetPolicy","iam:GetPolicyVersion","ec2:DescribeRegions","ec2:DescribeInstances"],"Resource":"*"}]}' "$CUSTOMER_ROLE_NAME"

  # Fixture: three roles an agent workload would run under, with the policies
  # that give them model, tool and data access, one role trusting another, one
  # role with administrator access, and one instance that still allows IMDSv1.
  ensure_role /agents/ agent-orchestrator '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"bedrock.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
  ensure_role /agents/ support-copilot-runtime '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
  ensure_role /agents/ claims-triage-agent '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"},{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:role/agents/agent-orchestrator"},"Action":"sts:AssumeRole"}]}'
  ensure_attached_policy agent-orchestrator-delegate '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::000000000000:role/agents/claims-triage-agent"},{"Effect":"Allow","Action":["bedrock:InvokeAgent","bedrock:InvokeModel"],"Resource":"*"}]}' agent-orchestrator
  # The AWS-managed AdministratorAccess policy: the posture analyzer reports it.
  $aws iam attach-role-policy --role-name agent-orchestrator --policy-arn arn:aws:iam::aws:policy/AdministratorAccess || fail "AdministratorAccess was not attached to agent-orchestrator"
  ensure_attached_policy support-copilot-model-invoke '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["bedrock:InvokeModel","bedrock:InvokeModelWithResponseStream"],"Resource":"arn:aws:bedrock:us-east-1::foundation-model/*"}]}' support-copilot-runtime
  ensure_attached_policy support-copilot-knowledge-read '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::support-knowledge-base","arn:aws:s3:::support-knowledge-base/*"]}]}' support-copilot-runtime
  ensure_attached_policy claims-triage-tools '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["dynamodb:GetItem","dynamodb:Query","sqs:SendMessage","secretsmanager:GetSecretValue"],"Resource":"*"}]}' claims-triage-agent
  if [ "$($aws ec2 describe-instances --filters Name=tag:zasp-fixture,Values=agent-host Name=instance-state-name,Values=pending,running --query 'length(Reservations)' --output text)" = "0" ]; then
    local image
    image="$($aws ec2 describe-images --query 'Images[0].ImageId' --output text)" || fail "fixture image was not found"
    $aws ec2 run-instances --image-id "$image" --instance-type t3.micro --count 1 --metadata-options HttpTokens=optional,HttpEndpoint=enabled \
      --tag-specifications 'ResourceType=instance,Tags=[{Key=zasp-fixture,Value=agent-host},{Key=Name,Value=support-copilot-host}]' >/dev/null || fail "fixture instance was not created"
  fi
}

# Starts one worker mode in the foreground. Only modes whose dependencies this
# stack provides are listed; the others need queues, keys or endpoints it does
# not create yet.
cmd_worker() {
  [ "$#" -eq 1 ] || fail "usage: $0 worker {scheduler|outbox|discovery}"
  load_environment
  export ZASP_WORKER_MODE="$1" ZASP_WORKER_ID="real-stack-$1" ZASP_AWS_REGION=us-east-1
  export ZASP_POLL_INTERVAL=1s ZASP_LEASE_DURATION=30s ZASP_SHUTDOWN_TIMEOUT=5s ZASP_BATCH_SIZE=10 ZASP_PROVIDER_TIMEOUT=10s
  export ZASP_DISCOVERY_PARSER_VERSION=inventory-parser-2026.08.20 ZASP_DISCOVERY_TOOL_VERSION=collector-tool-2026.08.20
  case "$1" in
    scheduler) export ZASP_POSTGRES_DSN="$(dsn zasp_svc_scheduler)" ZASP_DATABASE_AUTHORITY=zasp_discovery_scheduler ;;
    outbox)
      # Publishes queued discovery jobs (for example a sync a user requested)
      # to the discovery queue. Each mode gets its own health port so the
      # three can run together; the worker honours this only in development
      # mode (see README.md).
      provision_local_cloud
      export ZASP_LOCAL_HEALTH_PORT=8083
      export ZASP_POSTGRES_DSN="$(dsn zasp_svc_outbox)" ZASP_DATABASE_AUTHORITY=zasp_outbox_worker
      export ZASP_DISCOVERY_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/000000000000/agentsec-discovery-jobs
      export ZASP_OUTBOX_ROLE_ARN=arn:aws:iam::000000000000:role/zasp-real-stack-outbox ZASP_OUTBOX_WEB_IDENTITY_TOKEN_FILE="$TOKEN_FILE"
      ;;
    discovery)
      provision_local_cloud
      [ -x /opt/zasp/security/cartography/bin/security-worker ] && [ -x /opt/zasp/security/prowler/bin/security-worker ] ||
        echo "real-stack: the AWS collector needs the security analyzers; run '$0 security-workers' (an AWS discovery run fails without them)" >&2
      export ZASP_LOCAL_HEALTH_PORT=8082
      set -a; . "$STATE/cloud.env"; set +a
      export ZASP_POSTGRES_DSN="$(dsn zasp_svc_discovery)" ZASP_DATABASE_AUTHORITY=zasp_discovery_worker
      export ZASP_TEMPORAL_EXECUTOR_POSTGRES_DSN="$(dsn zasp_svc_temporal_executor)" ZASP_TEMPORAL_COMPENSATION_POSTGRES_DSN="$(dsn zasp_svc_temporal_compensation)"
      export ZASP_AUTHORIZATION_WORKER_KEY_FILE="$SECRETS/forward.seed" ZASP_AUTHORIZATION_COMPENSATION_KEY_FILE="$SECRETS/compensation.seed"
      export ZASP_DISCOVERY_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/000000000000/agentsec-discovery-jobs
      export ZASP_DISCOVERY_ROLE_ARN=arn:aws:iam::000000000000:role/zasp-real-stack-discovery
      export ZASP_DISCOVERY_WEB_IDENTITY_TOKEN_FILE="$TOKEN_FILE" ZASP_DISCOVERY_SECRET_PREFIX=zasp-real-stack/discovery
      export ZASP_EVIDENCE_BUCKET=zasp-real-stack-evidence ZASP_EVIDENCE_BUCKET_OWNER=000000000000
      export ZASP_DISCOVERY_AWS_COLLECTOR_VERSION=aws-collector-2026.08.20 ZASP_DISCOVERY_KUBERNETES_COLLECTOR_VERSION=kubernetes-collector-2026.08.20
      export ZASP_DISCOVERY_GITHUB_COLLECTOR_VERSION=github-collector-2026.08.20 ZASP_DISCOVERY_OKTA_COLLECTOR_VERSION=okta-collector-2026.08.20
      export ZASP_KUBERNETES_EGRESS_CIDRS=203.0.113.0/24 ZASP_DISCOVERY_READINESS_TIMEOUT=5s
      export ZASP_GITHUB_APP_ID=123456 ZASP_GITHUB_PRIVATE_KEY_REFERENCE=ref:github/app-private-key
      export ZASP_OKTA_CLIENT_ID=0oa1234567890abcdef ZASP_OKTA_CLIENT_SECRET_REFERENCE=ref:okta/client-secret
      ;;
    *) fail "worker mode '$1' is not available on this stack yet" ;;
  esac
  exec "$BIN/agentsec-worker"
}

# Installs the two Python analyzers the AWS collector runs as subprocesses,
# at the fixed paths the worker executes, from the same hash-pinned lock files
# the worker image is built from (deploy/production/worker.Dockerfile).
cmd_security_workers() {
  local source="$ROOT/workers/security-python" root=/opt/zasp/security python="${ZASP_REAL_STACK_PYTHON:-python3.13}" name
  command -v "$python" >/dev/null || fail "Python 3.13 is required (set ZASP_REAL_STACK_PYTHON)"
  "$python" -c 'import sys; sys.exit(sys.version_info[:2] != (3, 13))' || fail "Python 3.13 is required (set ZASP_REAL_STACK_PYTHON)"
  mkdir -p "$root" 2>/dev/null || fail "create $root (needs root) and make it writable by this user"
  for name in cartography prowler; do
    # The pinned third-party packages are installed once (about 2 GB each).
    # The analyzer itself is reinstalled every time, so it follows the source.
    if ! { [ -x "$root/$name/bin/security-worker" ] && "$root/$name/bin/security-worker" health >/dev/null 2>&1; }; then
      rm -rf "${root:?}/$name"
      "$python" -m venv "$root/$name" || fail "$name environment was not created"
      PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 "$root/$name/bin/pip" install -q --require-hashes --no-deps -r "$source/build-requirements.lock" || fail "$name build requirements were not installed"
      PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 "$root/$name/bin/pip" install -q --require-hashes --no-build-isolation --no-deps -r "$source/$name/requirements.lock" || fail "$name requirements were not installed"
    fi
    # pip builds in the directory it is given; a copy keeps the repository clean.
    local staged
    staged="$(mktemp -d)" || fail "$name analyzer was not staged"
    cp -R "$source/pyproject.toml" "$source/security_worker" "$staged/" || fail "$name analyzer was not staged"
    PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 "$root/$name/bin/pip" install -q --force-reinstall --no-build-isolation --no-deps "$staged" || { rm -rf "$staged"; fail "$name analyzer was not installed"; }
    rm -rf "$staged"
    "$root/$name/bin/security-worker" health >/dev/null || fail "$name analyzer is not healthy"
  done
  echo "real-stack: security analyzers installed in $root"
}

cmd_down() {
  docker stop "$PG_CONTAINER" zasp-real-stack-localstack zasp-real-stack-opensearch >/dev/null 2>&1 || true
  docker compose -f "$COMPOSE" stop
  echo "real-stack: stopped; data is kept. Remove '$PG_CONTAINER' and '$STATE' to start over."
}

case "${1:-}" in
  up) shift; cmd_up "$@" ;;
  bootstrap) shift; cmd_bootstrap "$@" ;;
  api) shift; cmd_api "$@" ;;
  worker) shift; cmd_worker "$@" ;;
  security-workers) shift; cmd_security_workers "$@" ;;
  down) shift; cmd_down "$@" ;;
  *) fail "usage: $0 {up|bootstrap <organization name> <domain> <admin email>|api|worker <mode>|security-workers|down}" ;;
esac
