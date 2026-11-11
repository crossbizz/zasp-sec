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
PG_CONTAINER="zasp-real-stack-db"
PG_PORT="${ZASP_REAL_STACK_PG_PORT:-55432}"
FGA_URL="http://127.0.0.1:8088"
FGA_TOKEN="${ZASP_LOCAL_OPENFGA_TOKEN:-local-openfga-smoke-only}"
# The public origin must be HTTPS and must not be localhost or an IP address:
# the connector OAuth callbacks refuse those hosts.
PUBLIC_ORIGIN="${ZASP_REAL_STACK_ORIGIN:-https://zasp.local-stack.test:8443}"
OPERATOR="zasp_local"

fail() { echo "real-stack: $*" >&2; exit 1; }
dsn() { echo "postgres://$1@127.0.0.1:$PG_PORT/postgres?sslmode=disable"; }

ROLES=(
  ZASP_DISCOVERY_API_DB_PRINCIPAL=zasp_local_api
  ZASP_DISCOVERY_WORKER_DB_PRINCIPAL=zasp_local_discovery
  ZASP_RUNTIME_INGEST_DB_PRINCIPAL=zasp_local_ingest
  ZASP_RUNTIME_WORKER_DB_PRINCIPAL=zasp_local_runtime
  ZASP_OUTBOX_WORKER_DB_PRINCIPAL=zasp_local_outbox
  ZASP_RUNTIME_GATEWAY_DB_PRINCIPAL=zasp_local_gateway
  ZASP_DISCOVERY_SCHEDULER_DB_PRINCIPAL=zasp_local_scheduler
  ZASP_PROJECTION_RISK_DB_PRINCIPAL=zasp_local_projection_risk
  ZASP_PROJECTION_GRAPH_DB_PRINCIPAL=zasp_local_projection_graph
  ZASP_PROJECTION_SEARCH_DB_PRINCIPAL=zasp_local_projection_search
  ZASP_RUNTIME_COORDINATOR_DB_PRINCIPAL=zasp_local_coordinator
  ZASP_RUNTIME_ARCHIVE_DB_PRINCIPAL=zasp_local_archive
  ZASP_RUNTIME_INDEX_DB_PRINCIPAL=zasp_local_index
  ZASP_RUNTIME_CORRELATION_DB_PRINCIPAL=zasp_local_correlation
  ZASP_RUNTIME_PROJECTION_DB_PRINCIPAL=zasp_local_runtime_projection
  ZASP_GATEWAY_CONTROL_DB_PRINCIPAL=zasp_local_gateway_control
  ZASP_SECURITY_AGENT_API_DB_PRINCIPAL=zasp_local_security_agent_api
  ZASP_SECURITY_AGENT_WORKER_DB_PRINCIPAL=zasp_local_security_agent_worker
  ZASP_SECURITY_AGENT_ACTION_DB_PRINCIPAL=zasp_local_security_agent_action
  ZASP_POLICY_DEPLOYMENT_DB_PRINCIPAL=zasp_local_policy_deployment
  ZASP_RED_TEAM_WORKER_DB_PRINCIPAL=zasp_local_red_team_worker
  ZASP_RED_TEAM_OUTBOX_DB_PRINCIPAL=zasp_local_red_team_outbox
  ZASP_RED_TEAM_ADAPTER_DB_PRINCIPAL=zasp_local_red_team_adapter
  ZASP_ATTACK_LAB_CONTROLLER_DB_PRINCIPAL=zasp_local_attack_lab_controller
  ZASP_ATTACK_LAB_OUTBOX_DB_PRINCIPAL=zasp_local_attack_lab_outbox
  ZASP_ATTACK_LAB_PROXY_DB_PRINCIPAL=zasp_local_attack_lab_proxy
  ZASP_RECOVERY_WORKER_DB_PRINCIPAL=zasp_local_recovery
  ZASP_RECOVERY_OUTBOX_DB_PRINCIPAL=zasp_local_recovery_outbox
  ZASP_TEMPORAL_EXECUTOR_DB_PRINCIPAL=zasp_local_temporal_executor
  ZASP_TEMPORAL_COMPENSATION_DB_PRINCIPAL=zasp_local_temporal_compensation
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
  export ZASP_TEMPORAL_ADDRESS=127.0.0.1:7233 ZASP_TEMPORAL_NAMESPACE=zasp-dev
  export ZASP_TEMPORAL_TASK_QUEUE=zasp-security-agent ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE=zasp-discovery
  export ZASP_OPENFGA_URL="$FGA_URL" ZASP_OPENFGA_TOKEN_FILE="$SECRETS/openfga.token"
}

build_binaries() {
  mkdir -p "$BIN"
  go build -C "$ROOT/services/platform" -o "$BIN/" ./agentsec-api ./agentsec-migrate ./cmd/zasp-bootstrap ./cmd/zasp-authorization-reconcile
}

start_database() {
  if docker inspect "$PG_CONTAINER" >/dev/null 2>&1; then
    docker start "$PG_CONTAINER" >/dev/null
  else
    # The schema fingerprints are computed with the database's default
    # collation, so the database must use C (or C.UTF-8) collation. Any other
    # locale makes the migration refuse at release 13 with no SQL error.
    docker run -d --name "$PG_CONTAINER" -e POSTGRES_USER="$OPERATOR" -e POSTGRES_DB=postgres \
      -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_INITDB_ARGS="--no-locale --encoding=UTF8" \
      -p "127.0.0.1:$PG_PORT:5432" "$PG_IMAGE" -c max_connections=300 >/dev/null
  fi
  for _ in $(seq 1 120); do
    if psql -X -Atc 'select 1' "$(dsn "$OPERATOR")" >/dev/null 2>&1; then break; fi
    sleep 0.5
  done
  psql -X -Atc 'select 1' "$(dsn "$OPERATOR")" >/dev/null || fail "product database did not start"
  [ "$(psql -X -Atc "select datcollate from pg_database where datname=current_database()" "$(dsn "$OPERATOR")")" = "C" ] || fail "product database collation is not C"
  for assignment in "${ROLES[@]}"; do
    role="${assignment#*=}"
    psql -X -q -v ON_ERROR_STOP=1 "$(dsn "$OPERATOR")" -c "DO \$\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='$role') THEN CREATE ROLE $role LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; END IF; END \$\$"
  done
}

generate_keys() {
  mkdir -p "$SECRETS"
  chmod 700 "$STATE" "$SECRETS"
  if [ ! -f "$SECRETS/keys.env" ]; then
    (
      umask 077
      {
        echo "ZASP_WORKFLOW_SIGNING_KEY=$(openssl rand -hex 32)"
        echo "ZASP_TOKEN_REVEAL_KEY=$(openssl rand 32 | basenc --base64url | tr -d '=\n')"
        echo "ZASP_STYTCH_WEBHOOK_SECRET=whsec_$(openssl rand -base64 32 | tr -d '\n')"
      } > "$SECRETS/keys.env"
      openssl rand 64 > "$SECRETS/forward.seed"
      openssl rand 64 > "$SECRETS/compensation.seed"
      printf '%s' "$FGA_TOKEN" > "$SECRETS/openfga.token"
      chmod 0400 "$SECRETS/forward.seed" "$SECRETS/compensation.seed" "$SECRETS/openfga.token"
    )
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

migrate() { ZASP_POSTGRES_DSN="$(dsn "$OPERATOR")" "$BIN/agentsec-migrate" "$1" || fail "agentsec-migrate $1 refused"; }

cmd_up() {
  mkdir -p "$STATE"
  docker compose -f "$COMPOSE" up -d
  start_database
  generate_keys
  build_binaries
  publish_model
  STYTCH_PROJECT_ID="${STYTCH_PROJECT_ID:-project-unset}" STYTCH_SECRET="${STYTCH_SECRET:-secret-unset}" STYTCH_PUBLIC_TOKEN="${STYTCH_PUBLIC_TOKEN:-public-token-unset}" load_environment
  if [ "$(psql -X -Atc "select to_regnamespace('zasp_authorization80_worker') is not null" "$(dsn "$OPERATOR")")" != "t" ]; then
    migrate up-authorization-runtime-profile
  fi
  export ZASP_AUTHORIZATION_WORKER_KEY_FILE="$SECRETS/forward.seed" ZASP_AUTHORIZATION_COMPENSATION_KEY_FILE="$SECRETS/compensation.seed"
  for command in register-temporal-executor-principals register-authorization-verifier register-worker-authorization-verifier register-compensation-authorization-verifier; do
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
  if [ ! -f "$STATE/organization.env" ]; then
    printf 'ZASP_STYTCH_ORGANIZATION_ID=%s\n' "$reference" > "$STATE/organization.env"
    export ZASP_STYTCH_ORGANIZATION_ID="$reference"
    migrate register-identity-session-verifier
    migrate register-identity-webhook-verifier
  fi
  # One projector pass applies the new Organization's permissions.
  ZASP_POSTGRES_DSN="$(dsn zasp_local_outbox)" "$BIN/zasp-authorization-reconcile" -mode reconcile -organization "$organization" -limit 1 -timeout 1m >/dev/null || fail "permission projection was not applied"
  echo "$result"
}

cmd_api() {
  require_provider
  load_environment
  [ -n "${ZASP_STYTCH_ORGANIZATION_ID:-}" ] || fail "run '$0 bootstrap' first"
  # The connector credential path is fixed by the API. This stack has no AWS
  # account, so connector, policy-history and export readiness stay unavailable.
  [ -f /var/run/secrets/eks.amazonaws.com/serviceaccount/token ] || fail "create /var/run/secrets/eks.amazonaws.com/serviceaccount/token (any non-empty file) first"
  export HOSTNAME=agentsec-api-real-stack
  export ZASP_PRODUCT_LISTEN_ADDRESS=127.0.0.1:4000 ZASP_INTERNAL_LISTEN_ADDRESS=127.0.0.1:4081
  export ZASP_TRUSTED_PROXY_CIDRS=127.0.0.0/8 ZASP_REQUEST_RATE_PER_SECOND=1000 ZASP_REQUEST_BURST=2000 ZASP_COOKIE_SECURE=true
  export ZASP_PROVIDER_TIMEOUT=10s ZASP_REQUEST_TIMEOUT=15s ZASP_SHUTDOWN_TIMEOUT=5s ZASP_READINESS_INTERVAL=1s ZASP_READINESS_MAX_INTERVAL=10s
  export ZASP_DISCOVERY_PARSER_VERSION=inventory-parser-2026.08.20 ZASP_DISCOVERY_TOOL_VERSION=collector-tool-2026.08.20
  export ZASP_POSTGRES_DSN="$(dsn zasp_local_api)" ZASP_SECURITY_AGENT_POSTGRES_DSN="$(dsn zasp_local_security_agent_api)"
  export ZASP_STYTCH_AUTHORIZE_URL="$ZASP_STYTCH_BASE_URL/v1/b2b/public/oauth/${ZASP_REAL_STACK_OAUTH_PROVIDER:-google}/start"
  export ZASP_CONNECTOR_AWS_REGION=us-east-1 ZASP_CONNECTOR_ROLE_ARN=arn:aws:iam::000000000000:role/zasp-real-stack-api-connectors
  export ZASP_CONNECTOR_WEB_IDENTITY_TOKEN_FILE=/var/run/secrets/eks.amazonaws.com/serviceaccount/token
  export ZASP_CONNECTOR_KMS_KEY_ARN=arn:aws:kms:us-east-1:000000000000:key/11111111-1111-1111-1111-111111111111
  export ZASP_CONNECTOR_SECRET_PREFIX=zasp-real-stack/connectors/oauth
  export ZASP_POLICY_HISTORY_ENDPOINT=http://127.0.0.1:4092 ZASP_POLICY_HISTORY_INDEX=zasp-runtime-events-v1
  export ZASP_AWS_CUSTOMER_ROLE_PREFIXES='["arn:aws:iam::123456789012:role/zasp-reference/"]'
  export ZASP_AWS_CUSTOMER_ROLE_ARNS='["arn:aws:iam::123456789012:role/zasp-reference/real-stack"]'
  export ZASP_KUBERNETES_EGRESS_CIDRS=203.0.113.0/24 ZASP_FINDING_TICKET_EGRESS_CIDRS=192.0.2.64/28
  export ZASP_GITHUB_CLIENT_ID=Iv1.1234567890abcdef ZASP_GITHUB_CLIENT_SECRET_REFERENCE=ref:github/client-secret
  export ZASP_GITHUB_APP_ID=123456 ZASP_GITHUB_PRIVATE_KEY_REFERENCE=ref:github/app-private-key
  export ZASP_OKTA_CLIENT_ID=0oa1234567890abcdef ZASP_OKTA_CLIENT_SECRET_REFERENCE=ref:okta/client-secret
  exec "$BIN/agentsec-api"
}

cmd_down() {
  docker stop "$PG_CONTAINER" >/dev/null 2>&1 || true
  docker compose -f "$COMPOSE" stop
  echo "real-stack: stopped; data is kept. Remove '$PG_CONTAINER' and '$STATE' to start over."
}

case "${1:-}" in
  up) shift; cmd_up "$@" ;;
  bootstrap) shift; cmd_bootstrap "$@" ;;
  api) shift; cmd_api "$@" ;;
  down) shift; cmd_down "$@" ;;
  *) fail "usage: $0 {up|bootstrap <organization name> <domain> <admin email>|api|down}" ;;
esac
