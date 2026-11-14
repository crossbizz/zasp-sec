#!/bin/sh
# Starts one process of the Zasp evaluation pod. Every container of the pod
# runs this script with the name of its process.
#
# It is the in-cluster counterpart of deploy/local/real-stack/stack.sh: the
# same programs, the same settings and the same order, with every dependency
# reached on the pod's loopback interface. Keep the two in step.
#
# POSIX sh: it runs in the API image (Alpine), the worker image (Debian) and
# the LocalStack, PostgreSQL and Neo4j images.
set -eu

STATE=/var/lib/zasp          # persistent: fga.env, organization.env
RUN=/run/zasp                # per pod start: copied secrets, cloud.env
SECRETS="$RUN/secrets"
MOUNTED=/zasp/secret         # the Kubernetes Secret, read only by 'prepare'
CONFIG=/zasp/config
TOKEN_FILE=/var/run/secrets/eks.amazonaws.com/serviceaccount/token
LOCAL_CLOUD=http://127.0.0.1:4566
SEARCH_URL=http://127.0.0.1:9200
FGA_URL=http://127.0.0.1:8088
NEO4J_URI=neo4j+s://localhost:7687
NEO4J_WORKER_USER=zasp_graph_worker
NEO4J_WORKER_ROLE=zasp_graph_writer
PROJECTION_SECRET_PREFIX=zasp-real-stack/projection
OPERATOR=zasp_operator

fail() { echo "zasp: $*" >&2; exit 1; }

# The DSN of a database login. The in-pod PostgreSQL listens on loopback only
# and trusts loopback connections, as the local stack's does. An external
# PostgreSQL takes the operator DSN and one password shared by the service
# logins from the Secret.
dsn() {
  if [ "${ZASP_DATABASE_MODE:-pod}" = external ]; then
    if [ "$1" = "$OPERATOR" ]; then
      cat "$SECRETS/operator-dsn"
    else
      printf 'postgres://%s:%s@%s/zasp?sslmode=require' "$1" "$(cat "$SECRETS/service-password")" "$ZASP_DATABASE_HOST"
    fi
  else
    printf 'postgres://%s@127.0.0.1:5432/zasp?sslmode=disable' "$1"
  fi
}

# Settings shared by the operator commands, the API and the workers.
# shellcheck disable=SC2034
load_environment() {
  set -a
  ZASP_WORKFLOW_SIGNING_KEY="$(cat "$SECRETS/workflow-signing-key")"
  ZASP_TOKEN_REVEAL_KEY="$(cat "$SECRETS/token-reveal-key")"
  ZASP_STYTCH_WEBHOOK_SECRET="$(cat "$SECRETS/stytch-webhook-secret")"
  ZASP_STYTCH_PROJECT_ID="$(cat "$SECRETS/stytch-project-id")"
  ZASP_STYTCH_SECRET="$(cat "$SECRETS/stytch-secret")"
  ZASP_STYTCH_PUBLIC_TOKEN="$(cat "$SECRETS/stytch-public-token")"
  # shellcheck disable=SC1091
  [ ! -f "$STATE/fga.env" ] || . "$STATE/fga.env"
  # shellcheck disable=SC1091
  [ ! -f "$STATE/organization.env" ] || . "$STATE/organization.env"
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
  ZASP_MIGRATION_DB_PRINCIPAL="$OPERATOR"
  ZASP_MIGRATION_TIMEOUT=20m
  ZASP_DEPLOYMENT_MODE=saas
  ZASP_ORGANIZATION_ID=
  ZASP_RUNTIME_SERVICES_ENABLED=true
  # Development mode: required for the in-pod AWS emulator. See values.yaml.
  ZASP_ENVIRONMENT="test"
  ZASP_RUNTIME_SERVICES_TIMEOUT=10s
  ZASP_LOCAL_CLOUD_ENDPOINT="$LOCAL_CLOUD"
  ZASP_TEMPORAL_ADDRESS=127.0.0.1:7233
  ZASP_TEMPORAL_NAMESPACE=zasp-dev
  ZASP_TEMPORAL_TASK_QUEUE=zasp-security-agent
  ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE=zasp-discovery
  ZASP_OPENFGA_URL="$FGA_URL"
  ZASP_OPENFGA_TOKEN_FILE="$SECRETS/openfga-token"
  # Written by the 'schema' step from the API image's agentsec-migrate.
  [ ! -f "$RUN/approval.checksum" ] || ZASP_APPROVAL_MAINTENANCE_PROFILE_CHECKSUM="$(cat "$RUN/approval.checksum")"
  ZASP_APPROVAL_MAINTENANCE_KEY_FILE="$SECRETS/approval-delivery.key"
  set +a
}

# Copies one key of the Secret to a file only this user can read. The
# programs refuse key files that other users can read.
copy_secret() {
  [ -f "$MOUNTED/$1" ] || fail "the Secret has no key '$1' (see values.yaml, section secrets)"
  cp "$MOUNTED/$1" "$SECRETS/$1.partial"
  chmod "${2:-0400}" "$SECRETS/$1.partial"
  mv -f "$SECRETS/$1.partial" "$SECRETS/$1"
}

# Runs first, as the product user: lays out the secrets and the fixed paths
# the Security Agent workers read.
cmd_prepare() {
  mkdir -p "$SECRETS"
  chmod 700 "$SECRETS"
  rm -f "$SECRETS"/*
  for name in workflow-signing-key token-reveal-key stytch-webhook-secret stytch-project-id stytch-secret stytch-public-token \
    forward.seed compensation.seed approval-delivery.key openfga-token gateway-signing.key gateway-policy-keys.json \
    red-team-adapter.token red-team-adapter-ca.pem; do
    copy_secret "$name"
  done
  if [ "${ZASP_DATABASE_MODE:-pod}" = external ]; then
    copy_secret operator-dsn
    copy_secret service-password
  fi
  rm -f /var/run/secrets/zasp-security-agent-action/gateway-signing-private-key /var/run/zasp-policy-verifier/policy-keys.json \
    /var/run/secrets/zasp-security-agent/openrouter-api-token
  cp "$SECRETS/gateway-signing.key" /var/run/secrets/zasp-security-agent-action/gateway-signing-private-key
  chmod 0400 /var/run/secrets/zasp-security-agent-action/gateway-signing-private-key
  cp "$SECRETS/gateway-policy-keys.json" /var/run/zasp-policy-verifier/policy-keys.json
  chmod 0400 /var/run/zasp-policy-verifier/policy-keys.json
  if [ -s "$MOUNTED/planner-api-key" ]; then
    # The worker requires the mode a Kubernetes secret mount has.
    cp "$MOUNTED/planner-api-key" /var/run/secrets/zasp-security-agent/openrouter-api-token
    chmod 0444 /var/run/secrets/zasp-security-agent/openrouter-api-token
  fi
  [ -s "$TOKEN_FILE" ] || fail "the workload identity token is not mounted at $TOKEN_FILE"
}

migrate() { ZASP_POSTGRES_DSN="$(dsn "$OPERATOR")" /app/agentsec-migrate "$1" || fail "agentsec-migrate $1 refused"; }

# Installs or verifies the schema, registers the verification keys, and
# creates the first organization when one is configured and none exists.
cmd_schema() {
  /app/agentsec-migrate approval-maintenance-checksum > "$RUN/approval.checksum" || fail "agentsec-migrate is not in this image (it must be the API image)"
  load_environment
  if ! ZASP_POSTGRES_DSN="$(dsn "$OPERATOR")" /app/agentsec-migrate verify-baseline >/dev/null 2>&1; then
    migrate install-baseline
    migrate verify-baseline >/dev/null
  fi
  export ZASP_AUTHORIZATION_WORKER_KEY_FILE="$SECRETS/forward.seed" ZASP_AUTHORIZATION_COMPENSATION_KEY_FILE="$SECRETS/compensation.seed"
  for command in register-authorization-verifier register-worker-authorization-verifier register-compensation-authorization-verifier register-approval-maintenance-verifier; do
    migrate "$command"
  done
  if [ ! -f "$STATE/organization.env" ] && [ -n "${ZASP_BOOTSTRAP_ORGANIZATION_NAME:-}" ]; then
    cmd_bootstrap "$ZASP_BOOTSTRAP_ORGANIZATION_NAME" "$ZASP_BOOTSTRAP_ORGANIZATION_DOMAIN" "$ZASP_BOOTSTRAP_ADMIN_EMAIL" >/dev/null
  fi
  if [ ! -f "$STATE/organization.env" ]; then
    echo "zasp: no organization yet. The API waits for one: set bootstrap.* in the values, or run './zasp bootstrap-admin'." >&2
  fi
}

# Creates or resolves the first organization and its administrator, then binds
# this deployment's sign-in to it. Idempotent. Runs in the API image.
cmd_bootstrap() {
  [ "$#" -eq 3 ] || fail "usage: entrypoint.sh bootstrap <organization name> <domain> <admin email>"
  load_environment
  result="$(ZASP_POSTGRES_DSN="$(dsn "$OPERATOR")" /app/zasp-bootstrap -organization-name "$1" -domain "$2" -admin-email "$3")" || fail "bootstrap refused (see the stage above)"
  reference="$(printf '%s' "$result" | sed -E 's/.*"organization_reference":"([^"]+)".*/\1/')"
  case "$reference" in
    organization-*) ;;
    *) fail "bootstrap returned no organization reference" ;;
  esac
  if [ ! -f "$STATE/organization.env" ]; then
    export ZASP_STYTCH_ORGANIZATION_ID="$reference"
    migrate register-identity-session-verifier
    migrate register-identity-webhook-verifier
    printf 'ZASP_STYTCH_ORGANIZATION_ID=%s\n' "$reference" > "$STATE/organization.env.partial"
    mv -f "$STATE/organization.env.partial" "$STATE/organization.env"
  fi
  echo "$result"
}

# Creates the authorization store and publishes the product's model, once.
# Runs in the LocalStack image, which has curl.
cmd_fga_model() {
  [ ! -f "$STATE/fga.env" ] || return 0
  token="$(cat "$MOUNTED/openfga-token")"
  store="$(curl -fsS -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -d '{"name":"zasp"}' "$FGA_URL/stores" | sed -E 's/.*"id":"([^"]+)".*/\1/')"
  model="$(curl -fsS -H "Authorization: Bearer $token" -H 'Content-Type: application/json' --data-binary "@$CONFIG/authorization-model.json" "$FGA_URL/stores/$store/authorization-models" | sed -E 's/.*"authorization_model_id":"([^"]+)".*/\1/')"
  echo "$store$model" | grep -Eq '^[0-9A-Z]{52}$' || fail "the authorization store or model was not created"
  printf 'ZASP_OPENFGA_STORE_ID=%s\nZASP_OPENFGA_MODEL_ID=%s\n' "$store" "$model" > "$STATE/fga.env.partial"
  chmod 644 "$STATE/fga.env.partial"
  mv -f "$STATE/fga.env.partial" "$STATE/fga.env"
}

# Creates the user the graph worker signs in as. Runs in the Neo4j image.
# The passwords are hexadecimal, so they need no escaping.
cmd_graph_user() {
  printf 'CREATE OR REPLACE USER %s SET PLAINTEXT PASSWORD "%s" SET PASSWORD CHANGE NOT REQUIRED;\n' "$NEO4J_WORKER_USER" "$NEO4J_WORKER_PASSWORD" |
    NEO4J_USERNAME=neo4j NEO4J_PASSWORD="$NEO4J_ADMIN_PASSWORD" cypher-shell -a neo4j+ssc://localhost:7687 -d system --format plain >/dev/null ||
    fail "the graph worker user was not created"
}

# The production schema jobs for the search index and the graph constraints.
cmd_search_init() {
  exec env ZASP_WORKER_MODE=projection-search-init ZASP_ENVIRONMENT=test ZASP_LOCAL_CLOUD_ENDPOINT="$LOCAL_CLOUD" \
    ZASP_AWS_REGION=us-east-1 ZASP_PROJECTION_INIT_ROLE_ARN=arn:aws:iam::000000000000:role/zasp-real-stack-projection-init \
    ZASP_PROJECTION_INIT_WEB_IDENTITY_TOKEN_FILE="$TOKEN_FILE" ZASP_PROJECTION_INIT_TIMEOUT=30s \
    ZASP_OPENSEARCH_ENDPOINT="$SEARCH_URL" ZASP_OPENSEARCH_INDEX=zasp-inventory-v1 /app/agentsec-worker
}
cmd_graph_init() {
  exec env ZASP_WORKER_MODE=projection-graph-init ZASP_ENVIRONMENT=test ZASP_LOCAL_CLOUD_ENDPOINT="$LOCAL_CLOUD" \
    ZASP_AWS_REGION=us-east-1 ZASP_PROJECTION_INIT_ROLE_ARN=arn:aws:iam::000000000000:role/zasp-real-stack-projection-init \
    ZASP_PROJECTION_INIT_WEB_IDENTITY_TOKEN_FILE="$TOKEN_FILE" ZASP_PROJECTION_INIT_TIMEOUT=30s \
    ZASP_PROJECTION_SECRET_PREFIX="$PROJECTION_SECRET_PREFIX" ZASP_NEO4J_URI="$NEO4J_URI" ZASP_NEO4J_SCHEMA_CREDENTIAL_REFERENCE=ref:neo4j/auth/graph-schema \
    ZASP_LOCAL_NEO4J_CA_FILE=/zasp/neo4j-tls/ca.crt /app/agentsec-worker
}

# The Security Agent planning worker needs a first test-selector revision.
# 'selector-count' (PostgreSQL image) records whether one exists;
# 'selector-configure' (API image) installs it when none does.
cmd_selector_count() {
  psql -X -Atc "SET ROLE zasp_discovery_authority; SELECT count(*) FROM zasp_temporal75.configuration" "$(dsn "$OPERATOR")" | tail -1 > "$RUN/test-selector.count" ||
    fail "the test-selector configuration was not read"
}
cmd_selector_configure() {
  [ "$(cat "$RUN/test-selector.count")" = "0" ] || return 0
  ZASP_POSTGRES_DSN="$(dsn "$OPERATOR")" ZASP_MIGRATION_TIMEOUT=60s ZASP_TEST_SELECTOR_CONFIGURATION='{"revision":1,"cadence_seconds":300,"enabled":true}' \
    /app/agentsec-migrate configure-temporal-test-selector || fail "the test-selector configuration was refused"
}

# The API cannot start before the first organization exists.
wait_for_organization() {
  while [ ! -f "$STATE/organization.env" ]; do
    echo "zasp: waiting for the first organization (set bootstrap.* in the values, or run './zasp bootstrap-admin')"
    sleep 15
  done
}

cmd_api() {
  wait_for_organization
  load_environment
  export HOSTNAME=agentsec-api
  export ZASP_PUBLIC_ORIGIN
  export ZASP_PRODUCT_LISTEN_ADDRESS=127.0.0.1:4000 ZASP_INTERNAL_LISTEN_ADDRESS=127.0.0.1:4081
  export ZASP_TRUSTED_PROXY_CIDRS=127.0.0.0/8 ZASP_REQUEST_RATE_PER_SECOND=1000 ZASP_REQUEST_BURST=2000 ZASP_COOKIE_SECURE=true
  export ZASP_PROVIDER_TIMEOUT=10s ZASP_REQUEST_TIMEOUT=15s ZASP_SHUTDOWN_TIMEOUT=5s ZASP_READINESS_INTERVAL=1s ZASP_READINESS_MAX_INTERVAL=10s
  export ZASP_DISCOVERY_PARSER_VERSION=inventory-parser-2026.08.20 ZASP_DISCOVERY_TOOL_VERSION=collector-tool-2026.08.20
  ZASP_POSTGRES_DSN="$(dsn zasp_svc_api)"
  ZASP_SECURITY_AGENT_POSTGRES_DSN="$(dsn zasp_svc_security_agent_api)"
  ZASP_APPROVAL_MAINTENANCE_POSTGRES_DSN="$(dsn zasp_svc_approval_maintenance)"
  export ZASP_POSTGRES_DSN ZASP_SECURITY_AGENT_POSTGRES_DSN ZASP_APPROVAL_MAINTENANCE_POSTGRES_DSN
  export ZASP_STYTCH_BASE_URL
  export ZASP_STYTCH_AUTHORIZE_URL="$ZASP_STYTCH_BASE_URL/v1/b2b/public/oauth/${ZASP_OAUTH_PROVIDER:-google}/start"
  export ZASP_CONNECTOR_AWS_REGION=us-east-1 ZASP_CONNECTOR_ROLE_ARN=arn:aws:iam::000000000000:role/zasp-real-stack-api-connectors
  export ZASP_CONNECTOR_WEB_IDENTITY_TOKEN_FILE="$TOKEN_FILE"
  export ZASP_CONNECTOR_KMS_KEY_ARN=arn:aws:kms:us-east-1:000000000000:key/11111111-1111-1111-1111-111111111111
  export ZASP_CONNECTOR_SECRET_PREFIX=zasp-real-stack/connectors/oauth
  export ZASP_POLICY_HISTORY_ENDPOINT="$SEARCH_URL" ZASP_POLICY_HISTORY_INDEX=zasp-runtime-events-v1
  export ZASP_AWS_CUSTOMER_ROLE_PREFIXES='["arn:aws:iam::000000000000:role/zasp-reference/"]'
  export ZASP_AWS_CUSTOMER_ROLE_ARNS='["arn:aws:iam::000000000000:role/zasp-reference/customer-read"]'
  export ZASP_KUBERNETES_EGRESS_CIDRS=203.0.113.0/24 ZASP_FINDING_TICKET_EGRESS_CIDRS=192.0.2.64/28
  export ZASP_GITHUB_CLIENT_ID=Iv1.1234567890abcdef ZASP_GITHUB_CLIENT_SECRET_REFERENCE=ref:github/client-secret
  export ZASP_GITHUB_APP_ID=123456 ZASP_GITHUB_PRIVATE_KEY_REFERENCE=ref:github/app-private-key
  export ZASP_OKTA_CLIENT_ID=0oa1234567890abcdef ZASP_OKTA_CLIENT_SECRET_REFERENCE=ref:okta/client-secret
  exec /app/agentsec-api
}

# One worker mode. The health ports are the local stack's; each binds the
# pod's loopback interface, which development mode requires.
cmd_worker() {
  [ "$#" -eq 1 ] || fail "usage: entrypoint.sh worker <mode>"
  load_environment
  export ZASP_WORKER_MODE="$1" ZASP_WORKER_ID="zasp-$1" ZASP_AWS_REGION=us-east-1
  export ZASP_POLL_INTERVAL=1s ZASP_LEASE_DURATION=30s ZASP_SHUTDOWN_TIMEOUT=5s ZASP_BATCH_SIZE=10 ZASP_PROVIDER_TIMEOUT=10s
  export ZASP_DISCOVERY_PARSER_VERSION=inventory-parser-2026.08.20 ZASP_DISCOVERY_TOOL_VERSION=collector-tool-2026.08.20
  case "$1" in
    scheduler)
      export ZASP_LOCAL_HEALTH_PORT=8081 ZASP_DATABASE_AUTHORITY=zasp_discovery_scheduler
      ZASP_POSTGRES_DSN="$(dsn zasp_svc_scheduler)"
      ;;
    outbox)
      export ZASP_LOCAL_HEALTH_PORT=8083 ZASP_DATABASE_AUTHORITY=zasp_outbox_worker
      ZASP_POSTGRES_DSN="$(dsn zasp_svc_outbox)"
      export ZASP_DISCOVERY_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/000000000000/agentsec-discovery-jobs
      export ZASP_OUTBOX_ROLE_ARN=arn:aws:iam::000000000000:role/zasp-real-stack-outbox ZASP_OUTBOX_WEB_IDENTITY_TOKEN_FILE="$TOKEN_FILE"
      ;;
    discovery)
      set -a
      # shellcheck disable=SC1091
      . "$RUN/cloud.env"
      set +a
      export ZASP_LOCAL_HEALTH_PORT=8082 ZASP_DATABASE_AUTHORITY=zasp_discovery_worker
      ZASP_POSTGRES_DSN="$(dsn zasp_svc_discovery)"
      ZASP_TEMPORAL_EXECUTOR_POSTGRES_DSN="$(dsn zasp_svc_temporal_executor)"
      ZASP_TEMPORAL_COMPENSATION_POSTGRES_DSN="$(dsn zasp_svc_temporal_compensation)"
      export ZASP_TEMPORAL_EXECUTOR_POSTGRES_DSN ZASP_TEMPORAL_COMPENSATION_POSTGRES_DSN
      export ZASP_AUTHORIZATION_WORKER_KEY_FILE="$SECRETS/forward.seed" ZASP_AUTHORIZATION_COMPENSATION_KEY_FILE="$SECRETS/compensation.seed"
      export ZASP_DISCOVERY_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/000000000000/agentsec-discovery-jobs
      export ZASP_DISCOVERY_ROLE_ARN=arn:aws:iam::000000000000:role/zasp-real-stack-discovery
      export ZASP_DISCOVERY_WEB_IDENTITY_TOKEN_FILE="$TOKEN_FILE" ZASP_DISCOVERY_SECRET_PREFIX=zasp-real-stack/discovery
      export ZASP_EVIDENCE_BUCKET=zasp-real-stack-evidence ZASP_EVIDENCE_BUCKET_OWNER=000000000000
      export ZASP_DISCOVERY_AWS_COLLECTOR_VERSION=collector_v1 ZASP_DISCOVERY_KUBERNETES_COLLECTOR_VERSION=collector_v1
      export ZASP_DISCOVERY_GITHUB_COLLECTOR_VERSION=collector_v1 ZASP_DISCOVERY_OKTA_COLLECTOR_VERSION=collector_v1
      export ZASP_KUBERNETES_EGRESS_CIDRS=203.0.113.0/24 ZASP_DISCOVERY_READINESS_TIMEOUT=5s
      export ZASP_GITHUB_APP_ID=123456 ZASP_GITHUB_PRIVATE_KEY_REFERENCE=ref:github/app-private-key
      export ZASP_OKTA_CLIENT_ID=0oa1234567890abcdef ZASP_OKTA_CLIENT_SECRET_REFERENCE=ref:okta/client-secret
      ;;
    security-agent)
      set -a
      # shellcheck disable=SC1091
      . "$RUN/cloud.env"
      set +a
      export ZASP_LOCAL_HEALTH_PORT=8084 ZASP_DATABASE_AUTHORITY=zasp_security_agent_worker
      ZASP_POSTGRES_DSN="$(dsn zasp_svc_security_agent_worker)"
      ZASP_TEMPORAL_EXECUTOR_POSTGRES_DSN="$(dsn zasp_svc_temporal_executor)"
      ZASP_TEMPORAL_COMPENSATION_POSTGRES_DSN="$(dsn zasp_svc_temporal_compensation)"
      export ZASP_TEMPORAL_EXECUTOR_POSTGRES_DSN ZASP_TEMPORAL_COMPENSATION_POSTGRES_DSN
      export ZASP_AUTHORIZATION_WORKER_KEY_FILE="$SECRETS/forward.seed" ZASP_AUTHORIZATION_COMPENSATION_KEY_FILE="$SECRETS/compensation.seed"
      export ZASP_SECURITY_AGENT_PLANNER_ENDPOINT=https://openrouter.ai/api/v1/chat/completions ZASP_SECURITY_AGENT_PLANNER_MODEL=openai/gpt-5-mini
      export ZASP_SECURITY_AGENT_PLANNER_TOKEN_FILE=/var/run/secrets/zasp-security-agent/openrouter-api-token
      export ZASP_SECURITY_AGENT_PLANNER_TIMEOUT=20s ZASP_SECURITY_AGENT_PLANNER_MAX_TOKENS=2048 ZASP_SECURITY_AGENT_PLANNER_POLICY_VERSION=security-agent-planner-v1
      export ZASP_GATEWAY_SIGNING_KEY_ID=zasp-gateway ZASP_GATEWAY_SIGNING_PRIVATE_KEY_FILE=/var/run/secrets/zasp-security-agent-action/gateway-signing-private-key
      export ZASP_GATEWAY_POLICY_KEYS_FILE=/var/run/zasp-policy-verifier/policy-keys.json
      export ZASP_EVIDENCE_BUCKET=zasp-real-stack-evidence ZASP_EVIDENCE_BUCKET_OWNER=000000000000
      export ZASP_RED_TEAM_ROLE_ARN=arn:aws:iam::000000000000:role/zasp-real-stack-discovery ZASP_RED_TEAM_WEB_IDENTITY_TOKEN_FILE="$TOKEN_FILE"
      # The existing-test runner and its adapter are not part of this chart.
      # The worker requires their configuration to start; a run that reaches a
      # test step fails there. The image reference only has to name a digest.
      export ZASP_RED_TEAM_RUNNER_IMAGE="zasp/agentsec-red-team-runner@sha256:0000000000000000000000000000000000000000000000000000000000000000"
      export ZASP_RED_TEAM_RUNNER_TIMEOUT=5m ZASP_RED_TEAM_TARGET_ENDPOINT=https://agentsec-red-team-adapter.zasp.svc.cluster.local/v1/evaluate
      export ZASP_RED_TEAM_TARGET_TOKEN_FILE="$SECRETS/red-team-adapter.token" ZASP_RED_TEAM_TARGET_CA_FILE="$SECRETS/red-team-adapter-ca.pem"
      ;;
    security-agent-action)
      export ZASP_LOCAL_HEALTH_PORT=8085 ZASP_DATABASE_AUTHORITY=zasp_security_agent_action_worker
      ZASP_POSTGRES_DSN="$(dsn zasp_svc_security_agent_action)"
      export ZASP_GATEWAY_SIGNING_KEY_ID=zasp-gateway ZASP_GATEWAY_SIGNING_PRIVATE_KEY_FILE=/var/run/secrets/zasp-security-agent-action/gateway-signing-private-key
      ;;
    projection-graph)
      export ZASP_LOCAL_HEALTH_PORT=8091 ZASP_DATABASE_AUTHORITY=zasp_projection_graph_worker
      ZASP_POSTGRES_DSN="$(dsn zasp_svc_projection_graph)"
      export ZASP_PROJECTION_ROLE_ARN=arn:aws:iam::000000000000:role/zasp-real-stack-projection-graph ZASP_PROJECTION_WEB_IDENTITY_TOKEN_FILE="$TOKEN_FILE"
      export ZASP_PROJECTION_SECRET_PREFIX="$PROJECTION_SECRET_PREFIX" ZASP_NEO4J_URI="$NEO4J_URI" ZASP_NEO4J_CREDENTIAL_REFERENCE=ref:neo4j/auth/graph-worker
      export ZASP_NEO4J_EXPECTED_PRINCIPAL="$NEO4J_WORKER_USER" ZASP_NEO4J_EXPECTED_ROLE="$NEO4J_WORKER_ROLE"
      export ZASP_LOCAL_NEO4J_CA_FILE=/zasp/neo4j-tls/ca.crt
      ;;
    projection-search)
      export ZASP_LOCAL_HEALTH_PORT=8092 ZASP_DATABASE_AUTHORITY=zasp_projection_search_worker
      ZASP_POSTGRES_DSN="$(dsn zasp_svc_projection_search)"
      export ZASP_PROJECTION_ROLE_ARN=arn:aws:iam::000000000000:role/zasp-real-stack-projection-search ZASP_PROJECTION_WEB_IDENTITY_TOKEN_FILE="$TOKEN_FILE"
      export ZASP_OPENSEARCH_ENDPOINT="$SEARCH_URL" ZASP_OPENSEARCH_INDEX=zasp-inventory-v1
      ;;
    projection-risk)
      export ZASP_LOCAL_HEALTH_PORT=8093 ZASP_DATABASE_AUTHORITY=zasp_projection_risk_worker
      ZASP_POSTGRES_DSN="$(dsn zasp_svc_projection_risk)"
      ;;
    *) fail "worker mode '$1' is not part of this chart" ;;
  esac
  export ZASP_POSTGRES_DSN
  exec /app/agentsec-worker
}

# Applies pending permission changes every few seconds. A new organization,
# member or resource answers 'authorization_pending' until a pass has run.
cmd_projector() {
  load_environment
  reconcile_dsn="$(dsn zasp_svc_outbox)"
  trap 'exit 0' INT TERM
  while :; do
    ZASP_POSTGRES_DSN="$reconcile_dsn" /app/zasp-authorization-reconcile -mode reconcile -limit 20 -timeout 1m ||
      echo "zasp: a permission pass failed; it is repeated" >&2
    sleep "${ZASP_PROJECT_INTERVAL:-5}"
  done
}

# The TLS front: serves the web application and forwards /api to the API with
# the headers a trusted ingress sends. Runs in the web image.
cmd_front() {
  export ZASP_FRONT_ORIGIN="$ZASP_PUBLIC_ORIGIN" ZASP_FRONT_API=http://127.0.0.1:4000
  export ZASP_FRONT_WEB_DIR=/app ZASP_FRONT_WEB_PORT=3100 ZASP_FRONT_LISTEN=0.0.0.0 ZASP_FRONT_LISTEN_PORT=8443
  export ZASP_FRONT_CERT=/zasp/front-tls/tls.crt ZASP_FRONT_KEY=/zasp/front-tls/tls.key
  exec node "$CONFIG/front.mjs"
}

# An idle container of the API image for the administrator: bootstrap,
# verify-baseline and status run here through 'kubectl exec'.
cmd_toolbox() {
  trap 'exit 0' INT TERM
  while :; do sleep 3600 & wait $!; done
}

cmd_verify() {
  load_environment
  ZASP_POSTGRES_DSN="$(dsn "$OPERATOR")" /app/agentsec-migrate verify-baseline
}

# One line per process: whether its readiness endpoint answers 200. Runs in
# the toolbox container (the API image is Alpine, which has wget).
cmd_status() {
  for entry in api:4081 worker-scheduler:8081 worker-discovery:8082 worker-outbox:8083 worker-security-agent:8084 \
    worker-security-agent-action:8085 worker-projection-graph:8091 worker-projection-search:8092 worker-projection-risk:8093; do
    name="${entry%%:*}"
    if wget -q -T 3 -O /dev/null "http://127.0.0.1:${entry##*:}/readyz" 2>/dev/null; then state=ready; else state="not ready"; fi
    printf '%-30s %s\n' "$name" "$state"
  done
}

case "${1:-}" in
  prepare) cmd_prepare ;;
  schema) cmd_schema ;;
  bootstrap) shift; cmd_bootstrap "$@" ;;
  fga-model) cmd_fga_model ;;
  graph-user) cmd_graph_user ;;
  search-init) cmd_search_init ;;
  graph-init) cmd_graph_init ;;
  selector-count) cmd_selector_count ;;
  selector-configure) cmd_selector_configure ;;
  api) cmd_api ;;
  worker) shift; cmd_worker "$@" ;;
  projector) cmd_projector ;;
  front) cmd_front ;;
  toolbox) cmd_toolbox ;;
  verify) cmd_verify ;;
  status) cmd_status ;;
  *) fail "unknown process '${1:-}'" ;;
esac
