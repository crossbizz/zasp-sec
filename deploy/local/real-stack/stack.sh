#!/usr/bin/env bash
# Runs the product API against real dependencies on one machine: PostgreSQL 18,
# the pinned Temporal and OpenFGA servers, and a real Stytch project.
# See README.md in this directory for what this does and does not establish.
# Written for bash 3.2 (the macOS system bash) as well as current bash.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
STATE="${ZASP_REAL_STACK_STATE:-${XDG_STATE_HOME:-$HOME/.local/state}/zasp-real-stack}"
BIN="$STATE/bin"
SECRETS="$STATE/secrets"
COMPOSE="$ROOT/deploy/local/temporal-openfga.compose.yaml"
# Background processes started by 'start': one pid file and one log each.
RUN="$STATE/run"
LOGS="$STATE/logs"
TLS="$STATE/tls"
# Optional: the Stytch credentials, kept in a file instead of the shell.
if [ -f "$STATE/provider.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$STATE/provider.env"
  set +a
fi

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
# The graph database is Neo4j Community, serving Bolt over TLS only, on the
# scheme and port the graph worker requires. Its certificate comes from a
# local authority the worker trusts in development mode only. Development-only.
NEO4J_IMAGE="${ZASP_REAL_STACK_NEO4J_IMAGE:-public.ecr.aws/docker/library/neo4j:5.26-community}"
NEO4J_CONTAINER="zasp-real-stack-neo4j"
NEO4J_URI="neo4j+s://localhost:7687"
NEO4J_WORKER_USER="zasp_graph_worker"
# The role name the worker is told to expect. Community has no roles, so this
# only satisfies the setting; see README.md.
NEO4J_WORKER_ROLE="zasp_graph_writer"
PROJECTION_SECRET_PREFIX="zasp-real-stack/projection"
TOKEN_FILE=/var/run/secrets/eks.amazonaws.com/serviceaccount/token
FGA_URL="http://127.0.0.1:8088"
FGA_TOKEN="${ZASP_LOCAL_OPENFGA_TOKEN:-local-openfga-smoke-only}"
# The public origin must be HTTPS and must not be localhost or an IP address:
# the connector OAuth callbacks refuse those hosts.
PUBLIC_ORIGIN="${ZASP_REAL_STACK_ORIGIN:-https://zasp.local-stack.test:8443}"
# The operator is not a superuser, exactly as on managed PostgreSQL. The
# cluster superuser is used only to create that role and its database.
# The TLS front listens on the origin's port; the web application behind it
# on a loopback port of its own.
ORIGIN_AUTHORITY="${PUBLIC_ORIGIN#https://}"
ORIGIN_HOST="${ORIGIN_AUTHORITY%%:*}"
case "$ORIGIN_AUTHORITY" in
  *:*) ORIGIN_PORT="${ORIGIN_AUTHORITY##*:}" ;;
  *) ORIGIN_PORT=443 ;;
esac
WEB_PORT="${ZASP_REAL_STACK_WEB_PORT:-3100}"
OPERATOR="zasp_operator"
PG_SUPERUSER="postgres"
PG_DATABASE="zasp"

fail() { echo "real-stack: $*" >&2; exit 1; }

# One machine runs one stack. The containers (PostgreSQL, Neo4j, LocalStack,
# OpenSearch, Temporal, OpenFGA), their ports and the fixed secret paths under
# /var/run are shared by every state directory, while the secrets a stack puts
# into them are generated per state directory: the Neo4j user's password, the
# graph and external-ID secrets in LocalStack, the customer role's trust
# policy, the verification keys registered in the database and the Security
# Agent key files. A command run with a second state directory would replace
# all of those and break the stack that created them. Every command that
# writes them therefore first claims the machine for its state directory and
# refuses when another state directory holds it.
#
# The holder is recorded in OWNER_FILE. Without a record (a stack created
# before this check) it is read from the Neo4j container, which mounts the
# certificate directory of the state that created it.
OWNER_FILE="${ZASP_REAL_STACK_OWNER_FILE:-${XDG_STATE_HOME:-$HOME/.local/state}/zasp-real-stack.owner}"
machine_owner() {
  if [ -f "$OWNER_FILE" ]; then
    head -n 1 "$OWNER_FILE"
    return 0
  fi
  local mount
  mount="$(docker inspect zasp-real-stack-neo4j --format '{{range .Mounts}}{{println .Source}}{{end}}' 2>/dev/null | grep -E '/tls/neo4j$' | head -n 1 || true)"
  [ -z "$mount" ] || echo "${mount%/tls/neo4j}"
}
claim_machine() {
  mkdir -p "$STATE"
  local mine owner
  mine="$(cd "$STATE" && pwd -P)"
  owner="$(machine_owner)"
  # A holder whose state directory is gone holds nothing.
  if [ -n "$owner" ] && [ "$owner" != "$mine" ] && [ -d "$owner/secrets" ] && [ "${ZASP_REAL_STACK_TAKE_OVER:-}" != "1" ]; then
    fail "this machine's stack belongs to the state directory '$owner'; '$mine' is another one.
  The containers and the secrets inside them are shared: continuing would replace that stack's Neo4j password,
  LocalStack secrets, registered verification keys and Security Agent key files.
  Use that state directory (ZASP_REAL_STACK_STATE='$owner'), or stop that stack and take the machine over on
  purpose with ZASP_REAL_STACK_TAKE_OVER=1 (that stack then no longer works until it takes the machine back)."
  fi
  if [ "$owner" != "$mine" ] || [ ! -f "$OWNER_FILE" ]; then
    mkdir -p "$(dirname "$OWNER_FILE")"
    printf '%s\n' "$mine" > "$OWNER_FILE.$$" && mv "$OWNER_FILE.$$" "$OWNER_FILE" || fail "could not record the stack's state directory in $OWNER_FILE"
  fi
}
# URL-safe base64 without padding. (basenc is GNU-only; openssl is everywhere.)
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '=\n'; }
# psql from this machine when it is installed, otherwise the one inside the
# product database container.
run_psql() {
  if command -v psql >/dev/null 2>&1; then
    psql "$@"
    return
  fi
  [ -z "$EXTERNAL_HOST" ] || fail "psql is required for an external database"
  local arguments=() argument
  for argument in "$@"; do arguments+=("${argument/@127.0.0.1:$PG_PORT\//@127.0.0.1:5432/}"); done
  docker exec -i "$PG_CONTAINER" psql "${arguments[@]}"
}
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
    if run_psql -X -Atc 'select 1' "$super" >/dev/null 2>&1; then break; fi
    sleep 0.5
  done
  run_psql -X -Atc 'select 1' "$super" >/dev/null || fail "product database did not start"
  if [ "$(run_psql -X -Atc "select count(*) from pg_roles where rolname='$OPERATOR'" "$super")" != "1" ]; then
    run_psql -X -q -v ON_ERROR_STOP=1 "$super" -c "CREATE ROLE $OPERATOR LOGIN CREATEROLE BYPASSRLS"
  fi
  if [ "$(run_psql -X -Atc "select count(*) from pg_database where datname='$PG_DATABASE'" "$super")" != "1" ]; then
    run_psql -X -q -v ON_ERROR_STOP=1 "$super" -c "CREATE DATABASE $PG_DATABASE OWNER $OPERATOR TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C'"
  fi
  [ "$(run_psql -X -Atc "select datcollate from pg_database where datname=current_database()" "$(dsn "$OPERATOR")")" = "C" ] || fail "product database collation is not C"
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
      reveal="$(openssl rand 32 | b64url)"
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
  printf '%s.%s.%s' "$(printf '{"alg":"none","typ":"JWT"}' | b64url)" \
    "$(printf '{"iss":"zasp-real-stack","sub":"system:serviceaccount:zasp:local","aud":"sts.amazonaws.com"}' | b64url)" \
    "bG9jYWwtZGV2ZWxvcG1lbnQtb25seQ" > "$TOKEN_FILE" || fail "write $TOKEN_FILE"
}

# Runs the production search-schema job against the local search node.
init_search() {
  env -i PATH="$PATH" ZASP_WORKER_MODE=projection-search-init ZASP_ENVIRONMENT=test ZASP_LOCAL_CLOUD_ENDPOINT="$LOCAL_CLOUD" \
    ZASP_AWS_REGION=us-east-1 ZASP_PROJECTION_INIT_ROLE_ARN=arn:aws:iam::000000000000:role/zasp-real-stack-projection-init \
    ZASP_PROJECTION_INIT_WEB_IDENTITY_TOKEN_FILE="$TOKEN_FILE" ZASP_PROJECTION_INIT_TIMEOUT=30s \
    ZASP_OPENSEARCH_ENDPOINT="$SEARCH_URL" ZASP_OPENSEARCH_INDEX=zasp-inventory-v1 "$BIN/agentsec-worker" || fail "search schema initialization refused"
}

# The passwords of the graph database administrator and of the graph worker.
ensure_graph_passwords() {
  local name
  for name in neo4j-admin neo4j-worker; do
    [ -f "$SECRETS/$name.password" ] && continue
    (umask 077; openssl rand -hex 24 > "$SECRETS/$name.password.partial" && mv "$SECRETS/$name.password.partial" "$SECRETS/$name.password") || fail "graph database password was not generated"
  done
}

# Creates the certificate the graph database serves on Bolt: an authority that
# may only vouch for 'localhost', and a server certificate from it. As for the
# browser certificate, the authority's key is deleted once it has signed. The
# directory is mounted into the container, whose user is not this one, so the
# files are world-readable inside the private $TLS directory.
ensure_graph_certificate() {
  local directory="$TLS/neo4j"
  if [ -f "$directory/ca.crt" ] && [ -f "$directory/public.crt" ] && [ -f "$directory/private.key" ] &&
    openssl x509 -in "$directory/public.crt" -noout -checkend 86400 >/dev/null 2>&1; then
    return 0
  fi
  mkdir -p "$TLS"
  chmod 700 "$TLS"
  mkdir -p "$directory"
  (
    umask 077
    cd "$directory" || exit 1
    rm -f ca.crt ca.key ca.srl public.crt private.key server.csr openssl.cnf
    printf '%s\n' '[req]' 'distinguished_name = dn' 'prompt = no' '[dn]' 'CN = unused' \
      '[ca]' 'basicConstraints = critical, CA:TRUE, pathlen:0' 'keyUsage = critical, keyCertSign' 'subjectKeyIdentifier = hash' \
      'nameConstraints = critical, permitted;DNS:localhost' \
      '[leaf]' 'basicConstraints = critical, CA:FALSE' 'keyUsage = critical, digitalSignature, keyEncipherment' \
      'extendedKeyUsage = serverAuth' 'subjectAltName = DNS:localhost' > openssl.cnf
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 825 -keyout ca.key -out ca.crt \
      -subj "/CN=Zasp local stack development CA for the graph database" -config openssl.cnf -extensions ca >/dev/null 2>&1 &&
      openssl req -new -newkey rsa:2048 -nodes -keyout private.key -out server.csr -subj "/CN=localhost" -config openssl.cnf >/dev/null 2>&1 &&
      openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -sha256 -days 825 \
        -extfile openssl.cnf -extensions leaf -out public.crt >/dev/null 2>&1
    status=$?
    rm -f ca.key ca.srl server.csr openssl.cnf
    [ "$status" -eq 0 ] || { rm -f ca.crt public.crt private.key; exit 1; }
    chmod 644 ca.crt public.crt private.key
  ) || fail "the graph database certificate was not created (openssl is required)"
  chmod 755 "$directory"
  # A running database still serves the certificate it started with.
  GRAPH_CERTIFICATE_CREATED=1
}

# Runs Cypher from standard input as the graph database administrator. The
# password reaches the container through the environment, not the command line.
graph_shell() {
  NEO4J_USERNAME=neo4j NEO4J_PASSWORD="$(tr -d '\n' < "$SECRETS/neo4j-admin.password")" \
    docker exec -i -e NEO4J_USERNAME -e NEO4J_PASSWORD "$NEO4J_CONTAINER" cypher-shell -a neo4j+ssc://localhost:7687 -d system --format plain
}

# Starts the graph database and creates the user the graph worker signs in as.
start_graph_database() {
  ensure_graph_passwords
  GRAPH_CERTIFICATE_CREATED=0
  ensure_graph_certificate
  if docker inspect "$NEO4J_CONTAINER" >/dev/null 2>&1; then
    if [ "$GRAPH_CERTIFICATE_CREATED" -eq 1 ]; then docker restart "$NEO4J_CONTAINER" >/dev/null; else docker start "$NEO4J_CONTAINER" >/dev/null; fi
  else
    # The administrator password only takes effect on the first start. The
    # HTTP interface and usage reporting are off; Bolt refuses plaintext.
    NEO4J_AUTH="neo4j/$(tr -d '\n' < "$SECRETS/neo4j-admin.password")" docker run -d --name "$NEO4J_CONTAINER" -p 127.0.0.1:7687:7687 -e NEO4J_AUTH \
      -e NEO4J_server_http_enabled=false -e NEO4J_dbms_usage__report_enabled=false -e NEO4J_server_bolt_tls__level=REQUIRED \
      -e NEO4J_dbms_ssl_policy_bolt_enabled=true -e NEO4J_dbms_ssl_policy_bolt_base__directory=/ssl/bolt \
      -e NEO4J_dbms_ssl_policy_bolt_private__key=private.key -e NEO4J_dbms_ssl_policy_bolt_public__certificate=public.crt \
      -e NEO4J_dbms_ssl_policy_bolt_client__auth=NONE \
      -e NEO4J_server_memory_heap_initial__size=256m -e NEO4J_server_memory_heap_max__size=512m -e NEO4J_server_memory_pagecache_size=128m \
      -v "$TLS/neo4j:/ssl/bolt:ro" "$NEO4J_IMAGE" >/dev/null
  fi
  local ready=0
  for _ in $(seq 1 90); do
    if echo 'SHOW CURRENT USER;' | graph_shell >/dev/null 2>&1; then ready=1; break; fi
    sleep 2
  done
  [ "$ready" -eq 1 ] || fail "the graph database did not start, or does not accept the stored administrator password (remove the container '$NEO4J_CONTAINER' to recreate it)"
  # The password is hexadecimal, so it needs no escaping.
  printf 'CREATE OR REPLACE USER %s SET PLAINTEXT PASSWORD "%s" SET PASSWORD CHANGE NOT REQUIRED;\n' "$NEO4J_WORKER_USER" "$(tr -d '\n' < "$SECRETS/neo4j-worker.password")" |
    graph_shell >/dev/null || fail "the graph worker user was not created"
}

# Runs the production graph-schema job against the local graph database, as
# the administrator: the worker itself never creates constraints.
init_graph() {
  env -i PATH="$PATH" ZASP_WORKER_MODE=projection-graph-init ZASP_ENVIRONMENT=test ZASP_LOCAL_CLOUD_ENDPOINT="$LOCAL_CLOUD" \
    ZASP_AWS_REGION=us-east-1 ZASP_PROJECTION_INIT_ROLE_ARN=arn:aws:iam::000000000000:role/zasp-real-stack-projection-init \
    ZASP_PROJECTION_INIT_WEB_IDENTITY_TOKEN_FILE="$TOKEN_FILE" ZASP_PROJECTION_INIT_TIMEOUT=30s \
    ZASP_PROJECTION_SECRET_PREFIX="$PROJECTION_SECRET_PREFIX" ZASP_NEO4J_URI="$NEO4J_URI" ZASP_NEO4J_SCHEMA_CREDENTIAL_REFERENCE=ref:neo4j/auth/graph-schema \
    ZASP_LOCAL_NEO4J_CA_FILE="$TLS/neo4j/ca.crt" "$BIN/agentsec-worker" || fail "graph schema initialization refused"
}

migrate() { ZASP_POSTGRES_DSN="$(dsn "$OPERATOR")" "$BIN/agentsec-migrate" "$1" || fail "agentsec-migrate $1 refused"; }

cmd_up() {
  claim_machine
  docker compose -f "$COMPOSE" up -d
  start_local_cloud
  write_identity_token
  start_database
  generate_keys
  start_graph_database
  build_binaries
  publish_model
  init_search
  provision_local_cloud
  init_graph
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
  # 'start' repeats 'up' until one has completed.
  : > "$STATE/up.done"
  echo "real-stack: schema installed; next: $0 bootstrap <organization name> <domain> <admin email>"
}

cmd_bootstrap() {
  [ "$#" -eq 3 ] || fail "usage: $0 bootstrap <organization name> <domain> <admin email>"
  claim_machine
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
  claim_machine
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
  # The two graph database credentials, in the form the workers read: the
  # administrator for the one-shot schema job, the worker user for the worker.
  ensure_graph_passwords
  ensure_graph_secret graph-schema neo4j neo4j-admin
  ensure_graph_secret graph-worker "$NEO4J_WORKER_USER" neo4j-worker
  provision_customer_account
}

# Stores one graph database credential as the secret a worker resolves from
# ref:neo4j/auth/<identifier>. Arguments: identifier, principal, password file.
ensure_graph_secret() {
  local name="$PROJECTION_SECRET_PREFIX/neo4j/auth/$1" value
  value="{\"scheme\":\"basic\",\"principal\":\"$2\",\"credentials\":\"$(tr -d '\n' < "$SECRETS/$3.password")\"}"
  if $aws secretsmanager describe-secret --secret-id "$name" >/dev/null 2>&1; then
    $aws secretsmanager put-secret-value --secret-id "$name" --secret-string "$value" >/dev/null || fail "graph database secret $name was not updated"
  else
    $aws secretsmanager create-secret --name "$name" --secret-string "$value" >/dev/null || fail "graph database secret $name was not created"
  fi
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
  # The bedrock, bedrock-agentcore and lambda actions are optional. They let the
  # sync list the account's AI agents. Without them the sync still succeeds
  # and the AI service shows access_denied in the inventory.
  ensure_attached_policy zasp-customer-read-inventory '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:ListRoles","iam:ListAttachedRolePolicies","iam:GetPolicy","iam:GetPolicyVersion","ec2:DescribeRegions","ec2:DescribeInstances","bedrock:ListAgents","bedrock:GetAgent","bedrock-agentcore:ListAgentRuntimes","bedrock-agentcore:GetAgentRuntime","bedrock-agentcore:ListGateways","lambda:ListFunctions"],"Resource":"*"}]}' "$CUSTOMER_ROLE_NAME"

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
  [ "$#" -eq 1 ] || fail "usage: $0 worker {scheduler|outbox|discovery|security-agent|security-agent-action|projection-graph|projection-search|projection-risk}"
  claim_machine
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
      # The installed schema hands every discovery run the collector version
      # 'collector_v1' (zasp_temporal72.prepare_page). A worker configured with
      # any other value refuses to build its collector and the run fails.
      export ZASP_DISCOVERY_AWS_COLLECTOR_VERSION=collector_v1 ZASP_DISCOVERY_KUBERNETES_COLLECTOR_VERSION=collector_v1
      export ZASP_DISCOVERY_GITHUB_COLLECTOR_VERSION=collector_v1 ZASP_DISCOVERY_OKTA_COLLECTOR_VERSION=collector_v1
      # Microsoft and Salesforce are optional and off here: the local stack has
      # no tenant or org to collect from. To serve one, export
      # ZASP_DISCOVERY_MICROSOFT_COLLECTOR_VERSION=collector_v1 or
      # ZASP_DISCOVERY_SALESFORCE_COLLECTOR_VERSION=collector_v1 before starting
      # both this worker and the API; an unset variable leaves the collector
      # unregistered and the connector out of the catalog.
      export ZASP_KUBERNETES_EGRESS_CIDRS=203.0.113.0/24 ZASP_DISCOVERY_READINESS_TIMEOUT=5s
      export ZASP_GITHUB_APP_ID=123456 ZASP_GITHUB_PRIVATE_KEY_REFERENCE=ref:github/app-private-key
      export ZASP_OKTA_CLIENT_ID=0oa1234567890abcdef ZASP_OKTA_CLIENT_SECRET_REFERENCE=ref:okta/client-secret
      ;;
    security-agent)
      # Plans and executes Security Agent runs. The planner endpoint, model
      # and token path are fixed by the worker; the token comes from
      # OPENROUTER_API_KEY and is written only to that path. The pricing
      # approval of each Environment is read from the database when a planner
      # request is priced; ZASP_REAL_STACK_PRICING_BINDINGS may name an
      # override file. The planner client does not use a proxy, so planning
      # needs direct egress to openrouter.ai.
      [ -n "${OPENROUTER_API_KEY:-}" ] || fail "set OPENROUTER_API_KEY to start the Security Agent worker"
      provision_local_cloud
      provision_security_agent_secrets
      configure_test_selector
      set -a; . "$STATE/cloud.env"; set +a
      export ZASP_LOCAL_HEALTH_PORT=8084
      export ZASP_POSTGRES_DSN="$(dsn zasp_svc_security_agent_worker)" ZASP_DATABASE_AUTHORITY=zasp_security_agent_worker
      export ZASP_TEMPORAL_EXECUTOR_POSTGRES_DSN="$(dsn zasp_svc_temporal_executor)" ZASP_TEMPORAL_COMPENSATION_POSTGRES_DSN="$(dsn zasp_svc_temporal_compensation)"
      export ZASP_AUTHORIZATION_WORKER_KEY_FILE="$SECRETS/forward.seed" ZASP_AUTHORIZATION_COMPENSATION_KEY_FILE="$SECRETS/compensation.seed"
      export ZASP_SECURITY_AGENT_PLANNER_ENDPOINT=https://openrouter.ai/api/v1/chat/completions ZASP_SECURITY_AGENT_PLANNER_MODEL=openai/gpt-5-mini
      export ZASP_SECURITY_AGENT_PLANNER_TOKEN_FILE=/var/run/secrets/zasp-security-agent/openrouter-api-token
      export ZASP_SECURITY_AGENT_PLANNER_TIMEOUT=20s ZASP_SECURITY_AGENT_PLANNER_MAX_TOKENS=2048 ZASP_SECURITY_AGENT_PLANNER_POLICY_VERSION=security-agent-planner-v1
      export ZASP_GATEWAY_SIGNING_KEY_ID=real-stack-gateway ZASP_GATEWAY_SIGNING_PRIVATE_KEY_FILE=/var/run/secrets/zasp-security-agent-action/gateway-signing-private-key
      export ZASP_GATEWAY_POLICY_KEYS_FILE=/var/run/zasp-policy-verifier/policy-keys.json
      export ZASP_EVIDENCE_BUCKET=zasp-real-stack-evidence ZASP_EVIDENCE_BUCKET_OWNER=000000000000
      export ZASP_RED_TEAM_ROLE_ARN=arn:aws:iam::000000000000:role/zasp-real-stack-discovery ZASP_RED_TEAM_WEB_IDENTITY_TOKEN_FILE="$TOKEN_FILE"
      # The existing-test runner (Node and promptfoo at fixed paths) and its
      # in-cluster adapter are not part of this stack. The worker requires
      # their configuration to start; a run that reaches a test step fails
      # there. The image reference only has to name a digest.
      export ZASP_RED_TEAM_RUNNER_IMAGE="zasp/agentsec-red-team-runner@sha256:$(printf 'real-stack-no-runner' | sha256sum | cut -d' ' -f1)"
      export ZASP_RED_TEAM_RUNNER_TIMEOUT=5m ZASP_RED_TEAM_TARGET_ENDPOINT=https://agentsec-red-team-adapter.zasp.svc.cluster.local/v1/evaluate
      export ZASP_RED_TEAM_TARGET_TOKEN_FILE="$SECRETS/red-team-adapter.token" ZASP_RED_TEAM_TARGET_CA_FILE="$SECRETS/red-team-adapter-ca.pem"
      [ -z "${ZASP_REAL_STACK_PRICING_BINDINGS:-}" ] || export ZASP_TEMPORAL_PRICING_BINDINGS_FILE="$ZASP_REAL_STACK_PRICING_BINDINGS"
      ;;
    security-agent-action)
      # Executes the effects of temporary-policy, session-isolation and
      # connector-revocation actions and signs the policy envelopes the
      # gateway verifies. It needs only the database and the signing key.
      provision_security_agent_secrets
      export ZASP_LOCAL_HEALTH_PORT=8085
      export ZASP_POSTGRES_DSN="$(dsn zasp_svc_security_agent_action)" ZASP_DATABASE_AUTHORITY=zasp_security_agent_action_worker
      export ZASP_GATEWAY_SIGNING_KEY_ID=real-stack-gateway ZASP_GATEWAY_SIGNING_PRIVATE_KEY_FILE=/var/run/secrets/zasp-security-agent-action/gateway-signing-private-key
      ;;
    # The three projection workers turn a completed discovery snapshot into
    # the graph, the search index, and the findings and attack paths.
    projection-graph)
      provision_local_cloud
      export ZASP_LOCAL_HEALTH_PORT=8091
      export ZASP_POSTGRES_DSN="$(dsn zasp_svc_projection_graph)" ZASP_DATABASE_AUTHORITY=zasp_projection_graph_worker
      export ZASP_PROJECTION_ROLE_ARN=arn:aws:iam::000000000000:role/zasp-real-stack-projection-graph ZASP_PROJECTION_WEB_IDENTITY_TOKEN_FILE="$TOKEN_FILE"
      export ZASP_PROJECTION_SECRET_PREFIX="$PROJECTION_SECRET_PREFIX" ZASP_NEO4J_URI="$NEO4J_URI" ZASP_NEO4J_CREDENTIAL_REFERENCE=ref:neo4j/auth/graph-worker
      export ZASP_NEO4J_EXPECTED_PRINCIPAL="$NEO4J_WORKER_USER" ZASP_NEO4J_EXPECTED_ROLE="$NEO4J_WORKER_ROLE"
      # Trusted for the graph connection only, and only in development mode.
      export ZASP_LOCAL_NEO4J_CA_FILE="$TLS/neo4j/ca.crt"
      ;;
    projection-search)
      export ZASP_LOCAL_HEALTH_PORT=8092
      export ZASP_POSTGRES_DSN="$(dsn zasp_svc_projection_search)" ZASP_DATABASE_AUTHORITY=zasp_projection_search_worker
      export ZASP_PROJECTION_ROLE_ARN=arn:aws:iam::000000000000:role/zasp-real-stack-projection-search ZASP_PROJECTION_WEB_IDENTITY_TOKEN_FILE="$TOKEN_FILE"
      export ZASP_OPENSEARCH_ENDPOINT="$SEARCH_URL" ZASP_OPENSEARCH_INDEX=zasp-inventory-v1
      ;;
    projection-risk)
      export ZASP_LOCAL_HEALTH_PORT=8093
      export ZASP_POSTGRES_DSN="$(dsn zasp_svc_projection_risk)" ZASP_DATABASE_AUTHORITY=zasp_projection_risk_worker
      ;;
    *) fail "worker mode '$1' is not available on this stack yet" ;;
  esac
  exec "$BIN/agentsec-worker"
}

# The Security Agent worker reconciles the schedules of automatic agents from
# the test-selector configuration, an operator setting no other step installs.
# Without a first revision the worker refuses to start. An existing
# configuration is left as it is.
configure_test_selector() {
  local revision
  revision="$(psql -X -Atc "SET ROLE zasp_discovery_authority; SELECT count(*) FROM zasp_temporal75.configuration" "$(dsn "$OPERATOR")" | tail -1)" || fail "test-selector configuration was not read"
  [ "$revision" = "0" ] || return 0
  ZASP_POSTGRES_DSN="$(dsn "$OPERATOR")" ZASP_MIGRATION_TIMEOUT=60s ZASP_TEST_SELECTOR_CONFIGURATION='{"revision":1,"cadence_seconds":300,"enabled":true}' \
    "$BIN/agentsec-migrate" configure-temporal-test-selector || fail "test-selector configuration was refused"
}

# Writes the secrets the Security Agent workers read at fixed paths, with the
# modes a Kubernetes secret mount has. The gateway signing key and the red-team
# adapter credentials are generated once and kept in the stack's state.
provision_security_agent_secrets() {
  local key="$SECRETS/gateway-signing.key" public
  if [ ! -f "$key" ] || [ ! -f "$SECRETS/gateway-policy-keys.json" ]; then
    (
      umask 077
      openssl genpkey -algorithm ed25519 -outform DER -out "$SECRETS/gateway-signing.der" || exit 1
      public="$(openssl pkey -inform DER -in "$SECRETS/gateway-signing.der" -pubout -outform DER | tail -c 32 | base64 -w0 | tr '+/' '-_' | tr -d '=')" || exit 1
      # The worker's private key file is the 64-byte Ed25519 key (seed, then
      # public key) in unpadded base64url: 86 characters, no newline.
      { tail -c 32 "$SECRETS/gateway-signing.der"; openssl pkey -inform DER -in "$SECRETS/gateway-signing.der" -pubout -outform DER | tail -c 32; } | base64 -w0 | tr '+/' '-_' | tr -d '=' > "$key.partial" || exit 1
      printf '{"keys":[{"key_id":"real-stack-gateway","public_key":"%s"}]}' "$public" > "$SECRETS/gateway-policy-keys.json.partial" || exit 1
      rm -f "$SECRETS/gateway-signing.der"
      mv "$SECRETS/gateway-policy-keys.json.partial" "$SECRETS/gateway-policy-keys.json" && mv "$key.partial" "$key"
    ) || fail "gateway signing key was not generated"
  fi
  if [ ! -f "$SECRETS/red-team-adapter.token" ] || [ ! -f "$SECRETS/red-team-adapter-ca.pem" ]; then
    (
      umask 077
      openssl rand -hex 32 | tr -d '\n' > "$SECRETS/red-team-adapter.token.partial" || exit 1
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout /dev/null -days 365 -subj "/CN=real-stack red-team adapter (not deployed)" \
        -out "$SECRETS/red-team-adapter-ca.pem.partial" 2>/dev/null || exit 1
      chmod 0400 "$SECRETS/red-team-adapter.token.partial" "$SECRETS/red-team-adapter-ca.pem.partial"
      mv "$SECRETS/red-team-adapter-ca.pem.partial" "$SECRETS/red-team-adapter-ca.pem" && mv "$SECRETS/red-team-adapter.token.partial" "$SECRETS/red-team-adapter.token"
    ) || fail "red-team adapter credentials were not generated"
  fi
  install -d -m 0700 /var/run/secrets/zasp-security-agent /var/run/secrets/zasp-security-agent-action /var/run/zasp-policy-verifier ||
    fail "create /var/run/secrets/zasp-security-agent, /var/run/secrets/zasp-security-agent-action and /var/run/zasp-policy-verifier (needs root)"
  # Replace, never rewrite in place: the files are read-only.
  # The planner token is replaced only when a new one is given: the action
  # worker starts without it and must not remove the planner's.
  rm -f /var/run/secrets/zasp-security-agent-action/gateway-signing-private-key /var/run/zasp-policy-verifier/policy-keys.json
  if [ -n "${OPENROUTER_API_KEY:-}" ]; then
    rm -f /var/run/secrets/zasp-security-agent/openrouter-api-token
    (umask 077; printf '%s' "$OPENROUTER_API_KEY" > /var/run/secrets/zasp-security-agent/openrouter-api-token) || fail "planner token was not written"
    # The worker requires the mode a Kubernetes secret mount has (0444); the
    # directory above keeps other users out.
    chmod 0444 /var/run/secrets/zasp-security-agent/openrouter-api-token
  fi
  install -m 0400 "$key" /var/run/secrets/zasp-security-agent-action/gateway-signing-private-key || fail "gateway signing key was not installed"
  install -m 0400 "$SECRETS/gateway-policy-keys.json" /var/run/zasp-policy-verifier/policy-keys.json || fail "gateway policy keys were not installed"
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

# Creates the certificate the TLS front serves: a certificate authority that
# may only vouch for this one host name, and a server certificate from it. The
# authority's key is deleted once the server certificate is signed, so trusting
# ca.crt on this machine cannot be used to impersonate any other site.
ensure_certificate() {
  mkdir -p "$TLS"
  chmod 700 "$TLS"
  if [ -f "$TLS/ca.crt" ] && [ -f "$TLS/server.crt" ] && [ -f "$TLS/server.key" ] &&
    openssl x509 -in "$TLS/server.crt" -noout -checkend 86400 >/dev/null 2>&1 &&
    openssl x509 -in "$TLS/server.crt" -noout -text 2>/dev/null | grep -q "DNS:$ORIGIN_HOST"; then
    return 0
  fi
  (
    umask 077
    cd "$TLS" || exit 1
    rm -f ca.crt ca.key ca.srl server.crt server.key server.csr leaf.crt openssl.cnf
    printf '%s\n' '[req]' 'distinguished_name = dn' 'prompt = no' '[dn]' 'CN = unused' \
      '[ca]' 'basicConstraints = critical, CA:TRUE, pathlen:0' 'keyUsage = critical, keyCertSign' 'subjectKeyIdentifier = hash' \
      "nameConstraints = critical, permitted;DNS:$ORIGIN_HOST" \
      '[leaf]' 'basicConstraints = critical, CA:FALSE' 'keyUsage = critical, digitalSignature, keyEncipherment' \
      'extendedKeyUsage = serverAuth' "subjectAltName = DNS:$ORIGIN_HOST" > openssl.cnf
    # 825 days is the longest validity Apple platforms accept for a server certificate.
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 825 -keyout ca.key -out ca.crt \
      -subj "/CN=Zasp local stack development CA for $ORIGIN_HOST" -config openssl.cnf -extensions ca >/dev/null 2>&1 &&
      openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=$ORIGIN_HOST" -config openssl.cnf >/dev/null 2>&1 &&
      openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -sha256 -days 825 \
        -extfile openssl.cnf -extensions leaf -out leaf.crt >/dev/null 2>&1 &&
      cat leaf.crt ca.crt > server.crt
    status=$?
    rm -f ca.key ca.srl server.csr leaf.crt openssl.cnf
    [ "$status" -eq 0 ] || { rm -f ca.crt server.crt server.key; exit 1; }
  ) || fail "the TLS certificate was not created (openssl is required)"
  echo "real-stack: created a TLS certificate for $ORIGIN_HOST; to trust it in the browser, trust $TLS/ca.crt (see docs/operations/local-self-test.md)"
}

# The browser must reach the stack under its public host name: the session
# cookie and the sign-in redirect are bound to it. This script never edits
# system files; it prints the line to add.
hosts_mapped() {
  grep -Eq "^[[:space:]]*127\.0\.0\.1[[:space:]]+([^#]*[[:space:]])?$ORIGIN_HOST([[:space:]]|#|\$)" /etc/hosts 2>/dev/null
}
hosts_hint() {
  echo "real-stack: $ORIGIN_HOST is not mapped to this machine. Run once:"
  echo "  echo '127.0.0.1 $ORIGIN_HOST' | sudo tee -a /etc/hosts"
}

# Builds the web application when it has not been built or its sources changed.
build_web() {
  command -v node >/dev/null 2>&1 || fail "Node.js is required for the web application (see package.json for the version)"
  [ -d "$ROOT/node_modules" ] || fail "install the web dependencies first: (cd '$ROOT' && npm ci)"
  local stamp="$ROOT/dist/server/BUILD_ID"
  if [ -f "$ROOT/dist/standalone/server.js" ] && [ -f "$stamp" ] &&
    [ -z "$(find "$ROOT/app" "$ROOT/apps" "$ROOT/public" "$ROOT/worker" "$ROOT/package-lock.json" "$ROOT/vite.config.ts" "$ROOT/next.config.ts" -type f -newer "$stamp" 2>/dev/null | head -n 1)" ]; then
    return 0
  fi
  echo "real-stack: building the web application (about a minute)"
  (cd "$ROOT" && npm run build) || fail "the web application was not built"
  WEB_REBUILT=1
  [ -f "$ROOT/dist/standalone/server.js" ] || fail "the web application build produced no dist/standalone/server.js"
}

# Serves the web application over HTTPS on the public origin and forwards /api
# to the product API with the headers the production ingress sends. Foreground.
cmd_ui() {
  ensure_certificate
  build_web
  hosts_mapped || hosts_hint >&2
  export ZASP_FRONT_ORIGIN="$PUBLIC_ORIGIN" ZASP_FRONT_API=http://127.0.0.1:4000
  export ZASP_FRONT_WEB_DIR="$ROOT/dist/standalone" ZASP_FRONT_WEB_PORT="$WEB_PORT"
  export ZASP_FRONT_CERT="$TLS/server.crt" ZASP_FRONT_KEY="$TLS/server.key"
  exec node "$HERE/front.mjs"
}

# Applies pending permission changes every few seconds, in the foreground. A
# new Organization, member or resource answers 'authorization_unavailable'
# until a pass has run. In production a CronJob runs the same command with the
# same arguments once a minute.
cmd_project() {
  [ "$#" -eq 0 ] || fail "usage: $0 project"
  claim_machine
  require_provider
  load_environment
  local interval="${ZASP_REAL_STACK_PROJECT_INTERVAL:-5}" reconcile_dsn
  reconcile_dsn="$(dsn zasp_svc_outbox)"
  trap 'exit 0' INT TERM
  echo "real-stack: applying permission changes every ${interval}s"
  while :; do
    ZASP_POSTGRES_DSN="$reconcile_dsn" "$BIN/zasp-authorization-reconcile" -mode reconcile -limit 20 -timeout 1m ||
      echo "real-stack: $(date '+%H:%M:%S') a permission pass failed; it is repeated" >&2
    sleep "$interval"
  done
}

# The background processes of 'start', in start order.
PROCESSES="api worker-scheduler worker-discovery worker-outbox worker-projection-graph worker-projection-search worker-projection-risk worker-security-agent-action projector ui"

# The HTTP status of a local address, or 000 when nothing answers. A proxy
# configured for outbound traffic must not be asked for a loopback address.
http_status() {
  local code
  code="$(curl -s --noproxy '*' -m 5 -o /dev/null -w '%{http_code}' "$@" 2>/dev/null)" || true
  echo "${code:-000}"
}

# The status a process reports about itself: 200 when ready, 000 when nothing
# answers. The projector has no listener; it is ready while it runs.
process_status() {
  case "$1" in
    api) http_status http://127.0.0.1:4081/readyz ;;
    worker-scheduler) http_status http://127.0.0.1:8081/readyz ;;
    worker-discovery) http_status http://127.0.0.1:8082/readyz ;;
    worker-outbox) http_status http://127.0.0.1:8083/readyz ;;
    worker-projection-graph) http_status http://127.0.0.1:8091/readyz ;;
    worker-projection-search) http_status http://127.0.0.1:8092/readyz ;;
    worker-projection-risk) http_status http://127.0.0.1:8093/readyz ;;
    worker-security-agent-action) http_status http://127.0.0.1:8085/readyz ;;
    ui) http_status --cacert "$TLS/ca.crt" --resolve "$ORIGIN_HOST:$ORIGIN_PORT:127.0.0.1" "$PUBLIC_ORIGIN/sign-in" ;;
    projector) if process_alive projector; then echo 200; else echo 000; fi ;;
  esac
}

process_pid() { cat "$RUN/$1.pid" 2>/dev/null || true; }

# True when the recorded process still runs. The command is checked as well: a
# pid left in a file from before a reboot may belong to something else by now.
process_alive() {
  local pid
  pid="$(process_pid "$1")"
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null &&
    ps -p "$pid" -o command= 2>/dev/null | grep -Eq 'real-stack/(stack\.sh|front\.mjs)|agentsec-(api|worker)'
}

# Starts one process in the background unless it already runs. Arguments: the
# process name, then the stack.sh command that runs it in the foreground.
launch() {
  local name="$1"
  shift
  if process_alive "$name"; then
    echo "real-stack: $name is already running"
    return 0
  fi
  if [ "$(process_status "$name")" != "000" ]; then
    echo "real-stack: $name is already answering; it was not started by 'start' and is left alone"
    return 0
  fi
  mkdir -p "$RUN" "$LOGS"
  nohup "$HERE/stack.sh" "$@" >> "$LOGS/$name.log" 2>&1 < /dev/null &
  echo "$!" > "$RUN/$name.pid"
  echo "real-stack: started $name (log: $LOGS/$name.log)"
}

# Waits until a process reports ready. Arguments: name, seconds.
wait_ready() {
  local name="$1" remaining="$2"
  while [ "$remaining" -gt 0 ]; do
    [ "$(process_status "$name")" = "200" ] && return 0
    if [ -f "$RUN/$name.pid" ] && ! process_alive "$name"; then
      echo "real-stack: $name stopped. Last lines of $LOGS/$name.log:" >&2
      tail -n 5 "$LOGS/$name.log" >&2 || true
      return 1
    fi
    sleep 2
    remaining=$((remaining - 2))
  done
  echo "real-stack: $name is not ready yet; see $LOGS/$name.log" >&2
  return 1
}

# True when 'up' has to run: it never completed, or a dependency is not running.
needs_up() {
  [ -f "$STATE/up.done" ] && [ -f "$SECRETS/keys.env" ] && [ -f "$STATE/fga.env" ] && [ -s "$TOKEN_FILE" ] &&
    [ -x "$BIN/agentsec-api" ] && [ -x "$BIN/agentsec-worker" ] && [ -x "$BIN/zasp-authorization-reconcile" ] || return 0
  local name
  for name in $(dependency_names); do
    dependency_running "$name" || return 0
  done
  return 1
}

dependency_names() {
  [ -n "$EXTERNAL_HOST" ] || echo postgres
  echo localstack opensearch neo4j temporal openfga
}

dependency_running() {
  case "$1" in
    postgres) [ "$(docker inspect --format '{{.State.Running}}' "$PG_CONTAINER" 2>/dev/null)" = "true" ] ;;
    localstack) curl -fsS -m 3 "$LOCAL_CLOUD/_localstack/health" 2>/dev/null | grep -q '"sts"' ;;
    opensearch) [ "$(http_status "$SEARCH_URL/_cluster/health")" = "200" ] ;;
    neo4j) [ "$(docker inspect --format '{{.State.Running}}' "$NEO4J_CONTAINER" 2>/dev/null)" = "true" ] && (exec 3<>/dev/tcp/127.0.0.1/7687) 2>/dev/null ;;
    temporal) (exec 3<>/dev/tcp/127.0.0.1/7233) 2>/dev/null ;;
    openfga) [ "$(http_status "$FGA_URL/healthz")" = "200" ] ;;
  esac
}

# Starts everything in the background: the dependencies and the schema when
# they are not up, the API, the six workers, the permission projector and
# the web application behind its TLS front. Safe to repeat.
cmd_start() {
  [ "$#" -eq 0 ] || fail "usage: $0 start"
  claim_machine
  require_provider
  command -v node >/dev/null 2>&1 || fail "Node.js is required for the web application (see package.json for the version)"
  [ -d "$ROOT/node_modules" ] || fail "install the web dependencies first: (cd '$ROOT' && npm ci)"
  # In a subshell: 'up' exports operator settings the processes must not inherit.
  if needs_up; then (cmd_up); fi
  if [ ! -f "$STATE/organization.env" ]; then
    echo "real-stack: no Organization yet. Create the first one, then run '$0 start' again:"
    echo "  $0 bootstrap <organization name> <domain> <admin email>"
    return 0
  fi
  # Created here once so the API and the workers do not create it concurrently.
  docker exec zasp-real-stack-localstack awslocal --region us-east-1 iam get-role --role-name "$CUSTOMER_ROLE_NAME" >/dev/null 2>&1 || provision_local_cloud
  ensure_certificate
  WEB_REBUILT=0
  build_web
  # A running web application still serves the build it started with.
  [ "$WEB_REBUILT" -eq 0 ] || stop_process ui
  [ -x /opt/zasp/security/cartography/bin/security-worker ] && [ -x /opt/zasp/security/prowler/bin/security-worker ] ||
    echo "real-stack: the security analyzers are not installed; an AWS sync will fail until '$0 security-workers' has run" >&2
  launch api api
  launch worker-scheduler worker scheduler
  launch worker-discovery worker discovery
  launch worker-outbox worker outbox
  launch worker-projection-graph worker projection-graph
  launch worker-projection-search worker projection-search
  launch worker-projection-risk worker projection-risk
  # The planning worker ('$0 worker security-agent') needs OPENROUTER_API_KEY
  # and is started by hand; the action worker needs nothing but the database.
  launch worker-security-agent-action worker security-agent-action
  launch projector project
  launch ui ui
  local failed=0
  wait_ready api 120 || failed=1
  wait_ready worker-scheduler 120 || failed=1
  wait_ready worker-discovery 180 || failed=1
  wait_ready worker-outbox 180 || failed=1
  wait_ready worker-projection-graph 120 || failed=1
  wait_ready worker-projection-search 120 || failed=1
  wait_ready worker-projection-risk 120 || failed=1
  wait_ready worker-security-agent-action 120 || failed=1
  wait_ready projector 4 || failed=1
  wait_ready ui 90 || failed=1
  cmd_status
  hosts_mapped || hosts_hint
  if [ "$failed" -eq 0 ]; then
    echo "real-stack: open $PUBLIC_ORIGIN/"
  else
    echo "real-stack: not everything is ready; see the logs in $LOGS" >&2
    return 1
  fi
}

# One line per dependency and per process.
cmd_status() {
  local name pid state ready
  for name in $(dependency_names); do
    if dependency_running "$name"; then state="running"; else state="stopped"; fi
    printf '%-26s %s\n' "$name" "$state"
  done
  for name in $PROCESSES; do
    pid="$(process_pid "$name")"
    ready="$(process_status "$name")"
    if process_alive "$name"; then
      state="running (pid $pid)"
    elif [ "$ready" != "000" ]; then
      state="running (not started by 'start')"
    else
      state="stopped"
    fi
    if [ "$state" = "stopped" ]; then
      printf '%-26s %s\n' "$name" "$state"
    elif [ "$ready" = "200" ]; then
      printf '%-26s %s, ready\n' "$name" "$state"
    else
      printf '%-26s %s, not ready\n' "$name" "$state"
    fi
  done
  if hosts_mapped; then state="present"; else state="missing"; fi
  printf '%-26s %s\n' "hosts entry" "$state"
  if [ -x /opt/zasp/security/cartography/bin/security-worker ] && [ -x /opt/zasp/security/prowler/bin/security-worker ]; then state="installed"; else state="not installed"; fi
  printf '%-26s %s\n' "security analyzers" "$state"
}

# Stops one process 'start' started, if it runs, and forgets its pid.
stop_process() {
  local name="$1" pid waited=0
  pid="$(process_pid "$name")"
  if process_alive "$name"; then
    kill "$pid" 2>/dev/null || true
    while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt 10 ]; do
      sleep 1
      waited=$((waited + 1))
    done
    kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
    echo "real-stack: stopped $name"
  fi
  rm -f "$RUN/$name.pid"
}

# Stops the processes 'start' started. The containers keep running; 'down'
# stops those too.
cmd_stop() {
  local name reversed=""
  for name in $PROCESSES; do reversed="$name $reversed"; done
  for name in $reversed; do stop_process "$name"; done
}

cmd_down() {
  cmd_stop
  docker stop "$PG_CONTAINER" zasp-real-stack-localstack zasp-real-stack-opensearch "$NEO4J_CONTAINER" >/dev/null 2>&1 || true
  docker compose -f "$COMPOSE" stop
  echo "real-stack: stopped; data is kept. Remove '$PG_CONTAINER' and '$STATE' to start over."
}

case "${1:-}" in
  up) shift; cmd_up "$@" ;;
  bootstrap) shift; cmd_bootstrap "$@" ;;
  api) shift; cmd_api "$@" ;;
  worker) shift; cmd_worker "$@" ;;
  security-workers) shift; cmd_security_workers "$@" ;;
  ui) shift; cmd_ui "$@" ;;
  project) shift; cmd_project "$@" ;;
  start) shift; cmd_start "$@" ;;
  status) shift; cmd_status "$@" ;;
  stop) shift; cmd_stop "$@" ;;
  down) shift; cmd_down "$@" ;;
  *) fail "usage: $0 {start|status|stop|up|bootstrap <organization name> <domain> <admin email>|api|worker <mode>|ui|project|security-workers|down}" ;;
esac
