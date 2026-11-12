#!/usr/bin/env bash
# Rebuilds the baseline schema artifact (baseline.sql.gz, roles.sql,
# baseline.sha256) from the historical migration chain.
#
# The historical chain needs a PostgreSQL superuser. Managed PostgreSQL (Neon,
# RDS, Cloud SQL) gives the owner CREATEROLE but not SUPERUSER, so the chain
# cannot run there. This script runs the chain once on a throwaway superuser
# database, replays the result as a non-superuser owner, rewrites the
# historical self-verification to the baseline integrity check (rules.sql),
# proves every readiness predicate still agrees with the superuser
# installation, and dumps the result. `agentsec-migrate install-baseline`
# installs that dump with no superuser.
#
# Requirements: docker, go, psql. Takes about three minutes.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PLATFORM="$(cd "$HERE/../.." && pwd)"
PG_IMAGE="${ZASP_BASELINE_PG_IMAGE:-public.ecr.aws/docker/library/postgres:18.3}"
CONTAINER="${ZASP_BASELINE_CONTAINER:-zasp-baseline-generator}"
PORT="${ZASP_BASELINE_PORT:-55460}"
OPERATOR=zasp_operator
# The approval-notification delivery login. Unlike the other service logins it
# does not inherit: it acts only through SET LOCAL ROLE inside owned calls.
APPROVAL_LOGIN=zasp_svc_approval_maintenance
REFERENCE_PORT="$PORT"
REPLAY_PORT="$((PORT + 1))"
ACTIVE_PORT="$REFERENCE_PORT"
# ZASP_BASELINE_KEEP=<directory> keeps the intermediate files and both
# database containers. A later run with the same directory reuses the
# superuser installation, which is the slow part, so changes to the rules or
# the comparison can be tried in seconds.
if [ -n "${ZASP_BASELINE_KEEP:-}" ]; then
  WORK="$ZASP_BASELINE_KEEP"; mkdir -p "$WORK"
else
  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"; docker rm -f "$CONTAINER-reference" "$CONTAINER-replay" >/dev/null 2>&1 || true' EXIT
fi

fail() { echo "baseline: $*" >&2; exit 1; }
url() { echo "postgres://$1@127.0.0.1:$ACTIVE_PORT/$2?sslmode=disable"; }
start_postgres() {
  docker rm -f "$1" >/dev/null 2>&1 || true
  docker run -d --name "$1" -e POSTGRES_USER=postgres -e POSTGRES_HOST_AUTH_METHOD=trust \
    -e POSTGRES_INITDB_ARGS="--no-locale --encoding=UTF8" -p "127.0.0.1:$2:5432" "$PG_IMAGE" -c max_connections=100 >/dev/null
  for _ in $(seq 1 120); do psql -X -Atc 'select 1' "postgres://postgres@127.0.0.1:$2/postgres?sslmode=disable" >/dev/null 2>&1 && break; sleep 0.5; done
  # The image restarts the server once after initialisation.
  sleep 2
  for _ in $(seq 1 120); do psql -X -Atc 'select 1' "postgres://postgres@127.0.0.1:$2/postgres?sslmode=disable" >/dev/null 2>&1 && break; sleep 0.5; done
}
sql() { psql -X -q -v ON_ERROR_STOP=1 "$@"; }

# The fixed service logins. Deployments set a password on each; the names are
# part of the baseline because the principal bindings are stored in it.
LOGINS=(
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

# Zero-argument boolean predicates in the product schemas, evaluated by the
# cluster superuser so both installations are read the same way.
predicates() {
  local database="$1" names name
  names="$(psql -X -Atc "select n.nspname||'.'||p.proname from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where p.pronargs=0 and p.prorettype='bool'::regtype and p.provolatile<>'v' and n.nspname<>'zasp_baseline'
      and (n.nspname like 'zasp\_%' or (n.nspname='public' and p.proname like 'zasp\_%')) order by 1" "$(url postgres "$database")")"
  for name in $names; do
    echo "$name=$(psql -X -Atc "select $name()" "$(url postgres "$database")" 2>/dev/null | tail -1 | cut -c1-8)"
  done
  # Each layer's readiness, called with the identity its registration records.
  names="$(psql -X -Atc "select n.nspname from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where p.proname='ready' and p.pronargs=2 and n.nspname like 'zasp\_%' and to_regclass(n.nspname||'.registration') is not null order by 1" "$(url postgres "$database")")"
  for name in $names; do
    echo "$name.ready(registration)=$(psql -X -Atc "select $name.ready(checksum,fingerprint) from $name.registration" "$(url postgres "$database")" 2>/dev/null | tail -1 | cut -c1-8)"
  done
}

# agentsec-migrate embeds the artifact this script produces, so a first run
# needs placeholders for the build.
for artifact in baseline.sql.gz roles.sql baseline.sha256; do [ -f "$HERE/$artifact" ] || : > "$HERE/$artifact"; done
go build -C "$PLATFORM" -o "$WORK/agentsec-migrate" ./agentsec-migrate

if [ -n "${ZASP_BASELINE_KEEP:-}" ] && [ "$(psql -X -Atc "select count(*) from zasp_schema_versions" "$(url postgres reference)" 2>/dev/null)" = "61" ]; then
  echo "baseline: reusing the kept superuser installation"
else
  echo "baseline: installing the historical chain as a superuser"
  start_postgres "$CONTAINER-reference" "$REFERENCE_PORT"
  sql "$(url postgres postgres)" -c "CREATE ROLE $OPERATOR LOGIN SUPERUSER" \
    -c "CREATE DATABASE reference OWNER $OPERATOR TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C'"
  for assignment in "${LOGINS[@]}"; do
    sql "$(url "$OPERATOR" reference)" -c "CREATE ROLE ${assignment#*=} LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
  done
  (
    for assignment in "${LOGINS[@]}"; do export "${assignment?}"; done
    export ZASP_MIGRATION_DB_PRINCIPAL="$OPERATOR" ZASP_MIGRATION_TIMEOUT=20m ZASP_POSTGRES_DSN="$(url "$OPERATOR" reference)"
    "$WORK/agentsec-migrate" up-authorization-runtime-profile || fail "historical chain refused"
    "$WORK/agentsec-migrate" register-temporal-executor-principals || fail "executor principal registration refused"
  )
fi

# Approval-notification delivery. The chain ships the approval-maintenance
# profile inactive and without an installer. The baseline installs it, binds
# its dedicated login and activates it (activation.sql).
if [ "$(psql -X -Atc "select to_regprocedure('zasp_approval_maintenance.activate_projection(text)') is not null" "$(url postgres reference)")" != "t" ]; then
  echo "baseline: installing and activating approval-notification delivery"
  [ "$(psql -X -Atc "select to_regnamespace('zasp_approval_maintenance') is null" "$(url postgres reference)")" = "t" ] || fail "a partial approval-maintenance installation exists; remove the kept containers"
  sql "$(url "$OPERATOR" reference)" -c "CREATE ROLE $APPROVAL_LOGIN LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
  ZASP_MIGRATION_TIMEOUT=20m ZASP_POSTGRES_DSN="$(url "$OPERATOR" reference)" "$WORK/agentsec-migrate" up-approval-maintenance-profile || fail "approval-maintenance profile refused"
  {
    echo "BEGIN;"
    echo "GRANT zasp_approval_maintenance_worker TO $APPROVAL_LOGIN;"
    echo "SELECT zasp_approval_maintenance.register_principal('$APPROVAL_LOGIN');"
    echo "SET LOCAL ROLE zasp_discovery_authority;"
    cat "$HERE/activation.sql"
    # The profile records its own catalog fingerprint; activation changed the catalog.
    echo "UPDATE zasp_approval_maintenance.registration SET fingerprint=zasp_approval_maintenance.fingerprint() WHERE singleton;"
    echo "COMMIT;"
  } > "$WORK/activation-run.sql"
  sql "$(url "$OPERATOR" reference)" -f "$WORK/activation-run.sql" >/dev/null
  [ "$(psql -X -Atc "select zasp_approval_maintenance.ready()" "$(url postgres reference)")" = "t" ] || fail "approval-maintenance profile is not ready after activation"
fi
docker exec "$CONTAINER-reference" pg_dumpall -U postgres --roles-only --no-role-passwords > "$WORK/roles.raw"
docker exec "$CONTAINER-reference" pg_dump -U postgres -d reference --inserts --rows-per-insert=200 > "$WORK/reference.sql"
predicates reference > "$WORK/reference.predicates"
# The reference structure is compared after the same membership rewrite the
# dump receives, because views and policies print the relation name.
psql -X -At -v ON_ERROR_STOP=1 -v memberships=pg_auth_members -f "$HERE/structure.sql" "$(url postgres reference)" \
  | sed -E 's/pg_catalog\.pg_auth_members/zasp_baseline.role_memberships/g; s/(^|[^A-Za-z0-9_.])pg_auth_members/\1zasp_baseline.role_memberships/g' > "$WORK/reference.structure"

echo "baseline: replaying as a non-superuser owner"
ACTIVE_PORT="$REPLAY_PORT"
start_postgres "$CONTAINER-replay" "$REPLAY_PORT"
sql "$(url postgres postgres)" -c "CREATE ROLE $OPERATOR LOGIN CREATEROLE BYPASSRLS" \
  -c "CREATE DATABASE baseline OWNER $OPERATOR TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C'"

# Role script: the product roles, their attributes and memberships. A
# non-superuser cannot set SUPERUSER/REPLICATION/BYPASSRLS, and can set
# CREATEROLE/CREATEDB only if it holds them itself. All five are off, which is
# what a new role gets, so the script does not name them. The operator
# cannot attribute a grant to another role, and already holds
# ADMIN on every role it creates, so its own grant keeps INHERIT and SET only.
grep -E "^(CREATE ROLE|ALTER ROLE|GRANT) " "$WORK/roles.raw" | grep -E "zasp_" \
  | grep -vE "^(CREATE|ALTER) ROLE $OPERATOR[ ;]" \
  | sed -E "s/ GRANTED BY [a-z_0-9]+//; s/ NOSUPERUSER//; s/ NOREPLICATION//; s/ NOBYPASSRLS//; s/ NOCREATEROLE//; s/ NOCREATEDB//" \
  | sed -E "s/^(GRANT [a-z_0-9]+ TO $OPERATOR) WITH ADMIN OPTION, INHERIT TRUE;/\1 WITH INHERIT TRUE, SET TRUE;/" > "$WORK/roles.sql"
grep -qE "^GRANT zasp_discovery_authority TO $OPERATOR WITH INHERIT TRUE, SET TRUE;$" "$WORK/roles.sql" || fail "operator authority grant not found in the role dump"
if grep -E "(SUPERUSER|REPLICATION|BYPASSRLS)" "$WORK/roles.sql" | grep -vE " NO(SUPERUSER|REPLICATION|BYPASSRLS)" | grep -q .; then fail "a product role needs a superuser-only attribute"; fi

# Predicates read memberships through the baseline view (see prelude.sql).
grep -v '^\\' "$WORK/reference.sql" \
  | sed -E 's/pg_catalog\.pg_auth_members/zasp_baseline.role_memberships/g; s/(^|[^A-Za-z0-9_.])pg_auth_members/\1zasp_baseline.role_memberships/g' > "$WORK/transformed.sql"
grep -vE '^ALTER .* OWNER TO [a-z_0-9]+;$' "$WORK/transformed.sql" > "$WORK/objects.sql"
grep -E '^ALTER .* OWNER TO [a-z_0-9]+;$' "$WORK/transformed.sql" | grep -vE " OWNER TO $OPERATOR;$" > "$WORK/owners.sql"
owners="$(sed -E 's/.* OWNER TO ([a-z_0-9]+);$/\1/' "$WORK/owners.sql" | sort -u | paste -sd, -)"
cat > "$WORK/baseline-owner.sql" <<'SQL'
DO $$ DECLARE o record; BEGIN
  FOR o IN SELECT format('ALTER %s %s OWNER TO zasp_discovery_authority', CASE c.relkind WHEN 'v' THEN 'VIEW' ELSE 'TABLE' END, c.oid::regclass) AS statement
           FROM pg_class c WHERE c.relnamespace = 'zasp_baseline'::regnamespace AND c.relkind IN ('r', 'v')
           UNION ALL SELECT format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority', p.oid::regprocedure)
           FROM pg_proc p WHERE p.pronamespace = 'zasp_baseline'::regnamespace LOOP
    EXECUTE o.statement;
  END LOOP;
  ALTER SCHEMA zasp_baseline OWNER TO zasp_discovery_authority;
END $$;
SQL
target="$(url "$OPERATOR" baseline)"
sql "$target" -f "$WORK/roles.sql"
sql "$target" -f "$HERE/prelude.sql"
sql "$target" -f "$WORK/objects.sql" >/dev/null
# Ownership, the rewrite rules and the removal of the temporary privileges run
# in one transaction, as they do in the installer.
{
  echo "BEGIN;"
  echo "SELECT pg_catalog.set_config('zasp_baseline.owners', '$owners', true);"
  cat "$HERE/grant.sql" "$WORK/owners.sql" "$WORK/baseline-owner.sql" "$HERE/rules.sql" "$HERE/revoke.sql"
  echo "COMMIT;"
} > "$WORK/ownership.sql"
sql "$target" -f "$WORK/ownership.sql" >/dev/null

echo "baseline: comparing catalog structure with the superuser installation"
psql -X -At -v ON_ERROR_STOP=1 -v memberships=zasp_baseline.role_memberships -f "$HERE/structure.sql" "$(url postgres baseline)" > "$WORK/baseline.structure"
if diff "$WORK/reference.structure" "$WORK/baseline.structure" > "$WORK/structure.diff"; then :; else
  head -40 "$WORK/structure.diff" >&2
  fail "catalog structure differs from the superuser installation ($(grep -c '^[<>]' "$WORK/structure.diff") lines)"
fi

echo "baseline: comparing readiness predicates with the superuser installation"
sql "$target" -c "SELECT zasp_baseline.seal('$(printf '0%.0s' $(seq 64))')" >/dev/null
predicates baseline > "$WORK/baseline.predicates"
sql "$(url postgres baseline)" -c "DELETE FROM zasp_baseline.seal"
# Two predicates differ on purpose:
# - the worker gate, which the baseline opens (rules.sql R8);
# - zasp_temporal67.base_ready, a layer-67 check that layer 68 superseded. It
#   is false in the historical install and nothing reads it: its only caller,
#   zasp_temporal67.ready, is rewritten by R3.
EXPECTED='^(zasp_authorization80_worker\.runtime_ready|zasp_temporal67\.base_ready)='
if diff <(grep -vE "$EXPECTED" "$WORK/reference.predicates") <(grep -vE "$EXPECTED" "$WORK/baseline.predicates") > "$WORK/predicates.diff"; then :; else
  cat "$WORK/predicates.diff" >&2
  fail "readiness predicates differ from the superuser installation"
fi
grep -q '^zasp_authorization80_worker\.runtime_ready=t$' "$WORK/baseline.predicates" || fail "worker gate is not open"

docker exec "$CONTAINER-replay" pg_dump -U postgres -d baseline --inserts --rows-per-insert=200 | grep -v '^\\' > "$WORK/baseline.sql"
gzip -n -9 -c "$WORK/baseline.sql" > "$HERE/baseline.sql.gz"
cp "$WORK/roles.sql" "$HERE/roles.sql"
sha256sum < "$WORK/baseline.sql" | cut -d' ' -f1 > "$HERE/baseline.sha256"
echo "baseline: wrote baseline.sql.gz ($(wc -c < "$HERE/baseline.sql.gz") bytes), roles.sql, baseline.sha256 ($(cat "$HERE/baseline.sha256"))"
echo "baseline: $(wc -l < "$WORK/reference.predicates") readiness predicates and $(wc -l < "$WORK/reference.structure") structural facts agree"
