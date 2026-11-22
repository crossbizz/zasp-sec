#!/usr/bin/env bash
# Rehearse the actual predecessor -> V2 operator upgrade in a private PG cluster.
set -euo pipefail
repo_dir="$(git rev-parse --show-toplevel)"
fixture_dir="$(mktemp -d)"
pg_bin="${ZASP_BASELINE_PG_BIN:-$(pg_config --bindir)}"
pg_data="$fixture_dir/cluster"
socket_dir="$fixture_dir/socket"
cleanup() {
  if [[ -f "$pg_data/postmaster.pid" ]]; then "$pg_bin/pg_ctl" -D "$pg_data" -m fast -w stop >/dev/null; fi
  rm -rf -- "$fixture_dir"
}
trap cleanup EXIT
mkdir "$socket_dir"
"$pg_bin/initdb" -D "$pg_data" -U postgres --auth=trust --no-locale --encoding=UTF8 >/dev/null
"$pg_bin/pg_ctl" -D "$pg_data" -l "$fixture_dir/server.log" -w -o "-k $socket_dir -c listen_addresses='' -c unix_socket_permissions=0700" start >/dev/null
export PGHOST="$socket_dir" PGPORT=5432 PGUSER=postgres
"$pg_bin/psql" -X -v ON_ERROR_STOP=1 -d postgres -c "CREATE ROLE zasp_operator LOGIN CREATEROLE BYPASSRLS" >/dev/null
"$pg_bin/createdb" -O zasp_operator -T template0 v2_upgrade
previous=2f2ad720f069180dfa473b63e435a608c57aa865
git -C "$repo_dir" archive "$previous" services/platform/go.mod services/platform/go.sum services/platform/migrations/baseline | tar -x -C "$fixture_dir"
export ZASP_V2_UPGRADE_TEST_DSN="postgres://zasp_operator@/v2_upgrade?host=$socket_dir&sslmode=disable"
cat >"$fixture_dir/services/platform/main.go" <<'GO'
package main
import (
  "context"
  "log"
  "os"
  "github.com/jackc/pgx/v5"
  "github.com/zasp-ai/zasp-sec/services/platform/migrations/baseline"
)
func main() {
  ctx := context.Background()
  conn, err := pgx.Connect(ctx, os.Getenv("ZASP_V2_UPGRADE_TEST_DSN"))
  if err != nil { log.Fatal(err) }
  defer conn.Close(ctx)
  if err = baseline.Install(ctx, conn); err != nil { log.Fatal(err, ": ", err.(*baseline.StageError).Err) }
}
GO
go run -C "$fixture_dir/services/platform" .
go test -C "$repo_dir/services/platform" -count=1 ./migrations/baseline -run '^TestV2UpgradePopulatedBaseline$'
"$pg_bin/createdb" -O zasp_operator -T template0 v2_fresh
export ZASP_POSTGRES_DSN="postgres://zasp_operator@/v2_fresh?host=$socket_dir&sslmode=disable"
go run -C "$repo_dir/services/platform" ./agentsec-migrate install-baseline
fresh_catalog="$("$pg_bin/psql" -XAt "$ZASP_POSTGRES_DSN" -c "SELECT zasp_baseline.content()")"
upgraded_catalog="$("$pg_bin/psql" -XAt "$ZASP_V2_UPGRADE_TEST_DSN" -c "SELECT zasp_baseline.content()")"
if [[ -z "$fresh_catalog" || "$fresh_catalog" != "$upgraded_catalog" ]]; then
  # Emit object names and definition hashes, never table contents.
  awk '/^  WITH scope\(oid\)/ {emit=1} emit && /^  SELECT encode\(sha256/ {exit} emit {print}' \
      "$repo_dir/services/platform/migrations/baseline/prelude.sql" >"$fixture_dir/facts.sql"
  echo "  SELECT split_part(v,'|',1),split_part(v,'|',2),md5(v) FROM facts ORDER BY 1,2,3" >>"$fixture_dir/facts.sql"
  for db in v2_upgrade v2_fresh; do
    PGOPTIONS="-c search_path=pg_catalog" "$pg_bin/psql" -XAt -v ON_ERROR_STOP=1 -U zasp_operator -d "$db" -f "$fixture_dir/facts.sql" >"$fixture_dir/$db.catalog"
  done
  diff -u "$fixture_dir/v2_fresh.catalog" "$fixture_dir/v2_upgrade.catalog" >&2 || true
  echo "The upgraded catalog differs from the fresh release." >&2
  exit 1
fi
echo "The populated upgrade preserves the fixture and matches the fresh catalog."

# Exercise the installed public authorization and data paths, including compiled
# CLI and endpoint clients. The release fixture runs only in this throwaway DB.
export ZASP_BASELINE_RELEASE_TEST_DSN="postgres://postgres@/v2_fresh?host=$socket_dir&sslmode=disable"
go test -C "$repo_dir/services/platform" -count=1 -timeout=20m -v -run \
  '^Test(Addon|AgentPurpose|AgentSuggestions|CLILogin|EndpointFleet|ManagedBrowserProfile|ImportedTicketProof|Pilot|PrivateAddon|Workload).*OnInstalledBaselinePostgres$' ./apiserver
go test -C "$repo_dir/services/platform" -count=1 -timeout=10m -v \
  -run '^TestComplianceExportOnInstalledBaselinePostgres$' ./agentsec-worker
