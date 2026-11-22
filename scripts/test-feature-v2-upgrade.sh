#!/usr/bin/env bash
# Rehearse the actual predecessor -> V2 operator upgrade in a private PG cluster.
set -euo pipefail
case "${1:-}" in
  "") upgrade_only=false ;;
  --upgrade-only) upgrade_only=true ;;
  *) echo "Usage: $0 [--upgrade-only]" >&2; exit 2 ;;
esac
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
git -C "$repo_dir" archive "$previous" services/platform services/health | tar -x -C "$fixture_dir"
export ZASP_V2_UPGRADE_TEST_DSN="postgres://zasp_operator@/v2_upgrade?host=$socket_dir&sslmode=disable"
export ZASP_V2_UPGRADE_ADMIN_TEST_DSN="postgres://postgres@/v2_upgrade?host=$socket_dir&sslmode=disable"
# Compile the identical contract test against each release's own application
# and migrations. The overlay supplies the driver without changing either tree.
build_probe() {
  local tree="$1" label="$2"
  python3 - "$tree" "$repo_dir" "$fixture_dir/$label-overlay.json" <<'PYTHON'
import json, sys
from pathlib import Path
source, repo, output = map(Path, sys.argv[1:])
output.write_text(json.dumps({"Replace": {
    str(source / "services/platform/apiserver/v2_upgrade_binary_test.go"):
    str(repo / "scripts/upgrade-fixtures/api_runtime_test.go")
}}))
PYTHON
  go test -C "$tree/services/platform" -overlay "$fixture_dir/$label-overlay.json" -c -o "$fixture_dir/$label-api" ./apiserver
}
build_probe "$fixture_dir" predecessor
build_probe "$repo_dir" candidate
export ZASP_V2_UPGRADE_PREDECESSOR_API="$fixture_dir/predecessor-api"
export ZASP_V2_UPGRADE_CANDIDATE_API="$fixture_dir/candidate-api"
go build -C "$fixture_dir/services/platform" -o "$fixture_dir/prior-migrate" ./agentsec-migrate
go build -C "$repo_dir/services/platform" -o "$fixture_dir/current-migrate" ./agentsec-migrate
export ZASP_POSTGRES_DSN="$ZASP_V2_UPGRADE_TEST_DSN"
"$fixture_dir/prior-migrate" install-baseline
"$fixture_dir/prior-migrate" verify-baseline
go test -C "$repo_dir/services/platform" -count=1 -v ./migrations/baseline -run '^TestV2UpgradePopulatedBaseline$'
"$fixture_dir/current-migrate" upgrade-feature-v2
"$fixture_dir/current-migrate" verify-baseline
# The predecessor's operator verifier pins its artifact even when its API can
# still read the upgraded catalog. Inspect the reason for a nonzero exit.
if "$fixture_dir/prior-migrate" verify-baseline >"$fixture_dir/prior-check.json"; then
  echo "The old operator unexpectedly accepted the new artifact." >&2
  exit 1
fi
python3 - "$fixture_dir/prior-check.json" <<'PYTHON'
import json, sys
with open(sys.argv[1]) as contents:
    state = json.load(contents)
if state.get("sealed") is not True or state.get("intact") is not True or state.get("current") is not False:
    raise SystemExit("Expected an intact catalog sealed by a different release.")
PYTHON
"$pg_bin/createdb" -O zasp_operator -T template0 v2_fresh
export ZASP_POSTGRES_DSN="postgres://zasp_operator@/v2_fresh?host=$socket_dir&sslmode=disable"
"$fixture_dir/current-migrate" install-baseline
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

if [[ "$upgrade_only" == true ]]; then exit 0; fi

# Exercise the installed public authorization and data paths, including compiled
# CLI and endpoint clients. The release fixture runs only in this throwaway DB.
export ZASP_BASELINE_RELEASE_TEST_DSN="postgres://postgres@/v2_fresh?host=$socket_dir&sslmode=disable"
go test -C "$repo_dir/services/platform" -count=1 -timeout=20m -v -run \
  '^Test(Addon|AgentPurpose|AgentActionAnalysis|TicketCohort|AgentSuggestions|CLILogin|EndpointFleet|ManagedBrowserProfile|ImportedTicketProof|TicketCohort|Pilot|PrivateAddon|Workload).*OnInstalledBaselinePostgres$' ./apiserver
go test -C "$repo_dir/services/platform" -count=1 -timeout=10m -v \
  -run '^TestComplianceExportOnInstalledBaselinePostgres$' ./agentsec-worker
