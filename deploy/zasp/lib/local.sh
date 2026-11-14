# Profile 'local': the whole product on one machine, for evaluation.
# Drives deploy/local/real-stack/stack.sh. Sourced by ./zasp.
# shellcheck shell=bash
# shellcheck disable=SC2119,SC2120

LOCAL_STACK="${ZASP_LOCAL_STACK_SCRIPT:-$ZASP_ROOT/deploy/local/real-stack/stack.sh}"
LOCAL_STATE="${ZASP_STATE_DIR:-${ZASP_REAL_STACK_STATE:-${XDG_STATE_HOME:-$HOME/.local/state}/zasp-real-stack}}"
LOCAL_ORIGIN="${ZASP_ORIGIN:-${ZASP_REAL_STACK_ORIGIN:-https://zasp.local-stack.test:8443}}"
LOCAL_DEPENDENCIES="${ZASP_DEPENDENCIES:-${ZASP_REAL_STACK_DEPENDENCIES:-docker}}"
export ZASP_REAL_STACK_STATE="$LOCAL_STATE" ZASP_REAL_STACK_ORIGIN="$LOCAL_ORIGIN" ZASP_REAL_STACK_DEPENDENCIES="$LOCAL_DEPENDENCIES"
[ -z "${ZASP_OAUTH_PROVIDER:-}" ] || export ZASP_REAL_STACK_OAUTH_PROVIDER="$ZASP_OAUTH_PROVIDER"
[ -z "${ZASP_POSTGRES_BIN:-}" ] || export ZASP_REAL_STACK_PG_BIN="$ZASP_POSTGRES_BIN"
[ -z "${ZASP_POSTGRES_DATA:-}" ] || export ZASP_REAL_STACK_PG_DATA="$ZASP_POSTGRES_DATA"

LOCAL_ORIGIN_AUTHORITY="${LOCAL_ORIGIN#https://}"
LOCAL_ORIGIN_HOST="${LOCAL_ORIGIN_AUTHORITY%%:*}"
case "$LOCAL_ORIGIN_AUTHORITY" in
  *:*) LOCAL_ORIGIN_PORT="${LOCAL_ORIGIN_AUTHORITY##*:}" ;;
  *) LOCAL_ORIGIN_PORT=443 ;;
esac
LOCAL_TOKEN_DIRECTORY=/var/run/secrets/eks.amazonaws.com/serviceaccount

local_stack() { "$LOCAL_STACK" "$@"; }
local_native() { [ "$LOCAL_DEPENDENCIES" = native ]; }
local_bootstrapped() { [ -f "$LOCAL_STATE/organization.env" ]; }

# True when the directory exists and is writable, or can be created.
local_directory_usable() {
  local directory="$1"
  while [ ! -e "$directory" ]; do directory="$(dirname "$directory")"; done
  [ -d "$directory" ] && [ -w "$directory" ]
}
local_port_in_use() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

local_doctor() {
  doctor_begin
  local directory port busy=""
  # Programs.
  doctor_tool curl "used by every step" "install curl with your package manager"
  doctor_tool openssl "generates keys and the local TLS certificate" "install openssl with your package manager"
  doctor_tool go "builds the API and worker programs" "install Go from https://go.dev/dl/ (the version in services/platform/go.mod is downloaded automatically)"
  doctor_tool node "builds and serves the web application" "install Node.js $(local_node_version) from https://nodejs.org/"
  doctor_tool npm "installs the web dependencies" "comes with Node.js"
  if command -v node >/dev/null 2>&1 && [ "$(node --version 2>/dev/null)" != "v$(local_node_version)" ]; then
    doctor_warn "node is $(node --version 2>/dev/null); package.json asks for $(local_node_version)" "another version may build, but only that one is tested"
  fi
  case "$LOCAL_DEPENDENCIES" in
    docker)
      doctor_tool docker "runs PostgreSQL, Temporal, OpenFGA, LocalStack, OpenSearch and Neo4j" "install Docker Engine or Docker Desktop, or set ZASP_DEPENDENCIES=native (reduced stack)"
      if command -v docker >/dev/null 2>&1; then
        if docker info >/dev/null 2>&1; then doctor_ok "the Docker daemon answers"; else doctor_missing "the Docker daemon does not answer" "start Docker, and make sure this user may use it"; fi
        if docker compose version >/dev/null 2>&1; then doctor_ok "docker compose"; else doctor_missing "docker compose is not available" "install the Docker Compose plugin"; fi
      fi
      ;;
    native)
      if [ -n "${ZASP_REAL_STACK_PG_BIN:-}" ] && [ -x "$ZASP_REAL_STACK_PG_BIN/pg_ctl" ] || command -v pg_ctl >/dev/null 2>&1 || [ -x /usr/lib/postgresql/18/bin/pg_ctl ] || [ -x /opt/homebrew/opt/postgresql@18/bin/pg_ctl ]; then
        doctor_ok "PostgreSQL server programs (initdb, pg_ctl)"
      else
        doctor_missing "PostgreSQL 18 server programs (initdb, pg_ctl) were not found" "install PostgreSQL 18 and set ZASP_POSTGRES_BIN to the directory that holds pg_ctl"
      fi
      doctor_tool "${ZASP_REAL_STACK_OPENFGA_BIN:-openfga}" "authorization service" "install OpenFGA 1.21.0: go install github.com/openfga/openfga/cmd/openfga@v1.21.0"
      doctor_tool "${ZASP_REAL_STACK_TEMPORAL_BIN:-temporal}" "workflow service (development server)" "install the Temporal CLI: https://docs.temporal.io/cli"
      doctor_tool "${ZASP_REAL_STACK_MOTO_BIN:-moto_server}" "AWS emulator" "pip install 'moto[server]'"
      doctor_tool "${ZASP_REAL_STACK_AWS_BIN:-aws}" "creates the emulated AWS resources" "pip install awscli"
      doctor_tool python3 "packages the emulated account's sample function" "install Python 3"
      doctor_warn "native dependencies are a reduced stack" "no sync, search or graph, and the API's /readyz answers 503; use Docker for the full stack"
      ;;
    *) doctor_missing "ZASP_DEPENDENCIES is '$LOCAL_DEPENDENCIES'" "set it to docker or native" ;;
  esac
  if [ -d "$ZASP_ROOT/node_modules" ]; then doctor_ok "web dependencies are installed (node_modules)"; else doctor_warn "web dependencies are not installed" "./zasp install runs 'npm ci'"; fi

  # The public origin.
  case "$LOCAL_ORIGIN" in
    https://*) ;;
    *) doctor_missing "ZASP_ORIGIN is '$LOCAL_ORIGIN'" "it must start with https://" ;;
  esac
  case "$LOCAL_ORIGIN_HOST" in
    localhost|*.localhost|*.local|"") doctor_missing "ZASP_ORIGIN host '$LOCAL_ORIGIN_HOST' is refused by the connector sign-in callbacks" "use a name such as zasp.local-stack.test" ;;
    *[!0-9.]*) doctor_ok "public origin $LOCAL_ORIGIN" ;;
    *) doctor_missing "ZASP_ORIGIN host '$LOCAL_ORIGIN_HOST' is an IP address" "use a name such as zasp.local-stack.test" ;;
  esac
  if grep -Eq "^[[:space:]]*127\.0\.0\.1[[:space:]]+([^#]*[[:space:]])?$LOCAL_ORIGIN_HOST([[:space:]]|#|\$)" "${ZASP_HOSTS_FILE:-/etc/hosts}" 2>/dev/null; then
    doctor_ok "$LOCAL_ORIGIN_HOST resolves to this machine (hosts file)"
  else
    doctor_missing "$LOCAL_ORIGIN_HOST is not mapped to this machine" "run: echo '127.0.0.1 $LOCAL_ORIGIN_HOST' | sudo tee -a /etc/hosts"
  fi

  # Fixed paths the API and workers read, as in a Kubernetes pod.
  if local_directory_usable "$LOCAL_TOKEN_DIRECTORY"; then
    doctor_ok "$LOCAL_TOKEN_DIRECTORY is writable (workload identity token)"
  else
    doctor_missing "$LOCAL_TOKEN_DIRECTORY cannot be written by this user" "run: sudo mkdir -p $LOCAL_TOKEN_DIRECTORY && sudo chown \"\$USER\" $LOCAL_TOKEN_DIRECTORY"
  fi
  for directory in /var/run/secrets/zasp-security-agent /var/run/secrets/zasp-security-agent-action /var/run/zasp-policy-verifier; do
    if local_directory_usable "$directory"; then
      doctor_ok "$directory is writable (Security Agent key files)"
    else
      doctor_missing "$directory cannot be written by this user" "run: sudo mkdir -p $directory && sudo chown \"\$USER\" $directory"
    fi
  done

  # Identity provider: the one dependency that cannot run on this machine.
  doctor_setting STYTCH_PROJECT_ID "identity provider project" "create a B2B project at https://stytch.com/ and copy the project ID from its API keys page"
  doctor_setting STYTCH_SECRET "identity provider API secret" "from the same API keys page"
  doctor_setting STYTCH_PUBLIC_TOKEN "identity provider public token" "from the same API keys page"
  if local_bootstrapped; then
    doctor_ok "the first organization exists"
  else
    doctor_optional_setting ZASP_ORGANIZATION_NAME "name of the first organization" "needed by './zasp up'; or pass it to './zasp bootstrap-admin'"
    doctor_optional_setting ZASP_ORGANIZATION_DOMAIN "email domain of the first organization" "needed by './zasp up'; or pass it to './zasp bootstrap-admin'"
    doctor_optional_setting ZASP_ADMIN_EMAIL "address of the first administrator" "needed by './zasp up'; or pass it to './zasp bootstrap-admin'"
  fi
  if ! local_native; then
    doctor_optional_setting OPENROUTER_API_KEY "model provider key for the Security Agent planner" "optional: without it Security Agent runs stay queued. Create a key at https://openrouter.ai/"
    if [ -x /opt/zasp/security/cartography/bin/security-worker ] && [ -x /opt/zasp/security/prowler/bin/security-worker ]; then
      doctor_ok "security analyzers are installed (/opt/zasp/security)"
    else
      doctor_warn "security analyzers are not installed" "optional: an AWS sync fails without them. Run: ./zasp install --with-analyzers (Python 3.13, about 4 GB)"
    fi
  fi

  # Ports, only before the stack exists: afterwards they are the stack's own.
  if [ ! -f "$LOCAL_STATE/up.done" ]; then
    for port in 4000 4081 "$LOCAL_ORIGIN_PORT" 3100 7233 8088 4566 "${ZASP_REAL_STACK_PG_PORT:-55434}"; do
      if local_port_in_use "$port"; then busy="$busy $port"; fi
    done
    if [ -n "$busy" ]; then doctor_warn "ports already in use on 127.0.0.1:$busy" "the stack needs them; stop whatever listens there"; else doctor_ok "the stack's ports are free"; fi
  fi
  doctor_end
}

local_node_version() { sed -nE 's/^[[:space:]]*"node":[[:space:]]*"([^"]+)".*/\1/p' "$ZASP_ROOT/package.json" | head -n 1; }

local_secrets_init() {
  require_tool openssl
  local_stack keys
  say "Generated on this machine (kept in $LOCAL_STATE/secrets, readable by you only):"
  local file state
  for file in keys.env forward.seed compensation.seed approval-delivery.key openfga.token; do
    if [ -f "$LOCAL_STATE/secrets/$file" ]; then state=present; else state=MISSING; fi
    case "$file" in
      keys.env) secret_row "$state" "$file" "workflow signing key, token reveal key, identity webhook secret (API)" ;;
      forward.seed) secret_row "$state" "$file" "authorization worker key (discovery and Security Agent workers)" ;;
      compensation.seed) secret_row "$state" "$file" "authorization compensation key (same workers)" ;;
      approval-delivery.key) secret_row "$state" "$file" "approval notification delivery key (API, workers, permission projector)" ;;
      openfga.token) secret_row "$state" "$file" "token the product presents to the local OpenFGA" ;;
    esac
  done
  say "Generated on first start: the graph database passwords, the emulated AWS account's external ID,"
  say "the gateway policy signing key, the local TLS certificate ($LOCAL_STATE/tls) and the database logins (no password: loopback only)."
  say ""
  say "Supplied by you, in $ZASP_CONFIG_FILE:"
  secret_row "$(supplied_state STYTCH_PROJECT_ID)" STYTCH_PROJECT_ID "identity provider project (required; API and bootstrap)"
  secret_row "$(supplied_state STYTCH_SECRET)" STYTCH_SECRET "identity provider API secret (required; API and bootstrap)"
  secret_row "$(supplied_state STYTCH_PUBLIC_TOKEN)" STYTCH_PUBLIC_TOKEN "identity provider public token (required; sign-in start)"
  secret_row "$(if [ -n "${OPENROUTER_API_KEY:-}" ]; then echo present; else echo optional; fi)" OPENROUTER_API_KEY "model provider key (optional; Security Agent planner)"
  say ""
  say "Not used by the local profile: GitHub App, Okta and Nango credentials (placeholders are created in the AWS emulator)"
  say "and AWS role ARNs (the emulator's fixed account is used). See docs/getting-started/administrator.md."
}

# Installs the web dependencies when they are missing, or when
# package-lock.json changed since they were last installed here. The digest of
# the lock file they were installed from is kept in the state directory.
# "npm ci" deletes node_modules before it installs, and it follows a symbolic
# link when it does: a node_modules that is a link to a shared directory is
# therefore never touched.
local_web_dependencies() {
  local stamp="$LOCAL_STATE/web-dependencies.sha256" digest
  digest="$(openssl dgst -sha256 < "$ZASP_ROOT/package-lock.json" | sed -E 's/^.*= ?//')" || die "could not read package-lock.json"
  if [ -e "$ZASP_ROOT/node_modules" ]; then
    # Present and never recorded: taken as installed from this lock file.
    if [ ! -f "$stamp" ] || [ "$(cat "$stamp")" = "$digest" ]; then
      local_record_web_dependencies "$stamp" "$digest"
      return 0
    fi
    [ ! -L "$ZASP_ROOT/node_modules" ] ||
      die "package-lock.json changed, and node_modules is a symbolic link, which zasp does not replace.
  Run 'npm ci' in the directory it points to, then delete $stamp."
    note "package-lock.json changed; installing the web dependencies again (npm ci)"
  else
    note "installing the web dependencies (npm ci)"
  fi
  (cd "$ZASP_ROOT" && run npm ci) || die "npm ci failed"
  local_record_web_dependencies "$stamp" "$digest"
}
local_record_web_dependencies() {
  [ "${ZASP_DRY_RUN:-0}" = "0" ] || return 0
  mkdir -p "$LOCAL_STATE" && printf '%s\n' "$2" > "$1"
}

local_install() {
  local analyzers=0 argument
  for argument in "$@"; do
    case "$argument" in
      --with-analyzers) analyzers=1 ;;
      *) die "usage: zasp install [--with-analyzers]" ;;
    esac
  done
  local_doctor || die "prerequisites are missing (see above)"
  local_web_dependencies
  note "starting the dependencies and installing the database schema"
  run "$LOCAL_STACK" up || die "installation failed (see the message above)"
  if [ "$analyzers" -eq 1 ]; then
    note "installing the security analyzers (several minutes)"
    run "$LOCAL_STACK" security-workers || die "the security analyzers were not installed"
  fi
}

# Creates the first organization and invites its first administrator. With no
# arguments the three values come from the configuration file.
local_bootstrap_admin() {
  local name="${1:-${ZASP_ORGANIZATION_NAME:-}}" domain="${2:-${ZASP_ORGANIZATION_DOMAIN:-}}" email="${3:-${ZASP_ADMIN_EMAIL:-}}"
  [ "$#" -eq 0 ] || [ "$#" -eq 3 ] || die "usage: zasp bootstrap-admin [<organization name> <email domain> <administrator email>]"
  [ -n "$name" ] && [ -n "$domain" ] && [ -n "$email" ] ||
    die "set ZASP_ORGANIZATION_NAME, ZASP_ORGANIZATION_DOMAIN and ZASP_ADMIN_EMAIL in $ZASP_CONFIG_FILE, or pass the three values"
  run "$LOCAL_STACK" bootstrap "$name" "$domain" "$email" >/dev/null || die "the first administrator was not created (see the stage above and docs/operations/first-organization-bootstrap.md)"
  note "organization '$name' exists and $email is its administrator."
  note "The identity provider sent $email an invitation; a second run sends no second one."
}

local_up() {
  [ "$#" -eq 0 ] || die "usage: zasp up"
  local_install
  if ! local_bootstrapped; then
    [ -n "${ZASP_ORGANIZATION_NAME:-}" ] && [ -n "${ZASP_ORGANIZATION_DOMAIN:-}" ] && [ -n "${ZASP_ADMIN_EMAIL:-}" ] ||
      die "the schema is installed. Next, create the first administrator and start:
  ./zasp bootstrap-admin '<organization name>' <email domain> <administrator email>
  ./zasp start
  (or set ZASP_ORGANIZATION_NAME, ZASP_ORGANIZATION_DOMAIN and ZASP_ADMIN_EMAIL in $ZASP_CONFIG_FILE and run ./zasp up again)"
    local_bootstrap_admin
  fi
  local_start
}

local_start() {
  [ "$#" -eq 0 ] || die "usage: zasp start"
  run "$LOCAL_STACK" start || die "not everything started (see above, and ./zasp logs)"
  [ "${ZASP_DRY_RUN:-0}" = "0" ] || return 0
  if ! local_bootstrapped; then
    return 0
  fi
  say ""
  say "Zasp is running."
  say "  Open       $LOCAL_ORIGIN/"
  say "  Sign in    The first administrator opens the invitation email from the identity provider (Stytch) and accepts it"
  say "             on the page it leads to. Later sign-ins use the sign-in page (OAuth: ${ZASP_OAUTH_PROVIDER:-google})."
  say "  Browser    Trust $LOCAL_STATE/tls/ca.crt, or accept the certificate warning once."
  say "  Operate    ./zasp status    ./zasp logs api    ./zasp stop"
}

local_stop() {
  [ "$#" -eq 0 ] || die "usage: zasp stop"
  run "$LOCAL_STACK" down
}

local_status() {
  [ "$#" -eq 0 ] || die "usage: zasp status"
  local_stack status
}

local_logs() {
  local name="" follow=0 argument
  for argument in "$@"; do
    case "$argument" in
      --follow|-f) follow=1 ;;
      -*) die "usage: zasp logs [name] [--follow]" ;;
      *) [ -z "$name" ] || die "usage: zasp logs [name] [--follow]"; name="$argument" ;;
    esac
  done
  if [ -z "$name" ]; then
    say "Logs are kept in $LOCAL_STATE/logs. Names:"
    if [ -d "$LOCAL_STATE/logs" ]; then
      find "$LOCAL_STATE/logs" -maxdepth 1 -name '*.log' -exec basename {} .log \; | sort | sed 's/^/  /'
    fi
    local_native || say "  postgres localstack opensearch neo4j temporal openfga   (container logs)"
    return 0
  fi
  case "$name" in
    */*|.*) die "'$name' is not a log name" ;;
  esac
  if [ -f "$LOCAL_STATE/logs/$name.log" ]; then
    if [ "$follow" -eq 1 ]; then exec tail -n 100 -f "$LOCAL_STATE/logs/$name.log"; fi
    tail -n 100 "$LOCAL_STATE/logs/$name.log"
    return 0
  fi
  local_native && die "no log named '$name' (run ./zasp logs for the names)"
  local container=""
  case "$name" in
    postgres) container=zasp-real-stack-pg ;;
    localstack|opensearch|neo4j) container="zasp-real-stack-$name" ;;
    temporal|openfga)
      if [ "$follow" -eq 1 ]; then exec docker compose -f "$ZASP_ROOT/deploy/local/temporal-openfga.compose.yaml" logs --tail 100 -f "$name"; fi
      docker compose -f "$ZASP_ROOT/deploy/local/temporal-openfga.compose.yaml" logs --tail 100 "$name"
      return 0
      ;;
    *) die "no log named '$name' (run ./zasp logs for the names)" ;;
  esac
  if [ "$follow" -eq 1 ]; then exec docker logs --tail 100 -f "$container"; fi
  docker logs --tail 100 "$container"
}

# Rebuilds the programs from this checkout and restarts. The database schema
# is not migrated: a checkout whose schema differs needs a reinstall.
local_upgrade() {
  [ "$#" -eq 0 ] || die "usage: zasp upgrade"
  [ -f "$LOCAL_STATE/up.done" ] || die "nothing is installed yet; run ./zasp up"
  run "$LOCAL_STACK" stop
  note "rebuilding the API and worker programs"
  run "$LOCAL_STACK" build || die "the programs were not built"
  if [ "${ZASP_DRY_RUN:-0}" = "0" ] && ! local_stack verify >/dev/null 2>&1; then
    die "the installed database schema is not the one this checkout expects (./zasp status; deploy/local/real-stack/stack.sh verify).
  There is no in-place schema upgrade between releases. To move to this checkout:
    ./zasp backup            # keeps the old data for reference; it cannot be restored into the new schema
    ./zasp uninstall --yes
    ./zasp up
  See docs/operations/baseline-schema-install.md, 'Reinstalling over an earlier artifact'."
  fi
  local_web_dependencies
  # 'start' repeats the installation steps (all idempotent) when this marker
  # is absent, and rebuilds the web application when its sources are newer.
  run rm -f "$LOCAL_STATE/up.done"
  local_start
}

# A backup is one archive: a dump of the product database cluster (and of the
# OpenFGA database), plus the keys and settings of the state directory. It
# contains secrets; it is written readable by its owner only.
local_backup() {
  [ "$#" -le 1 ] || die "usage: zasp backup [file]"
  local target="${1:-zasp-backup-local-$(date -u +%Y%m%dT%H%M%SZ).tar.gz}" staging item
  [ -f "$LOCAL_STATE/up.done" ] || die "nothing is installed yet; there is nothing to back up"
  [ ! -e "$target" ] || die "$target already exists"
  require_tool tar
  staging="$(mktemp -d)" || die "could not create a temporary directory"
  chmod 700 "$staging"
  mkdir "$staging/dump" "$staging/state"
  if ! local_stack dump "$staging/dump"; then
    rm -rf "$staging"
    die "the backup was not written"
  fi
  for item in secrets tls fga.env organization.env cloud.env provider.env; do
    [ ! -e "$LOCAL_STATE/$item" ] || cp -Rp "$LOCAL_STATE/$item" "$staging/state/" || { rm -rf "$staging"; die "could not copy $item"; }
  done
  # Native mode keeps the Temporal development server's database here.
  for item in "$LOCAL_STATE"/temporal.db*; do
    [ ! -e "$item" ] || cp -p "$item" "$staging/state/" || { rm -rf "$staging"; die "could not copy $(basename "$item")"; }
  done
  {
    printf 'profile=local\ndependencies=%s\ncreated=%s\n' "$LOCAL_DEPENDENCIES" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'commit=%s\n' "$(git -C "$ZASP_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
    printf 'schema=%s\n' "$(local_stack verify 2>/dev/null | tr -d '\n' || true)"
  } > "$staging/manifest"
  if ! (umask 077; tar -czf "$target" -C "$staging" manifest dump state); then
    rm -rf "$staging"
    die "could not write $target"
  fi
  rm -rf "$staging"
  note "wrote $target (contains keys: store it like a secret)"
  local_native || note "not included: Temporal's workflow history, the search index and the graph. The last two are rebuilt by the next sync."
}

local_restore() {
  [ "$#" -eq 1 ] || die "usage: zasp restore <file> --yes"
  local source="$1" staging
  [ -f "$source" ] || die "$source does not exist"
  require_yes "restore replaces the product database and the keys in $LOCAL_STATE with the contents of $source."
  require_tool tar
  staging="$(mktemp -d)" || die "could not create a temporary directory"
  chmod 700 "$staging"
  tar -xzf "$source" -C "$staging" || { rm -rf "$staging"; die "$source is not a readable archive"; }
  if ! grep -qx 'profile=local' "$staging/manifest" 2>/dev/null || [ ! -f "$staging/dump/postgres.sql" ]; then
    rm -rf "$staging"
    die "$source is not a backup of the local profile"
  fi
  if ! grep -qx "dependencies=$LOCAL_DEPENDENCIES" "$staging/manifest"; then
    local taken
    taken="$(grep '^dependencies=' "$staging/manifest" || true)"
    rm -rf "$staging"
    die "$source was taken with $taken; this configuration uses dependencies=$LOCAL_DEPENDENCIES"
  fi
  run "$LOCAL_STACK" stop
  mkdir -p "$LOCAL_STATE" && chmod 700 "$LOCAL_STATE"
  # Key files are read-only; remove the old ones before copying.
  run rm -rf "$LOCAL_STATE/secrets" "$LOCAL_STATE/tls"
  run cp -Rp "$staging/state/." "$LOCAL_STATE/"
  if ! run "$LOCAL_STACK" load "$staging/dump"; then
    rm -rf "$staging"
    die "the database was not restored"
  fi
  rm -rf "$staging"
  note "restored. Start the product with: ./zasp start"
}

local_uninstall() {
  [ "$#" -eq 0 ] || die "usage: zasp uninstall --yes"
  require_yes "uninstall deletes the local deployment: its containers or processes, every database and the keys in $LOCAL_STATE."
  run "$LOCAL_STACK" reset --yes
  note "removed. $ZASP_CONFIG_FILE and the built programs' sources were left in place."
}
