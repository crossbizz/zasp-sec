# Shared helpers of the zasp entry point. Sourced, never executed.
# shellcheck shell=bash

say() { printf '%s\n' "$*"; }
note() { printf 'zasp: %s\n' "$*"; }
die() { printf 'zasp: %s\n' "$*" >&2; exit 1; }

# Reads KEY=VALUE lines from the configuration file and exports them. The file
# is data, not a script: nothing in it is executed or expanded. A variable
# that is already set in the environment wins over the file.
load_config() {
  local file="$1" line key value number=0
  ZASP_CONFIG_PRESENT=0
  [ -f "$file" ] || return 0
  ZASP_CONFIG_PRESENT=1
  while IFS= read -r line || [ -n "$line" ]; do
    number=$((number + 1))
    line="${line%$'\r'}"
    # Leading blanks, comments and an optional 'export'.
    line="${line#"${line%%[![:space:]]*}"}"
    case "$line" in
      ''|'#'*) continue ;;
      'export '*) line="${line#export }" ;;
    esac
    case "$line" in
      *=*) ;;
      *) die "$file line $number is not KEY=VALUE" ;;
    esac
    key="${line%%=*}"
    value="${line#*=}"
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || die "$file line $number: '$key' is not a setting name"
    # Trailing blanks, then one pair of surrounding quotes.
    value="${value%"${value##*[![:space:]]}"}"
    case "$value" in
      \"*\") value="${value#\"}"; value="${value%\"}" ;;
      \'*\') value="${value#\'}"; value="${value%\'}" ;;
    esac
    if [ -z "${!key+set}" ]; then
      export "$key=$value"
    fi
  done < "$file"
}

# Writes a configuration file from the documented example. An existing file is
# never replaced. The file will hold credentials, so only its owner may read it.
config_init() {
  local profile="$1" example="$ZASP_ROOT/deploy/zasp/zasp.env.example"
  case "$profile" in
    local|kubernetes|aws) ;;
    *) die "unknown profile '$profile' (local, kubernetes or aws)" ;;
  esac
  if [ -e "$ZASP_CONFIG_FILE" ]; then
    note "$ZASP_CONFIG_FILE already exists; it was not changed"
    return 0
  fi
  [ -f "$example" ] || die "$example is missing"
  [ -d "$(dirname "$ZASP_CONFIG_FILE")" ] || die "the directory of $ZASP_CONFIG_FILE does not exist"
  (umask 077; sed "s/^ZASP_PROFILE=.*/ZASP_PROFILE=$profile/" "$example" > "$ZASP_CONFIG_FILE") || die "could not write $ZASP_CONFIG_FILE"
  note "wrote $ZASP_CONFIG_FILE (readable by you only). Fill in the settings marked REQUIRED for profile '$profile', then run: ./zasp doctor"
}

# --- doctor -----------------------------------------------------------------
# Every check prints one line. 'MISSING' lines make doctor exit with status 1;
# 'warn' lines do not.
DOCTOR_MISSING=0
DOCTOR_WARNINGS=0
doctor_begin() {
  DOCTOR_MISSING=0
  DOCTOR_WARNINGS=0
  say "zasp doctor: profile $ZASP_PROFILE"
  if [ "${ZASP_CONFIG_PRESENT:-0}" = "1" ]; then
    doctor_ok "configuration file $ZASP_CONFIG_FILE"
    config_private "$ZASP_CONFIG_FILE" || doctor_warn "$ZASP_CONFIG_FILE can be read by other users" "run: chmod 600 '$ZASP_CONFIG_FILE'"
  else
    doctor_warn "no configuration file at $ZASP_CONFIG_FILE" "run: ./zasp config init --profile $ZASP_PROFILE"
  fi
}
doctor_ok() { printf '  ok       %s\n' "$1"; }
doctor_missing() {
  DOCTOR_MISSING=$((DOCTOR_MISSING + 1))
  printf '  MISSING  %s\n' "$1"
  [ -z "${2:-}" ] || printf '           %s\n' "$2"
}
doctor_warn() {
  DOCTOR_WARNINGS=$((DOCTOR_WARNINGS + 1))
  printf '  warn     %s\n' "$1"
  [ -z "${2:-}" ] || printf '           %s\n' "$2"
}
doctor_end() {
  say "$DOCTOR_MISSING missing, $DOCTOR_WARNINGS warnings"
  if [ "$DOCTOR_MISSING" -gt 0 ]; then
    say "Fix every MISSING line, then run ./zasp doctor again."
    return 1
  fi
  return 0
}
# A program on PATH. Arguments: program, what needs it, how to get it.
doctor_tool() {
  if command -v "$1" >/dev/null 2>&1; then
    doctor_ok "$1 ($2)"
  else
    doctor_missing "$1 is not installed ($2)" "${3:-}"
  fi
}
# A required setting. Arguments: name, what it is, how to obtain it. The value
# is never printed.
doctor_setting() {
  if [ -n "${!1:-}" ]; then
    doctor_ok "$1 is set ($2)"
  else
    doctor_missing "$1 is not set ($2)" "${3:-}"
  fi
}
doctor_optional_setting() {
  if [ -n "${!1:-}" ]; then
    doctor_ok "$1 is set ($2)"
  else
    doctor_warn "$1 is not set ($2)" "${3:-}"
  fi
}
# True when only the owner can read the file.
config_private() {
  local mode
  mode="$(stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null || echo 600)"
  case "$mode" in
    *00) return 0 ;;
    *) return 1 ;;
  esac
}

# --- running commands -------------------------------------------------------
# Runs a command that changes something, or prints it with --dry-run. Never
# pass a secret as an argument: arguments are printed.
run() {
  if [ "${ZASP_DRY_RUN:-0}" = "1" ]; then
    printf 'would run:'
    printf ' %q' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}
require_yes() {
  [ "${ZASP_YES:-0}" = "1" ] || die "$1
  Run the command again with --yes to confirm."
}
require_tool() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required for this command (run ./zasp doctor)"
}

# --- secrets ----------------------------------------------------------------
# Random material in the shapes the product reads. Values go to files or
# pipes, never to the terminal.
random_hex() { openssl rand -hex "$1" | tr -d '\n'; }
random_base64url() { openssl rand "$1" | openssl base64 -A | tr '+/' '-_' | tr -d '=\n'; }
random_base64() { openssl rand "$1" | openssl base64 -A | tr -d '\n'; }

# One row of the secrets report. Arguments: state, name, what it is for.
secret_row() { printf '  %-10s %-44s %s\n' "$1" "$2" "$3"; }
# State of a secret a person supplies through the configuration file.
supplied_state() { if [ -n "${!1:-}" ]; then echo present; else echo MISSING; fi; }
