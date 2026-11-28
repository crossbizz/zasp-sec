# VPS component operations share the top-level CLI's config, profile and dry run.
# Sourced by zasp after selecting the target installation.
# shellcheck shell=bash

vps_validate_providers() {
  case "${ZASP_SECRETS_PROVIDER:-aws-secrets-manager}" in
    aws-secrets-manager) ;;
    *) die "general platform secrets require aws-secrets-manager; use ZASP_CONNECTOR_SECRETS_PROVIDER=openbao for connector credentials" ;;
  esac
  case "${ZASP_CONNECTOR_SECRETS_PROVIDER:-openbao}" in openbao|aws-secrets-manager) ;; *) die "invalid ZASP_CONNECTOR_SECRETS_PROVIDER" ;; esac
  case "${ZASP_RECOVERY_SIGNING_PROVIDER:-openbao}" in openbao|aws-kms) ;; *) die "invalid ZASP_RECOVERY_SIGNING_PROVIDER" ;; esac
  case "${ZASP_EVIDENCE_PROVIDER:-s3}" in s3) ;; *) die "core evidence requires version-addressed S3 objects; R2 is available for offsite archives" ;; esac
  case "${ZASP_EVIDENCE_ENCRYPTION:-provider-managed}" in aws-kms|provider-managed) ;; *) die "invalid ZASP_EVIDENCE_ENCRYPTION" ;; esac
  case "${ZASP_QUEUE_PROVIDER:-sqs}" in sqs) ;; *) die "job delivery requires SQS broker receipts and renewable visibility leases" ;; esac
  case "${ZASP_AUDIT_EXPORT_QUEUE_ENCRYPTION:-provider-managed}" in aws-kms|provider-managed) ;; *) die "invalid ZASP_AUDIT_EXPORT_QUEUE_ENCRYPTION" ;; esac
  [ -z "${ZASP_QUEUE_ENCRYPTION:-}" ] || die "global queue encryption is unavailable; use ZASP_AUDIT_EXPORT_QUEUE_ENCRYPTION for the audit export pair"
  ZASP_BACKUP_PROVIDER="${ZASP_BACKUP_PROVIDER-r2}"
  case "$ZASP_BACKUP_PROVIDER" in local|s3|r2) ;; *) die "invalid VPS backup provider" ;; esac
  export ZASP_BACKUP_PROVIDER
}

vps_select_operation() {
  die "Select a VPS operation: install namespaces, install application, or status application. Application updates run through signed production CD. See docs/operations/vps-first-deployment.md."
}

vps_component() {
  local action="$1" component="$2"
  require_tool python3
  case "$component" in
    namespaces)
      [ "$action" = install ] || die "use install namespaces to initialize the production namespaces"
      run python3 "$ZASP_LIB/vps_production.py" namespaces ;;
    application)
      case "$action" in
        install) run node "$ZASP_ROOT/scripts/release-security/deploy.mjs" install-vps-production ;;
        status) run python3 "$ZASP_LIB/vps_production.py" status ;;
        *) vps_select_operation ;;
      esac ;;
    dependencies)
      case "$action" in doctor|install|status) ;; *) die "dependencies supports doctor, install and status" ;; esac
      python3 "$ZASP_LIB/vps_dependencies.py" "$ZASP_ROOT" "${ZASP_VPS_KUBE_CONTEXT:-}" "${ZASP_VPS_CLUSTER_UID:-}" "$action"
      ;;
    openbao|nango)
      python3 "$ZASP_LIB/vps_services.py" "$action" "$component"
      ;;
    *) die "select namespaces, application, dependencies, openbao or nango" ;;
  esac
}

vps_dispatch() {
  local action="$1" unit="" failed=0
  shift
  [ "$#" -le 1 ] || die "select a single VPS component"
  unit="${1:-}"
  case "$action" in
    nango)
      [ "$unit" = dashboard ] || die "usage: zasp --profile vps nango dashboard"
      vps_component dashboard nango ;;
    secrets_init|secrets_unseal)
      [ "${unit:-openbao}" = openbao ] || die "VPS secrets operations operate on openbao"
      vps_component "${action#secrets_}" openbao ;;
    doctor)
      if [ -n "$unit" ]; then vps_component doctor "$unit"; return; fi
      require_tool python3
      python3 "$ZASP_LIB/vps_doctor.py" ;;
    status)
      if [ -n "$unit" ]; then vps_component status "$unit"; return; fi
      for unit in dependencies openbao nango application; do
        if ! vps_component status "$unit"; then note "$unit: readiness check did not pass"; failed=1; fi
      done
      return "$failed" ;;
    install|start|stop|upgrade|logs)
      [ -n "$unit" ] || vps_select_operation
      vps_component "$action" "$unit" ;;
    up|bootstrap_admin|uninstall|demo) vps_select_operation ;;
    *) die "unsupported VPS operation" ;;
  esac
}
