import assert from 'node:assert/strict';

const applicationPackage = 'github.com/zasp-ai/zasp-sec/services/platform/apiserver';
function group(top, cases, postgresJoins) {
  return Object.freeze({top, postgresJoins, subcases: cases.length,
    names: Object.freeze([top, ...cases.map(name => `${top}/${name}`)])});
}
export const CONNECTOR_ACCEPTANCE_GROUPS = Object.freeze({
  'approval-test74': group('TestApprovalActivationNativeTest74DeliveryFlow', [], 2),
  'approval-ordered-planning': group('TestApprovalActivationNativeOrderedPlanningDeliveryFlow', [], 2),
  'approval-ordered-progress': group('TestApprovalActivationNativeOrderedProgressDeliveryFlow', [
    'provider-evidence-unchanged',
    'provider-evidence-ordinary-field',
    'provider-evidence-timestamp-instant',
    'provider-canonical-row-leaf',
  ], 2),
  'approval-flow': group('TestApprovalActivationNativeFindingDeliveryFlow', [
    'measured_combined_activation_and_complete_projection',
    'native_signed_delivery_settles_exact_receipt',
    'future_native_enqueue_inherits_organization_activation',
    'permission_revocation_preserves_membership_and_prevents_send',
    'captured_attempt_settles_after_permission_revocation_without_fresh_authority',
  ], 2),
  approval: group('TestApprovalActivationNativeCapturedOriginControls', [
    'planning_proof_wrong_purpose',
    'planning_proof_wrong_phase',
    'planning_proof_wrong_principal',
    'planning_proof_expired',
    'planning_proof_non-null_request',
    'planning_proof_wrong_canonical_digest',
    'planning_proof_wrong_job_digest',
    'planning_proof_other_task',
    'planning_proof_changed_target',
    'planning_proof_changed_revision',
    'planning_proof_repeatable_read',
    'planning_proof_serializable',
    'planning_proof_state_repeatable_read',
    'planning_proof_recovery_serializable',
    'planning_proof_compensation_forward_call',
    'planning_proof_canonical_formatting',
    'catalog_privacy_and_inactive_registration',
    'genuine_revoked_capture_stays_inactive',
    'wrong_pins_roll_back_both_families',
    'own_catalog_drift_fails_closed_and_rollback_restores',
    'executor_cannot_invoke_operator_activation',
  ], 1),
  oauth: group('TestConnectorMaintenanceAuthenticatedOAuthEnqueuePostgres', [
    'genuine_same_transaction_origin_and_immutable_enrichment',
    'rollback_removes_every_enqueue_and_provenance_write',
  ], 1),
  lifecycle: group('TestConnectorMaintenanceNativeLifecyclePostgres', [
    'genuine_enqueue_controlled_cutover_and_composed_projection',
    'genuine_callback_consumption_captures_only_its_original_effects',
    'reserve_without_attempt_and_deny_cross_scope_or_unowned_replay',
    'revocation_blocks_forward_work_while_exact_captured_cleanup_settles',
    'consumed_callback_revocation_retains_only_exact_rejection_cleanup',
  ], 2),
  pkce: group('TestConnectorMaintenancePKCERestartRecoveryPostgres', [
    'live_preparation_failure_retries_before_captured_provider_admission_and_excludes_live_lease_adoption',
    'restart_after_revocation_permits_only_exact_captured_deletion_without_settlement_on_failure',
    'second_restart_preserves_original_lineage_and_settles_exact_cleanup_once',
  ], 2),
  callback: group('TestConnectorMaintenanceCallbackRestartRecoveryPostgres', [
    'genuine_callback_consumption_survives_discarded_API_adapter',
    'expired_revoked_callback_permits_exact_deletion_but_failure_never_settles',
    'second_worker_restart_rotates_receipts_and_atomically_rejects_once',
  ], 2),
  'approval-overflow': group('TestApprovalActivationNativeAuthenticCaptureOverflow', [], 2),
  'approval-future-test74': group('TestApprovalActivationNativeFutureTest74DeliveryFlow', [], 2),
  'approval-future-progress': group('TestApprovalActivationNativeFutureOrderedProgressDeliveryFlow', [
    'provider-evidence-unchanged',
    'provider-evidence-ordinary-field',
    'provider-evidence-timestamp-instant',
    'provider-canonical-row-leaf',
  ], 2),
  'optional-egress-audit': group('TestOptionalEgressCurrentAuditNativePostgres', [
    'compiled_audit_install_and_purpose_boundaries',
    'required_catalog_and_durable_optional_switch',
    'canonical_source_and_tenant_profile_isolation',
    'concurrent_dispatch_mints_exactly_one_claim',
    'captured_settlement_survives_revoke_and_read_denies',
    'disable_and_pending_projection_deny_new_dispatch',
    'mounted_expiry_converges_without_background_worker',
    'operator_rotation_preserves_captured_binding_and_no_raw_storage',
  ], 1),
  'retention-audit': group('TestRetentionAuditProfileNativePostgres', [
    'prepared_exact_recipe_and_noinherit_owner',
    'registered_purposes_and_explicit_local_cutover',
    'same_full_receipt_current_writers_before_expiry',
    'immutable_origin_scope_switch_and_legacy_replay',
    'audited_policy_expiry_and_idempotent_cycle',
    'mixed_replay_preserves_whole_receipts_without_resurrection',
    'real_api_visibility_unknown_and_foreign_scope_denied',
    'independent_live_guard_drift_refuses_and_rolls_back',
  ], 1),
});
export function selectConnectorAcceptanceGroup(args) {
  assert.ok(Array.isArray(args) && args.length === 1 &&
    typeof args[0] === 'string' && Object.hasOwn(CONNECTOR_ACCEPTANCE_GROUPS, args[0]),
  'one fixed connector acceptance group is required');
  return CONNECTOR_ACCEPTANCE_GROUPS[args[0]];
}
// Only errors issued by the unchanged acceptance assertions carry diagnostics.
const traceFailureStages = new WeakMap();
const traceFailureEvents = new WeakMap();
export function describeConnectorAcceptanceTraceFailure(error) {
  return error !== null && (typeof error === 'object' || typeof error === 'function')
    ? traceFailureStages.get(error) ?? 'unknown' : 'unknown';
}
export function describeConnectorAcceptanceTraceEvent(error) {
  return error !== null && (typeof error === 'object' || typeof error === 'function')
    ? traceFailureEvents.get(error) ?? null : null;
}
// This validates application test events, not Temporal or OpenFGA internals.
export function validateConnectorAcceptanceTrace(rows, selected) {
  let stage = 'selection';
  try {
    assert.ok(Object.values(CONNECTOR_ACCEPTANCE_GROUPS).includes(selected));
    stage = 'empty';
    assert.ok(Array.isArray(rows) && rows.length > 0);
    stage = 'events';
    assert.ok(rows.every(row => row && row.Package === applicationPackage &&
      ['start', 'run', 'output', 'pass'].includes(row.Action) &&
      (row.Test === undefined || selected.names.includes(row.Test))), 'unexpected connector test event');
    for (const action of ['run', 'pass']) {
      stage = action === 'run' ? 'run-roster' : 'pass-roster';
      assert.deepEqual(rows.filter(row => row.Action === action && row.Test).map(row => row.Test).sort(),
        selected.names.slice().sort(), 'connector acceptance roster differs');
    }
    stage = 'package-pass';
    assert.equal(rows.filter(row => row.Action === 'pass' && row.Test === undefined).length, 1);
  } catch (error) {
    if (stage === 'events') {
      // Inspect only fixed shape/category after refusal; never retain payloads.
      try {
        const row = rows.find(row => !row || row.Package !== applicationPackage ||
          !['start', 'run', 'output', 'pass'].includes(row.Action) ||
          (row.Test !== undefined && !selected.names.includes(row.Test)));
        stage = !row ? 'event-shape' : row.Package !== applicationPackage ? 'event-package' :
          !['start', 'run', 'output', 'pass'].includes(row.Action) ? 'event-action' : 'event-case';
        if (stage === 'event-case' && error !== null && (typeof error === 'object' || typeof error === 'function')) {
          const test = row.Test;
          const testShape = typeof test === 'string' ? (test === '' ? 'empty-string' : 'nonempty-string') : test === null ? 'null' : 'non-string';
          const caseClass = typeof test !== 'string' ? 'non-string' :
            Object.values(CONNECTOR_ACCEPTANCE_GROUPS).some(group => group !== selected && group.names.includes(test)) ? 'other-fixed-group' :
              test === 'TestApprovalActivationOldWriterProcess' ? 'source-known-owned-helper' : 'unrecognized';
          const action = row.Action;
          if (['start', 'run', 'output', 'pass'].includes(action)) traceFailureEvents.set(error, Object.freeze({action, testShape, caseClass}));
        }
      } catch { stage = 'events'; }
    }
    if (error !== null && (typeof error === 'object' || typeof error === 'function')) traceFailureStages.set(error, stage);
    throw error;
  }
}

// Diagnostic observations never decide acceptance and never reflect raw output.
export function parseConnectorNativeObservation(output) {
  if (typeof output !== 'string' || Buffer.byteLength(output) > 16384) return null;
  const line = output.replace(/^[ \t]*[a-z_]+\.go:[0-9]{1,6}: /, '').replace(/\n$/, '');
  let match = /^connector cutover prepare stage=(invalid|live-before|model-read|live-after|deadline|unknown)$/.exec(line);
  if (match) return {kind: 'cutover', stage: match[1]};
  match = /^connector cutover activation stage=(invalid|permit|deadline|old-credential|writer-absence|new-model|sql-begin|sql-role|sql-lock|sql-baseline|sql-activation|sql-result|sql-commit|unknown)$/.exec(line);
  if (match) return {kind: 'activation', stage: match[1]};
  match = /^connector preparation stage=(release|begin|result|local-state|quarantine|unknown)$/.exec(line);
  if (match) return {kind: 'preparation', stage: match[1]};
  match = /^approval payload observation stage=payload-load outcome=(context-deadline|context-canceled|lease-margin|denied|unavailable|other-error|run-mismatch) parent_live=(true|false) lease_live=(true|false) provider_live=(true|false)$/.exec(line);
  if(match) {
    if(match[3]==='false'&&match[4]==='true')return null;
    return {kind:'approval-payload',value:{stage:'payload-load',outcome:match[1],parentLive:match[2]==='true',leaseLive:match[3]==='true',providerLive:match[4]==='true'}};
  }
  match = /^connector lease observation stage=(preparation-finish|preparation-forward|captured-compensation|revocation-pending|revocation-applied|recovery-forward|unknown) outcome=(denied|unavailable|operation|other) parent_live=(true|false) lease_live=(true|false) provider_bound=(true|false) provider_live=(true|false)$/.exec(line);
  if (match) {
    if(match[5]==='false'&&match[6]==='true')return null;
    return {kind:'lease',value:{stage:match[1],outcome:match[2],parentLive:match[3]==='true',leaseLive:match[4]==='true',providerBound:match[5]==='true',providerLive:match[6]==='true'}};
  }
  if (line === 'connector catalog diagnostic=unavailable') return {kind: 'catalog-summary', value: {observed: false}};
  match = /^connector catalog diagnostic=observed before_rows=([0-9]{1,4}) after_rows=([0-9]{1,4}) before_duplicates=([0-9]{1,4}) after_duplicates=([0-9]{1,4}) before_registered=(true|false) after_registered=(true|false) before_guc_equal=(true|false) after_guc_equal=(true|false) owner_guc_stable=(true|false) api_guc_stable=(true|false)$/.exec(line);
  if (match) {
    const counts = match.slice(1,5).map(Number);
    if (counts.some(value => value > 4096)) return null;
    return {kind: 'catalog-summary', value: {observed: true, beforeRows: counts[0], afterRows: counts[1], beforeDuplicates: counts[2], afterDuplicates: counts[3], beforeRegistered: match[5] === 'true', afterRegistered: match[6] === 'true', beforeGUCEqual: match[7] === 'true', afterGUCEqual: match[8] === 'true', ownerGUCStable: match[9] === 'true', apiGUCStable: match[10] === 'true'}};
  }
  match = /^connector catalog kind=(namespace|table|view|column|constraint|index|policy|trigger|function) before=([0-9]{1,4}) after=([0-9]{1,4}) added=([0-9]{1,4}) removed=([0-9]{1,4}) changed=([0-9]{1,4})$/.exec(line);
  if (!match || match.slice(2).some(value => Number(value) > 4096)) return null;
  return {kind: 'catalog-object', value: {kind: match[1], before: Number(match[2]), after: Number(match[3]), added: Number(match[4]), removed: Number(match[5]), changed: Number(match[6])}};
}
