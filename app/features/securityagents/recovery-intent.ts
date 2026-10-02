export type RecoveryRequestIdentity = { readonly definition_version: number; readonly input_digest: string };
export type RecoveryIntentSource = {
  readonly run_id: string;
  readonly parent_version: number;
  readonly status: string;
  readonly request_identity: RecoveryRequestIdentity;
};
export type RecoveryIntent = {
  readonly id: string;
  readonly version: number;
  readonly body: RecoveryRequestIdentity & { readonly diagnostic: "history_unavailable"; readonly stop_original: true };
};

const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export function createSingleTestRecoveryIntent(view: RecoveryIntentSource, runID: string, version: number): RecoveryIntent {
  const identity = view?.request_identity;
  if (!productID.test(runID) || view?.run_id !== runID || view.status !== "not_requested"
    || !Number.isSafeInteger(version) || version < 1 || view.parent_version !== version
    || !identity || !Number.isInteger(identity.definition_version)
    || identity.definition_version < 1 || identity.definition_version > 1000000
    || typeof identity.input_digest !== "string" || !/^[0-9a-f]{64}$/.test(identity.input_digest)) {
    throw new TypeError("Recovery identity changed or is unavailable");
  }
  return Object.freeze({ id: runID, version, body: Object.freeze({
    definition_version: identity.definition_version, input_digest: identity.input_digest,
    diagnostic: "history_unavailable" as const, stop_original: true as const,
  }) });
}
