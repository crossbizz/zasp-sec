import { APITransportError } from "../../../apps/web/api/client";
import type { SaaSSignInStatus } from "../../../apps/web/api/generated";

const uuid = "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const productID = new RegExp(`^pid_${uuid}$`);
const reference = new RegExp(`^ref:nango/connection/${uuid}$`);
const failureCode = /^[a-z][a-z0-9_]{1,63}$/;
const callback = new RegExp(`^/connectors\\?(?:saas_connection=${uuid}&saas_sign_in=pid_${uuid}|saas_sign_in=pid_${uuid}&saas_sign_in_error=[a-z][a-z0-9_]{1,63})$`);

// Callback addresses are a display-only surface. Never return a URL's data.
export function isSaaSCallback(location: string): boolean {
  return callback.test(location);
}

export function decodeSaaSSignInStatus(value: unknown): SaaSSignInStatus {
  const v = value as Partial<SaaSSignInStatus> | null;
  if (!v || typeof v !== "object" || Object.keys(v).sort().join(",") !== "attempt_id,connection_reference,failure_code,integration_id,integration_version,status" ||
    typeof v.attempt_id !== "string" || !productID.test(v.attempt_id) || typeof v.integration_id !== "string" || !productID.test(v.integration_id) ||
    !Number.isSafeInteger(v.integration_version) || Number(v.integration_version) < 1 ||
    !(["pending", "consumed", "completed", "failed", "superseded"] as const).some(s => s === v.status) ||
    (v.status === "completed" ? typeof v.connection_reference !== "string" || !reference.test(v.connection_reference) : v.connection_reference !== null) ||
    (v.failure_code !== null && (typeof v.failure_code !== "string" || !failureCode.test(v.failure_code) || v.status !== "failed"))) {
    throw new APITransportError("invalid_response", "Invalid provider sign-in status");
  }
  return v as SaaSSignInStatus;
}
