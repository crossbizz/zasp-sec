import { APITransportError, requireAPIData, type APIClient } from "./client";

const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export type CLIRequest = { request_id: string; environment_id: string; code_challenge: string; request_proof: string; expires: number };

export function readCLIRequest(hash: string, now = Date.now()): CLIRequest | undefined {
  if (!hash.startsWith("#") || hash.length > 512) return;
  const fields = new URLSearchParams(hash.slice(1));
  if (fields.size !== 4 || ["request_id", "environment_id", "code_challenge", "request_proof"].some((key) => fields.getAll(key).length !== 1)) return;
  const request_id = fields.get("request_id")!, environment_id = fields.get("environment_id")!;
  const code_challenge = fields.get("code_challenge")!, request_proof = fields.get("request_proof")!;
  if (!productID.test(request_id) || !productID.test(environment_id) || !/^[A-Za-z0-9_-]{43}$/.test(code_challenge) ||
      !/^[0-9]{1,12}\.[A-Za-z0-9_-]{43}$/.test(request_proof)) return;
  const expires = Number(request_proof.split(".")[0]) * 1000;
  if (expires <= now || expires > now + 11 * 60_000) return;
  return { request_id, environment_id, code_challenge, request_proof, expires };
}

export async function approveCLIRequest(client: APIClient, request: CLIRequest, code: string, scope: string) {
  if (!/^[0-9a-f]{8}$/.test(code) || request.expires <= Date.now() || !scope.endsWith("/" + request.environment_id)) {
    throw new Error("Invalid or expired approval");
  }
  const result = await client.POST("/api/v1/cli/auth/approve", {
    params: { header: { "X-CSRF-Token": "" } },
    headers: { "X-Zasp-Expected-Scope": scope },
    body: { request_id: request.request_id, environment_id: request.environment_id, request_proof: request.request_proof,
      code_challenge: request.code_challenge, client_id: "zaspctl", comparison_code: code },
  });
  return requireAPIData(result, (value) => {
    if (typeof value !== "object" || value === null || !("approved" in value) || value.approved !== true || Object.keys(value).length !== 1) {
      throw new APITransportError("invalid_response", "Invalid CLI approval response");
    }
    return true;
  });
}
