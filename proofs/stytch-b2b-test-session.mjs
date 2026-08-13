#!/usr/bin/env node

const STYTCH_TEST_BASE_URL = "https://test.stytch.com";
const STYTCH_B2B_MAGIC_LINK_TOKEN = "DOYoip3rvIMMW5lgItikFK-Ak1CfMsgjuiCyI7uuU94=";
const SESSION_DURATION_MINUTES = 60;
const REQUEST_TIMEOUT_MS = 5_000;
const RESPONSE_BYTE_LIMIT = 64 * 1024;

class ProofError extends Error {}

function requireTestCredentials(environment) {
  const projectId = environment.STYTCH_PROJECT_ID;
  const secret = environment.STYTCH_SECRET;

  if (!projectId?.startsWith("project-test-")) {
    throw new ProofError("STYTCH_PROJECT_ID must be a Stytch Test project.");
  }
  if (!secret?.startsWith("secret-test-")) {
    throw new ProofError("STYTCH_SECRET must be a Stytch Test secret.");
  }

  return { projectId, secret };
}

function resolveBaseUrl(environment) {
  const override = environment.STYTCH_PROOF_BASE_URL;
  if (!override) return STYTCH_TEST_BASE_URL;
  if (environment.STYTCH_PROOF_ALLOW_LOOPBACK !== "1") {
    throw new ProofError("loopback override requires STYTCH_PROOF_ALLOW_LOOPBACK=1.");
  }

  let parsed;
  try {
    parsed = new URL(override);
  } catch {
    throw new ProofError("STYTCH_PROOF_BASE_URL must be an HTTP loopback URL.");
  }

  const isLoopback = parsed.hostname === "127.0.0.1" || parsed.hostname === "[::1]";
  if (
    parsed.protocol !== "http:" ||
    !isLoopback ||
    parsed.pathname !== "/" ||
    parsed.search ||
    parsed.hash ||
    parsed.username ||
    parsed.password
  ) {
    throw new ProofError("STYTCH_PROOF_BASE_URL must be an HTTP loopback URL.");
  }

  return parsed.origin;
}

function requireNonEmptyObject(value, field) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length === 0) {
    throw new ProofError(`response did not include a non-empty ${field}.`);
  }
}

function requireSessionResponse(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ProofError("Stytch response was not valid JSON.");
  }

  requireNonEmptyObject(value.member, "Member");
  requireNonEmptyObject(value.organization, "Organization");
  requireNonEmptyObject(value.member_session, "Member session");
  if (typeof value.member_session.member_session_id !== "string" || value.member_session.member_session_id.trim() === "") {
    throw new ProofError("response did not include a member session ID.");
  }
  if (typeof value.session_jwt !== "string" || value.session_jwt.trim() === "") {
    throw new ProofError("response did not include a session JWT.");
  }
}

function responseTooLarge() {
  return new ProofError(`response exceeded the ${RESPONSE_BYTE_LIMIT}-byte limit.`);
}

async function readBoundedJson(response) {
  const declaredLength = response.headers.get("content-length");
  if (declaredLength && /^\d+$/.test(declaredLength) && Number(declaredLength) > RESPONSE_BYTE_LIMIT) {
    try {
      await response.body?.cancel();
    } catch {
      // The response is already being rejected, so a best-effort cancellation is sufficient.
    }
    throw responseTooLarge();
  }

  if (!response.body) {
    throw new ProofError("Stytch response was not valid JSON.");
  }

  const reader = response.body.getReader();
  const chunks = [];
  let byteLength = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      byteLength += value.byteLength;
      if (byteLength > RESPONSE_BYTE_LIMIT) {
        try {
          await reader.cancel();
        } catch {
          // The response is already being rejected, so a best-effort cancellation is sufficient.
        }
        throw responseTooLarge();
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof ProofError) throw error;
    throw new ProofError("Stytch response could not be read.");
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(byteLength);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new ProofError("Stytch response was not valid JSON.");
  }
}

async function createTestSession(environment) {
  const { projectId, secret } = requireTestCredentials(environment);
  const baseUrl = resolveBaseUrl(environment);
  const authorization = Buffer.from(`${projectId}:${secret}`).toString("base64");
  let response;

  try {
    response = await fetch(`${baseUrl}/v1/b2b/magic_links/authenticate`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization: `Basic ${authorization}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        magic_links_token: STYTCH_B2B_MAGIC_LINK_TOKEN,
        session_duration_minutes: SESSION_DURATION_MINUTES,
      }),
      redirect: "error",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (error) {
    if (error instanceof Error && error.name === "TimeoutError") {
      throw new ProofError("request timed out.");
    }
    throw new ProofError("Stytch request failed.");
  }

  if (!response.ok) {
    throw new ProofError("Stytch returned an unsuccessful response.");
  }

  const body = await readBoundedJson(response);
  requireSessionResponse(body);
}

try {
  await createTestSession(process.env);
  console.log("Stytch B2B Test session created.");
} catch (error) {
  const message = error instanceof ProofError ? error.message : "unexpected failure.";
  console.error(`Stytch proof failed: ${message}`);
  process.exitCode = 1;
}
