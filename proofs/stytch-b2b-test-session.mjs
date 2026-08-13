#!/usr/bin/env node

const STYTCH_TEST_BASE_URL = "https://test.stytch.com";
const STYTCH_B2B_MAGIC_LINK_TOKEN = "DOYoip3rvIMMW5lgItikFK-Ak1CfMsgjuiCyI7uuU94=";
const SESSION_DURATION_MINUTES = 60;
const REQUEST_TIMEOUT_MS = 5_000;

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

  const isLoopback = parsed.hostname === "127.0.0.1" || parsed.hostname === "::1";
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
  requireNonEmptyObject(value.session, "Session");
  if (typeof value.session_jwt !== "string" || value.session_jwt.trim() === "") {
    throw new ProofError("response did not include a session JWT.");
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

  let body;
  try {
    body = await response.json();
  } catch {
    throw new ProofError("Stytch response was not valid JSON.");
  }
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
