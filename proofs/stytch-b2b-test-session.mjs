#!/usr/bin/env node

import { createHash, randomBytes, randomUUID } from "node:crypto";

const STYTCH_TEST_BASE_URL = "https://test.stytch.com";
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

function isTestId(value, prefix) {
  return typeof value === "string" && new RegExp(`^${prefix}-test-[A-Za-z0-9-]+$`).test(value);
}

function responseTooLarge() {
  return new ProofError(`response exceeded the ${RESPONSE_BYTE_LIMIT}-byte limit.`);
}

async function cancelResponseBody(response) {
  try {
    await response.body?.cancel();
  } catch {
    // The response is already being rejected, so a best-effort cancellation is sufficient.
  }
}

async function readBoundedJson(response) {
  const declaredLength = response.headers.get("content-length");
  if (declaredLength && /^\d+$/.test(declaredLength) && Number(declaredLength) > RESPONSE_BYTE_LIMIT) {
    await cancelResponseBody(response);
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
    if (error instanceof Error && (error.name === "AbortError" || error.name === "TimeoutError")) {
      throw new ProofError("request timed out.");
    }
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

async function requestJson({ authorization, baseUrl, body, method, path }) {
  let response;
  try {
    response = await fetch(`${baseUrl}${path}`, {
      method,
      headers: {
        Accept: "application/json",
        Authorization: `Basic ${authorization}`,
        "Content-Type": "application/json",
      },
      body: body === undefined ? undefined : JSON.stringify(body),
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
    await cancelResponseBody(response);
    throw new ProofError("Stytch returned an unsuccessful response.");
  }

  return readBoundedJson(response);
}

function createProofIdentity() {
  const marker = randomUUID();
  const password = randomBytes(48).toString("base64url");
  return Object.freeze({
    emailAddress: `zasp-m0-02-${marker}@example.com`,
    marker,
    organizationName: `Zasp M0-02 Proof ${marker}`,
    organizationSlug: `zasp-m0-02-proof-${marker}`,
    password,
    passwordHash: createHash("sha512").update(password).digest("hex"),
  });
}

function requireProofOwnedOrganization(value, identity) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ProofError("created Organization was not proof-owned.");
  }

  const organization = value.organization;
  if (
    !organization ||
    typeof organization !== "object" ||
    Array.isArray(organization) ||
    !isTestId(organization.organization_id, "organization") ||
    organization.organization_name !== identity.organizationName ||
    organization.organization_slug !== identity.organizationSlug
  ) {
    throw new ProofError("created Organization was not proof-owned.");
  }

  return Object.freeze({
    marker: identity.marker,
    organizationId: organization.organization_id,
    organizationName: identity.organizationName,
    organizationSlug: identity.organizationSlug,
  });
}

function requirePasswordOnlyOrganization(value) {
  const organization = value.organization;
  const allowed = organization.allowed_auth_methods;
  if (
    organization.auth_methods !== "RESTRICTED" ||
    !Array.isArray(allowed) ||
    allowed.length !== 1 ||
    allowed[0] !== "password"
  ) {
    throw new ProofError("created Organization was not password-only.");
  }
}

function requireScopedOrganization(value, cleanupTarget, operation) {
  requireNonEmptyObject(value.organization, "Organization");
  if (value.organization.organization_id !== cleanupTarget.organizationId) {
    throw new ProofError(`${operation} Organization ID did not match.`);
  }
}

function requireMigratedMember(value, cleanupTarget, identity) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ProofError("Stytch response was not valid JSON.");
  }
  if (value.member_created !== true) {
    throw new ProofError("migration did not create a new Member.");
  }
  requireScopedOrganization(value, cleanupTarget, "migrated");

  requireNonEmptyObject(value.member, "Member");
  const memberId = value.member.member_id;
  if (!isTestId(memberId, "member") || value.member_id !== memberId) {
    throw new ProofError("response did not include a consistent Test Member ID.");
  }
  if (value.member.organization_id !== cleanupTarget.organizationId) {
    throw new ProofError("Member Organization ID did not match.");
  }
  if (value.member.email_address !== identity.emailAddress) {
    throw new ProofError("Member email address did not match.");
  }

  return memberId;
}

function requireSessionResponse(value, cleanupTarget, identity, memberId) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ProofError("Stytch response was not valid JSON.");
  }
  if (value.organization_id !== cleanupTarget.organizationId) {
    throw new ProofError("response Organization ID did not match.");
  }
  requireScopedOrganization(value, cleanupTarget, "authenticated");

  requireNonEmptyObject(value.member, "Member");
  if (!isTestId(value.member.member_id, "member") || value.member.member_id !== memberId || value.member_id !== memberId) {
    throw new ProofError("response did not include a consistent Test Member ID.");
  }
  if (value.member.organization_id !== cleanupTarget.organizationId) {
    throw new ProofError("Member Organization ID did not match.");
  }
  if (value.member.email_address !== identity.emailAddress) {
    throw new ProofError("Member email address did not match.");
  }

  requireNonEmptyObject(value.member_session, "Member session");
  if (!isTestId(value.member_session.member_session_id, "member-session")) {
    throw new ProofError("response did not include a Test member session ID.");
  }
  if (value.member_session.organization_id !== cleanupTarget.organizationId) {
    throw new ProofError("Member session Organization ID did not match.");
  }
  if (value.member_session.member_id !== memberId) {
    throw new ProofError("Member session Member ID did not match.");
  }

  if (value.member_authenticated !== true) {
    throw new ProofError("Member was not fully authenticated.");
  }
  if (typeof value.session_jwt !== "string" || value.session_jwt.trim() === "") {
    throw new ProofError("response did not include a session JWT.");
  }
}

function assertCleanupTarget(cleanupTarget, identity) {
  if (
    !cleanupTarget ||
    !isTestId(cleanupTarget.organizationId, "organization") ||
    cleanupTarget.marker !== identity.marker ||
    cleanupTarget.organizationName !== identity.organizationName ||
    cleanupTarget.organizationSlug !== identity.organizationSlug
  ) {
    throw new ProofError("disposable Organization cleanup failed.");
  }
}

async function deleteProofOwnedOrganization({ authorization, baseUrl, cleanupTarget, identity }) {
  assertCleanupTarget(cleanupTarget, identity);
  const response = await requestJson({
    authorization,
    baseUrl,
    method: "DELETE",
    path: `/v1/b2b/organizations/${cleanupTarget.organizationId}`,
  });
  if (
    !response ||
    typeof response !== "object" ||
    Array.isArray(response) ||
    response.organization_id !== cleanupTarget.organizationId
  ) {
    throw new ProofError("disposable Organization cleanup failed.");
  }
}

async function createTestSession(environment) {
  const { projectId, secret } = requireTestCredentials(environment);
  const baseUrl = resolveBaseUrl(environment);
  const authorization = Buffer.from(`${projectId}:${secret}`).toString("base64");
  const identity = createProofIdentity();
  let cleanupTarget;
  let proofFailure;

  try {
    const createResponse = await requestJson({
      authorization,
      baseUrl,
      method: "POST",
      path: "/v1/b2b/organizations",
      body: {
        allowed_auth_methods: ["password"],
        auth_methods: "RESTRICTED",
        email_invites: "NOT_ALLOWED",
        mfa_policy: "OPTIONAL",
        organization_name: identity.organizationName,
        organization_slug: identity.organizationSlug,
      },
    });
    cleanupTarget = requireProofOwnedOrganization(createResponse, identity);
    requirePasswordOnlyOrganization(createResponse);

    const migrateResponse = await requestJson({
      authorization,
      baseUrl,
      method: "POST",
      path: "/v1/b2b/passwords/migrate",
      body: {
        email_address: identity.emailAddress,
        hash: identity.passwordHash,
        hash_type: "sha_512",
        organization_id: cleanupTarget.organizationId,
      },
    });
    const memberId = requireMigratedMember(migrateResponse, cleanupTarget, identity);

    const authenticateResponse = await requestJson({
      authorization,
      baseUrl,
      method: "POST",
      path: "/v1/b2b/passwords/authenticate",
      body: {
        email_address: identity.emailAddress,
        organization_id: cleanupTarget.organizationId,
        password: identity.password,
        session_duration_minutes: SESSION_DURATION_MINUTES,
      },
    });
    requireSessionResponse(authenticateResponse, cleanupTarget, identity, memberId);
  } catch (error) {
    proofFailure = error;
  } finally {
    if (cleanupTarget) {
      try {
        await deleteProofOwnedOrganization({ authorization, baseUrl, cleanupTarget, identity });
      } catch {
        proofFailure = new ProofError("disposable Organization cleanup failed.");
      }
    }
  }

  if (proofFailure) throw proofFailure;
}

try {
  await createTestSession(process.env);
  console.log("Stytch B2B Test session created and disposable Organization deleted.");
} catch (error) {
  const message = error instanceof ProofError ? error.message : "unexpected failure.";
  console.error(`Stytch proof failed: ${message}`);
  process.exitCode = 1;
}
