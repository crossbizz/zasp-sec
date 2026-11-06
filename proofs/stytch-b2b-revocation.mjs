#!/usr/bin/env node
import stytch, { StytchError } from "stytch";
import { pathToFileURL } from "node:url";
import { createTestSession, ProofError } from "./stytch-b2b-test-session.mjs";

export async function verifySessionRevocation(client, session) {
  const parameters = { session_jwt: session.projectSessionJwt, max_token_age_seconds: 0 };
  const authenticated = await client.sessions.authenticateJwt(parameters);
  const scope = authenticated?.member_session;
  if (
    !scope || typeof scope !== "object" || Array.isArray(scope) ||
    scope.member_session_id !== session.memberSessionId ||
    scope.member_id !== session.memberId ||
    scope.organization_id !== session.organizationId
  ) throw new ProofError("Revocation session scope did not match.");

  const revoked = await client.sessions.revoke({ member_session_id: session.memberSessionId });
  if (revoked?.status_code !== 200) throw new ProofError("Session revocation was not confirmed.");
  try {
    await client.sessions.authenticateJwt(parameters);
  } catch (error) {
    if (error instanceof StytchError && error.status_code === 404 && error.error_type === "session_not_found") return;
    throw new ProofError("Revoked session rejection was not confirmed.");
  }
  throw new ProofError("Revoked session was accepted.");
}

export async function runStytchRevocationProof(environment) {
  await createTestSession(environment, async ({ projectId, projectSecret, session }) => {
    const client = new stytch.B2BClient({ project_id: projectId, secret: projectSecret, timeout: 5_000 });
    await verifySessionRevocation(client, session);
  });
  return "Stytch Test session authenticated, revoked and rejected remotely; disposable Organization deleted.";
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    console.log(await runStytchRevocationProof(process.env));
  } catch {
    console.error("Stytch revocation proof failed; provider rejection or cleanup was not verified.");
    process.exitCode = 1;
  }
}
