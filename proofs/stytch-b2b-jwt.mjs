#!/usr/bin/env node

import stytch from "stytch";
import { pathToFileURL } from "node:url";

import { createTestSession, ProofError } from "./stytch-b2b-test-session.mjs";

const LOCAL_VALIDATION_ONLY_SECRET = "invalid-local-validation-only";
const SUCCESS_SUMMARY = "Stytch B2B fresh JWT validated locally; old JWT validated through forced remote authentication; disposable Organization deleted.";

function requireMatchingSession(response, session, requireExpandedScope = false) {
  const memberSession = response?.member_session;
  if (
    !memberSession ||
    typeof memberSession !== "object" ||
    Array.isArray(memberSession) ||
    memberSession.member_session_id !== session.memberSessionId ||
    memberSession.member_id !== session.memberId ||
    memberSession.organization_id !== session.organizationId
  ) {
    throw new ProofError("Stytch JWT validation scope did not match.");
  }
  if (requireExpandedScope) {
    const member = response.member;
    const organization = response.organization;
    if (
      !member ||
      typeof member !== "object" ||
      Array.isArray(member) ||
      member.member_id !== session.memberId ||
      member.organization_id !== session.organizationId ||
      !organization ||
      typeof organization !== "object" ||
      Array.isArray(organization) ||
      organization.organization_id !== session.organizationId
    ) {
      throw new ProofError("Stytch JWT validation scope did not match.");
    }
  }
}

function createSessionVerifier(createClient) {
  return async ({ projectId, projectSecret, session }) => {
    try {
      const localClient = createClient({
        project_id: projectId,
        secret: LOCAL_VALIDATION_ONLY_SECRET,
      });
      const freshResponse = await localClient.sessions.authenticateJwt({
        session_jwt: session.projectSessionJwt,
      });
      requireMatchingSession(freshResponse, session);

      const remoteClient = createClient({
        project_id: projectId,
        secret: projectSecret,
      });
      const remoteResponse = await remoteClient.sessions.authenticateJwt({
        max_token_age_seconds: 0,
        session_jwt: session.projectSessionJwt,
      });
      requireMatchingSession(remoteResponse, session, true);
    } catch (error) {
      if (error instanceof ProofError) throw error;
      throw new ProofError("Stytch JWT validation failed.");
    }
  };
}

export async function runStytchJwtProof(
  environment,
  { createClient = (config) => new stytch.B2BClient(config) } = {},
) {
  await createTestSession(environment, createSessionVerifier(createClient));
  return SUCCESS_SUMMARY;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    console.log(await runStytchJwtProof(process.env));
  } catch (error) {
    const message = error instanceof ProofError ? error.message : "unexpected failure.";
    console.error(`Stytch JWT proof failed: ${message}`);
    process.exitCode = 1;
  }
}
