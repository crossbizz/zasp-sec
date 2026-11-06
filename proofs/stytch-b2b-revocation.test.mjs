import assert from "node:assert/strict";
import test from "node:test";
import { StytchError } from "stytch";
import { verifySessionRevocation } from "./stytch-b2b-revocation.mjs";

const session = { memberSessionId: "owned-session", memberId: "owned-member", organizationId: "owned-org", projectSessionJwt: "synthetic" };
const scope = { member_session: { member_session_id: session.memberSessionId, member_id: session.memberId, organization_id: session.organizationId } };
function rejection(status_code = 404, error_type = "session_not_found") {
  return new StytchError({ status_code, error_type, request_id: "synthetic", error_message: "synthetic", error_url: "", error_details: undefined });
}
function client(behavior = {}) {
  const calls = [];
  let reads = 0;
  return { calls, sessions: {
    async authenticateJwt(args) {
      calls.push(["authenticateJwt", args]);
      if (++reads === 1) return behavior.scope ?? scope;
      if (behavior.accepted) return scope;
      throw behavior.error ?? rejection();
    },
    async revoke(args) {
      calls.push(["revoke", args]);
      if (behavior.revokeFailure) throw new Error("synthetic transport failure");
      return { status_code: behavior.revokeStatus ?? 200 };
    },
  } };
}
test("only exact owned-session revocation plus explicit remote not-found rejection passes", async () => {
  const good = client();
  await verifySessionRevocation(good, session);
  assert.deepEqual(good.calls, [
    ["authenticateJwt", { session_jwt: session.projectSessionJwt, max_token_age_seconds: 0 }],
    ["revoke", { member_session_id: session.memberSessionId }],
    ["authenticateJwt", { session_jwt: session.projectSessionJwt, max_token_age_seconds: 0 }],
  ]);
  for (const behavior of [
    { accepted: true }, { error: new Error("network failure") },
    { error: rejection(500) }, { error: rejection(401, "project_not_found") },
    { error: { status_code: 404, error_type: "session_not_found" } }, { revokeFailure: true }, { revokeStatus: 500 },
  ]) await assert.rejects(verifySessionRevocation(client(behavior), session));
  const wrong = client({ scope: { member_session: { ...scope.member_session, organization_id: "other-org" } } });
  await assert.rejects(verifySessionRevocation(wrong, session));
  assert.equal(wrong.calls.length, 1);
});
