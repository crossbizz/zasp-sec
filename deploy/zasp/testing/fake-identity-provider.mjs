// A stand-in for the identity provider's directory API, for packaging tests
// on a machine that has no Stytch project. It answers the four requests
// `zasp-bootstrap` makes (find or create an Organization, find or invite a
// member) and nothing else: it issues no session, so nobody can sign in
// through it. The product accepts a plain-HTTP loopback identity provider
// only when ZASP_ENVIRONMENT is `test`.
//
//   node deploy/zasp/testing/fake-identity-provider.mjs 4990
//   export ZASP_STYTCH_BASE_URL=http://127.0.0.1:4990
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { pathToFileURL } from "node:url";

export function createFakeIdentityProvider() {
  const organizations = [];
  const members = [];
  const routes = {
    "/v1/b2b/organizations/search": body => {
      const slugs = body?.query?.operands?.find(operand => operand.filter_name === "organization_slugs")?.filter_value ?? [];
      return { status_code: 200, organizations: organizations.filter(item => slugs.includes(item.organization_slug)) };
    },
    "/v1/b2b/organizations": body => {
      const organization = {
        organization_id: `organization-test-${randomUUID()}`,
        organization_name: body.organization_name,
        organization_slug: body.organization_slug,
        email_allowed_domains: body.email_allowed_domains ?? [],
        trusted_metadata: body.trusted_metadata ?? {},
      };
      organizations.push(organization);
      return { status_code: 200, organization };
    },
    "/v1/b2b/organizations/members/search": body => {
      const emails = body?.query?.operands?.find(operand => operand.filter_name === "member_emails")?.filter_value ?? [];
      const scope = body?.organization_ids ?? [];
      return { status_code: 200, members: members.filter(item => scope.includes(item.organization_id) && emails.includes(item.email_address)) };
    },
    "/v1/b2b/magic_links/email/invite": body => {
      const member = { member_id: `member-test-${randomUUID()}`, organization_id: body.organization_id, email_address: body.email_address, status: "invited" };
      members.push(member);
      return { status_code: 200, member };
    },
  };
  return createServer((request, response) => {
    const chunks = [];
    request.on("data", chunk => chunks.push(chunk));
    request.on("end", () => {
      const route = routes[new URL(request.url, "http://localhost").pathname];
      let body;
      try { body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"); } catch { body = undefined; }
      if (request.method !== "POST" || !route || body === undefined) {
        response.writeHead(404, { "content-type": "application/json" });
        response.end(JSON.stringify({ status_code: 404, error_type: "not_found" }));
        return;
      }
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify(route(body)));
    });
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.argv[2] ?? "4990");
  createFakeIdentityProvider().listen(port, "127.0.0.1", () => console.log(`fake identity provider on http://127.0.0.1:${port} (test only; issues no sessions)`));
}
