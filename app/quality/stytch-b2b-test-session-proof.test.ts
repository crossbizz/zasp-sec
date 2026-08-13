import { createHash } from "node:crypto";
import { once } from "node:events";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

const repositoryRoot = process.cwd();
const runnerPath = resolve(repositoryRoot, "proofs/stytch-b2b-test-session.mjs");
const contractProjectId = ["project", "test", "contract"].join("-");
const contractSecret = ["secret", "test", "contract"].join("-");
const liveProjectId = ["project", "live", "contract"].join("-");
const liveSecret = ["secret", "live", "contract"].join("-");
const organizationId = "organization-test-11111111-1111-4111-8111-111111111111";
const memberId = "member-test-22222222-2222-4222-8222-222222222222";
const memberSessionId = "member-session-test-33333333-3333-4333-8333-333333333333";
const responseByteLimit = 64 * 1024;
const servers: Server[] = [];

type JsonObject = Record<string, unknown>;

type CapturedRequest = {
  authorization: string;
  body: JsonObject | undefined;
  method: string;
  url: string;
};

type RunnerResult = {
  exitCode: number | null;
  stderr: string;
  stdout: string;
};

type ProviderBehavior = {
  authenticateResponse?: (response: JsonObject) => JsonObject;
  cleanupResponse?: (response: JsonObject) => JsonObject;
  createResponse?: (response: JsonObject) => JsonObject;
  migrateResponse?: (response: JsonObject) => JsonObject;
  stallMigrateBody?: boolean;
  status?: Partial<Record<"authenticate" | "cleanup" | "create" | "migrate", number>>;
};

async function startLoopbackServer(
  handler: (request: IncomingMessage, response: ServerResponse) => Promise<void> | void,
): Promise<{ baseUrl: string; server: Server }> {
  const server = createServer((request, response) => {
    void Promise.resolve(handler(request, response)).catch(() => {
      if (!response.headersSent) response.writeHead(500);
      response.end();
    });
  });
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Loopback server did not expose a TCP address");
  }

  return { baseUrl: `http://127.0.0.1:${address.port}`, server };
}

async function startIpv6LoopbackServer(
  handler: (request: IncomingMessage, response: ServerResponse) => Promise<void> | void,
): Promise<{ baseUrl: string; server: Server }> {
  const server = createServer((request, response) => {
    void Promise.resolve(handler(request, response)).catch(() => {
      if (!response.headersSent) response.writeHead(500);
      response.end();
    });
  });
  servers.push(server);
  server.listen(0, "::1");
  try {
    await Promise.race([
      once(server, "listening"),
      once(server, "error").then(([error]) => { throw error; }),
    ]);
  } catch (error) {
    servers.splice(servers.indexOf(server), 1);
    throw error;
  }
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("IPv6 loopback server did not expose a TCP address");
  }

  return { baseUrl: `http://[::1]:${address.port}`, server };
}

async function readRequestBody(request: IncomingMessage): Promise<JsonObject | undefined> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  if (chunks.length === 0) return undefined;
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as JsonObject;
}

function sendJson(response: ServerResponse, status: number, body: JsonObject) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}

async function startProofProvider(behavior: ProviderBehavior = {}, addressFamily: "ipv4" | "ipv6" = "ipv4") {
  const requests: CapturedRequest[] = [];
  let organizationName = "";
  let organizationSlug = "";
  let memberEmail = "";

  const startServer = addressFamily === "ipv6" ? startIpv6LoopbackServer : startLoopbackServer;
  const { baseUrl } = await startServer(async (request, response) => {
    const method = request.method ?? "";
    const url = request.url ?? "";
    const body = await readRequestBody(request);
    requests.push({
      authorization: request.headers.authorization ?? "",
      body,
      method,
      url,
    });

    if (method === "POST" && url === "/v1/b2b/organizations") {
      organizationName = String(body?.organization_name ?? "");
      organizationSlug = String(body?.organization_slug ?? "");
      const status = behavior.status?.create ?? 200;
      if (status !== 200) {
        sendJson(response, status, { provider_detail: "create-body-must-not-appear" });
        return;
      }
      const baseResponse: JsonObject = {
        status_code: 200,
        organization: {
          organization_id: organizationId,
          organization_name: organizationName,
          organization_slug: organizationSlug,
          auth_methods: "RESTRICTED",
          allowed_auth_methods: ["password"],
          email_invites: "NOT_ALLOWED",
          mfa_policy: "OPTIONAL",
        },
      };
      sendJson(response, 200, behavior.createResponse?.(baseResponse) ?? baseResponse);
      return;
    }

    if (method === "POST" && url === "/v1/b2b/passwords/migrate") {
      memberEmail = String(body?.email_address ?? "");
      const status = behavior.status?.migrate ?? 200;
      if (status !== 200) {
        sendJson(response, status, { provider_detail: "migrate-body-must-not-appear" });
        return;
      }
      if (behavior.stallMigrateBody) {
        response.writeHead(200, { "content-type": "application/json" });
        response.write('{"provider_detail":"stalled-body-must-not-appear"');
        return;
      }
      const baseResponse: JsonObject = {
        status_code: 200,
        member_created: true,
        member_id: memberId,
        member: {
          member_id: memberId,
          organization_id: organizationId,
          email_address: memberEmail,
          email_address_verified: true,
          status: "active",
        },
        organization: {
          organization_id: organizationId,
          organization_name: organizationName,
          organization_slug: organizationSlug,
          auth_methods: "RESTRICTED",
          allowed_auth_methods: ["password"],
          email_invites: "NOT_ALLOWED",
          mfa_policy: "OPTIONAL",
        },
      };
      sendJson(response, 200, behavior.migrateResponse?.(baseResponse) ?? baseResponse);
      return;
    }

    if (method === "POST" && url === "/v1/b2b/passwords/authenticate") {
      const status = behavior.status?.authenticate ?? 200;
      if (status !== 200) {
        sendJson(response, status, { provider_detail: "authenticate-body-must-not-appear" });
        return;
      }
      const baseResponse: JsonObject = {
        status_code: 200,
        member_id: memberId,
        organization_id: organizationId,
        member_authenticated: true,
        member: {
          member_id: memberId,
          organization_id: organizationId,
          email_address: memberEmail,
          email_address_verified: true,
          status: "active",
        },
        member_session: {
          member_session_id: memberSessionId,
          member_id: memberId,
          organization_id: organizationId,
        },
        organization: {
          organization_id: organizationId,
          organization_name: organizationName,
          organization_slug: organizationSlug,
          auth_methods: "RESTRICTED",
          allowed_auth_methods: ["password"],
          email_invites: "NOT_ALLOWED",
          mfa_policy: "OPTIONAL",
        },
        session_jwt: "jwt-test-must-not-appear-in-output",
        session_token: "session-token-must-not-appear-in-output",
      };
      sendJson(response, 200, behavior.authenticateResponse?.(baseResponse) ?? baseResponse);
      return;
    }

    if (method === "DELETE" && url === `/v1/b2b/organizations/${organizationId}`) {
      const status = behavior.status?.cleanup ?? 200;
      if (status !== 200) {
        sendJson(response, status, { provider_detail: "cleanup-body-must-not-appear" });
        return;
      }
      const baseResponse: JsonObject = { status_code: 200, organization_id: organizationId };
      sendJson(response, 200, behavior.cleanupResponse?.(baseResponse) ?? baseResponse);
      return;
    }

    sendJson(response, 404, { provider_detail: "unexpected-route-body-must-not-appear" });
  });

  return { baseUrl, requests };
}

async function runProof(extraEnvironment: Record<string, string | undefined> = {}): Promise<RunnerResult> {
  return new Promise((resolveResult, reject) => {
    const child = spawn(process.execPath, [runnerPath], {
      cwd: repositoryRoot,
      env: {
        ...process.env,
        STYTCH_PROJECT_ID: contractProjectId,
        STYTCH_SECRET: contractSecret,
        ...extraEnvironment,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString(); });
    child.on("error", reject);
    child.on("close", (exitCode) => resolveResult({ exitCode, stderr, stdout }));
  });
}

function requireBody(request: CapturedRequest): JsonObject {
  if (!request.body) throw new Error("Expected request JSON body");
  return request.body;
}

function nestedObject(value: unknown): JsonObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Expected nested JSON object");
  }
  return value as JsonObject;
}

function withoutField(value: JsonObject, field: string): JsonObject {
  const result = { ...value };
  delete result[field];
  return result;
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map(async (server) => {
    server.closeAllConnections();
    await new Promise<void>((resolveServer) => server.close(() => resolveServer()));
  }));
});

describe("Stytch disposable B2B test-session proof CLI", () => {
  it("creates, migrates, authenticates, and deletes one proof-owned Test Organization", async () => {
    // Production break caught: changing sequence, ownership markers, password migration, session duration, cleanup, or safe output breaks the disposable proof contract.
    const { baseUrl, requests } = await startProofProvider();

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result).toEqual({
      exitCode: 0,
      stderr: "",
      stdout: "Stytch B2B Test session created and disposable Organization deleted.\n",
    });
    expect(requests.map(({ method, url }) => `${method} ${url}`)).toEqual([
      "POST /v1/b2b/organizations",
      "POST /v1/b2b/passwords/migrate",
      "POST /v1/b2b/passwords/authenticate",
      `DELETE /v1/b2b/organizations/${organizationId}`,
    ]);
    expect(requests.every(({ authorization }) => authorization === `Basic ${Buffer.from(`${contractProjectId}:${contractSecret}`).toString("base64")}`)).toBe(true);

    const createBody = requireBody(requests[0]);
    expect(createBody).toMatchObject({
      auth_methods: "RESTRICTED",
      allowed_auth_methods: ["password"],
      email_invites: "NOT_ALLOWED",
      mfa_policy: "OPTIONAL",
    });
    const slug = String(createBody.organization_slug);
    const marker = slug.match(/^zasp-m0-02-proof-([a-f0-9-]+)$/)?.[1];
    expect(marker).toBeTruthy();
    expect(createBody.organization_name).toBe(`Zasp M0-02 Proof ${marker}`);

    const migrateBody = requireBody(requests[1]);
    expect(migrateBody).toMatchObject({
      email_address: `zasp-m0-02-${marker}@example.com`,
      hash_type: "sha_512",
      organization_id: organizationId,
    });
    const authenticateBody = requireBody(requests[2]);
    expect(authenticateBody).toMatchObject({
      email_address: `zasp-m0-02-${marker}@example.com`,
      organization_id: organizationId,
      session_duration_minutes: 60,
    });
    const password = String(authenticateBody.password);
    expect(password).toMatch(/^[A-Za-z0-9_-]{40,}$/);
    expect(migrateBody.hash).toBe(createHash("sha512").update(password).digest("hex"));
    expect(`${result.stdout}${result.stderr}`).not.toContain(password);
    expect(`${result.stdout}${result.stderr}`).not.toContain(String(migrateBody.hash));
    expect(`${result.stdout}${result.stderr}`).not.toContain(contractSecret);
    expect(`${result.stdout}${result.stderr}`).not.toContain("jwt-test-must-not-appear-in-output");
    expect(`${result.stdout}${result.stderr}`).not.toContain("session-token-must-not-appear-in-output");
  });

  it("deletes the proof-owned Organization after password migration fails", async () => {
    // Production break caught: an intermediate provider failure could leak the disposable Organization if finally cleanup is skipped.
    const { baseUrl, requests } = await startProofProvider({ status: { migrate: 500 } });

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("Stytch proof failed: Stytch returned an unsuccessful response.\n");
    expect(requests.map(({ method, url }) => `${method} ${url}`)).toEqual([
      "POST /v1/b2b/organizations",
      "POST /v1/b2b/passwords/migrate",
      `DELETE /v1/b2b/organizations/${organizationId}`,
    ]);
    expect(`${result.stdout}${result.stderr}`).not.toContain("migrate-body-must-not-appear");
  });

  it("deletes the proof-owned Organization when authentication is incomplete", async () => {
    // Production break caught: an intermediate session could be accepted or leave disposable identity state behind.
    const { baseUrl, requests } = await startProofProvider({
      authenticateResponse: (response) => ({ ...response, member_authenticated: false }),
    });

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toBe("Stytch proof failed: Member was not fully authenticated.\n");
    expect(requests.at(-1)).toMatchObject({
      method: "DELETE",
      url: `/v1/b2b/organizations/${organizationId}`,
    });
  });

  it("deletes the proof-owned Organization when Stytch does not confirm password-only authentication", async () => {
    // Production break caught: accepting an unexpectedly broader authentication policy or skipping cleanup would invalidate isolation and leak proof state.
    const { baseUrl, requests } = await startProofProvider({
      createResponse: (response) => ({
        ...response,
        organization: {
          ...nestedObject(response.organization),
          allowed_auth_methods: ["password", "sso"],
        },
      }),
    });

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toBe("Stytch proof failed: created Organization was not password-only.\n");
    expect(requests.at(-1)).toMatchObject({
      method: "DELETE",
      url: `/v1/b2b/organizations/${organizationId}`,
    });
  });

  it("cleans up after password migration returns inconsistent Member identifiers", async () => {
    // Production break caught: authenticating a Member whose stable identifier changed during migration could cross an identity boundary or leak the owned Organization.
    const { baseUrl, requests } = await startProofProvider({
      migrateResponse: (response) => ({ ...response, member_id: "member-test-other" }),
    });

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toBe("Stytch proof failed: response did not include a consistent Test Member ID.\n");
    expect(requests.at(-1)?.method).toBe("DELETE");
  });

  it.each([
    {
      description: "missing",
      migrateResponse: (response: JsonObject) => withoutField(response, "member_created"),
    },
    {
      description: "false",
      migrateResponse: (response: JsonObject) => ({ ...response, member_created: false }),
    },
  ])("rejects a $description member_created migration result and cleans up", async ({ migrateResponse }) => {
    // Production break caught: reusing an existing Member would violate the proof's unique per-run identity guarantee.
    const { baseUrl, requests } = await startProofProvider({ migrateResponse });

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toBe("Stytch proof failed: migration did not create a new Member.\n");
    expect(requests.at(-1)?.method).toBe("DELETE");
  });

  it.each([
    {
      description: "missing expanded Organization",
      migrateResponse: (response: JsonObject) => withoutField(response, "organization"),
      expectedError: "response did not include a non-empty Organization.",
    },
    {
      description: "mismatched expanded Organization",
      migrateResponse: (response: JsonObject) => ({
        ...response,
        organization: { ...nestedObject(response.organization), organization_id: "organization-test-other" },
      }),
      expectedError: "migrated Organization ID did not match.",
    },
  ])("rejects a $description in the migration result and cleans up", async ({ migrateResponse, expectedError }) => {
    // Production break caught: accepting a missing or cross-tenant expanded Organization would under-validate the documented migration response.
    const { baseUrl, requests } = await startProofProvider({ migrateResponse });

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toBe(`Stytch proof failed: ${expectedError}\n`);
    expect(requests.at(-1)?.method).toBe("DELETE");
  });

  it.each([
    {
      description: "non-Test ID",
      createResponse: (response: JsonObject) => ({
        ...response,
        organization: { ...nestedObject(response.organization), organization_id: "organization-live-unowned" },
      }),
    },
    {
      description: "mismatched name",
      createResponse: (response: JsonObject) => ({
        ...response,
        organization: { ...nestedObject(response.organization), organization_name: "Someone else's Organization" },
      }),
    },
    {
      description: "mismatched slug",
      createResponse: (response: JsonObject) => ({
        ...response,
        organization: { ...nestedObject(response.organization), organization_slug: "someone-elses-organization" },
      }),
    },
  ])("refuses cleanup for a create response with a $description", async ({ createResponse }) => {
    // Production break caught: cleanup must never delete a Live, unowned, or marker-mismatched Organization returned by a compromised response.
    const { baseUrl, requests } = await startProofProvider({ createResponse });

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("Stytch proof failed: created Organization was not proof-owned.\n");
    expect(requests).toHaveLength(1);
    expect(requests[0]?.method).toBe("POST");
  });

  it("fails the proof when cleanup returns an error", async () => {
    // Production break caught: reporting success after cleanup failure would conceal leaked proof-owned identity state.
    const { baseUrl, requests } = await startProofProvider({ status: { cleanup: 500 } });

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("Stytch proof failed: disposable Organization cleanup failed.\n");
    expect(requests.at(-1)?.method).toBe("DELETE");
    expect(`${result.stdout}${result.stderr}`).not.toContain("cleanup-body-must-not-appear");
  });

  it("reports cleanup failure when the primary operation and cleanup both fail", async () => {
    // Production break caught: preserving only the primary error would conceal that proof-owned identity state may remain after failed cleanup.
    const { baseUrl, requests } = await startProofProvider({
      status: { cleanup: 500, migrate: 500 },
    });

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("Stytch proof failed: disposable Organization cleanup failed.\n");
    expect(requests.map(({ method, url }) => `${method} ${url}`)).toEqual([
      "POST /v1/b2b/organizations",
      "POST /v1/b2b/passwords/migrate",
      `DELETE /v1/b2b/organizations/${organizationId}`,
    ]);
    expect(`${result.stdout}${result.stderr}`).not.toContain("migrate-body-must-not-appear");
    expect(`${result.stdout}${result.stderr}`).not.toContain("cleanup-body-must-not-appear");
  });

  it("fails cleanup when Stytch confirms a different Organization ID", async () => {
    // Production break caught: a mismatched delete confirmation could be mistaken for cleanup of the exact proof-owned target.
    const { baseUrl } = await startProofProvider({
      cleanupResponse: (response) => ({ ...response, organization_id: "organization-test-other" }),
    });

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toBe("Stytch proof failed: disposable Organization cleanup failed.\n");
  });

  it.each([
    {
      description: "Member",
      authenticateResponse: (response: JsonObject) => ({
        ...response,
        member: { ...nestedObject(response.member), organization_id: "organization-test-other" },
      }),
      expectedError: "Member Organization ID did not match.",
    },
    {
      description: "Member session",
      authenticateResponse: (response: JsonObject) => ({
        ...response,
        member_session: { ...nestedObject(response.member_session), organization_id: "organization-test-other" },
      }),
      expectedError: "Member session Organization ID did not match.",
    },
  ])("fails closed and cleans up when the $description scope mismatches", async ({ authenticateResponse, expectedError }) => {
    // Production break caught: accepting a cross-Organization response component could bind a real session to the wrong tenant.
    const { baseUrl, requests } = await startProofProvider({ authenticateResponse });

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toBe(`Stytch proof failed: ${expectedError}\n`);
    expect(requests.at(-1)?.method).toBe("DELETE");
  });

  it.each([
    {
      description: "missing expanded Organization",
      authenticateResponse: (response: JsonObject) => withoutField(response, "organization"),
      expectedError: "response did not include a non-empty Organization.",
    },
    {
      description: "mismatched expanded Organization",
      authenticateResponse: (response: JsonObject) => ({
        ...response,
        organization: { ...nestedObject(response.organization), organization_id: "organization-test-other" },
      }),
      expectedError: "authenticated Organization ID did not match.",
    },
  ])("fails closed and cleans up for an authentication result with a $description", async ({ authenticateResponse, expectedError }) => {
    // Production break caught: accepting a missing or cross-tenant expanded Organization would under-validate the documented authenticate response.
    const { baseUrl, requests } = await startProofProvider({ authenticateResponse });

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toBe(`Stytch proof failed: ${expectedError}\n`);
    expect(requests.at(-1)?.method).toBe("DELETE");
  });

  it.each([
    {
      description: "top-level Organization ID",
      authenticateResponse: (response: JsonObject) => ({ ...response, organization_id: "organization-test-other" }),
      expectedError: "response Organization ID did not match.",
    },
    {
      description: "top-level Member ID",
      authenticateResponse: (response: JsonObject) => ({ ...response, member_id: "member-test-other" }),
      expectedError: "response did not include a consistent Test Member ID.",
    },
    {
      description: "non-Test Member session ID",
      authenticateResponse: (response: JsonObject) => ({
        ...response,
        member_session: { ...nestedObject(response.member_session), member_session_id: "member-session-live-other" },
      }),
      expectedError: "response did not include a Test member session ID.",
    },
    {
      description: "Member session Member ID",
      authenticateResponse: (response: JsonObject) => ({
        ...response,
        member_session: { ...nestedObject(response.member_session), member_id: "member-test-other" },
      }),
      expectedError: "Member session Member ID did not match.",
    },
    {
      description: "blank session JWT",
      authenticateResponse: (response: JsonObject) => ({
        ...response,
        provider_detail: "provider-body-must-not-appear-in-output",
        session_jwt: "",
      }),
      expectedError: "response did not include a session JWT.",
    },
  ])("fails closed, redacts, and cleans up for a mismatched $description", async ({ authenticateResponse, expectedError }) => {
    // Production break caught: accepting an incomplete or cross-scope session component could treat an invalid Stytch response as a real login.
    const { baseUrl, requests } = await startProofProvider({ authenticateResponse });

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe(`Stytch proof failed: ${expectedError}\n`);
    expect(requests.at(-1)?.method).toBe("DELETE");
    expect(`${result.stdout}${result.stderr}`).not.toContain("provider-body-must-not-appear-in-output");
  });

  it("accepts an explicitly gated IPv6 loopback lifecycle", async (context) => {
    // Production break caught: rejecting [::1] would silently narrow the documented loopback-only test gate.
    let provider: Awaited<ReturnType<typeof startProofProvider>>;
    try {
      provider = await startProofProvider({}, "ipv6");
    } catch (error) {
      const code = error instanceof Error ? (error as Error & { code?: string }).code : undefined;
      if (code === "EADDRNOTAVAIL" || code === "EAFNOSUPPORT") {
        context.skip();
        return;
      }
      throw error;
    }

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: provider.baseUrl,
    });

    expect(result.exitCode).toBe(0);
    expect(provider.requests).toHaveLength(4);
  });

  it("rejects Live credentials before attempting any request", async () => {
    // Production break caught: accepting a Live key could create or delete production identity state.
    const result = await runProof({
      STYTCH_PROJECT_ID: liveProjectId,
      STYTCH_SECRET: liveSecret,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("Stytch proof failed: STYTCH_PROJECT_ID must be a Stytch Test project.\n");
    expect(`${result.stdout}${result.stderr}`).not.toContain(liveSecret);
  });

  it("rejects a Live secret paired with a Test project before network I/O", async () => {
    // Production break caught: validating only the Project ID prefix could authorize destructive proof traffic with a Live secret.
    let requests = 0;
    const { baseUrl } = await startLoopbackServer((_request, response) => {
      requests += 1;
      response.end();
    });

    const result = await runProof({
      STYTCH_PROJECT_ID: contractProjectId,
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
      STYTCH_SECRET: liveSecret,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("Stytch proof failed: STYTCH_SECRET must be a Stytch Test secret.\n");
    expect(requests).toBe(0);
    expect(`${result.stdout}${result.stderr}`).not.toContain(liveSecret);
  });

  it("rejects a loopback override until the explicit test gate is enabled", async () => {
    // Production break caught: an inherited environment variable could redirect credentialed create/delete traffic away from Stytch Test.
    let requests = 0;
    const { baseUrl } = await startLoopbackServer((_request, response) => {
      requests += 1;
      response.end();
    });

    const result = await runProof({ STYTCH_PROOF_BASE_URL: baseUrl });

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toBe("Stytch proof failed: loopback override requires STYTCH_PROOF_ALLOW_LOOPBACK=1.\n");
    expect(requests).toBe(0);
  });

  it("rejects arbitrary API hosts even when the loopback test gate is enabled", async () => {
    // Production break caught: the test gate must not become a general credentialed host override.
    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: "https://untrusted.example.test",
    });

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("Stytch proof failed: STYTCH_PROOF_BASE_URL must be an HTTP loopback URL.\n");
  });

  it("fails safely without following a provider redirect", async () => {
    // Production break caught: following a provider redirect can forward authenticated proof traffic to an unintended host.
    let redirectTargetRequests = 0;
    const { baseUrl: redirectTargetUrl } = await startLoopbackServer((_request, response) => {
      redirectTargetRequests += 1;
      sendJson(response, 200, { provider_detail: "redirect-body-must-not-appear" });
    });
    const { baseUrl: redirectSourceUrl } = await startLoopbackServer((_request, response) => {
      response.writeHead(302, { location: redirectTargetUrl });
      response.end();
    });

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: redirectSourceUrl,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toBe("Stytch proof failed: Stytch request failed.\n");
    expect(redirectTargetRequests).toBe(0);
    expect(`${result.stdout}${result.stderr}`).not.toContain("redirect-body-must-not-appear");
  });

  it("rejects an oversized declared provider response before parsing", async () => {
    // Production break caught: trusting an oversized Content-Length can let a provider response consume unbounded memory.
    const { baseUrl } = await startLoopbackServer((_request, response) => {
      response.writeHead(200, {
        "content-length": String(responseByteLimit + 1),
        "content-type": "application/json",
      });
      response.end("{}");
    });

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toBe("Stytch proof failed: response exceeded the 65536-byte limit.\n");
  });

  it("rejects a streamed provider response that exceeds the byte limit", async () => {
    // Production break caught: a chunked provider response can bypass a Content-Length-only limit and exhaust memory.
    const { baseUrl } = await startLoopbackServer((_request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ unused_large_value: "x".repeat(responseByteLimit) }));
    });

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toBe("Stytch proof failed: response exceeded the 65536-byte limit.\n");
  });

  it("aborts a stalled response body by the deadline and still attempts owned cleanup", async () => {
    // Production break caught: a provider that never finishes a body could hang the CLI forever or bypass finally cleanup after ownership is established.
    const { baseUrl, requests } = await startProofProvider({ stallMigrateBody: true });
    const startedAt = performance.now();

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });
    const elapsedMs = performance.now() - startedAt;

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("Stytch proof failed: request timed out.\n");
    expect(elapsedMs).toBeGreaterThanOrEqual(4_500);
    expect(elapsedMs).toBeLessThan(8_000);
    expect(requests.at(-1)).toMatchObject({
      method: "DELETE",
      url: `/v1/b2b/organizations/${organizationId}`,
    });
    expect(`${result.stdout}${result.stderr}`).not.toContain("stalled-body-must-not-appear");
  }, 10_000);
});
