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
const contractMemberId = "member-test-contract";
const contractOrganizationId = "organization-test-contract";
const responseByteLimit = 64 * 1024;
const servers: Server[] = [];

type RunnerResult = {
  exitCode: number | null;
  stderr: string;
  stdout: string;
};

type ProviderContractFixture = {
  member: { member_id: string; organization_id?: string };
  member_authenticated: boolean;
  member_id: string;
  member_session: {
    member_id: string;
    member_session_id?: string;
    organization_id?: string;
  };
  organization: { organization_id?: string } | null;
  organization_id?: string;
  session_jwt: string;
  session_token: string;
  status_code: number;
};

function validProviderResponse(): ProviderContractFixture {
  return {
    status_code: 200,
    member_id: contractMemberId,
    organization_id: contractOrganizationId,
    member: {
      member_id: contractMemberId,
      organization_id: contractOrganizationId,
    },
    organization: null,
    member_session: {
      member_session_id: "member-session-test-contract",
      member_id: contractMemberId,
      organization_id: contractOrganizationId,
    },
    member_authenticated: true,
    session_jwt: "jwt-test-must-not-appear-in-output",
    session_token: "session-token-must-not-appear-in-output",
  };
}

async function startLoopbackServer(
  handler: (request: IncomingMessage, response: ServerResponse) => void,
): Promise<{ baseUrl: string; server: Server }> {
  const server = createServer(handler);
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
  handler: (request: IncomingMessage, response: ServerResponse) => void,
): Promise<{ baseUrl: string; server: Server }> {
  const server = createServer(handler);
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

afterEach(async () => {
  await Promise.all(servers.splice(0).map(async (server) => {
    server.closeAllConnections();
    await new Promise<void>((resolveServer) => server.close(() => resolveServer()));
  }));
});

describe("Stytch B2B test-session proof CLI", () => {
  it("accepts the null-expanded sandbox Organization when stable scopes match and prints only a safe summary", async () => {
    // Production break caught: rejecting the real null-expanded sandbox shape prevents the proof, while changing request/auth/output handling can leak a credential or session artifact.
    let requestBody = "";
    let authorization = "";
    let requestUrl = "";
    const { baseUrl } = await startLoopbackServer((request, response) => {
      requestUrl = request.url ?? "";
      authorization = request.headers.authorization ?? "";
      request.setEncoding("utf8");
      request.on("data", (chunk: string) => { requestBody += chunk; });
      request.on("end", () => {
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify(validProviderResponse()));
      });
    });

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result).toEqual({
      exitCode: 0,
      stderr: "",
      stdout: "Stytch B2B Test session created.\n",
    });
    expect(requestUrl).toBe("/v1/b2b/magic_links/authenticate");
    expect(authorization).toBe(`Basic ${Buffer.from(`${contractProjectId}:${contractSecret}`).toString("base64")}`);
    expect(JSON.parse(requestBody)).toEqual({
      magic_links_token: "DOYoip3rvIMMW5lgItikFK-Ak1CfMsgjuiCyI7uuU94=",
      session_duration_minutes: 60,
    });
    expect(`${result.stdout}${result.stderr}`).not.toContain(contractSecret);
    expect(`${result.stdout}${result.stderr}`).not.toContain("jwt-test-must-not-appear-in-output");
    expect(`${result.stdout}${result.stderr}`).not.toContain("session-token-must-not-appear-in-output");
  });

  it("accepts a matching expanded Organization when the provider returns one", async () => {
    // Production break caught: rejecting a valid expanded Organization would make the proof incompatible with the documented non-sandbox response.
    const providerResponse = validProviderResponse();
    providerResponse.organization = { organization_id: contractOrganizationId };
    const { baseUrl } = await startLoopbackServer((_request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify(providerResponse));
    });

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result).toEqual({
      exitCode: 0,
      stderr: "",
      stdout: "Stytch B2B Test session created.\n",
    });
  });

  it.each([
    { description: "missing", organizationId: undefined },
    { description: "blank", organizationId: "   " },
    { description: "non-Test", organizationId: "organization-live-contract" },
  ])("rejects a $description top-level Organization ID", async ({ organizationId }) => {
    // Production break caught: accepting a missing/blank stable Organization ID would create an unscoped authenticated session.
    const providerResponse = validProviderResponse();
    providerResponse.organization = { organization_id: contractOrganizationId };
    providerResponse.organization_id = organizationId;
    const { baseUrl } = await startLoopbackServer((_request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify(providerResponse));
    });

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("Stytch proof failed: response did not include a Test Organization ID.\n");
  });

  it.each([
    {
      description: "Member",
      mutate: (response: ProviderContractFixture) => {
        response.member.organization_id = "organization-test-other";
      },
    },
    {
      description: "Member session",
      mutate: (response: ProviderContractFixture) => {
        response.member_session.organization_id = "organization-test-other";
      },
    },
  ])("rejects a $description scoped to a different Organization", async ({ description, mutate }) => {
    // Production break caught: accepting cross-Organization response components could bind a session to the wrong tenant.
    const providerResponse = validProviderResponse();
    mutate(providerResponse);
    const { baseUrl } = await startLoopbackServer((_request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify(providerResponse));
    });

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe(`Stytch proof failed: ${description} Organization ID did not match.\n`);
  });

  it("rejects an expanded Organization scoped to a different Organization ID", async () => {
    // Production break caught: trusting a mismatched expanded Organization could cross tenant boundaries despite a valid stable ID.
    const providerResponse = validProviderResponse();
    providerResponse.organization = { organization_id: "organization-test-other" };
    const { baseUrl } = await startLoopbackServer((_request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify(providerResponse));
    });

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("Stytch proof failed: expanded Organization ID did not match.\n");
  });

  it("rejects a Member that is not fully authenticated", async () => {
    // Production break caught: treating an intermediate authentication state as a full login could bypass required factors.
    const providerResponse = validProviderResponse();
    providerResponse.member_authenticated = false;
    const { baseUrl } = await startLoopbackServer((_request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify(providerResponse));
    });

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("Stytch proof failed: Member was not fully authenticated.\n");
  });

  it("accepts an explicitly gated IPv6 loopback override", async (context) => {
    // Production break caught: rejecting [::1] would make the documented IPv6 loopback test gate unavailable.
    let baseUrl: string;
    try {
      ({ baseUrl } = await startIpv6LoopbackServer((_request, response) => {
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify(validProviderResponse()));
      }));
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
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result).toEqual({
      exitCode: 0,
      stderr: "",
      stdout: "Stytch B2B Test session created.\n",
    });
  });

  it("rejects Live credentials before attempting any request", async () => {
    // Production break caught: accepting a Live key could create or modify production identity state.
    const result = await runProof({
      STYTCH_PROJECT_ID: liveProjectId,
      STYTCH_SECRET: liveSecret,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("Stytch proof failed: STYTCH_PROJECT_ID must be a Stytch Test project.\n");
    expect(`${result.stdout}${result.stderr}`).not.toContain(liveSecret);
  });

  it("rejects a loopback override until the explicit test gate is enabled", async () => {
    // Production break caught: an inherited environment variable could redirect credentialed traffic away from test.stytch.com.
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
    expect(`${result.stdout}${result.stderr}`).not.toContain(contractSecret);
  });

  it("fails safely without following a provider redirect", async () => {
    // Production break caught: following a provider redirect can forward authenticated proof traffic to an unintended host.
    let redirectTargetRequests = 0;
    const { baseUrl: redirectTargetUrl } = await startLoopbackServer((_request, response) => {
      redirectTargetRequests += 1;
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ provider_detail: "redirect-body-must-not-appear-in-output" }));
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
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("Stytch proof failed: Stytch request failed.\n");
    expect(redirectTargetRequests).toBe(0);
    expect(`${result.stdout}${result.stderr}`).not.toContain(contractSecret);
    expect(`${result.stdout}${result.stderr}`).not.toContain("redirect-body-must-not-appear-in-output");
  });

  it("rejects an oversized declared provider response before parsing it", async () => {
    // Production break caught: trusting an oversized Content-Length can let a provider response consume unbounded memory.
    const { baseUrl } = await startLoopbackServer((_request, response) => {
      response.writeHead(200, {
        "content-length": String(responseByteLimit + 1),
        "content-type": "application/json",
      });
      response.end(JSON.stringify({
        ...validProviderResponse(),
        provider_detail: "declared-oversize-body-must-not-appear-in-output",
      }));
    });

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("Stytch proof failed: response exceeded the 65536-byte limit.\n");
    expect(`${result.stdout}${result.stderr}`).not.toContain("declared-oversize-body-must-not-appear-in-output");
    expect(`${result.stdout}${result.stderr}`).not.toContain(contractSecret);
  });

  it("rejects a streamed provider response that exceeds the byte limit", async () => {
    // Production break caught: a chunked response can bypass a Content-Length-only limit and exhaust memory.
    const { baseUrl } = await startLoopbackServer((_request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({
        ...validProviderResponse(),
        provider_detail: "streamed-oversize-body-must-not-appear-in-output",
        unused_large_value: "x".repeat(responseByteLimit),
      }));
    });

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("Stytch proof failed: response exceeded the 65536-byte limit.\n");
    expect(`${result.stdout}${result.stderr}`).not.toContain("streamed-oversize-body-must-not-appear-in-output");
    expect(`${result.stdout}${result.stderr}`).not.toContain(contractSecret);
  });

  it("rejects a member session without its provider member_session_id", async () => {
    // Production break caught: accepting an arbitrary member_session object can treat an incomplete Stytch response as authenticated.
    const providerResponse = validProviderResponse();
    providerResponse.member_session.member_session_id = undefined;
    const { baseUrl } = await startLoopbackServer((_request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({
        ...providerResponse,
        provider_detail: "member-session-id-must-not-be-optional",
      }));
    });

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("Stytch proof failed: response did not include a member session ID.\n");
    expect(`${result.stdout}${result.stderr}`).not.toContain("member-session-id-must-not-be-optional");
  });

  it("fails closed on an incomplete provider response without echoing its body", async () => {
    // Production break caught: treating a partial provider response as a usable authenticated session could bypass identity checks.
    const providerResponse = validProviderResponse();
    providerResponse.session_jwt = "";
    const { baseUrl } = await startLoopbackServer((_request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({
        ...providerResponse,
        provider_detail: "provider-body-must-not-appear-in-output",
      }));
    });

    const result = await runProof({
      STYTCH_PROOF_ALLOW_LOOPBACK: "1",
      STYTCH_PROOF_BASE_URL: baseUrl,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("Stytch proof failed: response did not include a session JWT.\n");
    expect(`${result.stdout}${result.stderr}`).not.toContain("provider-body-must-not-appear-in-output");
  });
});
