import { createHash, generateKeyPairSync, sign, webcrypto } from "node:crypto";
import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { APIClient } from "../../../apps/web/api/client";
import { PrivateAddonScan } from "./PrivateAddonScan";

afterEach(() => vi.unstubAllGlobals());
const id = "pid_11111111-2222-4333-8444-555555555555";
const origin = "https://worker.test.invalid";
const archive = "fixture bytes";
const keys = generateKeyPairSync("ed25519");
const manifest = "sha256:" + "a".repeat(64);

type Mode = "memory_only" | "encrypted_24h";
function grant(outer: Mode, inner: Mode = outer) {
  const expires = Math.floor(Date.now() / 1000) + 240,
    until = expires + 86_100;
  const cap = {
    version:
      inner === "memory_only"
        ? "private-addon-upload.v1"
        : "private-addon-upload-retained.v1",
    audience: origin,
    scope: [id, id, id].join("/"),
    actor: id,
    id,
    sha256: "sha256:" + createHash("sha256").update(archive).digest("hex"),
    size: archive.length,
    expires,
    registry: true,
    ...(inner === "encrypted_24h" ? { retain_until: until } : {}),
  };
  const raw = Buffer.from(JSON.stringify(cap)),
    sig = sign(
      null,
      Buffer.concat([Buffer.from("zasp-private-addon-upload.v1\0"), raw]),
      keys.privateKey,
    );
  return {
    id,
    retention: outer,
    upload_url: origin + "/v1/uploads/" + id,
    upload_grant:
      raw.toString("base64url") + "." + Buffer.from(sig).toString("base64url"),
    verification_key: keys.publicKey.export({ format: "jwk" }).x,
    expires_at: new Date(expires * 1000).toISOString(),
    result_delivery: "registry",
    ...(outer === "encrypted_24h"
      ? { retain_until: new Date(until * 1000).toISOString() }
      : {}),
  };
}
function result(retainedUntil?: string) {
  return {
    grant_id: id,
    registry_status: "recorded",
    receipt: {
      scan_id: id,
      version_id: id,
      manifest_digest: manifest,
      completeness: "complete",
      review_path: "/inventory/tools?addon=" + id,
    },
    result: {
      schema_version: "zasp-private-scan.v1",
      ruleset: "zasp-static.v2",
      status: "complete",
      manifest_digest: manifest,
      rule_counts: { "dependency.unpinned": 2 },
    },
    ...(retainedUntil
      ? {
          retention: {
            mode: "encrypted_24h",
            state: "retained",
            grant_id: id,
            expires_at: retainedUntil,
          },
        }
      : {}),
  };
}
async function start(g: ReturnType<typeof grant>, reply: unknown) {
  vi.stubGlobal("crypto", webcrypto);
  const post = vi.fn().mockResolvedValue({ data: g });
  const send = vi.fn().mockResolvedValue(
    new Response(JSON.stringify(reply), {
      headers: { "Content-Type": "application/json" },
    }),
  );
  vi.stubGlobal("fetch", send);
  const user = userEvent.setup();
  render(
    <PrivateAddonScan
      client={{ POST: post } as unknown as APIClient}
      environment={id}
      fresh
      reauthenticate={vi.fn()}
    />,
  );
  const file = new File([archive], "fixture.zip", { type: "application/zip" });
  Object.defineProperty(file, "arrayBuffer", {
    value: () => Promise.resolve(new TextEncoder().encode(archive).buffer),
  });
  fireEvent.change(screen.getByLabelText("Skill ZIP"), {
    target: { files: [file] },
  });
  const retention = screen.getByRole("checkbox", {
    name: /Retain an encrypted/,
  });
  expect(retention).not.toBeChecked();
  return { user, file, post, send, retention };
}

describe("private ZIP scan", () => {
  it("previews the exact recipient before a memory-only scan, binds the signed grant, and omits browser credentials", async () => {
    const g = grant("memory_only");
    const { user, post, send, file } = await start(g, result());
    await user.click(
      screen.getByRole("button", { name: "Review upload" }),
    );
    const confirm = await screen.findByRole("button", {
      name: "Scan on worker.test.invalid",
    });
    expect(post).toHaveBeenCalledWith(
      "/api/v1/addon-scan-uploads",
      expect.objectContaining({
        body: expect.objectContaining({ retention: "memory_only" }),
      }),
    );
    expect(send).not.toHaveBeenCalled();
    await user.click(confirm);
    await screen.findByText(
      /Scan complete. 2 static findings. Findings recorded/,
    );
    expect(
      screen.getByRole("link", { name: "Open version review" }),
    ).toHaveAttribute("href", "/inventory/tools?addon=" + id + "&environment_id=" + id);
    expect(send).toHaveBeenCalledWith(
      g.upload_url,
      expect.objectContaining({
        method: "PUT",
        body: file,
        credentials: "omit",
        redirect: "error",
        referrerPolicy: "no-referrer",
      }),
    );
  });
  it("accepts current rule counts from the private worker and displays them", async () => {
    const reply = result();
    const rule_counts = { "instruction.override": 1, "mcp.unpinned_exec": 1, "script.credential_path_access": 1, "script.remote_exec_pipe": 1 };
    const { user } = await start(grant("memory_only"), { ...reply, result: { ...reply.result, rule_counts } });
    await user.click(screen.getByRole("button", { name: "Review upload" }));
    await user.click(await screen.findByRole("button", { name: /Scan on/ }));
    expect(await screen.findByText(/Scan complete. 4 static findings/)).toBeVisible();
    for (const rule of Object.keys(rule_counts)) expect(screen.getByText(rule)).toBeVisible();
  });
  it.each([["zasp-static.v1", "instruction.override"], ["zasp-static.v2", "unknown.rule"]])(
    "rejects findings outside %s (%s)", async (ruleset, rule) => {
      const reply = result();
      const { user } = await start(grant("memory_only"), { ...reply, result: { ...reply.result, ruleset, rule_counts: { [rule]: 1 } } });
      await user.click(screen.getByRole("button", { name: "Review upload" }));
      await user.click(await screen.findByRole("button", { name: /Scan on/ }));
      expect(await screen.findByText(/worker could not confirm/)).toBeVisible();
      expect(screen.queryByRole("link", { name: "Open version review" })).toBeNull();
    },
  );
  it("clears a prepared upload when a replacement drop is invalid", async () => {
    const { user, send, post } = await start(grant("memory_only"), result());
    await user.click(screen.getByRole("button", { name: "Review upload" }));
    await screen.findByRole("button", { name: /Scan on/ });
    fireEvent.drop(screen.getByLabelText("Skill ZIP").parentElement!, { dataTransfer: { files: [new File(["hello"], "wrong.txt")] } });
    expect(screen.getByRole("status")).toHaveTextContent("Choose a .zip file");
    expect(screen.getByRole("button", { name: "Review upload" })).toBeDisabled();
    expect(send).not.toHaveBeenCalled();
    expect(post).toHaveBeenCalledTimes(1);
  });
  it("links the recorded partial receipt to the selected Environment with no version action", async () => {
    const original = result();
    const partial = { ...original, receipt: {...original.receipt, completeness: "partial", version_id: null, manifest_digest: null, review_path: null},
      result: {...original.result, status: "partial", manifest_digest: null} };
    const {user} = await start(grant("memory_only"),partial);
    await user.click(screen.getByRole("button",{name:"Review upload"}));
    await user.click(await screen.findByRole("button",{name:"Scan on worker.test.invalid"}));
    expect(await screen.findByRole("link",{name:"Open scan receipt"})).toHaveAttribute("href","/inventory/tools?scan=" + id + "&environment_id=" + id);
    expect(screen.queryByRole("link",{name:"Open version review"})).toBeNull();
  });
  it("previews the exact deadline, invalidates previous consent, and confirms a verified retention receipt", async () => {
    const g = grant("encrypted_24h");
    const { user, retention, post, send } = await start(
      g,
      result(g.retain_until),
    );
    await user.click(retention);
    await user.click(
      screen.getByRole("button", { name: "Review upload" }),
    );
    await screen.findByRole("button", { name: /Scan on/ });
    expect(await screen.findByText(g.retain_until!)).toBeVisible();
    expect(send).not.toHaveBeenCalled();
    await user.click(retention);
    expect(screen.queryByRole("button", { name: /Scan on/ })).toBeNull();
    await user.click(retention);
    await user.click(
      screen.getByRole("button", { name: "Review upload" }),
    );
    await user.click(
      await screen.findByRole("button", { name: /Scan on/ }),
    );
    expect(post).toHaveBeenNthCalledWith(
      2,
      "/api/v1/addon-scan-uploads",
      expect.objectContaining({
        body: expect.objectContaining({ retention: "encrypted_24h" }),
      }),
    );
    await screen.findByText(/Encrypted ZIP stored/);
    expect(retention).not.toBeChecked();
  });
  it.each([
    ["memory_only", "encrypted_24h"],
    ["encrypted_24h", "memory_only"],
  ] as const)(
    "refuses a %s response with a %s signed capability before sending bytes",
    async (outer, inner) => {
      const { user, send, retention } = await start(
        grant(outer, inner),
        result(),
      );
      if (outer === "encrypted_24h") await user.click(retention);
      await user.click(
        screen.getByRole("button", { name: "Review upload" }),
      );
      await screen.findByText(/Could not verify/);
      expect(send).not.toHaveBeenCalled();
      expect(screen.queryByRole("button", { name: /Scan on/ })).toBeNull();
    },
  );
  it("rejects a damaged grant signature before making the direct upload available", async () => {
    const g = grant("memory_only");
    const [raw, signature] = g.upload_grant.split(".");
    g.upload_grant =
      raw + "." + (signature[0] === "A" ? "B" : "A") + signature.slice(1);
    const { user, send } = await start(g, result());
    await user.click(
      screen.getByRole("button", { name: "Review upload" }),
    );
    await screen.findByText(/Could not verify/);
    expect(send).not.toHaveBeenCalled();
  });
  it("does not claim retained storage without a worker readback", async () => {
    const { user, retention } = await start(grant("encrypted_24h"), result());
    await user.click(retention);
    await user.click(
      screen.getByRole("button", { name: "Review upload" }),
    );
    await user.click(
      await screen.findByRole("button", { name: /Scan on/ }),
    );
    await screen.findByText(/encrypted ZIP may already be stored/);
    expect(
      screen.queryByRole("link", { name: "Open version review" }),
    ).toBeNull();
  });
});
