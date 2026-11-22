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
    until = expires + 20 * 3600;
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
  await user.click(screen.getByText("Scan a private skill ZIP"));
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
      screen.getByRole("button", { name: "Prepare private scan" }),
    );
    const confirm = await screen.findByRole("button", {
      name: "Send ZIP to worker.test.invalid",
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
      /Scan complete. dependency.unpinned \(2\). Findings recorded/,
    );
    expect(
      screen.getByRole("link", { name: "Open version review" }),
    ).toHaveAttribute("href", "/inventory/tools?addon=" + id);
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
  it("previews the exact deadline, invalidates previous consent, and confirms a verified retention receipt", async () => {
    const g = grant("encrypted_24h");
    const { user, retention, post, send } = await start(
      g,
      result(g.retain_until),
    );
    await user.click(retention);
    await user.click(
      screen.getByRole("button", { name: "Prepare private scan" }),
    );
    await screen.findByRole("button", { name: /Send ZIP to/ });
    expect(await screen.findByText(g.retain_until!)).toBeVisible();
    expect(send).not.toHaveBeenCalled();
    await user.click(retention);
    expect(screen.queryByRole("button", { name: /Send ZIP to/ })).toBeNull();
    await user.click(retention);
    await user.click(
      screen.getByRole("button", { name: "Prepare private scan" }),
    );
    await user.click(
      await screen.findByRole("button", { name: /Send ZIP to/ }),
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
        screen.getByRole("button", { name: "Prepare private scan" }),
      );
      await screen.findByText(/Could not prepare/);
      expect(send).not.toHaveBeenCalled();
      expect(screen.queryByRole("button", { name: /Send ZIP to/ })).toBeNull();
    },
  );
  it("rejects a damaged grant signature before making the direct upload available", async () => {
    const g = grant("memory_only");
    const [raw, signature] = g.upload_grant.split(".");
    g.upload_grant =
      raw + "." + (signature[0] === "A" ? "B" : "A") + signature.slice(1);
    const { user, send } = await start(g, result());
    await user.click(
      screen.getByRole("button", { name: "Prepare private scan" }),
    );
    await screen.findByText(/Could not prepare/);
    expect(send).not.toHaveBeenCalled();
  });
  it("does not claim retained storage without a worker readback", async () => {
    const { user, retention } = await start(grant("encrypted_24h"), result());
    await user.click(retention);
    await user.click(
      screen.getByRole("button", { name: "Prepare private scan" }),
    );
    await user.click(
      await screen.findByRole("button", { name: /Send ZIP to/ }),
    );
    await screen.findByText(
      /could not confirm this scan or its retention status/,
    );
    expect(
      screen.queryByRole("link", { name: "Open version review" }),
    ).toBeNull();
  });
});
