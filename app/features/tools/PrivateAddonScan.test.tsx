import { webcrypto } from "node:crypto";
import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { APIClient } from "../../../apps/web/api/client";
import { PrivateAddonScan } from "./PrivateAddonScan";

afterEach(() => vi.unstubAllGlobals());

describe("private ZIP scan", () => {
  it("previews the exact recipient before sending bytes and omits browser credentials", async () => {
    vi.stubGlobal("crypto", webcrypto);
    const id = "pid_11111111-2222-4333-8444-555555555555";
    const manifest = "sha256:" + "a".repeat(64);
    const url = "https://worker.test.invalid/v1/uploads/" + id;
    const post = vi
      .fn()
      .mockResolvedValue({
        data: {
          id,
          upload_url: url,
          upload_grant: "body." + "a".repeat(86),
          retention: "memory_only",
          result_delivery: "registry",
          expires_at: new Date(Date.now() + 240000).toISOString(),
        },
      });
    const send = vi
      .fn()
      .mockResolvedValue(
        new Response(
          JSON.stringify({
            grant_id: id,
            registry_status: "recorded",
            receipt: {
              manifest_digest: manifest,
              scan_id: id,
              version_id: id,
              completeness: "complete",
              review_path: "/inventory/tools?addon=" + id,
            },
            result: {
              manifest_digest: manifest,
              schema_version: "zasp-private-scan.v1",
              status: "complete",
              rule_counts: { "dependency.unpinned": 2 },
            },
          }),
          { headers: { "Content-Type": "application/json" } },
        ),
      );
    vi.stubGlobal("fetch", send);
    const user = userEvent.setup();
    render(
      <PrivateAddonScan
        client={{ POST: post } as unknown as APIClient}
        environment="staging"
        fresh
        reauthenticate={vi.fn()}
      />,
    );
    await user.click(screen.getByText("Scan a private skill ZIP"));
    const file = new File(["fixture bytes"], "fixture.zip", {
      type: "application/zip",
    });
    Object.defineProperty(file, "arrayBuffer", {
      value: () =>
        Promise.resolve(new TextEncoder().encode("fixture bytes").buffer),
    });
    fireEvent.change(screen.getByLabelText("Skill ZIP"), {
      target: { files: [file] },
    });
    await user.click(
      screen.getByRole("button", { name: "Prepare private scan" }),
    );
    const confirm = await screen.findByRole("button", {
      name: "Send ZIP to worker.test.invalid",
    });
    expect(post).toHaveBeenCalledTimes(1);
    expect(send).not.toHaveBeenCalled();
    await user.click(confirm);
    await screen.findByText(
      /Scan complete. dependency.unpinned \(2\). Findings recorded/,
    );
    expect(
      screen.getByRole("link", { name: "Open version review" }),
    ).toHaveAttribute("href", "/inventory/tools?addon=" + id);
    expect(send).toHaveBeenCalledWith(
      url,
      expect.objectContaining({
        method: "PUT",
        body: file,
        credentials: "omit",
        redirect: "error",
        referrerPolicy: "no-referrer",
      }),
    );
  });
});
