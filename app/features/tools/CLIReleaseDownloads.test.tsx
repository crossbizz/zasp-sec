import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { CLIReleaseDownloads, type CLIRelease } from "./CLIReleaseDownloads";

const release: CLIRelease = {
  version: "v1.2.3", commit: "a".repeat(40), manifest_sha256: "b".repeat(64),
  assets: [{ name: "zaspctl-windows-amd64.exe", bytes: 1024, sha256: "c".repeat(64) }],
};
describe("signed CLI downloads", () => {
  it("uses the source guidance until a bundle is staged", () => {
    render(<CLIReleaseDownloads release={{version:"",commit:"",manifest_sha256:"",assets:[]}} />);
    expect(screen.getByText(/currently offers the source build/)).toBeVisible();
    expect(screen.queryByRole("link")).toBeNull();
  });
  it("offers only the pinned platform and version on this deployment", () => {
    render(<CLIReleaseDownloads release={release} />);
    expect(screen.getByRole("link", { name: "Windows x64" })).toHaveAttribute("href", "/downloads/zaspctl/v1.2.3/zaspctl-windows-amd64.exe");
    expect(screen.getByText("signature")).toHaveAttribute("href", "/downloads/zaspctl/v1.2.3/manifest.ed25519");
  });
  it("rejects forwarded URLs or a noncanonical version", () => {
    const { rerender } = render(<CLIReleaseDownloads release={{ ...release, version: "../other" }} />);
    expect(screen.queryByRole("link")).toBeNull();
    rerender(<CLIReleaseDownloads release={{ ...release, assets: [{ ...release.assets[0], name: "https://example.invalid/tool" }] }} />);
    expect(screen.queryByRole("link")).toBeNull();
  });
});
