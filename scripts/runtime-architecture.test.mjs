import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";

const root = process.cwd();
const manifest = JSON.parse(
  readFileSync(resolve(root, "package.json"), "utf8"),
);

test("uses Vite without Cloudflare or server-rendering runtime adapters", () => {
  const installedPackages = {
    ...manifest.dependencies,
    ...manifest.devDependencies,
  };

  assert.equal(manifest.scripts.dev, "vite");
  assert.equal(manifest.scripts.build, "vite build");
  assert.equal(manifest.scripts.start, "vite preview");
  assert.ok(installedPackages.vite);

  for (const dependency of [
    "@cloudflare/vite-plugin",
    "@cloudflare/workers-types",
    "next",
    "vinext",
    "wrangler",
  ]) {
    assert.equal(installedPackages[dependency], undefined);
  }

  for (const cloudflareAdapter of [
    "cloudflare-env.d.ts",
    "next-env.d.ts",
    "next.config.ts",
    "worker/index.ts",
  ]) {
    assert.equal(existsSync(resolve(root, cloudflareAdapter)), false);
  }
});
