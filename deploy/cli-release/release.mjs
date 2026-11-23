#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { createHash, createPrivateKey, createPublicKey, randomUUID, sign, verify } from "node:crypto";
import { constants, chmodSync, closeSync, existsSync, fstatSync, lstatSync, mkdirSync, mkdtempSync, openSync, readdirSync, readSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const platforms = new Map([
  ["zaspctl-linux-amd64", ["linux", "amd64"]],
  ["zaspctl-darwin-arm64", ["darwin", "arm64"]],
  ["zaspctl-darwin-amd64", ["darwin", "amd64"]],
  ["zaspctl-windows-amd64.exe", ["windows", "amd64"]],
]);
const pinPath = "app/features/tools/cli-release-pin.json";
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const json = (value) => Buffer.from(JSON.stringify(value, null, 2) + "\n");
const emptyPin = { version: "", commit: "", manifest_sha256: "", assets: [] };

function expect(ok, message) { if (!ok) throw new Error(message); }
function checkRef(version, commit) {
  expect(/^v(?:0|[1-9]\d{0,7})\.(?:0|[1-9]\d{0,7})\.(?:0|[1-9]\d{0,7})$/.test(version), "Expected a release version such as v1.2.3.");
  expect(/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(commit), "Expected a full Git commit.");
}
function read(path, max, ownerOnly = false) {
  const original = lstatSync(path);
  expect(original.isFile() && original.size > 0 && original.size <= max, "Expected a bounded regular file.");
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0) | (constants.O_NOFOLLOW ?? 0));
  try {
    const st = fstatSync(fd);
    expect(st.isFile() && st.dev === original.dev && st.ino === original.ino && st.size === original.size, "Input changed during open.");
    expect(!ownerOnly || (st.mode & 0o077) === 0, "Use an owner-only signing key.");
    const data = Buffer.alloc(st.size + 1);
    let offset = 0;
    while (offset < data.length) {
      const count = readSync(fd, data, offset, data.length - offset, null);
      if (count === 0) break;
      offset += count;
    }
    const after = fstatSync(fd);
    expect(offset === st.size && after.size === st.size && st.mtimeMs === after.mtimeMs, "Input changed during read.");
    return data.subarray(0, offset);
  } finally { closeSync(fd); }
}
function inspectBuild(path, platform, commit) {
  const info = JSON.parse(execFileSync("go", ["version", "-m", "-json", path], { encoding: "utf8", maxBuffer: 256 * 1024 }));
  const settings = Object.fromEntries(info.Settings.map(({ Key, Value }) => [Key, Value]));
  expect(info.Path === "github.com/zasp-ai/zasp-sec/cmd/zaspctl" && settings.GOOS === platform[0] && settings.GOARCH === platform[1] &&
    settings.vcs === "git" && settings["vcs.revision"] === commit && settings["vcs.modified"] === "false", "Binary identity, platform or clean source commit did not match.");
  if (platform[0] === "darwin") expect(settings.CGO_ENABLED === "1", "macOS release needs its native Keychain implementation.");
}
function key(path, privateKey) {
  if (privateKey) {
    expect(process.platform !== "win32", "Sign on a protected Unix runner with an owner-only key.");
  }
  const data = read(path, 8192, privateKey);
  expect(privateKey || !data.includes("PRIVATE KEY"), "Supply the independently trusted public release key.");
  const parsed = privateKey ? createPrivateKey(data) : createPublicKey(data);
  expect(parsed.asymmetricKeyType === "ed25519", "Expected an Ed25519 release key.");
  return parsed;
}
function readAsset(folder, name) {
  expect(platforms.has(name), "Unknown release platform.");
  const data = read(join(folder, name), 96 * 1024 * 1024);
  return { name, bytes: data.length, sha256: digest(data) };
}
function newFolder(target, prepare) {
  expect(!existsSync(target), "Destination already exists.");
  mkdirSync(dirname(target), { recursive: true });
  const temp = mkdtempSync(join(dirname(target), ".zaspctl-stage-"));
  try { prepare(temp); renameSync(temp, target); }
  finally { if (existsSync(temp)) rmSync(temp, { recursive: true, force: true }); }
}
function copyBundle(from, to, names) {
  for (const name of names) {
    const max = name === "manifest.json" ? 8192 : name === "manifest.ed25519" ? 64 : 96 * 1024 * 1024;
    writeFileSync(join(to, name), read(join(from, name), max), { flag: "wx" });
  }
}

export function seal(version, commit, privatePath, candidates, out) {
  checkRef(version, commit);
  const signer = key(privatePath, true);
  const names = readdirSync(candidates).sort();
  expect(names.length > 0 && names.every((name) => platforms.has(name)), "Provide only known native CLI binaries in the candidate folder.");
  newFolder(out, (stage) => {
    copyBundle(candidates, stage, names);
    const assets = names.map((name) => {
      inspectBuild(join(stage, name), platforms.get(name), commit);
      return readAsset(stage, name);
    });
    const manifest = json({ schema: "zaspctl-release.v1", version, commit, assets });
    writeFileSync(join(stage, "manifest.json"), manifest, { flag: "wx" });
    writeFileSync(join(stage, "manifest.ed25519"), sign(null, manifest, signer), { flag: "wx" });
  });
}

export function verifyBundle(version, commit, publicPath, folder) {
  checkRef(version, commit);
  const raw = read(join(folder, "manifest.json"), 8192);
  const sig = read(join(folder, "manifest.ed25519"), 64);
  expect(sig.length === 64 && verify(null, raw, key(publicPath, false), sig), "Manifest signature did not verify with the trusted release key.");
  const manifest = JSON.parse(raw);
  expect(manifest.schema === "zaspctl-release.v1" && manifest.version === version && manifest.commit === commit &&
    Array.isArray(manifest.assets) && manifest.assets.length > 0 && manifest.assets.length <= platforms.size, "Signed version, commit or platform set did not match.");
  const names = manifest.assets.map((asset) => asset.name);
  expect(new Set(names).size === names.length && names.every((n) => platforms.has(n)), "Invalid platform set.");
  const assets = names.toSorted().map((name) => readAsset(folder, name));
  expect(json({ schema: "zaspctl-release.v1", version, commit, assets }).equals(raw), "Asset checksum, size or canonical release manifest did not match.");
  expect(readdirSync(folder).sort().join("\n") === [...names, "manifest.json", "manifest.ed25519"].sort().join("\n"), "Unexpected release files.");
  return { version, commit, manifest_sha256: digest(raw), assets };
}
function pin(checkout, value) {
  const path = join(checkout, pinPath);
  expect(lstatSync(path).isFile(), "Use a console checkout with the release pin file.");
  const temp = join(dirname(path), ".zaspctl-pin-" + randomUUID());
  try { writeFileSync(temp, json(value), { flag: "wx" }); renameSync(temp, path); }
  finally { rmSync(temp, { force: true }); }
}

export function stage(version, commit, publicPath, bundle, checkout) {
  const checked = verifyBundle(version, commit, publicPath, bundle);
  const dest = join(checkout, "public", "downloads", "zaspctl", version);
  if (!existsSync(dest)) {
    newFolder(dest, (folder) => {
      copyBundle(bundle, folder, [...checked.assets.map((a) => a.name), "manifest.json", "manifest.ed25519"]);
      verifyBundle(version, commit, publicPath, folder);
      for (const file of readdirSync(folder)) chmodSync(join(folder, file), 0o644);
      chmodSync(folder, 0o755);
    });
  }
  const installed = verifyBundle(version, commit, publicPath, dest);
  expect(installed.manifest_sha256 === checked.manifest_sha256, "A different artifact already occupies this immutable version.");
  pin(checkout, installed);
  return installed;
}
export function disable(checkout) { pin(checkout, emptyPin); }

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const [op, ...args] = process.argv.slice(2);
    if (op === "seal" && args.length === 5) seal(...args);
    else if (op === "verify" && args.length === 4) console.log(JSON.stringify(verifyBundle(...args)));
    else if (op === "stage" && args.length === 5) console.log(JSON.stringify(stage(...args)));
    else if (op === "disable" && args.length === 1) disable(...args);
    else throw new Error("Use seal VERSION COMMIT PRIVATE_KEY CANDIDATES NEW_BUNDLE, verify VERSION COMMIT TRUSTED_PUBLIC_KEY BUNDLE, stage VERSION COMMIT TRUSTED_PUBLIC_KEY BUNDLE CONSOLE_CHECKOUT, or disable CONSOLE_CHECKOUT.");
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
