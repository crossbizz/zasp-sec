// Offline verification of operator-collected staging evidence.
import { createHash, createPublicKey, verify } from "node:crypto";
import { constants } from "node:fs";
import { open, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { verifyBundle } from "../deploy/cli-release/release.mjs";

const evidenceID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const commitID = /^[a-f0-9]{40}$/;
const digest = /^[a-f0-9]{64}$/;
const versionID = /^v(?:0|[1-9]\d{0,7})\.(?:0|[1-9]\d{0,7})\.(?:0|[1-9]\d{0,7})$/;
const domain = Buffer.from("zasp.live-pilot.v1\0");
export const profiles = {
  native_signing: ["darwin_arm64_notarized", "darwin_amd64_notarized", "windows_authenticode", "staged_manifest", "console_download"],
  stytch_login: ["browser_authenticated", "findings_only_received", "review_opened"],
  aws_remediation: ["bedrock_discovered", "iam_discovered", "approval", "change_readback", "rollback_readback"],
  model_gateway: ["authenticated_route", "upstream_response"],
  remote_mcp: ["streamable_http_route", "remote_tool_response"],
  archive: ["encrypted_version_created", "exact_version_expired", "deletion_readback"],
  jamf: ["signed_install", "claude_version", "hook_precedence", "v2_rule", "ticket_pair", "upgrade", "rollback", "retired", "uninstalled"],
};
const assets = ["zaspctl-darwin-amd64", "zaspctl-darwin-arm64", "zaspctl-linux-amd64", "zaspctl-windows-amd64.exe"];
const common = ["schema", "lane", "profile", "environment", "commit", "observed_at", "evidence"];
const extra = {
  native_signing: ["version", "manifest_sha256"],
  archive: ["version_id", "deleted_version_id", "created_at", "deleted_at"],
  jamf: ["device_ref", "os_build", "harness_build", "hook_latency_ms"],
};
const sha = raw => createHash("sha256").update(raw).digest("hex");

function requireValue(value, reason) {
  if (!value) throw new Error(reason);
}
function fields(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && isDeepStrictEqual(Object.keys(value).sort(), [...keys].sort());
}
function id(value) {
  return typeof value === "string" && evidenceID.test(value);
}
async function bounded(file) {
  const f = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const st = await f.stat();
    requireValue(st.isFile() && st.size > 0 && st.size <= 256 * 1024, "Expected a bounded receipt file");
    const data = Buffer.alloc(st.size);
    let offset = 0;
    while (offset < data.length) {
      const {bytesRead} = await f.read(data, offset, data.length - offset, offset);
      requireValue(bytesRead > 0, "Receipt changed while reading");
      offset += bytesRead;
    }
    requireValue((await f.stat()).size === data.length, "Receipt changed while reading");
    return data;
  } finally {
    await f.close();
  }
}
function timestamp(value) {
  requireValue(typeof value === "string" && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/.test(value), "Expected a UTC timestamp");
  const n = Date.parse(value);
  requireValue(Number.isFinite(n) && new Date(n).toISOString() === (value.includes(".") ? value : value.replace("Z",".000Z")), "Invalid calendar date");
  return n;
}
function publicKey(pem) {
  requireValue(typeof pem === "string" && pem.startsWith("-----BEGIN PUBLIC KEY-----") && !pem.includes("PRIVATE KEY"), "Expected public trust material");
  const key = createPublicKey(pem);
  requireValue(key.asymmetricKeyType === "ed25519", "Expected Ed25519");
  return key;
}
function verifyEntry(raw, signature, key, profile, params) {
  const {environment, commit, lane, now} = params;
  requireValue(signature.length === 64 && verify(null, Buffer.concat([domain, raw]), key, signature), "Pilot receipt signature rejected");
  const v = JSON.parse(raw);
  // Canonical encoding makes duplicate properties invalid, including an
  // overwritten evidence ID or time, and keeps collector signing reproducible.
  requireValue(raw.equals(Buffer.from(JSON.stringify(v) + "\n")) && fields(v, [...common, ...(extra[profile] ?? [])]), "Noncanonical or unexpected receipt content");
  const observed = timestamp(v.observed_at);
  requireValue(v.schema === "zasp.live-pilot.v1" && v.lane === lane && v.profile === profile &&
    v.environment === environment && v.commit === commit && observed <= now && now - observed < 7 * 86400_000, "Wrong or stale staging observation");
  requireValue(fields(v.evidence, profiles[profile]) && Object.values(v.evidence).every(id) &&
    new Set(Object.values(v.evidence)).size === profiles[profile].length, "Missing distinct evidence references");
  const summary = {profile, observed_at: v.observed_at, receipt_sha256: sha(raw), evidence: v.evidence};
  if (profile === "native_signing") {
    requireValue(versionID.test(v.version) && digest.test(v.manifest_sha256), "Invalid native release binding");
    Object.assign(summary, {version: v.version, manifest_sha256: v.manifest_sha256});
  }
  if (profile === "archive") {
    const created = timestamp(v.created_at), deleted = timestamp(v.deleted_at);
    requireValue(typeof v.version_id === "string" && /^[A-Za-z0-9._~+/=-]{1,1024}$/.test(v.version_id) && v.version_id !== "null" && v.deleted_version_id === v.version_id && deleted <= observed &&
      deleted - created >= 86400_000, "Exact-version 24-hour retention unconfirmed");
    Object.assign(summary, {version_id: v.version_id, created_at: v.created_at, deleted_at: v.deleted_at});
  }
  if (profile === "jamf") {
    requireValue([v.device_ref, v.os_build, v.harness_build].every(id) && Array.isArray(v.hook_latency_ms) &&
      v.hook_latency_ms.length >= 20 && v.hook_latency_ms.length <= 4096 &&
      v.hook_latency_ms.every(n => Number.isFinite(n) && n >= 0), "Missing device, build or latency samples");
    const values = [...v.hook_latency_ms].sort((a,b) => a-b);
    const p95 = values[Math.ceil(values.length * 0.95)-1];
    requireValue(p95 <= 75, "Managed-device latency budget exceeded");
    Object.assign(summary, {device_ref:v.device_ref, os_build:v.os_build, harness_build:v.harness_build, samples:values.length, p95_ms:p95});
  }
  return summary;
}

export async function verifyPilot({commit, environment, trustFile, trustDigest, directory, stagedRoot, releaseKey, lane = "staging", now = Date.now()}) {
  requireValue(["fixture","staging"].includes(lane) && commitID.test(commit) && id(environment) && digest.test(trustDigest) && Number.isSafeInteger(now), "Expected release SHA, trusted digest, lane and staging Environment");
  const data = await bounded(trustFile);
  requireValue(sha(data) === trustDigest, "Pilot trust file differs from approved digest");
  const trust = JSON.parse(data);
  requireValue(fields(trust, ["lane","environment","keys","release_key_sha256"]) && trust.environment === environment && trust.lane === lane &&
    fields(trust.keys,Object.keys(profiles)) && sha(await bounded(releaseKey)) === trust.release_key_sha256, "Unexpected trust domain");
  const receipts = [];
  for (const profile of Object.keys(profiles)) {
    const key = publicKey(trust.keys[profile]);
    const names = profile === "jamf" ? ["jamf-1","jamf-2"] : [profile];
    for (const name of names) {
      const raw = await bounded(path.join(directory,name+".json"));
      const signature = await bounded(path.join(directory,name+".sig"));
      receipts.push(verifyEntry(raw,signature,key,profile,{environment,commit,lane,now}));
    }
  }
  const devices = receipts.filter(v => v.profile === "jamf").map(v => v.device_ref);
  requireValue(new Set(devices).size === 2, "Expected two distinct enrolled devices");
  const native = receipts.find(r => r.profile === "native_signing");
  const checked = verifyBundle(native.version,commit,releaseKey,path.join(stagedRoot,"public/downloads/zaspctl",native.version));
  const pin = JSON.parse(await bounded(path.join(stagedRoot,"app/features/tools/cli-release-pin.json")));
  requireValue(isDeepStrictEqual(pin,checked) && native.manifest_sha256 === checked.manifest_sha256 &&
    isDeepStrictEqual(checked.assets.map(a => a.name).sort(),assets), "Staged binaries, manifest or console pin differ from the signed source");
  return {schema:"zasp.live-pilot-assessment.v1",lane,environment,commit,assessed_at:new Date(now).toISOString(),trust_sha256:trustDigest,receipts};
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    const [lane,commit,environment,trustFile,trustDigest,directory,stagedRoot,releaseKey,target] = process.argv.slice(2);
    if (process.argv.length !== 11) throw new Error("Usage: verify-live-pilot.mjs LANE SHA ENV TRUST TRUST_SHA RECEIPTS STAGED_ROOT RELEASE_PUBLIC_KEY NEW_REPORT");
    const result = await verifyPilot({lane,commit,environment,trustFile,trustDigest,directory,stagedRoot,releaseKey});
    await writeFile(target, JSON.stringify(result,null,2)+"\n", {flag:"wx",mode:0o600});
    console.log(`Verified ${lane} pilot receipts.`);
  } catch (error) {
    console.error(error.code === "ENOENT" ? "A required pilot file is missing." : "Pilot verification failed.");
    process.exitCode=1;
  }
}
