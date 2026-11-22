import { spawnSync } from "node:child_process";
import { realpathSync, writeFileSync } from "node:fs";
import path from "node:path";

import {fileHash, sha256} from "./trust.mjs";
export {sha256};
export function requireThat(ok, message) {
  if (!ok) throw new Error("Candidate scan refused: " + message);
}

export async function fileDigest(filename) {
  requireThat(path.isAbsolute(filename) && realpathSync(filename) === filename,
    "expected regular file in protected staging");
  return fileHash(filename);
}

export function subjectID(kind, value) {
  if (kind === "go") return "go:" + value.name + "@" + value.platform;
  return "image:" + value.ref + "@" + value.digest + "#" + value.platform;
}

export function expectedScanSubjects(candidate) {
  const ids = ["npm:production", ...candidate.binaries.map(b => subjectID("go", b)),
    ...candidate.images.map(i => subjectID("image", i))];
  requireThat(new Set(ids).size === ids.length, "duplicate candidate subject");
  return ids.sort();
}

export function evidenceWriter(outputDir, id) {
  const prefix = sha256(id).slice(0, 32);
  return function write(label, data) {
    const bytes = Buffer.isBuffer(data) ? data : Buffer.from(JSON.stringify(data) + "\n");
    const file = prefix + "-" + label + ".json";
    writeFileSync(path.join(outputDir, file), bytes, {flag: "wx", mode: 0o600});
    return {file, sha256: sha256(bytes)};
  };
}

// Each call runs on the protected promotion runner with outbound traffic denied.
// Reply bodies and stderr may contain private package names. Never echo either.
export function execTool(bin, args, cwd, env) {
  const result = spawnSync(bin, args, {
    cwd, env, stdio: ["ignore", "pipe", "pipe"], maxBuffer: 256 * 1024 * 1024, timeout: 300_000,
  });
  requireThat(!result.error && result.status === 0 && !result.signal, "offline tool did not complete: " + path.basename(bin));
  return result.stdout;
}

export function parseStream(raw) {
  const text = raw.toString("utf8");
  const records = [];
  let start = -1, depth = 0, quoted = false, escape = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (start < 0) {
      if (/\s/.test(c)) continue;
      requireThat(c === "{", "invalid scanner stream");
      start = i;
    }
    if (quoted) {
      if (escape) escape = false;
      else if (c === "\\") escape = true;
      else if (c === '"') quoted = false;
    } else if (c === '"') quoted = true;
    else if (c === "{") depth++;
    else if (c === "}" && --depth === 0) {
      records.push(JSON.parse(text.slice(start, i + 1)));
      start = -1;
    }
  }
  requireThat(start < 0 && records.length > 0, "truncated or empty scanner stream");
  return records;
}

export function severity(value) {
  const normalized = String(value ?? "").toLowerCase();
  if (["medium", "moderate"].includes(normalized)) return "medium";
  if (["negligible", "low", "high", "critical"].includes(normalized)) return normalized;
  return "unknown";
}
