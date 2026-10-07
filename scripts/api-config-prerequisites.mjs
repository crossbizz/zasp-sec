import { readFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
// Read only the launcher's declaration; never run its value mapper.
const launcherSource = readFileSync(new URL("../scripts/api-start.mjs", import.meta.url), "utf8");
const declaredSuffixes = /for \(const suffix of (\[[^\]\n]+\])\)/.exec(launcherSource);
if (!declaredSuffixes || Buffer.byteLength(launcherSource) > 65536) throw new Error("API prerequisite aliases refused");
const suffixes = JSON.parse(declaredSuffixes[1]);
if (suffixes.length !== 3 || new Set(suffixes).size !== 3 || suffixes.some(n => !/^[A-Z_]+$/.test(n))) throw new Error("API prerequisite aliases refused");
const API_CREDENTIAL_ALIASES = Object.freeze(Object.fromEntries(suffixes.map(suffix => [`ZASP_STYTCH_${suffix}`, `STYTCH_${suffix}`])));

// Presence only. The production Go loader remains the syntax authority.
export function requiredNames(document, baseLoader, serviceLoader) {
  if ([document, baseLoader, serviceLoader].some(s => typeof s !== "string" || Buffer.byteLength(s) > 65536)) throw new Error("API prerequisite contract refused");
  const baseStart = document.indexOf("## Required base settings: 43 names");
  const serviceStart = document.indexOf("## Required runtime-service settings: 10 names");
  const end = document.indexOf("## Conditional and optional settings");
  if (!(baseStart >= 0 && serviceStart > baseStart && end > serviceStart)) throw new Error("API prerequisite contract refused");
  const names = text => [...text.matchAll(/`(ZASP_[A-Z0-9_]+)`/g)].map(m => m[1]);
  const base = names(document.slice(baseStart, serviceStart));
  const services = names(document.slice(serviceStart, end));
  const all = [...base, ...services];
  if (base.length !== 43 || services.length !== 10 || new Set(all).size !== 53 || base.some(n => !baseLoader.includes(`"${n}"`)) || services.some(n => !serviceLoader.includes(`"${n}"`))) throw new Error("API prerequisite contract refused");
  return Object.freeze(all);
}
export function inspectPrerequisiteNames(names, required) {
  if (!Array.isArray(names) || names.some(n => typeof n !== "string") || !Array.isArray(required) || required.length !== 53 || new Set(required).size !== 53 || required.some(n => !/^ZASP_[A-Z0-9_]+$/.test(n))) throw new Error("API prerequisite names refused");
  const present = new Set(names);
  const directPresent = required.filter(n => present.has(n));
  const supportedAliasNamesPresent = Object.fromEntries(Object.entries(API_CREDENTIAL_ALIASES).filter(([target, source]) => required.includes(target) && !present.has(target) && present.has(source)));
  const unboundNames = required.filter(n => !present.has(n) && !Object.hasOwn(supportedAliasNamesPresent, n));
  return { scope: "PREREQUISITE NAME PRESENCE ONLY; values, alias conflicts, syntax, runtime access and production readiness are unverified", requiredCount: required.length, directPresent, supportedAliasNamesPresent, unboundNames };
}
export function loadRequiredNames() {
  return requiredNames(readFileSync(new URL("../docs/operations/cloud-launch-configuration.md", import.meta.url), "utf8"), readFileSync(new URL("../services/platform/agentsec-api/runtime.go", import.meta.url), "utf8"), readFileSync(new URL("../services/platform/runtimeservices/config.go", import.meta.url), "utf8"));
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    if (process.argv.length !== 2) throw new Error("API prerequisite names refused");
    process.stdout.write(JSON.stringify(inspectPrerequisiteNames(Object.keys(process.env), loadRequiredNames())) + "\n");
  } catch {
    process.stderr.write("API prerequisite names refused\n");
    process.exitCode = 1;
  }
}
