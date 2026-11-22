import {existsSync, lstatSync, readFileSync, readdirSync, realpathSync} from "node:fs";
import path from "node:path";
import {collectPinnedNpmAdvisoryComponent, exactJSON, lockedProductionInventory, readBoundedInput} from "../npm-public-corpus.mjs";
import {loadPinnedSemver} from "../npm-public-corpus-semver.mjs";
import {evidenceWriter, requireThat, severity, sha256} from "./scan-common.mjs";

const {semver} = loadPinnedSemver();

// The existing matcher has already validated ordering and nonoverlap. Only
// suggest the fix that closes the interval containing the installed version.
export function npmFixes(affected, name, version) {
  const result = new Set();
  for (const entry of affected.filter(a=>a.package.name===name)) {
    for (const range of entry.ranges??[]) {
      let applies = false;
      for (const event of range.events) {
        if (event.introduced!==undefined) applies = event.introduced==="0" || semver.gte(version,event.introduced);
        else {
          if (applies && event.fixed && semver.lt(version,event.fixed)) result.add(event.fixed);
          applies = false;
        }
      }
    }
  }
  return [...result].sort(semver.compare);
}

function platformApplies(item, platform, libc) {
  const [os, goArch] = platform.split("/");
  const arch = {amd64:"x64", "386":"ia32", arm64:"arm64", arm:"arm", ppc64le:"ppc64"}[goArch] ?? goArch;
  function matches(restriction, value) {
    if (restriction === undefined) return true;
    requireThat(Array.isArray(restriction) && restriction.every(x => typeof x === "string"), "unsupported npm platform selector");
    const allow = restriction.filter(x => !x.startsWith("!"));
    return !restriction.includes("!" + value) && (!allow.length || allow.includes(value));
  }
  return matches(item.os, os === "windows" ? "win32" : os) &&
    matches(item.cpu, arch) && matches(item.libc, libc);
}

// The build signs the actual installed roster for each platform. Compare against
// both that roster and the exact lock; scope packages are containers, not entries.
export function physicalNpmInventory(root) {
  requireThat(path.isAbsolute(root) && realpathSync(root) === root, "invalid npm install root");
  const rows = [];
  function walk(modules) {
    if (!existsSync(modules)) return;
    requireThat(lstatSync(modules).isDirectory(), "linked npm package directory");
    for (const item of readdirSync(modules, {withFileTypes:true})) {
      if (item.name === ".bin" || item.name === ".package-lock.json") continue;
      requireThat(item.isDirectory() && !item.name.startsWith("."), "unsupported installed package entry");
      const target = path.join(modules, item.name);
      if (item.name.startsWith("@")) {
        for (const sub of readdirSync(target, {withFileTypes:true})) {
          requireThat(sub.isDirectory(), "linked scoped npm package");
          visit(path.join(target, sub.name));
        }
      } else visit(target);
    }
  }
  function visit(dir) {
    const data = exactJSON(readBoundedInput(path.join(dir, "package.json"), 4 << 20), 4 << 20);
    requireThat(typeof data.name === "string" && typeof data.version === "string" && rows.length < 10000,
      "unsupported npm package identity or tree size");
    rows.push({location:path.relative(root, dir).split(path.sep).join("/"), name:data.name, version:data.version});
    walk(path.join(dir, "node_modules"));
  }
  walk(path.join(root, "node_modules"));
  return rows.sort((a,b) => a.location < b.location ? -1 : a.location > b.location ? 1 : 0);
}

export function reconcileNpm(raw, rows, install) {
  const lock = exactJSON(raw, 4 << 20);
  const locked = lockedProductionInventory(raw).components;
  const observed = new Map(rows.map(r => [r.location, r]));
  const byLocation = new Map(locked.map(r => [r.location,r]));
  for (const p of rows) {
    const expected = byLocation.get(p.location);
    requireThat(expected?.name === p.name && expected?.version === p.version, "extra or substituted installed npm package");
  }
  for (const expected of locked) {
    if (observed.has(expected.location)) continue;
    const entry = lock.packages[expected.location];
    const ancestors = expected.location.split("/node_modules/");
    // A nested required dependency can belong to an optional platform package.
    let excluded = false;
    for (let i = 1; i <= ancestors.length; i++) {
      const parent = lock.packages[ancestors.slice(0, i).join("/node_modules/")];
      if (parent?.optional && !platformApplies(parent, install.platform, install.libc)) excluded = true;
    }
    requireThat(excluded || (entry.optional && !platformApplies(entry, install.platform, install.libc)), "missing applicable npm dependency");
  }
  requireThat(sha256(JSON.stringify(rows)) === install.inventorySha256, "build npm inventory digest mismatch");
}

export function scanNpm(candidate, config, intake, repoRoot, outputDir) {
  const id = "npm:production";
  const write = evidenceWriter(outputDir,id);
  const lockPath = path.join(repoRoot,"package-lock.json");
  const lock = readBoundedInput(lockPath,4<<20);
  requireThat(sha256(lock) === candidate.lockSha256, "lock digest mismatch");
  const source = intake.sources.find(s=>s.id === "npm");
  const npm = collectPinnedNpmAdvisoryComponent({corpusRoot: config.sources.npm,
    authority:{repository: source.origin, commit: source.version, observedAt:source.refreshedAt,
      manifestSHA256:source.npmManifestSha256}, lockPath, evaluatedAt: Date.now()});
  requireThat(npm.source.fullOfficialCorpusRosterSHA256 === source.sha256, "unverified npm corpus");
  const installed = [];
  for (const binding of candidate.npmInstalls) {
    const inputs = config.npmInstalls.filter(x=>x.platform===binding.platform && x.libc===binding.libc);
    requireThat(inputs.length===1, "expected one staged npm tree per platform and libc");
    const rows = physicalNpmInventory(inputs[0].root);
    reconcileNpm(lock, rows, binding);
    installed.push({platform:binding.platform, libc:binding.libc, rows});
  }
  const findings = npm.findings.flatMap(item => {
    const sourceRow = npm.source.records.find(r=>r.sha256===item.advisorySHA256);
    requireThat(sourceRow, "missing pinned npm advisory bytes");
    const raw = readFileSync(path.join(config.sources.npm,sourceRow.path));
    requireThat(sha256(raw)===sourceRow.sha256,"changed npm advisory");
    const osv = exactJSON(raw);
    return item.matches.map(m => {
      const fixes = npmFixes(osv.affected,m.name,m.version);
      return {advisory:item.id,package:m.name,version:m.version,ecosystem:"npm", severity:severity(item.severity),
        fix:fixes.length ? fixes.join(", ") : null, withdrawn: item.withdrawn !== null};
    });
  });
  return {id,findings,coverageGaps:[],artifacts:[write("npm-lock-report",npm),write("npm-installed",installed)]};
}
