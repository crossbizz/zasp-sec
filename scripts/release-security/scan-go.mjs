import {existsSync,readFileSync,readdirSync,realpathSync} from "node:fs";
import {gunzipSync} from "node:zlib";
import {pathToFileURL} from "node:url";
import path from "node:path";
import {loadPinnedSemver} from "../npm-public-corpus-semver.mjs";
import {evidenceWriter,execTool,fileDigest,parseStream,requireThat,severity,subjectID} from "./scan-common.mjs";

const {semver} = loadPinnedSemver();
const semVersion = value => String(value).replace(/^v/,"");
function normalizedVersion(value) {
  const v = semVersion(value);
  requireThat(semver.valid(v), "unsupported selected Go version");
  return v;
}

export function loadGoAdvisories(root) {
  const index = new Map();
  const ids = new Set();
  for (const entry of readdirSync(path.join(root,"ID"), {withFileTypes:true})) {
    requireThat(entry.isFile() && /^GO-[0-9]{4}-[0-9]+\.json(?:\.gz)?$/.test(entry.name), "unsupported Go database record");
    let raw = readFileSync(path.join(root,"ID",entry.name));
    if (entry.name.endsWith(".gz")) raw = gunzipSync(raw,{maxOutputLength:4<<20});
    const record = JSON.parse(raw);
    requireThat(entry.name.startsWith(record.id + ".") && !ids.has(record.id) && Array.isArray(record.affected),
      "duplicate or malformed Go advisory");
    if (record.withdrawn !== undefined) {
      requireThat(typeof record.withdrawn === "string" && Number.isFinite(Date.parse(record.withdrawn)) &&
        Date.parse(record.withdrawn)<=Date.now(), "invalid Go advisory withdrawal");
    }
    ids.add(record.id);
    for (const a of record.affected) {
      if (a.package?.ecosystem !== "Go") continue;
      if (!index.has(a.package.name)) index.set(a.package.name,[]);
      index.get(a.package.name).push({record,affected:a});
    }
  }
  requireThat(ids.size>0,"empty Go database");
  return index;
}

// Evaluate every selected module, including those that emitted no package or
// symbol trace. Unrecognized ranges cannot silently produce an "unaffected" result.
export function affectedGo(record, version) {
  const v = normalizedVersion(version);
  let covered = false;
  let hit = false;
  const fixes = [];
  if (record.versions?.length) {
    covered = true;
    hit = record.versions.some(item => semver.eq(normalizedVersion(item),v));
  }
  for (const range of record.ranges ?? []) {
    requireThat(range.type === "SEMVER" && Array.isArray(range.events) && range.events.length>0,
      "unsupported Go advisory range");
    covered = true;
    let lower = null,previous = null;
    for (const event of range.events) {
      requireThat(Object.keys(event).length===1,"ambiguous Go version event");
      if (event.introduced !== undefined) {
        const next = event.introduced === "0" ? "0.0.0" : normalizedVersion(event.introduced);
        requireThat(lower === null && (previous === null || semver.gte(next,previous)), "unordered Go range");
        lower = next;
      } else {
        const key = Object.keys(event)[0];
        requireThat(lower !== null && ["fixed","last_affected","limit"].includes(key),"unsupported Go advisory event");
        previous = normalizedVersion(event[key]);
        requireThat(semver.gte(previous,lower), "backwards Go advisory range");
        if (semver.gte(v,lower) && (key === "last_affected" ? semver.lte(v,previous) : semver.lt(v,previous))) {
          hit = true;
          if (key === "fixed") fixes.push(previous);
        }
        lower = null;
      }
    }
    if (lower !== null && semver.gte(v,lower)) hit = true;
  }
  requireThat(covered,"no supported Go advisory range");
  return {hit,fixes};
}

export function matchGo(inventory, index) {
  const found = new Map();
  for (const {package:name,version} of inventory) {
    for (const {record,affected} of index.get(name)??[]) {
      requireThat(version, "unversioned selected module has a known advisory");
      const {hit,fixes} = affectedGo(affected,version);
      if (!hit) continue;
      const key = JSON.stringify([record.id,name,version]);
      const previous = found.get(key);
      const versions = [...new Set([...(previous?.fixes??[]),...fixes])];
      const level = record.database_specific?.severity;
      // CVSS vectors without an admitted numeric evaluation remain unknown.
      found.set(key,{advisory:record.id,package:name,version,ecosystem:"Go",severity:severity(level),
        fixes:versions,withdrawn:typeof record.withdrawn === "string"});
    }
  }
  return [...found.values()].map(({fixes,...f})=>({...f,fix:fixes.length?fixes.join(", "):null}));
}

export async function scanGo(b,candidate,config,env,repoRoot,outputDir,index) {
  const id = subjectID("go",b);
  const write = evidenceWriter(outputDir,id);
  const file = config.binaries[id];
  requireThat(await fileDigest(file)===b.sha256,"binary digest mismatch");
  const bin = config.tools.go;
  const [os,arch] = b.platform.split("/");
  const runEnv = {...env,GOOS:os,GOARCH:arch};
  const root = path.join(repoRoot,b.root);
  requireThat(realpathSync(root)===root && root.startsWith(repoRoot+path.sep) && existsSync(path.join(root,"go.mod")), "invalid Go module root");
  const build = JSON.parse(execTool(bin,["version","-m","-json",file],root,runEnv));
  const settings = Object.fromEntries((build.Settings??[]).map(x=>[x.Key,x.Value]));
  requireThat(settings.GOOS===os && settings.GOARCH===arch && typeof build.Path==="string" && build.Path &&
    (!settings["vcs.revision"] || settings["vcs.revision"]===candidate.commit) && settings["vcs.modified"] !== "true",
    "binary platform or build provenance mismatch");
  const modules = parseStream(execTool(bin,["list","-mod=readonly","-m","-json","all"],root,runEnv));
  requireThat(modules.filter(x=>x.Main).length===1 && modules.find(x=>x.Main).Path===build.Main?.Path,
    "binary module does not match candidate source root");
  const selected = [];
  const byName = new Map();
  for (const m of modules) {
    if (m.Main) continue;
    requireThat(!m.Error && m.Path && !byName.has(m.Path), "invalid selected Go module");
    const v = m.Replace??m;
    if (m.Replace && !v.Version) {
      const dir = realpathSync(path.resolve(root,v.Path));
      requireThat(dir.startsWith(repoRoot+path.sep) && existsSync(path.join(dir,"go.mod")), "external local Go replacement");
      selected.push({package:m.Path,version:null,localReplacement:path.relative(repoRoot,dir)});
    } else {
      normalizedVersion(v.Version);
      selected.push({package:v.Path,version:v.Version});
    }
    byName.set(m.Path,m);
  }
  for (const d of build.Deps??[]) {
    const m = byName.get(d.Path);
    requireThat(m && d.Version===m.Version && (d.Replace?.Path??null)===(m.Replace?.Path??null) &&
      (d.Replace?.Version === "(devel)" ? "" : d.Replace?.Version??"")===(m.Replace?.Version??"") &&
      (!d.Sum || d.Sum === m.Sum) && (!d.Replace?.Sum || d.Replace.Sum === m.Replace?.Sum),
      "binary dependency differs from selected module graph");
  }
  const toolchain = /^go(\d+\.\d+)(?:\.(\d+))?$/.exec(build.GoVersion);
  requireThat(toolchain,"unsupported compiler version in candidate binary");
  const compilerVersion = toolchain[1]+"."+(toolchain[2]??"0");
  selected.push({package:"stdlib",version:compilerVersion},{package:"toolchain",version:compilerVersion});
  const findings = matchGo(selected,index);
  const dbURL = pathToFileURL(config.sources.go).href;
  const raw = execTool(config.tools.govulncheck,["-mode=binary","-json","-db="+dbURL,file],root,runEnv);
  const stream = parseStream(raw);
  const protocol = stream[0].config;
  requireThat(protocol?.scanner_name==="govulncheck" && protocol.protocol_version==="v1.0.0" &&
    protocol.scan_mode==="binary" && protocol.scan_level==="symbol" && protocol.db===dbURL &&
    stream.filter(r=>r.config).length===1, "govulncheck scan mode or database mismatch");
  const sboms = stream.filter(r=>r.SBOM);
  requireThat(sboms.length===1 && sboms[0].SBOM.go_version===build.GoVersion &&
    Array.isArray(sboms[0].SBOM.modules) && sboms[0].SBOM.modules.length>0, "govulncheck scan omitted binary inventory");
  const analyzed = new Set(findings.map(f=>f.advisory+"\0"+f.package));
  for (const row of stream) {
    requireThat(!row.error,"Go reachability scan error");
    if (row.finding) {
      const module = row.finding.trace?.[0]?.module;
      requireThat(module && analyzed.has(row.finding.osv+"\0"+module),"Go advisory and binary scan disagree");
    }
  }
  requireThat(await fileDigest(file)===b.sha256,"binary changed during scan");
  return {id,findings,coverageGaps:[],artifacts:[write("go-build",build),write("go-selected",selected),write("go-reachability",raw)]};
}
