import {execFileSync} from "node:child_process";
import {existsSync,mkdirSync,mkdtempSync,realpathSync,rmSync,writeFileSync} from "node:fs";
import os from "node:os";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {validateCandidate} from "./candidate.mjs";
import {checkIntake,hashTree} from "./intake.mjs";
import {fileHash,readBound,verifySigned} from "./trust.mjs";
import {expectedScanSubjects,fileDigest,requireThat} from "./scan-common.mjs";
import {loadGoAdvisories,scanGo} from "./scan-go.mjs";
import {scanImage} from "./scan-images.mjs";
import {scanNpm} from "./scan-npm.mjs";

export {expectedScanSubjects};

// Do not forward the CI environment. Signing credentials, proxy variables,
// private registry credentials, compiler/linker overrides and user configs
// have no role in matching local candidate inputs.
function toolEnv(config,work) {
  const home = path.join(work,"home");
  mkdirSync(home,{mode:0o700});
  return {HOME:home,TMPDIR:work,PATH:path.dirname(config.tools.go)+":/usr/bin:/bin",LANG:"C",LC_ALL:"C",
    GOENV:"off",GOWORK:"off",GOPROXY:"off",GOSUMDB:"off",GOTOOLCHAIN:"local",GOTELEMETRY:"off",
    GOMODCACHE:config.goModCache,GOCACHE:path.join(work,"go-cache"),GIT_ALLOW_PROTOCOL:"",
    SYFT_CHECK_FOR_APP_UPDATE:"false",SYFT_FILE_METADATA_SELECTION:"all",SYFT_FILE_METADATA_DIGESTS:"sha256",SYFT_JAVA_USE_NETWORK:"false",SYFT_GOLANG_SEARCH_REMOTE_LICENSES:"false",
    GRYPE_EXTERNAL_SOURCES_ENABLE:"false",GRYPE_EXTERNAL_SOURCES_MAVEN_SEARCH_UPSTREAM_BY_SHA1:"false",
    GRYPE_EXTERNAL_SOURCES_MAVEN_SEARCH_UPSTREAM_BY_SHA1_ENABLED:"false",GRYPE_DB_AUTO_UPDATE:"false",
    GRYPE_CHECK_FOR_APP_UPDATE:"false"};
}

async function verifyInputs(config,intake) {
  for (const tool of intake.tools) {
    requireThat(await fileDigest(config.tools[tool.id])===tool.sha256,"tool differs from intake: " + tool.id);
  }
  for (const id of ["go","grype"]) {
    const db = config.sources[id];
    requireThat(path.isAbsolute(db) && realpathSync(db)===db,"indirect database root");
    requireThat(await hashTree(db)===intake.sources.find(s=>s.id===id).sha256,"database differs from intake: " + id);
  }
}

export async function scanCandidate({candidate,intake,config,outputDir,repoRoot}) {
  checkIntake(intake);
  const expected = expectedScanSubjects(candidate);
  requireThat(path.isAbsolute(config.goModCache) && realpathSync(config.goModCache)===config.goModCache,"private local Go module cache required");
  requireThat(config.npmInstalls.length===candidate.npmInstalls.length,"incomplete npm platform inventory");
  await verifyInputs(config,intake);
  const work = mkdtempSync(path.join(os.tmpdir(),"zasp-candidate-scan-"));
  const env = toolEnv(config,work);
  try {
    const subjects = [scanNpm(candidate,config,intake,repoRoot,outputDir)];
    const goDB = loadGoAdvisories(config.sources.go);
    for (const b of candidate.binaries) subjects.push(await scanGo(b,candidate,config,env,repoRoot,outputDir,goDB));
    for (const image of candidate.images) {
      const dir = mkdtempSync(path.join(work,"oci-"));
      try {
        subjects.push(await scanImage(image,config,env,dir,outputDir,candidate,repoRoot));
      } finally { rmSync(dir,{recursive:true,force:true}); }
    }
    await verifyInputs(config,intake);
    checkIntake(intake);
    subjects.sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0);
    requireThat(JSON.stringify(subjects.map(s=>s.id))===JSON.stringify(expected),"missing scan subjects");
    return {subjects};
  } finally { rmSync(work,{recursive:true,force:true}); }
}

function cleanCommit(repo) {
  const git = args => execFileSync("/usr/bin/git",["--no-replace-objects","-c","core.fsmonitor=false",
    "-c","core.hooksPath=/dev/null","-c","protocol.allow=never","-C",repo,...args],
    {encoding:"utf8",timeout:60000,maxBuffer:16<<20,env:{PATH:"/usr/bin:/bin",GIT_CONFIG_NOSYSTEM:"1",
      GIT_CONFIG_GLOBAL:"/dev/null",GIT_NO_LAZY_FETCH:"1",GIT_OPTIONAL_LOCKS:"0"}}).trim();
  requireThat(!git(["status","--porcelain","--untracked-files=normal"]),"candidate checkout must be clean");
  return git(["rev-parse","HEAD"]);
}

export async function runScanner(candidateFile,intakeFile,configFile,output,keys) {
  const c = await verifySigned(candidateFile,keys.build,"zasp.release.candidate.v1");
  const i = await verifySigned(intakeFile,keys.intake,"zasp.release.intake.v1");
  const config = JSON.parse(await readBound(configFile,4<<20));
  const repo = realpathSync(config.repoRoot);
  const lock = await readBound(path.join(repo,"package-lock.json"),4<<20);
  const rendered = await readBound(config.rendered,16<<20);
  await validateCandidate(c.value,{commit:cleanCommit(repo),lock,rendered,repo});
  const dir = path.resolve(output);
  requireThat(realpathSync(path.dirname(dir))===path.dirname(dir) && !existsSync(dir),"output must be a new protected directory");
  mkdirSync(dir,{mode:0o700});
  try {
    const result = await scanCandidate({candidate:c.value,intake:i.value,config,outputDir:dir,repoRoot:repo});
    requireThat(cleanCommit(repo)===c.value.commit && await fileHash(candidateFile)===c.sha256 &&
      await fileHash(intakeFile)===i.sha256 && await fileHash(config.rendered)===c.value.renderedSha256,
      "release inputs changed during scan");
    const report = {format:"zasp.release.scan.v1",candidateSha256:c.sha256,intakeSha256:i.sha256,
      observedAt:new Date().toISOString(),subjects:result.subjects};
    writeFileSync(path.join(dir,"report.json"),JSON.stringify(report,null,2)+"\n",{flag:"wx",mode:0o600});
    return report;
  } catch (error) { rmSync(dir,{recursive:true,force:true}); throw error; }
}
if (process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  try {
    requireThat(process.argv.length===6,"usage: scan.mjs CANDIDATE INTAKE CONFIG NEW_OUTPUT_DIRECTORY");
    const result = await runScanner(...process.argv.slice(2),{build:process.env.ZASP_RELEASE_BUILD_PUBLIC_KEY,intake:process.env.ZASP_RELEASE_INTAKE_PUBLIC_KEY});
    console.log("Prepared unsigned evidence for " + result.subjects.length + " release subjects.");
  } catch (error) {
    // A subprocess message can hold private module names, paths or read data.
    console.error(error.message?.startsWith("Candidate scan refused:") ? error.message : "Candidate scan refused or incomplete.");
    process.exitCode=1;
  }
}
