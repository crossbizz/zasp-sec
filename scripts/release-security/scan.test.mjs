import assert from "node:assert/strict";
import {execFileSync} from "node:child_process";
import {mkdirSync,mkdtempSync,readFileSync,realpathSync,rmSync,writeFileSync} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {hashTree} from "./intake.mjs";
import {expectedScanSubjects,fileDigest,parseStream,sha256,subjectID} from "./scan-common.mjs";
import {affectedGo,matchGo} from "./scan-go.mjs";
import {grypeFindings,prepareOCI,verifyImageBinaries} from "./scan-images.mjs";
import {npmFixes,physicalNpmInventory,reconcileNpm} from "./scan-npm.mjs";
import {scanCandidate} from "./scan.mjs";

function tmp(t) {
  const dir = mkdtempSync(path.join(os.tmpdir(),"zasp-release-scanner-test-"));
  t.after(()=>rmSync(dir,{recursive:true,force:true}));
  return dir;
}
const json = v => Buffer.from(JSON.stringify(v));
const put = (name,data) => {mkdirSync(path.dirname(name),{recursive:true});writeFileSync(name,data);};
const lockEntry = version => ({version,integrity:"sha512-YQ==",resolved:"https://registry.npmjs.org/widget/-/widget-"+version+".tgz"});
const exampleLock = version => json({lockfileVersion:3,packages:{"":{},"node_modules/widget":lockEntry(version)}});
const range = {ranges:[{type:"SEMVER",events:[{introduced:"0"},{fixed:"1.2.0"}]}]};
const id = "GHSA-2345-6789-cfgh";

test("the signed npm roster detects omitted, extra, and substituted physical dependencies",t=>{
  const dir=tmp(t);
  put(path.join(dir,"node_modules/widget/package.json"),json({name:"widget",version:"1.0.0"}));
  const rows=physicalNpmInventory(dir);
  const install={platform:"linux/amd64",libc:"glibc",inventorySha256:sha256(JSON.stringify(rows))};
  reconcileNpm(exampleLock("1.0.0"),rows,install);
  assert.deepEqual(npmFixes([{package:{name:"widget"},ranges:[{events:[{introduced:"0"},{fixed:"0.5.0"},{introduced:"1.0.0"},{fixed:"1.2.1"}]}]}],"widget","1.0.0"),["1.2.1"]);
  assert.throws(()=>reconcileNpm(exampleLock("1.0.1"),rows,install),/substituted/);
  assert.throws(()=>reconcileNpm(exampleLock("1.0.0"),[],install),/missing/);
  const lock=JSON.parse(exampleLock("1.0.0"));
  lock.packages["node_modules/optional"]={...lockEntry("1.0.0"),optional:true,os:["darwin"]};
  reconcileNpm(json(lock),rows,install);
  assert.throws(()=>reconcileNpm(json(lock),rows,{...install,platform:"darwin/amd64"}),/missing/);
  assert.throws(()=>reconcileNpm(exampleLock("1.0.0"),rows,{...install,inventorySha256:"a".repeat(64)}),/digest/);
});

test("selected Go module remains affected without a reachable trace, with exact fixed boundaries",()=>{
  const index=new Map([["example.org/dep",[{record:{id:"GO-2026-1000"},affected:range}]]]);
  const rows=matchGo([{package:"example.org/dep",version:"v1.1.0"}],index);
  assert.equal(rows[0].severity,"unknown"); assert.equal(rows[0].fix,"1.2.0");
  assert.deepEqual(matchGo([{package:"example.org/dep",version:"v1.2.0"}],index),[]);
  assert.throws(()=>affectedGo({ranges:[{type:"GIT",events:[{introduced:"0"}]}]},"1.1.0"),/unsupported/);
  assert.throws(()=>matchGo([{package:"example.org/dep",version:null}],index),/unversioned/);
  assert.deepEqual(parseStream(Buffer.from('{\n"test":"} {", "n":1\n}\n{"b":2}')), [{test:"} {",n:1},{b:2}]);
  assert.throws(()=>parseStream(Buffer.from('{"x":1')),/truncated/);
});

function buildOCI(layout,platform="linux/amd64") {
  const blob=(bytes,mediaType)=>{
    const digest=sha256(bytes); put(path.join(layout,"blobs","sha256",digest),bytes);
    return {mediaType,digest:"sha256:"+digest,size:bytes.length};
  };
  const [os,architecture]=platform.split("/");
  const layer=blob(Buffer.alloc(1024),"application/vnd.oci.image.layer.v1.tar");
  const config=blob(json({os,architecture,rootfs:{type:"layers",diff_ids:[layer.digest]},config:{}}),"application/vnd.oci.image.config.v1+json");
  const manifest=blob(json({schemaVersion:2,layers:[layer],config}),"application/vnd.oci.image.manifest.v1+json");
  put(path.join(layout,"oci-layout"),json({imageLayoutVersion:"1.0.0"}));
  put(path.join(layout,"index.json"),json({schemaVersion:2,manifests:[manifest]}));
  return {blob,manifest,layer,platform,ref:"local.test/zasp/image",digest:manifest.digest};
}

test("an OCI root must bind the rendered digest and every platform child",async t=>{
  const dir=tmp(t),layout=path.join(dir,"layout");
  const img=buildOCI(layout);
  const alternate={...img.manifest,digest:"sha256:"+"a".repeat(64),platform:{os:"linux",architecture:"arm64"}};
  const multi=img.blob(json({schemaVersion:2,manifests:[{...img.manifest,platform:{os:"linux",architecture:"amd64"}},alternate]}),
    "application/vnd.oci.image.index.v1+json");
  put(path.join(layout,"index.json"),json({schemaVersion:2,manifests:[multi]}));
  const subject={...img,deploymentDigest:multi.digest};
  await assert.rejects(prepareOCI(subject,layout,path.join(dir,"miss")),/unscanned child/);
  const roster=[subject,{...subject,platform:"linux/arm64",digest:alternate.digest}];
  await prepareOCI(subject,layout,path.join(dir,"verified"),roster);
  assert.equal(JSON.parse(readFileSync(path.join(dir,"verified","index.json"))).manifests[0].digest,img.digest);
  put(path.join(layout,"blobs","sha256",img.layer.digest.slice(7)),Buffer.alloc(1024,3));
  await assert.rejects(prepareOCI(subject,layout,path.join(dir,"changed"),roster),/OCI digest/);
});

test("an independently scanned binary must be the file inside its shipped image",()=>{
  const dockerfile = "FROM example-build AS build\nFROM example-runtime\nWORKDIR /app\nCOPY --from=build /out/sample ./\n";
  const binaries = [{name:"sample",platform:"linux/amd64",sha256:"c".repeat(64)}];
  const syft = {files:[{location:{path:"/app/sample"},digests:[{algorithm:"sha256",value:"c".repeat(64)}]}]};
  verifyImageBinaries(syft,dockerfile,binaries,"linux/amd64");
  syft.files[0].digests[0].value="d".repeat(64);
  assert.throws(()=>verifyImageBinaries(syft,dockerfile,binaries,"linux/amd64"),/different digest/);
  assert.throws(()=>verifyImageBinaries({},dockerfile,binaries,"linux/amd64"),/missing/);
});

test("Grype ignored vulnerabilities still go through release adjudication",()=>{
  const entry={artifact:{type:"deb",name:"example-package",version:"1.0"},vulnerability:{id:"CVE-2026-50000",severity:"High",fix:{versions:["1.1"]}}};
  assert.equal(grypeFindings({descriptor:{name:"grype"},matches:[],ignoredMatches:[entry]})[0].severity,"high");
  assert.throws(()=>grypeFindings({matches:[]}),/invalid Grype/);
});

function advisoryCorpus(dir,iso) {
  const data={id,published:iso,modified:iso,database_specific:{severity:"HIGH"},affected:[{package:{name:"widget",ecosystem:"npm"},...range}]};
  const withdrawn={...data,id:"GHSA-2345-6789-cfgj",withdrawn:iso};
  const rows=[];
  for(const value of [data,withdrawn]){
    const file="advisories/github-reviewed/2026/"+value.id+".json",raw=json(value);
    put(path.join(dir,file),raw);rows.push({path:file,bytes:raw.length,sha256:sha256(raw)});
  }
  const git=args=>execFileSync("/usr/bin/git",["-C",dir,...args],{encoding:"utf8"}).trim();
  git(["init","--quiet"]);git(["add","advisories"]);git(["-c","user.name=Fixture","-c","user.email=fixture@example.invalid","-c","commit.gpgsign=false","commit","--quiet","-m","test"]);
  return {id:"npm",origin:"https://github.com/github/advisory-database",version:git(["rev-parse","HEAD"]),refreshedAt:iso,
    sha256:sha256(JSON.stringify(rows)),npmManifestSha256:sha256(JSON.stringify(rows))};
}
function toolDouble(dir,name,body) {
  const file=path.join(dir,name);
  writeFileSync(file,"#!"+process.execPath+"\n"+body+"\n",{mode:0o700});
  return file;
}

test("offline candidate scanner retains raw npm, Go and OCI evidence and refuses substitution",async t=>{
  const dir=tmp(t), go=realpathSync(execFileSync("go",["env","GOROOT"],{encoding:"utf8"}).trim()+"/bin/go");
  const repo=path.join(dir,"source"), mod=path.join(repo,"cmd","sample");
  const cache=path.join(dir,"modcache"), out=path.join(dir,"report");
  for(const d of [mod,cache,out])mkdirSync(d,{recursive:true});
  put(path.join(mod,"go.mod"),"module example.org/sample\n\ngo 1.21\n");
  put(path.join(mod,"main.go"),"package main\nfunc main() {}\n");
  const binaryFile=path.join(dir,"hello");
  execFileSync(go,["build","-buildvcs=false","-o",binaryFile,"."],{cwd:mod,
    env:{...process.env,GOTOOLCHAIN:"local",GOWORK:"off",GOSUMDB:"off",GOPROXY:"off",CGO_ENABLED:"0",GOOS:"linux",GOARCH:"amd64"}});
  const sources={npm:path.join(dir,"npm"),go:path.join(dir,"go-db"),grype:path.join(dir,"grype-db")};
  const fixedTime=new Date().toISOString();
  const npm=advisoryCorpus(sources.npm,fixedTime);
  put(path.join(sources.go,"ID","GO-2026-9999.json"),json({id:"GO-2026-9999",affected:[{package:{ecosystem:"Go",name:"stdlib"},...range}]}));
  put(path.join(sources.grype,"6","vulnerability.db"),"synthetic DB marker");
  const tools={go,govulncheck:toolDouble(dir,"govulncheck",`if(!process.argv.includes("-mode=binary")||process.env.GOPROXY!=="off")process.exit(1);
const build=JSON.parse(require("node:child_process").execFileSync("go",["version","-m","-json",process.argv.at(-1)]));
console.log(JSON.stringify({config:{scanner_name:"govulncheck",protocol_version:"v1.0.0",scan_level:"symbol",scan_mode:"binary",db:process.argv.find(x=>x.startsWith("-db=")).slice(4)}}));
console.log(JSON.stringify({SBOM:{roots:[build.Path],go_version:build.GoVersion,modules:[{path:"stdlib",version:build.GoVersion}]}}));`),
    syft:toolDouble(dir,"syft",`const fs=require("node:fs"); if(process.env.SYFT_CHECK_FOR_APP_UPDATE!=="false")process.exit(1);
if(process.argv[2]==="scan"){if(!fs.existsSync(process.argv[3].slice(8)+"/oci-layout"))process.exit(1);
console.log(JSON.stringify({descriptor:{name:"syft"},artifacts:[{id:"fixture-package"}]}));}
else if (process.argv[2]==="convert")console.log(JSON.stringify({spdxVersion:"SPDX-2.3",packages:[{name:"fixture-package"}]}));else process.exit(1);`),
    grype:toolDouble(dir,"grype",`if(process.env.GRYPE_DB_AUTO_UPDATE!=="false"||!require("node:fs").existsSync(process.env.GRYPE_DB_CACHE_DIR+"/6/vulnerability.db"))process.exit(1);
console.log(JSON.stringify({descriptor:{name:"grype"},matches:[]}));`)};
  const intake={format:"zasp.release.intake.v1",observedAt:fixedTime,sources:[npm,
    {id:"go",origin:"https://vuln.go.dev",version:"fixture",refreshedAt:fixedTime,sha256:await hashTree(sources.go)},
    {id:"grype",origin:"https://grype.anchore.io/databases",version:"fixture",refreshedAt:fixedTime,sha256:await hashTree(sources.grype)}],
    tools:await Promise.all(Object.entries(tools).map(async ([id,file])=>({id,version:"test",sha256:await fileDigest(file)})))};
  const lock=exampleLock("1.1.0");put(path.join(repo,"package-lock.json"),lock);
  const install=path.join(dir,"install");put(path.join(install,"node_modules/widget/package.json"),json({name:"widget",version:"1.1.0"}));
  const layout=path.join(dir,"image");const {ref,digest,platform}=buildOCI(layout);
  const image={ref,digest,platform};const binary={name:"sample",root:"cmd/sample",platform,sha256:await fileDigest(binaryFile)};
  const binding={platform,libc:"glibc",inventorySha256:sha256(JSON.stringify(physicalNpmInventory(install)))};
  const candidate={lockSha256:sha256(lock),images:[image],binaries:[binary],npmInstalls:[binding],commit:"1".repeat(40)};
  const config={sources,tools,goModCache:cache,npmInstalls:[{root:install,...binding}],images:{[subjectID("image",image)]:layout},binaries:{[subjectID("go",binary)]:binaryFile}};
  const {subjects}=await scanCandidate({candidate,intake,config,repoRoot:repo,outputDir:out});
  assert.deepEqual(subjects.map(s=>s.id),expectedScanSubjects(candidate));
  const result=subjects.find(s=>s.id==="npm:production");
  assert.equal(result.findings.length,2);assert.equal(result.findings.filter(f=>f.withdrawn).length,1);
  assert.equal(result.findings[0].severity,"high");assert.equal(result.findings[0].fix,"1.2.0");
  for(const subject of subjects) for(const raw of subject.artifacts)assert.equal(await fileDigest(path.join(out,raw.file)),raw.sha256);
  put(path.join(sources.grype,"6","vulnerability.db"),"replaced");
  await assert.rejects(scanCandidate({candidate,intake,config,repoRoot:repo,outputDir:out}),/database differs/);
});
