import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
const root=execFileSync("git",["rev-parse","--show-toplevel"],{encoding:"utf8"}).trim();
const evidence=path.join(root,"docs/internal/security-agent-attack-lab-20260918/task-3");
const base=JSON.parse(fs.readFileSync(path.join(evidence,"review-base-blobs.json"),"utf8"));
const working=JSON.parse(fs.readFileSync(path.join(evidence,"blobs.json"),"utf8"));
const [label,...files]=process.argv.slice(2);
if(!/^[a-z0-9-]+$/.test(label)||files.length===0)throw Error("bounded supplement required");
const directory=path.join(evidence,label);fs.mkdirSync(directory);
let patch="";const manifest=[];
for(const file of files){
 const entry=base.find(item=>item.path===file)??working.find(item=>item.path===file);
 if(!entry)throw Error(`uncaptured baseline ${file}`);
 const before=base.find(item=>item.path===file)?.after??entry.before;
 const original=before ? path.join(directory,file+".blob") : "/dev/null";
 if(before){fs.mkdirSync(path.dirname(original),{recursive:true});fs.writeFileSync(original,execFileSync("git",["cat-file","blob",before],{cwd:root}),{flag:"wx"});}
 const after=execFileSync("git",["hash-object","-w","--",file],{cwd:root,encoding:"utf8"}).trim();
 const delta=spawnSync("git",["diff","--no-index","--",original,path.join(root,file)],{encoding:"utf8"});
 if(![0,1].includes(delta.status))throw Error(delta.stderr);
 patch+=delta.stdout.replace(/^diff --git .*$/m,`diff --git a/${file} b/${file}`).replace(/^--- .*$/m,before ? `--- a/${file}` : "--- /dev/null").replace(/^\+\+\+ .*$/m,`+++ b/${file}`);
 manifest.push({path:file,before,after,sha256:createHash("sha256").update(fs.readFileSync(path.join(root,file))).digest("hex")});
}
fs.writeFileSync(path.join(directory,"scoped.patch"),patch,{flag:"wx"});
fs.writeFileSync(path.join(directory,"blobs.json"),JSON.stringify(manifest,null,2)+"\n",{flag:"wx"});
console.log(JSON.stringify({directory,patchSHA256:createHash("sha256").update(patch).digest("hex"),files:manifest.length}));
