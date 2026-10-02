import fs from "node:fs";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
const directory="docs/internal/security-agent-attack-lab-20260918/task-3/";
const read=name=>JSON.parse(fs.readFileSync(directory+name,"utf8"));
const final=read("blobs.json"),base=read("review-base-blobs.json"),fix=read("review-fix-batch/blobs.json");
const ledgerPaths=new Set(["docs/internal/implementation_batches_v1.5.tsv","docs/internal/implementation_status_v1.5.md","docs/internal/implementation_production_availability_v1.5.tsv"]);
const blob=file=>execFileSync("git",["hash-object","--",file],{encoding:"utf8"}).trim();
for(const row of final){
 if(blob(row.path)!==row.after)throw Error("final source changed: "+row.path);
 if(row.before && blob(directory+"before/"+row.path+".blob")!==row.before)throw Error("before bytes changed: "+row.path);
 const reviewed=fix.find(item=>item.path===row.path)??base.find(item=>item.path===row.path);
 if(!ledgerPaths.has(row.path)&&reviewed?.after!==row.after)throw Error("source differs from reviewed base+fix: "+row.path);
 const published=row.path.match(/^services\/platform\/migrations\/sql\/(\d{4})_/);
 if(published&&Number(published[1])<=56)throw Error("published migration in task delta: "+row.path);
 console.log(createHash("sha256").update(fs.readFileSync(row.path)).digest("hex")+"  "+row.path);
}
execFileSync("git",["apply","--reverse","--check",directory+"scoped.patch"]);
console.log(`All ${final.length} final source/before blobs match. Product source equals reviewed base+fix; only three ledger paths differ. Reverse patch check passed; no published1..56 SQL is in the task delta.`);
