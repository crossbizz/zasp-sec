import fs from "node:fs";
import { execFileSync } from "node:child_process";
const git=args=>execFileSync("git",args,{encoding:"utf8"}).trim();
const tracked=git(["ls-files","services/platform/migrations/sql"]).split("\n").filter(file=>{const m=file.match(/\/([0-9]{4})_[^/]+\.(up|down)\.sql$/);return m&&Number(m[1])<=56;});
for(const file of tracked)if(git(["hash-object",file])!==git(["rev-parse","8733b16f8d939d38a8157dd2519e57fc6f630542:"+file]))throw Error("tracked accepted migration changed: "+file);
console.log(`${tracked.length} tracked published SQL files match original HEAD8733b16f8d939d38a8157dd2519e57fc6f630542 byte-for-byte.`);
const prior=JSON.parse(fs.readFileSync("docs/internal/compliance-connected-fix-20260918/connected-fix-blobs.json","utf8")).filter(row=>row.file.startsWith("services/platform/migrations/"));
for(const row of prior){if(git(["hash-object",row.file])!==row.after)throw Error("accepted56 blob changed: "+row.file);console.log(row.after+"  "+row.file);}
const task=JSON.parse(fs.readFileSync("docs/internal/security-agent-attack-lab-20260918/task-3/blobs.json","utf8"));
for(const row of task){if(!row.path.startsWith("services/platform/migrations/"))continue;if(!row.path.includes("attack_lab"))throw Error("predecessor migration changed in task delta: "+row.path);}
console.log("Task3 migration delta is Attack Lab57 only. Fresh compiled55/56 checksum+pin assertions are in final-release-pins.log; actual empty rollback56 restoration is in review-fix-registered-postgres.log.");
console.log("No complete pre-Task1 file snapshot exists for inherited52..55; this check does not claim byte-identical comparison of every such file.");
