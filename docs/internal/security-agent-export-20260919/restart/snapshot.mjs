// Freeze generated final-observer evidence before another owned run updates
// the convenience runtime files. No request envelopes or tokens are copied.
import {readFile,copyFile} from "node:fs/promises";
import path from "node:path";
import {fileURLToPath} from "node:url";
const evidence=path.dirname(fileURLToPath(import.meta.url));
const summary=JSON.parse(await readFile(path.join(evidence,"runtime/summary.json"),"utf8"));
if(!summary.consume_checkpoint_writes || Object.values(summary.consume_checkpoint_writes).some(n=>n!==0)) throw new Error("final zero-write checkpoint missing");
for(const name of ["summary.json","download.json"]) await copyFile(path.join(evidence,"runtime",name),path.join(evidence,"final-"+name));
await copyFile(path.join(evidence,"run-log.txt"),path.join(evidence,"final-run.log"));
await copyFile(path.join(evidence,"run-metadata.json"),path.join(evidence,"final-run.json"));
await copyFile(path.join(evidence,"operator-cleanup.json"),path.join(evidence,"final-cleanup.json"));
console.log(JSON.stringify({download_sha256:summary.download_sha256,writes:summary.consume_checkpoint_writes,children:summary.children.length}));
