import {spawn} from "node:child_process";
import {writeFile,readFile,readdir,copyFile} from "node:fs/promises";
import path from "node:path";
import {fileURLToPath} from "node:url";
const evidence=path.dirname(fileURLToPath(import.meta.url));
const cwd=path.resolve(evidence,"../../../../services/platform");
const env={...process.env,GOTOOLCHAIN:"local",GOPROXY:"off",GOSUMDB:"off"};
const commands=[];
async function run(args) {
  commands.push({command:"/opt/homebrew/bin/go",args});
  const child=spawn("/opt/homebrew/bin/go",args,{cwd,env,stdio:["ignore","pipe","pipe"]});
  let output="";
  child.stdout.on("data",b=>output+=b);child.stderr.on("data",b=>output+=b);
  const deadline=setTimeout(()=>child.kill("SIGKILL"),240000);
  const status=await new Promise((resolve,reject)=>{child.once("error",reject);child.once("close",resolve)});
  clearTimeout(deadline);return {status,output};
}
const packages=["./apiserver","./agentsec-worker","./agentsec-api"];
const registered=new Set();
for(const pkg of packages) for(const file of await readdir(path.join(cwd,pkg))) {
  if(!/(postgres|integration).*_test\.go$/.test(file)) continue;
  for(const match of (await readFile(path.join(cwd,pkg,file),"utf8")).matchAll(/^func (Test\w+)\(/gm)) registered.add(match[1]);
}
const listed=await run(["test",...packages,"-list","^Test(SecurityAgent(Export|Manual|Processor)|Compliance|ProductionSecurityAgent)"]);
if(listed.status!==0) throw new Error(listed.output);
const names=[...new Set(listed.output.split("\n").filter(s=>s.startsWith("Test")&&!/Postgres|Process$/.test(s)&&!registered.has(s)))].sort();
await writeFile(path.join(evidence,"native-selection.txt"),names.join("\n")+"\n");
console.log(`Native race selection: ${names.length} exact names, registered/Postgres/process children excluded.`);
const result=await run(["test","-race",...packages,"-run","^("+names.join("|")+")$","-count=1","-v","-timeout=180s"]);
console.log(result.output);
try { await copyFile(path.join(evidence,"native-race.log"),path.join(evidence,"native-race-prior.log")); await copyFile(path.join(evidence,"native-race.json"),path.join(evidence,"native-race-prior.json")); } catch (error) { if (error?.code !== "ENOENT") throw error; }
await writeFile(path.join(evidence,"native-race.log"),result.output);
await writeFile(path.join(evidence,"native-race.json"),JSON.stringify({commands,status:result.status,selected:names.length},null,2));
process.exitCode=result.status??1;
