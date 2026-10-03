import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
const PHASES=Object.freeze(["dependencies:check","health:contract:test","openapi:test","openapi:lint","openapi:check","ui-api:test","ui-api:check","raw-fetch:test","saas:tenancy:test","graph:neo4j:test","db:tenant-rls:test","test","typecheck","lint","production:imports:test","production:imports:source","staging:gate:test","production:release:test","build","production:imports:compiled","implementation:status:check"]);
const MAX_BYTES=256*1024;
const GENERIC='::error title=npm verify failed::npm run verify failed; phase unavailable.';
export function verifyFailureAnnotation(raw){
 if(!Buffer.isBuffer(raw)||raw.length>MAX_BYTES)return GENERIC;
 let phase=null;
 for(const line of raw.toString('utf8').split(/\r?\n/)){
  if(line.length>4096){if(line.startsWith('> '))phase=null;continue;}
  if(/^> [^ \t]+@[^ \t]+ [^\r\n]+$/.test(line)){
   const match=/^> zasp-agent-security-console@0\.1\.0 ([a-z:.-]+)$/.exec(line);
   phase=match&&PHASES.includes(match[1])?match[1]:null;
  }
 }
 return phase===null?GENERIC:`::error title=npm verify failed::npm run verify failed; latest observed phase: ${phase}.`;
}
function boundedLog(file){
 const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 try{const st=fs.fstatSync(fd);if(!st.isFile()||!Number.isSafeInteger(st.size)||st.size<0)throw Error();const length=Math.min(st.size,MAX_BYTES),offset=st.size-length,raw=Buffer.alloc(length);if(fs.readSync(fd,raw,0,length,offset)!==length)throw Error();const after=fs.fstatSync(fd);if(st.dev!==after.dev||st.ino!==after.ino||st.size!==after.size||st.mtimeMs!==after.mtimeMs)throw Error();if(offset){const newline=raw.indexOf(10);return newline<0?Buffer.alloc(0):raw.subarray(newline+1);}return raw;}finally{fs.closeSync(fd);}
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 let annotation=GENERIC;
 try{if(process.argv.length===3)annotation=verifyFailureAnnotation(boundedLog(process.argv[2]));}catch{/* Diagnostic failure never changes the verifier status or emits input details. */}
 process.stdout.write(annotation+'\n');
}
