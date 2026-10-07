import { collectPinnedNpmAdvisoryComponent, exactJSON, readBoundedInput } from './npm-public-corpus.mjs';
import { openSync,writeSync,fsyncSync,fchmodSync,closeSync,constants } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
const refused=()=>{throw new Error('public npm producer refused');};
const hash=b=>createHash('sha256').update(b).digest('hex');
const names=['--corpus-dir','--public-intake-receipt','--lock','--output'];
export function parseProducerArgs(args){
 if(!Array.isArray(args)||args.length!==8)refused();const result={};
 for(let i=0;i<args.length;i+=2){if(!names.includes(args[i])||Object.hasOwn(result,args[i])||typeof args[i+1]!=='string'||!path.isAbsolute(args[i+1])||args[i+1].includes('\0'))refused();result[args[i]]=path.normalize(args[i+1]);}
 if(!names.every(n=>Object.hasOwn(result,n))||new Set(Object.values(result)).size!==4)refused();return result;
}
export function producePublicNpmComponent(args,{now=Date.now()}={}){
 const options=parseProducerArgs(args);const raw=readBoundedInput(options['--public-intake-receipt'],1<<20);const receipt=exactJSON(raw);
 const fields=['format','repository','commit','observedAt','manifestSHA256','fullOfficialCorpusRosterSHA256','fullOfficialCorpusFiles','lockSHA256'];
 if(!receipt||typeof receipt!=='object'||Array.isArray(receipt)||Object.keys(receipt).length!==fields.length||!fields.every(k=>Object.hasOwn(receipt,k))||receipt.format!=='github-advisory-database-public-intake-v1'||receipt.repository!=='https://github.com/github/advisory-database'||typeof receipt.commit!=='string'||!/^[a-f0-9]{40}$/.test(receipt.commit)||!Number.isSafeInteger(receipt.fullOfficialCorpusFiles)||receipt.fullOfficialCorpusFiles<1||receipt.fullOfficialCorpusFiles>100000||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/.test(receipt.observedAt)||!Number.isFinite(Date.parse(receipt.observedAt))||!['manifestSHA256','fullOfficialCorpusRosterSHA256','lockSHA256'].every(k=>typeof receipt[k]==='string'&&/^[a-f0-9]{64}$/.test(receipt[k])))refused();
 const lock=readBoundedInput(options['--lock'],4<<20);if(hash(lock)!==receipt.lockSHA256)refused();
 const authority={repository:receipt.repository,commit:receipt.commit,observedAt:receipt.observedAt,manifestSHA256:receipt.manifestSHA256};
 const result=collectPinnedNpmAdvisoryComponent({corpusRoot:options['--corpus-dir'],authority,lockPath:options['--lock'],evaluatedAt:now});
 if(result.lockSHA256!==receipt.lockSHA256||result.source.fullOfficialCorpusRosterSHA256!==receipt.fullOfficialCorpusRosterSHA256||result.source.fullOfficialCorpusFiles!==receipt.fullOfficialCorpusFiles)refused();
 result.publicIntakeReceiptSHA256=hash(raw);result.sourceAuthority='Exact caller-provided public intake receipt and local committed blob closure; independent upstream admission review remains required.';result.releaseAccepted=false;
 const bytes=Buffer.from(JSON.stringify(result,null,2)+'\n');if(bytes.length>(128<<20))refused();
 const output=options['--output'];let fd;
 try{
  fd=openSync(output,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);let off=0;
  while(off<bytes.length){const n=writeSync(fd,bytes,off,bytes.length-off);if(n<=0)refused();off+=n;}
  fchmodSync(fd,0o400);fsyncSync(fd);closeSync(fd);fd=undefined;
  const parent=openSync(path.dirname(output),constants.O_RDONLY|constants.O_DIRECTORY);try{fsyncSync(parent);}finally{closeSync(parent);}
 }finally{if(fd!==undefined)closeSync(fd);}
 return {output,sha256:hash(bytes),bytes:bytes.length,releaseAccepted:false};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{const result=producePublicNpmComponent(process.argv.slice(2));process.stdout.write(JSON.stringify(result)+'\n');}
 catch{process.stderr.write('public npm producer refused\n');process.exitCode=1;}
}
