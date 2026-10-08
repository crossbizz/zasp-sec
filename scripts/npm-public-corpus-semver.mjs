import { createRequire } from 'node:module';
import { readdirSync, lstatSync, realpathSync, openSync, closeSync, fstatSync, readSync, constants } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
const fail=()=>{throw new Error('locked semver source refused');};
const digest=b=>createHash('sha256').update(b).digest('hex');
const fields=st=>['dev','ino','mode','uid','gid','nlink','size','mtimeNs','ctimeNs'].map(k=>st[k]);
const same=(a,b)=>fields(a).every((v,i)=>v===fields(b)[i]);
function readBound(file,cap){const fd=openSync(file,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);try{const st=fstatSync(fd,{bigint:true});if(!st.isFile()||st.size>BigInt(cap)||!same(st,lstatSync(file,{bigint:true})))fail();const raw=Buffer.alloc(Number(st.size));let n=0;while(n<raw.length){const got=readSync(fd,raw,n,raw.length-n,null);if(got<=0)fail();n+=got;}if(readSync(fd,Buffer.alloc(1),0,1,null)!==0||!same(st,fstatSync(fd,{bigint:true}))||!same(st,lstatSync(file,{bigint:true})))fail();return raw;}finally{closeSync(fd);}}
const pins=JSON.parse(readBound(fileURLToPath(new URL('./npm-public-corpus-semver-pins.json',import.meta.url)),1<<20));
export function loadPinnedSemver(root=fileURLToPath(new URL('../',import.meta.url))){
 root=path.resolve(root);const lock=JSON.parse(readBound(path.join(root,'package-lock.json'),4<<20));
 const selected=lock.packages?.[pins.lockLocation];
 if(lock.lockfileVersion!==3||selected?.version!==pins.version||selected?.integrity!==pins.integrity||pins.version!=='7.8.5')fail();
 const dir=path.join(root,pins.lockLocation);let cursor=root;
 for(const part of pins.lockLocation.split('/')){cursor=path.join(cursor,part);const st=lstatSync(cursor);if(st.isSymbolicLink()||!st.isDirectory())fail();}
 const names=[];function visit(parent){for(const name of readdirSync(parent).sort()){const p=path.join(parent,name),st=lstatSync(p);if(st.isSymbolicLink())fail();if(st.isDirectory())visit(p);else if(st.isFile()){if(names.length>=53)fail();names.push(path.relative(dir,p).split(path.sep).join('/'));}else fail();}}
 visit(dir);names.sort();if(JSON.stringify(names)!==JSON.stringify(pins.files.map(x=>x.path)))fail();
 const rows=[];let total=0;for(const expected of pins.files){if(!Number.isSafeInteger(expected.bytes)||expected.bytes<0||expected.bytes>(1<<20)||total+expected.bytes>(8<<20))fail();total+=expected.bytes;const raw=readBound(path.join(dir,expected.path),expected.bytes);rows.push({path:expected.path,bytes:raw.length,sha256:digest(raw)});}
 if(JSON.stringify(rows)!==JSON.stringify(pins.files)||digest(Buffer.from(JSON.stringify(rows)))!==pins.sourceTreeSHA256)fail();
 const pkg=JSON.parse(readBound(path.join(dir,'package.json'),1<<20));if(pkg.version!==pins.version||pkg.name!=='semver'||Object.keys(pkg.dependencies??{}).length)fail();
 const semver=createRequire(import.meta.url)(path.join(realpathSync(dir),'index.js'));
 return {semver,provenance:{lockLocation:pins.lockLocation,version:pins.version,integrity:pins.integrity,sourceTreeSHA256:pins.sourceTreeSHA256,files:rows,upstreamArchiveVerification:'Not independently reverified by this loader; lock SRI and exact source fingerprint are distinct bindings.'}};
}
