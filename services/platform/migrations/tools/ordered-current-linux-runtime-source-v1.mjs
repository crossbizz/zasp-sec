// Private preparation only. Enablement requires root-reviewed actual witness.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const expectedWitnessSHA256='468c02f31c83d0b2dd9bbe4fc2d6138591186ca88d66e967201148f0319d61fd';
const witnessIndependentlyApproved=true;
const sourceWitnessAcceptanceSHA256="13eda7ab5db5be3ad4d64df3449b18543b0fa12c45450de7c93e234ce9e87f8d";
const fail=message=>{throw Error('ordered-current linux runtime witness '+message);};
const sha=raw=>crypto.createHash('sha256').update(raw).digest('hex');
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const closed=(x,keys)=>object(x)&&JSON.stringify(Object.keys(x).sort())===JSON.stringify(keys.sort());
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const pid=x=>Number.isSafeInteger(x)&&x>0&&x<2147483648;
function schema(w){
 if(!closed(w,['format','sourceCommit','runtimeAuthority','query','identity','ownership','verification','cleanup'])||w.format!=='ordered-current-linux-pg-runtime-identity-witness-v1'||typeof w.sourceCommit!=='string'||!/^[a-f0-9]{40}$/.test(w.sourceCommit))fail('closed root schema');
 if(!closed(w.runtimeAuthority,['sidecarSHA256','buildEnvelopeSHA256','postgresOCIDigest','runtimeInventorySHA256','psqlClosureSHA256','additiveSidecarSHA256'])||Object.entries(w.runtimeAuthority).some(([k,v])=>k==='postgresOCIDigest'?typeof v!=='string'||!/^sha256:[a-f0-9]{64}$/.test(v):!hex(v)))fail('closed runtime authority schema');
 if(!closed(w.query,['setupSQLSHA256','identitySQLSHA256'])||!Object.values(w.query).every(hex))fail('closed query schema');
 const i=w.identity;
 if(!closed(i,['postgresVersion','serverVersionNum','serverEncoding','pgcryptoVersion'])||i.serverVersionNum!=='180003'||i.serverEncoding!=='UTF8'||i.pgcryptoVersion!=='1.4'||typeof i.postgresVersion!=='string'||!i.postgresVersion.startsWith('PostgreSQL 18.3 ')||i.postgresVersion.length>1024||/[^\x20-\x7e]/.test(i.postgresVersion))fail('closed fixed identity schema');
 const o=w.ownership;
 if(!closed(o,['transport','endpointSHA256','postmasterPID','queryBackendPID','queryBackendParentVerified','ownedRuntimeRootSHA256','preexistingZombiePIDs'])||o.transport!=='owned-unix-domain-socket'||!hex(o.endpointSHA256)||!hex(o.ownedRuntimeRootSHA256)||!pid(o.postmasterPID)||!pid(o.queryBackendPID)||o.postmasterPID===o.queryBackendPID||o.queryBackendParentVerified!==true||JSON.stringify(o.preexistingZombiePIDs)!=='[48674,48831]')fail('closed ownership schema');
 const v=w.verification;
 if(!closed(v,['preflight','postflight','sameRuntimeInventory','postgresBinarySHA256','psqlBinarySHA256'])||v.preflight!==true||v.postflight!==true||v.sameRuntimeInventory!==true||!hex(v.postgresBinarySHA256)||!hex(v.psqlBinarySHA256))fail('complete five-field verification schema');
 const c=w.cleanup;
 if(!closed(c,['pgCtlStopped','waitJoined','normalExit','endpointChecked','ownedResourcesRemoved','survivingOwnedResources'])||c.pgCtlStopped!==true||c.waitJoined!==true||c.normalExit!==true||c.endpointChecked!==true||c.ownedResourcesRemoved!==true||c.survivingOwnedResources!==0)fail('complete six-field cleanup schema');
}

const sourcePins={"consolidated-reference-contract.json":"d7e2149d8be0d1e04bd1f18e571bf55ffe4458cbe380bc1f406d3ef49aae02ff","consolidated-reference-select.sql":"23f8a023d001acbf0c257c653335603864eead2b9f963ebdbafc03e266577b57","development-admission.sql":"999db012258f1cd04880c8fd5451bd41d4317556bb00c9dec15d493b257ba3ef","development-checkpoint.json":"905664791351c9714bfa4769ab94a6c11c6f1744c11ff56c165536fc71d13705","development-collector.sql":"97f6547ee1a61a8af8c82dbf3bdba38a35b0df3eb60cd69c0ba3743d7bf6446f","development-manifest.json":"4820af14e63ea69b9285e5c69463436fe4ce01ef3a39111b7cbefc8adc2897f9","development-module.sql":"4add5c6dff44aa768bd524c357bc0310ee69c5833a6f9821df84d2b1376e2c74","effective-contract4.json":"06210a2df2f96445b2e864812c83672a46a747c57ffc5b8c4ba380c23e1ab7b0"};
const outputPins={"consolidated-reference-contract.json":"d7e2149d8be0d1e04bd1f18e571bf55ffe4458cbe380bc1f406d3ef49aae02ff","consolidated-reference-select.sql":"23f8a023d001acbf0c257c653335603864eead2b9f963ebdbafc03e266577b57","development-admission.sql":"999db012258f1cd04880c8fd5451bd41d4317556bb00c9dec15d493b257ba3ef","development-checkpoint.json":"d90c33fc2e39fdbb63a8f15d7418dbd910072714c6aaaa770beabb4feaee3cba","development-collector.sql":"97f6547ee1a61a8af8c82dbf3bdba38a35b0df3eb60cd69c0ba3743d7bf6446f","development-manifest.json":"978d70c09bacedc7ab7dea77eb8fdffc44739939291330bbfc91d3c5e44af962","development-module.sql":"90aaab166535b4ccfb248eb8e4ef103d86fd6c5072eab8cbbe34d362080ce8af","effective-contract4.json":"06210a2df2f96445b2e864812c83672a46a747c57ffc5b8c4ba380c23e1ab7b0"};
const canonical=x=>JSON.stringify(x,(_,v)=>object(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])):v);
const eq=(a,b)=>canonical(a)===canonical(b);
const byteOrder=(a,b)=>Buffer.compare(Buffer.from(a),Buffer.from(b));
const compilerPin='b27db0c0c4ee8eae75488371fb003f77f865977ddf88db23191e83cecce1d2d4';
function file(name,pin,max){
 const p=fileURLToPath(new URL(name,import.meta.url));
 for(let q=p;;q=path.dirname(q)){const s=fs.lstatSync(q);if(s.isSymbolicLink()||(q===p?!s.isFile():!s.isDirectory()))fail('regular file topology');if(path.dirname(q)===q)break;}
 const stat=fs.lstatSync(p);if(stat.size>max)fail('file byte cap');const raw=fs.readFileSync(p);if(raw.length>max||sha(raw)!==pin)fail('consumed file pin');return raw;
}
function compiler(){file('ordered-current-cloud-source-copy-v1.mjs',compilerPin,33554432);}
compiler();const {buildOrderedCurrentCloudSourceCopyV1,assertOrderedCurrentCloudSourceCopyV1}=await import('./ordered-current-cloud-source-copy-v1.mjs');compiler();
function noOverrides(){
 for(const name of ["ZASP_ORDERED_CURRENT_LINUX_RUNTIME_VERSION","ZASP_ORDERED_CURRENT_LINUX_RUNTIME_WITNESS","ZASP_ORDERED_CURRENT_LINUX_RUNTIME_WITNESS_SHA256","ZASP_ORDERED_CURRENT_LINUX_RUNTIME_PROFILE","ZASP_ORDERED_CURRENT_LINUX_RUNTIME_EXPECTED_POSTGRES"])if(Object.hasOwn(process.env,name))fail("caller-selected runtime authority");
}
function witness(){
 noOverrides();
 const raw=file('ordered-current-linux-runtime-identity-witness-v1.json',expectedWitnessSHA256,16384);let w;try{w=JSON.parse(raw.toString());}catch{fail('JSON witness');}schema(w);
 if(!witnessIndependentlyApproved)fail('reviewed actual witness not approved');return w;
}
export function assertOrderedCurrentLinuxRuntimeWitnessV1(raw){
 if(arguments.length!==1||!Buffer.isBuffer(raw)||raw.length===0||raw.length>16384)fail('raw byte schema or caller authority');
 let w;try{w=JSON.parse(raw.toString());}catch{fail('JSON witness');}schema(w);if(sha(raw)!==expectedWitnessSHA256)fail('fixed approved bytes');witness();return true;
}
function sourceOutputs(source){
 compiler();assertOrderedCurrentCloudSourceCopyV1(source);if(source.receipt.inputs.length!==171||source.receipt.outputs.length!==8)fail('fixed source receipt');
 const out={};for(const [name,pin]of Object.entries(sourcePins)){const raw=source.outputs['services/platform/migrations/ordered_current/'+name];if(!Buffer.isBuffer(raw)||sha(raw)!==pin)fail('consumed source output');out[name]=Buffer.from(raw);if(sha(out[name])!==pin)fail('copied source output');}return out;
}
function authored(source,w){
 const outputs=sourceOutputs(source),old=JSON.parse(outputs['development-manifest.json']),fresh=structuredClone(old),build=fresh.facts.filter(r=>r.kind==='build');
 if(build.length!==1||fresh.facts.length!==10052||!eq(Object.keys(build[0].fact).sort(),['compiled_source_sha256','contract_sha256','entry_spans','format_version','generator_sha256','module_sha256','pgcrypto','postgres','profile_checksum','purpose','reference_file_sha256'].sort())||build[0].fact.pgcrypto!=='1.4'||build[0].fact.entry_spans.length!==0||fresh.facts.some(r=>r.identity.includes('private-registration')))fail('immutable source build closure');
 const before=old.facts.find(r=>r.kind==='build').fact;build[0].fact.postgres=w.identity.postgresVersion;
 if(!eq(old.facts.filter(r=>r.kind!=='build'),fresh.facts.filter(r=>r.kind!=='build'))||Object.keys(before).some(k=>k!=='postgres'&&!eq(before[k],build[0].fact[k]))||before.postgres===build[0].fact.postgres)fail('postgres-only source delta');
 const rows=[...fresh.facts].sort((a,b)=>byteOrder(a.kind,b.kind)||byteOrder(a.identity,b.identity));fresh.payloadSHA256=sha(canonical(rows));
 outputs['development-manifest.json']=Buffer.from(canonical(fresh)+'\n');
 let module=outputs['development-module.sql'].toString();const literal=v=>canonical(v).replaceAll("'","''");
 const oldBuild="('build','provenance','"+literal(before)+"'::jsonb)",newBuild="('build','provenance','"+literal(build[0].fact)+"'::jsonb)";
 const registration="INSERT INTO zasp_authorization80_ordered_current.registration(singleton,format_version,profile_checksum,manifest_sha256) VALUES(true,1,'"+before.profile_checksum+"','"+old.payloadSHA256+"');";
 if(module.split(oldBuild).length!==2||module.split(registration).length!==2)fail('exact build and namespace registration sites');
 module=module.replace(oldBuild,newBuild).replace(registration,registration.replace(old.payloadSHA256,fresh.payloadSHA256));
 if(!module.includes("IF provenance->>'postgres' IS DISTINCT FROM pg_catalog.version() THEN RETURN false; END IF;"))fail('exact SQL version guard');outputs['development-module.sql']=Buffer.from(module);
 const checkpoint=JSON.parse(outputs['development-checkpoint.json']);checkpoint.payloadSHA256=fresh.payloadSHA256;checkpoint.manifestFileSHA256=sha(outputs['development-manifest.json']);checkpoint.moduleFileSHA256=sha(outputs['development-module.sql']);outputs['development-checkpoint.json']=Buffer.from(canonical(checkpoint)+'\n');
 for(const [name,pin]of Object.entries(outputPins))if(sha(outputs[name])!==pin)fail('fixed authored output pin');
 const receipt={format:'ordered-current-linux-runtime-source-receipt-v1',sourceReceipt:structuredClone(source.receipt),runtimeWitnessSHA256:expectedWitnessSHA256,sourceWitnessAcceptanceSHA256,outputPins:{...outputPins},buildDelta:['postgres'],nonbuildFactsUnchanged:10051,resultAuthority:'source-only; no native acceptance'};
 return {format:'ordered-current-linux-runtime-source-v1',status:'NATIVE-PARITY-PENDING',installable:false,nativeVerified:false,captureAuthority:false,runtimeIdentity:structuredClone(w.identity),receipt,outputs};
}
let cachedSource,cached;
export function buildOrderedCurrentLinuxRuntimeSourceV1(){
 if(arguments.length!==0)fail('caller-selected authority');const w=witness(),source=buildOrderedCurrentCloudSourceCopyV1(),result=authored(source,w);sourceOutputs(source);witness();compiler();
 if(cached&&!eq(cached.receipt,result.receipt))fail('deterministic receipt drift');cachedSource=source;cached=result;return { ...structuredClone({...result,outputs:undefined}),outputs:Object.fromEntries(Object.entries(result.outputs).map(([n,r])=>[n,Buffer.from(r)]))};
}
export function assertOrderedCurrentLinuxRuntimeSourceV1(result){
 if(arguments.length!==1)fail('caller authority');if(!cached)buildOrderedCurrentLinuxRuntimeSourceV1();const w=witness();sourceOutputs(cachedSource);const expected=authored(cachedSource,w);
 if(!closed(result,['format','status','installable','nativeVerified','captureAuthority','runtimeIdentity','receipt','outputs'])||!eq({...result,outputs:null},{...expected,outputs:null})||!closed(result.outputs,Object.keys(outputPins)))fail('closed runtime source receipt');
 for(const [name,pin]of Object.entries(outputPins))if(!Buffer.isBuffer(result.outputs[name])||sha(result.outputs[name])!==pin)fail('consumed output pin');witness();sourceOutputs(cachedSource);return true;
}
