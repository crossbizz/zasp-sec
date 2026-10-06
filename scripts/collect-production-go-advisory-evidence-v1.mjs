// Component collection only. Production release remains unconditionally refused.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {inflateRawSync} from 'node:zlib';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const ROOT='/workspace/zasp-sec';
const NODE='/workspace/scratch/toolchains/node-v22.23.1-linux-x64/bin/node';
const OWNED_CODE_PREFIX='/workspace/scratch/production-go-advisory-guarded-code-v1';
const OWNED_NODE=OWNED_CODE_PREFIX+'/node';
const SOURCE_COMMIT='026c164b9fefa4ec3c0226e8a644dff6f62c3076';
const GO='/workspace/scratch/toolchains/go/bin/go';
const SCANNER='/workspace/scratch/trivy-0.75.0/go-tools/govulncheck';
const PYTHON='/usr/bin/python3.13';
const RUNNER=path.join(ROOT,'scripts/production-advisory-owned-runner-v1.py');
const DATABASE='/workspace/scratch/official-go-vulndb-generated';
const DATABASE_MODIFIED='2026-10-01T20:24:15Z';
const DB_ROSTER='/workspace/scratch/official-go-vulndb-generated-roster.json';
const SOURCE_RECEIPT='/workspace/scratch/official-go-vulndb-prerequisite-receipt.json';
const MODULE_CACHE='/home/agent/go/pkg/mod';
const SNAPSHOT='/workspace/scratch/production-go-advisory-owned-inputs-v1';
const GOROOT=path.dirname(path.dirname(GO));
const PYTHON_LINKS=[
 {path:'/usr/lib/python3.13/_sysconfigdata__x86_64-linux-gnu.py',target:'_sysconfigdata__linux_x86_64-linux-gnu.py',resolved:'/usr/lib/python3.13/_sysconfigdata__linux_x86_64-linux-gnu.py',bytes:47376,sha256:'ca73fd2192c8164e4a3a8f314016ebc26c5da41d9dcc41481704c8a0a9ec4537'},
 {path:'/usr/lib/python3.13/config-3.13-x86_64-linux-gnu/libpython3.13.so',target:'../../x86_64-linux-gnu/libpython3.13.so.1',resolved:'/usr/lib/x86_64-linux-gnu/libpython3.13.so.1.0',bytes:7512760,sha256:'a60dd84858dc27edd2acd4029d0644611138d68a56022d61fd25a38cf28be798'},
 {path:'/usr/lib/python3.13/sitecustomize.py',target:'/etc/python3.13/sitecustomize.py',resolved:'/etc/python3.13/sitecustomize.py',bytes:155,sha256:'43d81125d92376b1a69d53a71126a041cc9a18d8080e92dea0a2ae23be138b1e'}
];
const ROOTS=Object.freeze({'health':'services/health','platform':'services/platform','event-ingest':'services/event-ingest','gateway-control':'services/gateway-control','runtime-gateway':'services/runtime-gateway','sensor-agent':'services/sensor-agent','cli':'cmd/agentsecctl'});
// Root must review the emitted current manifest before explicitly pinning it.
// Empty is intentional fail-closed pre-run state; no timestamps/reports are trust.
const APPROVED_INPUT_MANIFEST_SHA256='d25585907c7a50c963f215b1414ff3caae875e95cf284653234d78af8463c190';
const TOOL_PINS={
 [OWNED_NODE]:'93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068',
 [NODE]:'93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068',
 ['/usr/bin/git']:'356db14e102d68a1a37d8a1ac577dfd678d45d46e92f468bef8b7154e7bfdc60',
 [GO]:'3fb44b0d47becc087cf9e6002366bfbf136d3e08460f12389dbd04687dcf0dd0',
 [SCANNER]:'dbb441370210966cd75102a609865d33589917473bb705a04e3b9e9627af2bb2',
 [PYTHON]:'17b78e0a93175e86f9ac03141924fd7a7f0c0c52e66b34bfa0de20ffef989df1',
 [RUNNER]:'ff2151640e6d2f1d6715cc5cbf500d1478fd992a0dcbef2e67253f38984154e7',
 [DB_ROSTER]:'f5f4c48f0a2b43056b7923876cc929431f1ea3743ac5e5a41bed6ec3dacaf2e5',
 [SOURCE_RECEIPT]:'ea55917c36f6f9d644a23bde69af47395fb4c50d53ba11c582428d3cf34452b6'
};
const MAX_BYTES=64*1024*1024,MAX_MESSAGES=20000;
const fail=reason=>{throw Error('advisory component refused: '+reason);};
const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const canonical=value=>JSON.stringify(value,(_,v)=>v&&typeof v==='object'&&!Array.isArray(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])):v);
const object=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const closed=(v,keys)=>object(v)&&Object.keys(v).every(k=>keys.includes(k));
const string=v=>typeof v==='string'&&v.length>0&&v.length<=16384;
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
function noOverrides(){
 for(const [name,value]of Object.entries(process.env))if(value&&/^(?:ZASP_ADVISORY_|GOVULNCHECK_|TRIVY_|GOTOOLCHAIN$|GOFLAGS$|GOVULNDB$|PYTHONPATH$|PYTHONHOME$)/.test(name))fail('ambient authority override');
}
function safePath(file){
 if(!path.isAbsolute(file)||path.normalize(file)!==file)fail('path authority');
 for(let current=file;;current=path.dirname(current)){
  const stat=fs.lstatSync(current);if(stat.isSymbolicLink()||(current===file?!stat.isFile():!stat.isDirectory()))fail('regular-file topology');
  if(path.dirname(current)===current)break;
 }
}
function pinnedRead(file,pin){safePath(file);const stat=fs.lstatSync(file);if(stat.size>MAX_BYTES*4)fail('input byte cap');const raw=fs.readFileSync(file);if(pin!==undefined&&sha(raw)!==pin)fail('input bytes');return raw;}
function treeFiles(base,reviewedLinks=[]){
 const found=[];function walk(dir){for(const entry of fs.readdirSync(dir,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))){const file=path.join(dir,entry.name);if(entry.isSymbolicLink()){if(!reviewedLinks.some(r=>r.path===file))fail('tree symlink');found.push(file);continue;}if(entry.isDirectory())walk(file);else if(entry.isFile())found.push(file);else fail('tree type');}}
 const stat=fs.lstatSync(base);if(!stat.isDirectory()||stat.isSymbolicLink())fail('tree topology');walk(base);return found;
}
function checkGoRoster(base,expected){const actual=treeFiles(base).filter(f=>f.endsWith('.go')).map(f=>path.relative(base,f)).sort();if(canonical(actual)!==canonical([...expected].sort()))fail('extra or missing Go source');}
function entry(file){const raw=pinnedRead(file);return {path:file,bytes:raw.length,sha256:sha(raw)};}

function rootProtected(file){safePath(file);for(let p=file;;p=path.dirname(p)){const st=fs.lstatSync(p);if(st.uid!==0||(st.mode&0o022))fail('caller-writable runtime');if(path.dirname(p)===p)break;}}
function pythonTopology(){
 const links=PYTHON_LINKS.map(row=>{const st=fs.lstatSync(row.path);if(!st.isSymbolicLink()||st.uid!==0||(st.mode&0o777)!==0o777||fs.readlinkSync(row.path)!==row.target||fs.realpathSync(row.path)!==row.resolved)fail('reviewed Python link topology');rootProtected(row.resolved);const raw=pinnedRead(row.resolved,row.sha256),resolved=fs.lstatSync(row.resolved);if(raw.length!==row.bytes||(resolved.mode&0o777)!==0o644)fail('reviewed Python target');return {...row,linkMode:0o777,linkOwner:0,targetMode:0o644,targetOwner:0};});
 return {links,files:treeFiles('/usr/lib/python3.13',links).filter(f=>!f.includes('/__pycache__/')).map(file=>{const link=links.find(r=>r.path===file);const value=link?{path:file,bytes:link.bytes,sha256:link.sha256,resolved:link.resolved}:entry(file);rootProtected(link?.resolved??file);return value;})};
}
const escapeModule=s=>s.replace(/[A-Z]/g,c=>'!'+c.toLowerCase());
function sourceSums(source){const sums=new Map();for(const row of source.filter(r=>r.path.endsWith('/go.sum'))){const raw=pinnedRead(path.join(ROOT,row.path),row.sha256);for(const line of raw.toString('utf8').trim().split('\n')){const parts=line.split(' ');if(parts.length!==3||!/^h1:[A-Za-z0-9+/]{43}=$/.test(parts[2]))fail('source go.sum');const key=parts[0]+' '+parts[1];if(sums.has(key)&&sums.get(key)!==parts[2])fail('conflicting trusted sums');sums.set(key,parts[2]);}}return sums;}
function trustedGoMod(raw,expected){const actual='h1:'+crypto.createHash('sha256').update(sha(raw)+'  go.mod\n').digest('base64');if(actual!==expected)fail('module trusted go.mod sum');return actual;}
function externalClosure(modules,source){const sums=sourceSums(source),chosen=new Map(),files=new Map(),zipInputs=[],selectedDirs=new Set(),embedded=new Set();for(const root of Object.values(modules))for(const p of root.packages){const m=p.module;if(m&&!m.Main&&!m.Replace?.Dir){if(!m.Version||!m.Dir||!m.GoMod)fail('module source identity');chosen.set(m.Path+' '+m.Version,m);selectedDirs.add(p.dir);for(const name of p.embedFiles)embedded.add(path.join(p.dir,name));}}
 for(const [identity,m]of [...chosen].sort(([a],[b])=>a.localeCompare(b))){const h1=sums.get(identity);if(!h1)fail('missing trusted ZIP sum');const base=MODULE_CACHE+'/cache/download/'+escapeModule(m.Path)+'/@v/'+m.Version;const zip=base+'.zip',raw=pinnedRead(zip),members=normalModuleZIP(raw,m.Path,m.Version,h1);zipInputs.push({...entry(zip),module:m.Path,version:m.Version,h1});
  const expectedDir=MODULE_CACHE+'/'+escapeModule(m.Path)+'@'+m.Version;if(m.Dir!==expectedDir)fail('module directory mapping');for(const member of members){const file=expectedDir+'/'+member.relative;if(member.relative!=='go.mod'&&!selectedDirs.has(path.dirname(file))&&!embedded.has(file))continue;if(!pinnedRead(file,member.sha256).equals(member.raw))fail('module extracted bytes');files.set(file,{path:file,bytes:member.bytes,sha256:member.sha256,zipPath:zip,zipMember:member.relative,module:m.Path,version:m.Version,h1});}
  for(const suffix of ['.mod','.info','.ziphash']){const file=base+suffix,value=entry(file);if(suffix==='.mod')trustedGoMod(pinnedRead(file,value.sha256),sums.get(identity+'/go.mod'));if(suffix==='.ziphash'&&pinnedRead(file).toString().trim()!==h1)fail('module ziphash');files.set(file,value);}
 }
 // Full MVS metadata remains distinct from selected package module bodies.
 for(const root of Object.values(modules))for(const m of root.mvs){if(m.GoMod&&m.GoMod.startsWith(MODULE_CACHE+'/')){const value=entry(m.GoMod);trustedGoMod(pinnedRead(m.GoMod,value.sha256),sums.get(m.Path+' '+m.Version+'/go.mod'));files.set(m.GoMod,value);}if(m.Version&&!m.Main&&!m.Replace?.Dir){const info=MODULE_CACHE+'/cache/download/'+escapeModule(m.Path)+'/@v/'+m.Version+'.info';files.set(info,entry(info));}}
 return {files:[...files.values()].sort((a,b)=>a.path.localeCompare(b.path)),zipInputs};
}
function bindExternalPackageInputs(inputs,external){const indexed=new Map(external.map(r=>[r.path,r]));for(const row of inputs)if(row.path.startsWith(MODULE_CACHE+'/')){const expected=indexed.get(row.path);if(!expected||expected.sha256!==row.sha256||expected.bytes!==row.bytes)fail('external consumed ZIP member');}}
function snapshotRows(m){const rows=new Map();const put=(destination,value,mode=0o400)=>{const row={path:value.resolved??value.path,destination,bytes:value.bytes,sha256:value.sha256,mode};if(rows.has(destination)&&canonical(rows.get(destination))!==canonical(row))fail('snapshot conflicting source');rows.set(destination,row);};
 for(const x of m.source)put('repo/'+x.path,{...x,path:ROOT+'/'+x.path});for(const x of m.external.files)put('module-cache/'+path.relative(MODULE_CACHE,x.path),x);for(const x of m.goInputs)put('go/'+path.relative(GOROOT,x.path),x,x.executable?0o500:0o400);for(const x of m.pythonInputs)put('python/lib/python3.13/'+path.relative('/usr/lib/python3.13',x.path),x);put('python/bin/python3.13',m.tools.find(t=>t.path===PYTHON),0o500);put('scanner/govulncheck',m.tools.find(t=>t.path===SCANNER),0o500);put('runner.py',m.tools.find(t=>t.path===RUNNER));for(const x of m.database.files)put('database/'+x.path,{...x,path:DATABASE+'/'+x.path});return [...rows.values()].sort((a,b)=>a.destination.localeCompare(b.destination));}

// Normal Go module ZIP h1 binds all regular member bytes to trusted go.sum.
function normalModuleZIP(raw,module,version,expectedH1){
 if(!Buffer.isBuffer(raw)||raw.length<22||raw.length>MAX_BYTES)fail('module ZIP byte cap');
 const prefix=module+'@'+version+'/';let end=-1;for(let i=raw.length-22;i>=Math.max(0,raw.length-65557);i--)if(raw.readUInt32LE(i)===0x06054b50){end=i;break;}
 if(end<0||end+22+raw.readUInt16LE(end+20)!==raw.length||raw.readUInt16LE(end+4)||raw.readUInt16LE(end+6)||raw.readUInt16LE(end+8)!==raw.readUInt16LE(end+10))fail('module ZIP directory');
 const count=raw.readUInt16LE(end+10),length=raw.readUInt32LE(end+12),offset=raw.readUInt32LE(end+16);if(count===0||count===65535||offset+length!==end)fail('module ZIP bounds');
 const files=[],seen=new Set();let current=offset,total=0;for(let n=0;n<count;n++){
  if(current+46>end||raw.readUInt32LE(current)!==0x02014b50)fail('module ZIP member');const flags=raw.readUInt16LE(current+8),method=raw.readUInt16LE(current+10),compressed=raw.readUInt32LE(current+20),bytes=raw.readUInt32LE(current+24),nameBytes=raw.readUInt16LE(current+28),extra=raw.readUInt16LE(current+30),comment=raw.readUInt16LE(current+32),local=raw.readUInt32LE(current+42),attributes=raw.readUInt32LE(current+38),creator=raw.readUInt16LE(current+4)>>8;
  if(current+46+nameBytes+extra+comment>end||flags&1||![0,8].includes(method)||(creator===3&&((attributes>>>16)&0o170000)&&((attributes>>>16)&0o170000)!==0o100000))fail('module ZIP regular member');
  const encoded=raw.subarray(current+46,current+46+nameBytes),name=encoded.toString('utf8');if(!Buffer.from(name).equals(encoded)||!name.startsWith(prefix)||name.endsWith('/')||name.includes('\\')||name.split('/').some(x=>!x||x==='.'||x==='..')||seen.has(name))fail('module ZIP path');seen.add(name);
  if(local+30>offset||raw.readUInt32LE(local)!==0x04034b50||raw.readUInt16LE(local+8)!==method||raw.readUInt16LE(local+6)!==flags)fail('module ZIP local header');const localName=raw.readUInt16LE(local+26),localExtra=raw.readUInt16LE(local+28),start=local+30+localName+localExtra;if(!raw.subarray(local+30,local+30+localName).equals(encoded)||start+compressed>offset||bytes>MAX_BYTES||total+bytes>512*1024*1024)fail('module ZIP content bounds');
  let content;try{content=method===0?Buffer.from(raw.subarray(start,start+compressed)):inflateRawSync(raw.subarray(start,start+compressed),{maxOutputLength:Math.max(1,bytes)});}catch{fail('module ZIP decompression');}if(content.length!==bytes)fail('module ZIP size');total+=bytes;files.push({name,relative:name.slice(prefix.length),raw:content,bytes,sha256:sha(content)});current+=46+nameBytes+extra+comment;
 }
 if(current!==end)fail('module ZIP member count');const lines=files.sort((a,b)=>Buffer.compare(Buffer.from(a.name),Buffer.from(b.name))).map(f=>f.sha256+'  '+f.name+'\n').join('');if('h1:'+crypto.createHash('sha256').update(lines).digest('base64')!==expectedH1)fail('module ZIP trusted sum');return files;
}
function writeBoundSnapshot(base,rows){
 if(!Array.isArray(rows)||rows.length===0||rows.length>100000)fail('snapshot roster');const seen=new Set();let total=0;for(const row of rows){if(!object(row)||!string(row.destination)||path.posix.normalize(row.destination)!==row.destination||row.destination.startsWith('/')||row.destination.split('/').some(x=>x==='..'||x==='.')||seen.has(row.destination)||!Number.isSafeInteger(row.bytes)||row.bytes<0||!hex(row.sha256)||![0o400,0o500].includes(row.mode))fail('snapshot member');seen.add(row.destination);total+=row.bytes;}if(total>1024*1024*1024)fail('snapshot total cap');
 if(fs.existsSync(base)||fs.lstatSync(path.dirname(base)).isSymbolicLink())fail('snapshot conflict');fs.mkdirSync(base,{mode:0o700});try{
  for(const row of rows){const raw=row.raw??pinnedRead(row.path,row.sha256);if(!Buffer.isBuffer(raw)||raw.length!==row.bytes||sha(raw)!==row.sha256)fail('snapshot consumed bytes');const target=path.join(base,row.destination);fs.mkdirSync(path.dirname(target),{recursive:true,mode:0o700});fs.writeFileSync(target,raw,{flag:'wx',mode:row.mode});if(!pinnedRead(target,row.sha256).equals(raw))fail('snapshot write bytes');}
  verifySnapshot(base,rows);return base;
 }catch(error){fs.rmSync(base,{recursive:true,force:true});throw error;}
}
function verifySnapshot(base,rows){const actual=treeFiles(base).map(f=>path.relative(base,f)).sort(),expected=rows.map(r=>r.destination).sort();if(canonical(actual)!==canonical(expected)){const actualSet=new Set(actual),expectedSet=new Set(expected),missing=expected.filter(x=>!actualSet.has(x)),extra=actual.filter(x=>!expectedSet.has(x));fail('snapshot topology drift '+canonical({missing:missing.slice(0,4),extra:extra.slice(0,4)}));}for(const row of rows){const file=path.join(base,row.destination),stat=fs.lstatSync(file);if(stat.uid!==process.getuid()||(stat.mode&0o777)!==row.mode||pinnedRead(file,row.sha256).length!==row.bytes)fail('snapshot bytes or ownership');}}

// Strict JSON stream parser with duplicate-key detection before JSON.parse.
function strictStream(raw){
 if(!Buffer.isBuffer(raw)||raw.length===0||raw.length>MAX_BYTES)fail('stream byte cap');
 const s=raw.toString('utf8');if(!Buffer.from(s).equals(raw))fail('stream UTF8');let i=0;
 const white=()=>{while(i<s.length&&/\s/.test(s[i]))i++;};
 function token(depth=0){
  white();if(depth>64)fail('JSON nesting');const start=i;
  if(s[i]==='"'){
   i++;while(i<s.length){if(s[i]==='\\'){i+=2;continue;}if(s[i++]==='"'){try{return JSON.parse(s.slice(start,i));}catch{fail('JSON string');}}}fail('truncated JSON');
  }
  if(s[i]==='{'){
   i++;white();const keys=new Set();if(s[i]==='}'){i++;return;}
   while(true){white();if(s[i]!=='"')fail('JSON object key');const key=token(depth+1);if(keys.has(key))fail('duplicate JSON key');keys.add(key);white();if(s[i++]!==':')fail('JSON colon');token(depth+1);white();if(s[i]==='}'){i++;return;}if(s[i++]!==',')fail('JSON object delimiter');}
  }
  if(s[i]==='['){i++;white();if(s[i]===']'){i++;return;}while(true){token(depth+1);white();if(s[i]===']'){i++;return;}if(s[i++]!==',')fail('JSON array delimiter');}}
  const m=s.slice(i).match(/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/);if(!m)fail('JSON token');i+=m[0].length;
 }
 const out=[];while(true){white();if(i===s.length)break;const start=i;token();let value;try{value=JSON.parse(s.slice(start,i));}catch{fail('malformed JSON');}const finite=v=>{if(typeof v==='number'&&!Number.isFinite(v))fail('nonfinite JSON number');if(v&&typeof v==='object')for(const x of Object.values(v))finite(x);};finite(value);out.push(value);if(out.length>MAX_MESSAGES)fail('message cap');}return out;
}
function singleJSON(raw){const values=strictStream(raw);if(values.length!==1)fail('single JSON document');return values[0];}
export function inspectGoScanStream(raw){
 if(arguments.length!==1)fail('parser caller authority');const messages=strictStream(raw),advisories=new Map(),findings=[];let config,sbom;const messageCounts={};
 for(const message of messages){
  if(!object(message)||Object.keys(message).length!==1)fail('protocol envelope');const key=Object.keys(message)[0],v=message[key];messageCounts[key]=(messageCounts[key]??0)+1;if(!config&&key!=='config')fail('config ordering');if(!sbom&&['osv','finding'].includes(key))fail('SBOM ordering');
  if(key==='config'){
   if(config||!closed(v,['protocol_version','scanner_name','scanner_version','db','db_last_modified','go_version','scan_level','scan_mode'])||![DATABASE,SNAPSHOT+'/database'].some(database=>canonical(v)===canonical({protocol_version:'v1.0.0',scanner_name:'govulncheck',scanner_version:'v1.7.0',db:'file://'+database,db_last_modified:DATABASE_MODIFIED,go_version:'go1.25.13',scan_level:'package',scan_mode:'source'})))fail('scanner protocol/config');config=v;
  }else if(key==='SBOM'){
   if(sbom||!closed(v,['go_version','modules','roots'])||v.go_version!=='go1.25.13'||!Array.isArray(v.modules)||v.modules.length===0||v.modules.length>1000||!Array.isArray(v.roots)||v.roots.length===0||v.roots.length>10000||v.roots.some(x=>!string(x))||new Set(v.roots).size!==v.roots.length)fail('SBOM coverage');
   const root=Object.values(ROOTS).find(relative=>v.roots.every(r=>r==='github.com/zasp-ai/zasp-sec/'+relative||r.startsWith('github.com/zasp-ai/zasp-sec/'+relative+'/')));
   const replacements=root==='services/platform'?['../health']:['services/event-ingest','services/gateway-control','services/runtime-gateway','services/sensor-agent'].includes(root)?['../health','../platform']:[];
   const identities=new Map();for(const m of v.modules){if(!closed(m,['path','version'])||!string(m.path)||(m.version!==undefined&&!string(m.version)))fail('SBOM module inventory');const identity=canonical([m.path,m.version??null]);identities.set(identity,(identities.get(identity)??0)+1);if(m.path.startsWith('../')&&!replacements.includes(m.path))fail('unknown local replacement');}
   for(const [identity,count]of identities){const [module,version]=JSON.parse(identity);if(count!==1&&(count!==2||version!==null||!replacements.includes(module)))fail('SBOM module inventory');}
   for(const replacement of replacements)if(identities.get(canonical([replacement,null]))!==2)fail('closed local replacement multiplicity');
   sbom=v;
  }else if(key==='progress'){
   if(!closed(v,['message','timestamp'])||!string(v.message))fail('progress protocol');
  }else if(key==='osv'){
   if(!closed(v,['schema_version','id','modified','published','withdrawn','aliases','related','summary','details','affected','references','severity','database_specific','credits'])||!string(v.id)||!/^GO-[0-9]{4}-[0-9]+$/.test(v.id)||!string(v.modified)||!Array.isArray(v.affected)||(advisories.has(v.id)&&canonical(advisories.get(v.id))!==canonical(v)))fail('OSV protocol');advisories.set(v.id,v);
  }else if(key==='finding'){
   if(!object(v)||!advisories.has(v.osv)||!closed(v,['osv','fixed_version','trace'])||!string(v.osv)||!Array.isArray(v.trace)||v.trace.length===0||v.trace.length>100)fail('finding protocol');
   for(const t of v.trace)if(!closed(t,['module','version','package','function','receiver','position'])||!string(t.module))fail('finding trace');findings.push(v);
  }else fail('unknown scanner message');
 }
 if(!config||!sbom)fail('missing scanner/SBOM');
 const normalized=findings.map(f=>{const osv=advisories.get(f.osv);if(!osv)fail('finding OSV missing');return {id:f.osv,severity:'UNKNOWN',fixedVersion:f.fixed_version??null,trace:f.trace,advisorySHA256:sha(Buffer.from(canonical(osv)))};});
 return {format:'production-go-scan-inspection-v1',releaseAccepted:false,fullMVSClearance:false,scanLevel:'package',rawSHA256:sha(raw),messageCounts,config,sbom,findings:normalized,advisories:[...advisories.values()]};
}
function assertTools(){if(process.execPath!==OWNED_NODE)fail('owned Node tool authority');const prefix=fs.lstatSync(OWNED_CODE_PREFIX),node=fs.lstatSync(OWNED_NODE);if(prefix.isSymbolicLink()||!prefix.isDirectory()||prefix.uid!==process.getuid()||(prefix.mode&0o777)!==0o700||node.isSymbolicLink()||!node.isFile()||node.uid!==process.getuid()||(node.mode&0o777)!==0o500)fail('owned Node topology');for(const [file,pin]of Object.entries(TOOL_PINS))pinnedRead(file,pin);}
function owned(mode,snapshotManifest){
 assertTools();const started=Date.now();const python=snapshotManifest?SNAPSHOT+'/python/bin/python3.13':PYTHON,runner=snapshotManifest?SNAPSHOT+'/runner.py':RUNNER;const run=spawnSync(python,['-I','-S','-B',runner,mode],{cwd:ROOT,env:{PATH:path.dirname(PYTHON),TZ:'UTC',LANG:'C',LC_ALL:'C'},encoding:'utf8',timeout:190000,maxBuffer:96*1024*1024});
 if(run.error||run.signal||run.status!==0)fail('owned runner failure');const receipt=singleJSON(Buffer.from(run.stdout));const ended=Date.now(),receiptStart=Date.parse(receipt.startedAt),receiptEnd=Date.parse(receipt.endedAt);if(!Number.isFinite(receiptStart)||!Number.isFinite(receiptEnd)||receiptStart<started-1000||receiptEnd>ended+1000||receiptEnd<receiptStart||receiptEnd-receiptStart>185000)fail('owned timestamp bounds');
 if(!closed(receipt,['format','mode','startedAt','endedAt','childExit','stdoutBase64','stdoutSHA256','stderrSHA256','timeout','overflow','terminated','preexistingZombies','newSurvivors','adoptedReaped','waitJoined','releaseAccepted','runtimeInputs','preProcessIDs','postProcessIDs'])||receipt.format!=='production-advisory-owned-runner-v1'||receipt.mode!==mode||receipt.childExit!==0||receipt.timeout!==false||receipt.overflow!==false||receipt.terminated!==false||receipt.waitJoined!==true||receipt.releaseAccepted!==false||!Array.isArray(receipt.newSurvivors)||receipt.newSurvivors.length!==0||!Array.isArray(receipt.preexistingZombies)||!Number.isSafeInteger(receipt.adoptedReaped)||receipt.adoptedReaped<0||(typeof receipt.stdoutBase64!=='string'||receipt.stdoutBase64.length>Math.ceil(MAX_BYTES/3)*4)||!hex(receipt.stdoutSHA256)||!hex(receipt.stderrSHA256)||!Array.isArray(receipt.preProcessIDs)||!Array.isArray(receipt.postProcessIDs)||receipt.preProcessIDs.length>10000||receipt.postProcessIDs.length>10000||!Array.isArray(receipt.runtimeInputs)||receipt.runtimeInputs.length===0||receipt.runtimeInputs.length>100)fail('owned runner receipt');for(const roster of [receipt.preProcessIDs,receipt.postProcessIDs]){const identities=new Set();for(const row of roster){if(!closed(row,['pid','start','ppid','state'])||!Number.isSafeInteger(row.pid)||row.pid<=0||!Number.isSafeInteger(row.ppid)||row.ppid<0||typeof row.start!=='string'||!/^\d+$/.test(row.start)||typeof row.state!=='string'||!/[RSDZTtXIWP]/.test(row.state)||row.state.length!==1||identities.has(row.pid))fail('process identity roster');identities.add(row.pid);}}for(const input of receipt.runtimeInputs){if(!closed(input,['path','bytes','sha256'])||!hex(input.sha256)||!Number.isSafeInteger(input.bytes))fail('runtime library binding');if(snapshotManifest){const row=snapshotRows(snapshotManifest).find(r=>path.join(SNAPSHOT,r.destination)===input.path);if(row){if(row.sha256!==input.sha256||row.bytes!==input.bytes)fail('owned runtime snapshot binding');}else{rootProtected(input.path);const known=snapshotManifest.runtimeInputs.find(r=>r.path===input.path);if(!known||known.sha256!==input.sha256||known.bytes!==input.bytes)fail('unlisted runtime library');}}const bytes=pinnedRead(input.path,input.sha256);if(bytes.length!==input.bytes)fail('runtime library bytes');}
 const raw=Buffer.from(receipt.stdoutBase64,'base64');if(raw.toString('base64')!==receipt.stdoutBase64||sha(raw)!==receipt.stdoutSHA256||raw.length>MAX_BYTES)fail('consumed runner bytes');assertTools();return {raw,receipt};
}
function fixedCommand(args){const r=spawnSync('/usr/bin/git',['--no-replace-objects','-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null',...args],{cwd:ROOT,env:{PATH:'/usr/bin',LANG:'C',LC_ALL:'C',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',GIT_CONFIG_SYSTEM:'/dev/null',GIT_OPTIONAL_LOCKS:'0'},maxBuffer:64*1024*1024});if(r.error||r.signal||r.status!==0)fail('fixed source query');return r.stdout;}
function packageClosureSHA(values){return sha(Buffer.from(canonical(values.map(p=>({path:p.ImportPath,dir:p.Dir,goFiles:p.GoFiles??[],embedFiles:p.EmbedFiles??[],module:p.Module??null,standard:p.Standard===true})).sort((a,b)=>a.path.localeCompare(b.path)))));}
function manifest(){
 noOverrides();assertTools();if(fixedCommand(['rev-parse',SOURCE_COMMIT+'^{commit}']).toString().trim()!==SOURCE_COMMIT)fail('source commit');
 const listed=fixedCommand(['ls-tree','-r','--name-only','-z',SOURCE_COMMIT,'--',...Object.values(ROOTS)]).toString().split('\0').filter(Boolean).sort();const source=[];
 for(const relative of listed){if(!/^[A-Za-z0-9_./-]+$/.test(relative)||relative.includes('..'))fail('source path');const expected=fixedCommand(['show',SOURCE_COMMIT+':'+relative]);const raw=pinnedRead(path.join(ROOT,relative),sha(expected));source.push({path:relative,bytes:raw.length,sha256:sha(raw)});}
 for(const relative of Object.values(ROOTS))checkGoRoster(path.join(ROOT,relative),listed.filter(f=>f.startsWith(relative+'/')&&f.endsWith('.go')).map(f=>f.slice(relative.length+1)));
 const currentGo=fixedCommand(['ls-tree','-r','--name-only','-z','HEAD','--',...Object.values(ROOTS)]).toString().split('\0').filter(x=>x.endsWith('.go')).sort();if(canonical(currentGo)!==canonical(listed.filter(x=>x.endsWith('.go'))))fail('extra tracked Go source');
 const extra=fixedCommand(['ls-files','--others','--exclude-standard','-z','--',...Object.values(ROOTS)]).toString().split('\0').filter(x=>x.endsWith('.go'));if(extra.length)fail('untracked Go source');
 const roster=singleJSON(pinnedRead(DB_ROSTER,TOOL_PINS[DB_ROSTER]));if(!Array.isArray(roster)||roster.length!==9160)fail('database inventory');const database=[];
 for(const row of roster){if(!closed(row,['path','bytes','sha256'])||!string(row.path)||row.path.includes('..')||!hex(row.sha256))fail('database path');const raw=pinnedRead(path.join(DATABASE,row.path),row.sha256);if(raw.length!==row.bytes)fail('database size');database.push({...row});}
 if(canonical(treeFiles(DATABASE).map(f=>path.relative(DATABASE,f)).sort())!==canonical(roster.map(x=>x.path).sort()))fail('database extra member');
 const prerequisite=singleJSON(pinnedRead(SOURCE_RECEIPT,TOOL_PINS[SOURCE_RECEIPT]));if(prerequisite.commit!=='5cd8418cf9c867d344fda07a73ea844b0f34bca2'||prerequisite.generatedRosterSha256!==TOOL_PINS[DB_ROSTER]||prerequisite.originalGeneratedDBMetadata?.modified!==DATABASE_MODIFIED)fail('official database source');
 const modules={},packageInputs=new Map(),runtimeInputs=new Map(),sourcePaths=new Set(source.map(x=>path.join(ROOT,x.path)));
 for(const [name,relative]of Object.entries(ROOTS)){
  const graph=owned('graph-'+name),values=strictStream(graph.raw);for(const input of graph.receipt.runtimeInputs)runtimeInputs.set(input.path,input);if(values.length===0||values.length>1000)fail('MVS graph');const seen=new Set();for(const row of values){if(!object(row)||!string(row.Path)||seen.has(row.Path))fail('MVS module');seen.add(row.Path);}
  const packages=owned('packages-'+name),packageValues=strictStream(packages.raw);if(packageValues.length===0)fail('package closure');
  for(const p of packageValues){if(!object(p)||!string(p.Dir)||!string(p.ImportPath)||p.Error||p.DepsErrors)fail('Go package closure');for(const name of [...(p.GoFiles??[]),...(p.EmbedFiles??[])]){if(!string(name)||name.includes('..')||path.isAbsolute(name))fail('package file path');const file=path.join(p.Dir,name);if(!file.startsWith(ROOT+'/')&&!file.startsWith(MODULE_CACHE+'/')&&!file.startsWith(path.dirname(path.dirname(GO))+'/'))fail('package input root');if(file.startsWith(ROOT+'/')&&!sourcePaths.has(file))fail('untracked package input');packageInputs.set(file,entry(file));}}
  owned('verify-'+name);modules[relative]={mvs:values,mvsSHA256:sha(graph.raw),packages:packageValues.map(p=>({path:p.ImportPath,dir:p.Dir,goFiles:p.GoFiles??[],embedFiles:p.EmbedFiles??[],root:p.Dir===path.join(ROOT,relative)||p.Dir.startsWith(path.join(ROOT,relative)+'/'),module:p.Module??null,standard:p.Standard===true})),packageGraphSHA256:packageClosureSHA(packageValues)};
 }
 const python=pythonTopology(),pythonInputs=python.files,external=externalClosure(modules,source);
 bindExternalPackageInputs([...packageInputs.values()],external.files);
 const goInputs=treeFiles(GOROOT).map(file=>({...entry(file),executable:!!(fs.lstatSync(file).mode&0o111)}));
 for(const line of fs.readFileSync('/proc/self/maps','utf8').split('\n')){const match=line.match(/\s(\/[^\n]+)$/);if(match){const file=fs.realpathSync(match[1]);runtimeInputs.set(file,entry(file));}}
 const pcre=fs.realpathSync('/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0');runtimeInputs.set(pcre,entry(pcre));
 for(const x of runtimeInputs.values())if(!Object.hasOwn(TOOL_PINS,x.path))rootProtected(x.path);
 const goToolInputs=treeFiles(path.join(path.dirname(path.dirname(GO)),'pkg/tool/linux_amd64')).map(entry);
 return {format:'production-go-advisory-input-manifest-v1',sourceCommit:SOURCE_COMMIT,target:{goos:'linux',goarch:'amd64',cgo:false,scanLevel:'package'},roots:Object.values(ROOTS),source,runtimeInputs:[...runtimeInputs.values()].sort((a,b)=>a.path.localeCompare(b.path)),external,goInputs,pythonLinks:python.links,tools:Object.entries(TOOL_PINS).map(([file,pin])=>({...entry(file),sha256:pin})),pythonInputs,goToolInputs,packageInputs:[...packageInputs.values()].sort((a,b)=>a.path.localeCompare(b.path)),modules,database:{officialCommit:prerequisite.commit,rosterSHA256:TOOL_PINS[DB_ROSTER],files:database,originalModified:DATABASE_MODIFIED,actualLookupObservedAt:prerequisite.observedAt},releaseAccepted:false,coverage:{npm:false,goPackageRoots:7,goFullMVSAdvisories:false,shippingImages:0,renderedThirdPartyInventory:false}};
}
function inspectOwnedGoEnvironment(value){if(canonical(value)!==canonical({GOROOT:SNAPSHOT+'/go',GOMODCACHE:SNAPSHOT+'/module-cache',GOWORK:'off',GOENV:'',GOPROXY:'off',GOFLAGS:'-mod=readonly',GOTOOLCHAIN:'local',GOOS:'linux',GOARCH:'amd64',CGO_ENABLED:'0'}))fail('owned Go environment');}
function checkOwnedEnvironment(before){
 const identity=singleJSON(owned('snapshot-python',before).raw),expectedPython=SNAPSHOT+'/python';if(canonical(identity)!==canonical({prefix:expectedPython,path:[expectedPython+'/lib/python313.zip',expectedPython+'/lib/python3.13',expectedPython+'/lib/python3.13/lib-dynload'],executable:expectedPython+'/bin/python3.13',isolated:1,no_site:1}))fail('owned Python prefix');
 inspectOwnedGoEnvironment(singleJSON(owned('snapshot-env',before).raw));
}
function checkOwnedInputs(){
 const before=manifest(),rows=snapshotRows(before),space=fs.statfsSync('/workspace/scratch');if(space.bavail*space.bsize-rows.reduce((sum,r)=>sum+r.bytes,0)<2*1024*1024*1024)fail('snapshot disk reserve');writeBoundSnapshot(SNAPSHOT,rows);try{checkOwnedEnvironment(before);for(const [name,relative]of Object.entries(ROOTS)){const result=owned('snapshot-packages-'+name,before),actual=strictStream(result.raw);const normalize=p=>({path:p.ImportPath,goFiles:p.GoFiles??[],embedFiles:p.EmbedFiles??[]});const expected=before.modules[relative].packages.map(p=>({path:p.path,goFiles:p.goFiles,embedFiles:p.embedFiles}));if(canonical(actual.map(normalize).sort((a,b)=>a.path.localeCompare(b.path)))!==canonical(expected.sort((a,b)=>a.path.localeCompare(b.path))))fail('owned package closure');}verifySnapshot(SNAPSHOT,rows);return {format:'production-go-advisory-owned-input-check-v1',inputManifest:before,inputManifestSHA256:sha(Buffer.from(canonical(before))),snapshotFiles:rows.map(({path,destination,bytes,sha256,mode})=>({path,destination,bytes,sha256,mode})),releaseAccepted:false,actualScans:0};}finally{fs.rmSync(SNAPSHOT,{recursive:true,force:true});}
}


function bindDatabaseAdvisory(osv,raw,row){
 const db=singleJSON(raw);if(!row||row.path!=='ID/'+osv.id+'.json'||!hex(row.sha256)||raw.length!==row.bytes||sha(raw)!==row.sha256)fail('consumed advisory differs from pinned database');let relatedOmittedByReporter=false;
 if(canonical(db)!==canonical(osv)){
  if(!object(db)||!object(osv)||!Object.hasOwn(db,'related')||Object.hasOwn(osv,'related')||db.schema_version!=='1.3.1'||!Array.isArray(db.related)||db.related.length===0||db.related.length>1024||!db.related.every(string))fail('consumed advisory differs from pinned database');
  const otherwiseIdentical={...db};delete otherwiseIdentical.related;if(canonical(otherwiseIdentical)!==canonical(osv))fail('consumed advisory differs from pinned database');relatedOmittedByReporter=true;
 }
 return {id:db.id,databaseMember:row.path,bytes:raw.length,sha256:sha(raw),rawBase64:raw.toString('base64'),document:db,reportedOSV:osv,relatedOmittedByReporter};
}
function validateScannerModuleInventory(sbom,before,relative){const expected=new Set(before.modules[relative].packages.map(p=>p.standard?canonical(['stdlib','v1.25.13']):p.module?canonical(p.module.Replace?[p.module.Replace.Path,p.module.Replace.Version??null]:[p.module.Path,p.module.Version??null]):null).filter(Boolean));const actual=new Set(sbom.modules.map(m=>canonical([m.path,m.version??null])));if(canonical([...expected].sort())!==canonical([...actual].sort()))fail('scanner module/package inventory mismatch');}

export function deriveProductionGoAdvisoryManifestV1(){if(arguments.length!==0)fail('caller authority');return manifest();}
export function collectProductionGoAdvisoryEvidenceV1(){
 if(arguments.length!==0)fail('caller authority');if(!hex(APPROVED_INPUT_MANIFEST_SHA256))fail('manifest approval unavailable');
 const before=manifest(),text=canonical(before);if(sha(Buffer.from(text))!==APPROVED_INPUT_MANIFEST_SHA256)fail('approved manifest mismatch');
 const now=Date.now(),lookup=Date.parse(before.database.actualLookupObservedAt);if(!Number.isFinite(lookup)||lookup>now||now-lookup>24*60*60*1000)fail('official lookup freshness');
 const rows=snapshotRows(before),space=fs.statfsSync('/workspace/scratch');if(space.bavail*space.bsize-rows.reduce((sum,r)=>sum+r.bytes,0)<2*1024*1024*1024)fail('snapshot disk reserve');writeBoundSnapshot(SNAPSHOT,rows);const observations=[];try{
 checkOwnedEnvironment(before);
 for(const [name,relative]of Object.entries(ROOTS)){
  verifySnapshot(SNAPSHOT,rows);const result=owned('scan-'+name,before),inspection=inspectGoScanStream(result.raw),databaseBindings=[];for(const osv of inspection.advisories){const member='ID/'+osv.id+'.json',row=before.database.files.find(r=>r.path===member);databaseBindings.push(bindDatabaseAdvisory(osv,pinnedRead(path.join(SNAPSHOT,'database',member)),row));}const expectedRoots=before.modules[relative].packages.filter(p=>p.root).map(p=>p.path).sort();if(canonical([...inspection.sbom.roots].sort())!==canonical(expectedRoots))fail('scanner root inventory mismatch');validateScannerModuleInventory(inspection.sbom,before,relative);observations.push({moduleRoot:relative,receipt:result.receipt,inspection,databaseBindings});
 }
 verifySnapshot(SNAPSHOT,rows);const after=manifest();if(canonical(after)!==text)fail('final input drift');
 return {format:'production-go-advisory-component-v1',status:'COMPONENT-SCAN-ONLY',releaseAccepted:false,fullMVSClearance:false,inputManifestSHA256:APPROVED_INPUT_MANIFEST_SHA256,observations,missing:['npm-production','go-full-mvs-advisory-policy','nine-shipping-images','rendered-thirdparty-images','severity-policy']};
 }finally{fs.rmSync(SNAPSHOT,{recursive:true,force:true});}
}
if(process.argv[1]&&fs.realpathSync(process.argv[1])===fs.realpathSync(fileURLToPath(import.meta.url))){
 if(process.argv.length!==3||!['--manifest','--collect','--check-owned-inputs'].includes(process.argv[2]))fail('fixed CLI mode');
 const result=process.argv[2]==='--manifest'?deriveProductionGoAdvisoryManifestV1():process.argv[2]==='--check-owned-inputs'?checkOwnedInputs():collectProductionGoAdvisoryEvidenceV1();
 const output=Buffer.from(canonical(result)+'\n');if(output.length>128*1024*1024)fail('component output cap');process.stdout.write(output);
}
