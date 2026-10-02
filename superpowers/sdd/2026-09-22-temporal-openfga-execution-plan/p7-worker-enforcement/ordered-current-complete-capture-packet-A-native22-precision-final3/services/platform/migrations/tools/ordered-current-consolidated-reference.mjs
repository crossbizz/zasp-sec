// Validation is deliberately separate from admission. No caller-provided digest
// can authorize a new reference file, even when all internal hashes agree.
import crypto from 'node:crypto';
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const phases=['demand','keys','original','resolution','witness'];
const sections=['rawInputs','normalizationObservations','resolutions','witnesses'];
const fail=what=>{throw Error('complete reference '+what);};
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const integer=x=>Number.isSafeInteger(x)&&x>=0;
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const sorted=xs=>xs.slice().sort((a,b)=>Buffer.compare(Buffer.from(a),Buffer.from(b)));
function same(a,b){return JSON.stringify(canonical(a))===JSON.stringify(canonical(b));}
function canonical(x){return Array.isArray(x)?x.map(canonical):object(x)?Object.fromEntries(sorted(Object.keys(x)).map(k=>[k,canonical(x[k])])):x;}
function shape(x,keys,label){if(!object(x)||!same(sorted(Object.keys(x)),sorted(keys.split(' '))))fail(label+' fields');}
function scalarString(x){
 if(typeof x!=='string')fail('string type');
 for(let i=0;i<x.length;i++){const n=x.charCodeAt(i);if(n>=0xd800&&n<=0xdbff){const next=x.charCodeAt(++i);if(!(next>=0xdc00&&next<=0xdfff))fail('Unicode surrogate');}else if(n>=0xdc00&&n<=0xdfff)fail('Unicode surrogate');}
 return x;
}
class NumericLexeme{constructor(token){this.token=token;}}
function numberToken(token){
 const value=Number(token),parts=token.match(/^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/),digits=(parts[2]+(parts[3]??'')).replace(/^0+/,'');
 if(!Number.isFinite(value)||value===0&&digits)fail('JSON finite number or underflow');
 if(!digits)return value;
 // Inspect decimal digits before using the rounded binary64 value. Work stays
 // linear in the token length; a malicious exponent never allocates 10**n.
 const scale=Number(parts[4]??0)-(parts[3]?.length??0);
 let whole=digits;
 if(scale<0){const cut=-scale;if(cut>=whole.length||!/^[0]*$/.test(whole.slice(-cut)))return new NumericLexeme(token);whole=whole.slice(0,-cut);}
 else if(scale>0){if(whole.length+scale>16)return new NumericLexeme(token);whole+='0'.repeat(scale);}
 if(whole.length>16||BigInt(whole)>9007199254740991n)return new NumericLexeme(token);
 return value;
}
function parse(raw,wire=false){
 if(!Buffer.isBuffer(raw)||!raw.length||raw.length>16777217)fail('byte ceiling');
 const text=new TextDecoder('utf-8',{fatal:true}).decode(raw);let at=0;
 const ws=()=>{const start=at;while(/[ \t\r\n]/.test(text[at]??'x'))at++;if(wire&&start!==at&&!(at===text.length&&text.slice(start)==='\n'))fail('wire whitespace');};
 const str=()=>{const start=at++;let escape=false;for(;at<text.length;at++){const c=text[at];if(c==='"'&&!escape){at++;const s=scalarString(JSON.parse(text.slice(start,at)));if(wire&&JSON.stringify(s).replaceAll('\u2028','\\u2028').replaceAll('\u2029','\\u2029')!==text.slice(start,at))fail('wire string encoding');return s;}escape=c==='\\'&&!escape;}fail('JSON string');};
 const value=(depth=0)=>{
  if(depth>64)fail('JSON depth');ws();
  if(text[at]==='"')return str();
  if(text[at]==='{'){
   at++;const out=Object.create(null),seen=new Set();let previous=null;ws();if(text[at]==='}'){at++;return out;}
   for(;;){ws();if(text[at]!=='"')fail('JSON key');const k=str();if(seen.has(k))fail('duplicate JSON key');seen.add(k);if(wire&&previous!==null&&Buffer.compare(Buffer.from(previous),Buffer.from(k))>=0)fail('wire key order');previous=k;ws();if(text[at++]!==':')fail('JSON colon');out[k]=value(depth+1);ws();const end=text[at++];if(end==='}')return out;if(end!==',')fail('JSON object');}
  }
  if(text[at]==='['){at++;const out=[];ws();if(text[at]===']'){at++;return out;}for(;;){out.push(value(depth+1));ws();const end=text[at++];if(end===']')return out;if(end!==',')fail('JSON array');}}
  const token=text.slice(at).match(/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/)?.[0];if(!token)fail('JSON value');at+=token.length;return /^(true|false|null)$/.test(token)?JSON.parse(token):numberToken(token);
 };
 const out=value();ws();if(at!==text.length)fail('JSON trailing bytes');return out;
}
function typed(value,type){
 if(typeof type!=='string')fail('field type');
 if(type.endsWith('?')){if(value===null)return;type=type.slice(0,-1);}
 const checks={text:v=>typeof v==='string',boolean:v=>typeof v==='boolean',integer:v=>Number.isSafeInteger(v),number:v=>typeof v==='number'&&Number.isFinite(v)||v instanceof NumericLexeme,json:()=>true,'text[]':v=>Array.isArray(v)&&v.every(x=>typeof x==='string')};
 if(!checks[type]||!checks[type](value))fail('field type '+type);
}
function evidence(rows){
 if(!Array.isArray(rows))fail('reused evidence');
 for(const row of rows){shape(row,'fileSHA256 rowIdentity field siteSHA256 frameSHA256','evidence');if(!hex(row.fileSHA256)||!hex(row.siteSHA256)||!hex(row.frameSHA256)||typeof row.rowIdentity!=='string'||typeof row.field!=='string')fail('evidence identity');}
}
function pins(x){if(!object(x)||!Object.keys(x).length)fail('source pins');for(const [path,pin]of Object.entries(x))if(!hex(pin)||path.startsWith('/')||path.split('/').some(x=>['','..','.'].includes(x)))fail('source pin path');}
function validateContract(c,m,contractRaw){
 shape(c,'format status installable captureReady sourceFrameVersion compilerArtifactSHA256 compilerChecksum compiledSourceSHA256 sourceContractSHA256 closureSHA256 catalog1FileSHA256 requiredPostgres requiredServerVersionNum pgcrypto variant sessionUser requiredRole requiredTimeZone maxRows maxBytes phases rules reusedEvidence sourcePins','contract');
 if(c.format!=='ordered-current-complete-capture-contract-v1'||c.status!=='REFERENCE-CAPTURE-ONLY'||c.installable!==false||c.captureReady!==true||c.sourceFrameVersion!==1||c.requiredRole!=='zasp_discovery_authority'||c.requiredTimeZone!=='UTC'||c.requiredServerVersionNum!=='180003'||c.pgcrypto!=='1.4'||!['A','B'].includes(c.variant)||c.sessionUser!==(c.variant==='A'?'zasp_test':'zasp_e2e')||typeof c.requiredPostgres!=='string'||!c.requiredPostgres)fail('contract boundary');
 if(!integer(c.maxRows)||c.maxRows!==10000||!integer(c.maxBytes)||c.maxBytes!==16777216)fail('contract ceiling');
 for(const key of ['compilerArtifactSHA256','compilerChecksum','compiledSourceSHA256','sourceContractSHA256','closureSHA256','catalog1FileSHA256'])if(!hex(c[key]))fail('contract provenance');
 shape(m,'format source files','manifest');if(m.format!==1||typeof m.source!=='string')fail('manifest');pins(m.files);pins(c.sourcePins);evidence(c.reusedEvidence);
 if(m.files['services/platform/migrations/ordered_current/consolidated-capture-contract.json']!==sha(contractRaw))fail('manifest contract binding');
 for(const [path,pin]of Object.entries(c.sourcePins))if(m.files[path]!==pin)fail('manifest source binding');
 if(!Array.isArray(c.phases)||c.phases.length!==5||!object(c.rules)||!Object.keys(c.rules).length)fail('phase coverage');
 const assigned=new Set();
 c.phases.forEach((p,i)=>{
  shape(p,'id searchPath timeZone sqlSHA256 ruleIds','phase contract');if(p.id!==phases[i]||p.searchPath!==(p.id==='keys'?'pg_catalog':'pg_catalog, public')||p.timeZone!=='UTC'||!hex(p.sqlSHA256)||!Array.isArray(p.ruleIds))fail('phase contract');
  for(const id of p.ruleIds){if(typeof id!=='string'||assigned.has(id)||!Object.hasOwn(c.rules,id)||c.rules[id].phase!==p.id)fail('phase rule coverage');assigned.add(id);}
 });
 if(assigned.size!==Object.keys(c.rules).length)fail('rule coverage');
 for(const [id,r]of Object.entries(c.rules)){
  shape(r,'kind section phase fields fieldTypes sourceMaxRows refusalMaxRows bag rosterRuleId demandRuleId','rule');
  if(typeof r.kind!=='string'||!['demand','roster',...sections].includes(r.section)||!phases.includes(r.phase)||!Array.isArray(r.fields)||r.fields.some(x=>typeof x!=='string')||new Set(r.fields).size!==r.fields.length||!object(r.fieldTypes)||!same(sorted(r.fields),sorted(Object.keys(r.fieldTypes)))||typeof r.bag!=='boolean'||!(r.sourceMaxRows===null||integer(r.sourceMaxRows))||!integer(r.refusalMaxRows)||r.refusalMaxRows>c.maxRows||r.refusalMaxRows===0)fail('rule shape '+id);
  for(const t of Object.values(r.fieldTypes))if(typeof t!=='string'||!/^(?:text|boolean|integer|number|json|text\[\])\??$/.test(t))fail('rule type');
  if(r.section==='roster'&&(r.phase!=='keys'||r.fields.length||r.bag||r.rosterRuleId!==null))fail('roster rule');
  if(r.section==='demand'&&(r.phase!=='demand'||r.fields.length||r.bag||r.rosterRuleId!==null||r.demandRuleId!==null))fail('demand rule');
  if(r.section==='roster'&&(typeof r.demandRuleId!=='string'||c.rules[r.demandRuleId]?.section!=='demand')||r.section!=='roster'&&r.demandRuleId!==null)fail('demand linkage');
  if(r.rosterRuleId!==null&&(!Object.hasOwn(c.rules,r.rosterRuleId)||c.rules[r.rosterRuleId].section!=='roster'||r.phase!=='original'||r.bag))fail('roster binding');
  if(r.section==='witnesses'&&r.phase!=='witness'||r.section==='resolutions'&&r.phase!=='resolution')fail('rule section phase');
 }
 for(const [id,r]of Object.entries(c.rules))if(['roster','demand'].includes(r.section)){const link=r.section==='roster'?'rosterRuleId':'demandRuleId';if(Object.values(c.rules).filter(x=>x[link]===id).length!==1)fail('demand roster consumer coverage');}
}
export function checkOrderedConsolidatedReferenceEnvelope(raw,{contractRaw,manifestRaw}){
 if(!Buffer.isBuffer(raw)||raw.length>16777216||raw.at(-1)!==10||raw.at(-2)!==125)fail('publisher byte framing');
 const c=parse(contractRaw),m=parse(manifestRaw);validateContract(c,m,contractRaw);const e=parse(raw,true);
 shape(e,'format status installable sourceFrameVersion packetManifestSHA256 contractSHA256 closureSHA256 compilerArtifactSHA256 compilerChecksum compiledSourceSHA256 sourceContractSHA256 catalog1FileSHA256 sourcePins variant sessionUser role timeZone postgres serverVersionNum pgcrypto readOnly preAdmission postAdmission rolledBack frameRestored phases counts rawInputs normalizationObservations resolutions witnesses reusedEvidence','envelope');
 const bound={format:'ordered-current-complete-reference-v1',status:'REFERENCE-CAPTURE-ONLY',installable:false,sourceFrameVersion:1,packetManifestSHA256:sha(manifestRaw),contractSHA256:sha(contractRaw),closureSHA256:c.closureSHA256,compilerArtifactSHA256:c.compilerArtifactSHA256,compilerChecksum:c.compilerChecksum,compiledSourceSHA256:c.compiledSourceSHA256,sourceContractSHA256:c.sourceContractSHA256,catalog1FileSHA256:c.catalog1FileSHA256,sourcePins:c.sourcePins,role:c.requiredRole,timeZone:c.requiredTimeZone,postgres:c.requiredPostgres,serverVersionNum:c.requiredServerVersionNum,pgcrypto:c.pgcrypto,readOnly:true,preAdmission:true,postAdmission:true,rolledBack:true,frameRestored:true,reusedEvidence:c.reusedEvidence};
 for(const [k,v]of Object.entries(bound))if(!same(e[k],v))fail('provenance '+k);
 if(e.variant!==c.variant||e.sessionUser!==c.sessionUser)fail('fixture owner');
 if(raw.length>c.maxBytes)fail('final byte ceiling');
 shape(e.counts,'streamRows expandedRows streamBytes demandRows rosterRows ruleRows','counts');
 if(!object(e.counts.ruleRows)||!same(sorted(Object.keys(e.counts.ruleRows)),sorted(Object.keys(c.rules))))fail('rule count coverage');
 for(const key of ['streamRows','expandedRows','streamBytes','demandRows','rosterRows'])if(!integer(e.counts[key]))fail('count type');
 if(e.counts.expandedRows>c.maxRows||e.counts.streamBytes>c.maxBytes)fail('global ceiling');
 const counts=Object.fromEntries(Object.keys(c.rules).map(id=>[id,0])),rows=Object.fromEntries(phases.map(id=>[id,0])),expanded=Object.fromEntries(phases.map(id=>[id,0]));
 let roster=0,demand=0;
 for(const section of sections){
  if(!Array.isArray(e[section]))fail('section array');const seen=new Set();let previous=null;
  for(const row of e[section]){
   shape(row,'ruleId identity multiplicity fact','row');const r=c.rules[row.ruleId];
   if(!r||r.section!==section)fail('row section');
   if(typeof row.identity!=='string'||!row.identity||!integer(row.multiplicity)||row.multiplicity<1||!r.bag&&row.multiplicity!==1)fail('row multiplicity count');
   const key=JSON.stringify([row.ruleId,row.identity]);if(seen.has(key))fail('duplicate fact key');seen.add(key);
   if(previous&&(Buffer.compare(Buffer.from(previous[0]),Buffer.from(row.ruleId))>0||previous[0]===row.ruleId&&Buffer.compare(Buffer.from(previous[1]),Buffer.from(row.identity))>=0))fail('row order');previous=[row.ruleId,row.identity];
   if(!object(row.fact)||!same(sorted(Object.keys(row.fact)),sorted(r.fields)))fail('selected fields');for(const field of r.fields)typed(row.fact[field],r.fieldTypes[field]);
   counts[row.ruleId]+=row.multiplicity;rows[r.phase]++;expanded[r.phase]+=row.multiplicity;
  }
 }
 for(const [id,r]of Object.entries(c.rules)){
  const count=e.counts.ruleRows[id];if(!integer(count)||count>r.refusalMaxRows||r.sourceMaxRows!==null&&count>r.sourceMaxRows)fail('rule count bound');
  if(r.section==='roster'){counts[id]=count;roster+=count;rows.keys+=count;expanded.keys+=count;}
  else if(r.section==='demand'){counts[id]=count;demand+=count;rows.demand+=count;expanded.demand+=count;}
  else if(counts[id]!==count)fail('rule count');
  if(r.rosterRuleId!==null&&count!==e.counts.ruleRows[r.rosterRuleId])fail('roster count join');
  if(r.demandRuleId!==null&&count!==e.counts.ruleRows[r.demandRuleId])fail('demand count join');
 }
 if(e.counts.demandRows!==demand||e.counts.rosterRows!==roster||e.counts.streamRows!==Object.values(rows).reduce((a,b)=>a+b,0)||e.counts.expandedRows!==Object.values(expanded).reduce((a,b)=>a+b,0))fail('global counts');
 if(!Array.isArray(e.phases)||e.phases.length!==5)fail('phase coverage');let bytes=0;
 e.phases.forEach((p,i)=>{shape(p,'id searchPath timeZone sqlSHA256 rowCount expandedRows streamBytes','phase observation');const expected=c.phases[i];for(const k of ['id','searchPath','timeZone','sqlSHA256'])if(p[k]!==expected[k])fail('phase provenance');if(p.rowCount!==rows[p.id]||p.expandedRows!==expanded[p.id]||!integer(p.streamBytes)||p.streamBytes>c.maxBytes||p.rowCount===0&&p.streamBytes!==0||p.rowCount>0&&p.streamBytes===0)fail('phase count');bytes+=p.streamBytes;});
 if(bytes!==e.counts.streamBytes)fail('stream byte count');
}
export function admitOrderedConsolidatedReference(){throw Error('complete reference admission closed; no accepted file pin');}
