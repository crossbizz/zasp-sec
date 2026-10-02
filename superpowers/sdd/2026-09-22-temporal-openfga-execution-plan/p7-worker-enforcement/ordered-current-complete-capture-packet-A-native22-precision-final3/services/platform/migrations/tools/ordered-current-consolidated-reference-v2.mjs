// V2 validation remains separate from admission. Contract bytes select only
// reviewed symbolic frames; they never supply executable role-change SQL.
import crypto from 'node:crypto';
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const phases=['demand','keys','original','resolution','witness'];
const sections=['rawInputs','normalizationObservations','resolutions','witnesses'];
const frameIds=['collectorDiscoveryCatalog','sourceDiscoveryPublic','sourceInventoryPublic'];
const contextPrerequisiteIds=['exact-source-and-query','effective-user-and-session','same-inherited-settings','private-fixture-quiescence','no-unsupported-observers','closed-v2-lifecycle'];
const captureMaxRows=65536,captureMaxBytes=33554432;
const fail=what=>{throw Error('complete reference v2 '+what);};
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const integer=value=>Number.isSafeInteger(value)&&value>=0;
const hex=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const sorted=values=>values.slice().sort((left,right)=>Buffer.compare(Buffer.from(left),Buffer.from(right)));
const canonical=value=>Array.isArray(value)?value.map(canonical):object(value)?Object.fromEntries(sorted(Object.keys(value)).map(key=>[key,canonical(value[key])])):value;
const same=(left,right)=>JSON.stringify(canonical(left))===JSON.stringify(canonical(right));
function shape(value,keys,label){if(!object(value)||!same(sorted(Object.keys(value)),sorted(keys.split(' '))))fail(label+' fields');}
function scalarString(value){if(typeof value!=='string')fail('string type');for(let index=0;index<value.length;index++){const code=value.charCodeAt(index);if(code>=0xd800&&code<=0xdbff){const next=value.charCodeAt(++index);if(!(next>=0xdc00&&next<=0xdfff))fail('Unicode surrogate');}else if(code>=0xdc00&&code<=0xdfff)fail('Unicode surrogate');}return value;}
export class NumericLexeme{constructor(token){this.token=token;}}
function numberToken(token){
 const value=Number(token),parts=token.match(/^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/),digits=(parts[2]+(parts[3]??'')).replace(/^0+/,'');
 if(!Number.isFinite(value)||value===0&&digits)fail('JSON finite number or underflow');
 if(!digits)return value;
 const scale=Number(parts[4]??0)-(parts[3]?.length??0);let whole=digits;
 if(scale<0){const cut=-scale;if(cut>=whole.length||!/^[0]*$/.test(whole.slice(-cut)))return new NumericLexeme(token);whole=whole.slice(0,-cut);}else if(scale>0){if(whole.length+scale>16)return new NumericLexeme(token);whole+='0'.repeat(scale);}
 if(whole.length>16||BigInt(whole)>9007199254740991n)return new NumericLexeme(token);return value;
}
function parse(raw,wire=false){
 if(!Buffer.isBuffer(raw)||!raw.length||raw.length>captureMaxBytes+1)fail('byte ceiling');
 const text=new TextDecoder('utf-8',{fatal:true}).decode(raw);let at=0;
 const ws=()=>{const start=at;while(/[ \t\r\n]/.test(text[at]??'x'))at++;if(wire&&start!==at&&!(at===text.length&&text.slice(start)==='\n'))fail('wire whitespace');};
 const str=()=>{const start=at++;let escape=false;for(;at<text.length;at++){const char=text[at];if(char==='"'&&!escape){at++;const value=scalarString(JSON.parse(text.slice(start,at)));if(wire&&JSON.stringify(value).replaceAll('\u2028','\\u2028').replaceAll('\u2029','\\u2029')!==text.slice(start,at))fail('wire string encoding');return value;}escape=char==='\\'&&!escape;}fail('JSON string');};
 const value=(depth=0)=>{
  if(depth>64)fail('JSON depth');ws();
  if(text[at]==='"')return str();
  if(text[at]==='{'){at++;const out=Object.create(null),seen=new Set();let previous=null;ws();if(text[at]==='}'){at++;return out;}for(;;){ws();if(text[at]!=='"')fail('JSON key');const key=str();if(seen.has(key))fail('duplicate JSON key');seen.add(key);if(wire&&previous!==null&&Buffer.compare(Buffer.from(previous),Buffer.from(key))>=0)fail('wire key order');previous=key;ws();if(text[at++]!==':')fail('JSON colon');out[key]=value(depth+1);ws();const end=text[at++];if(end==='}')return out;if(end!==',')fail('JSON object');}}
  if(text[at]==='['){at++;const out=[];ws();if(text[at]===']'){at++;return out;}for(;;){out.push(value(depth+1));ws();const end=text[at++];if(end===']')return out;if(end!==',')fail('JSON array');}}
  const token=text.slice(at).match(/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/)?.[0];if(!token)fail('JSON value');at+=token.length;return /^(true|false|null)$/.test(token)?JSON.parse(token):numberToken(token);
 };
 const out=value();ws();if(at!==text.length)fail('JSON trailing bytes');return out;
}
function typed(value,type){if(type.endsWith('?')){if(value===null)return;type=type.slice(0,-1);}const checks={text:item=>typeof item==='string',boolean:item=>typeof item==='boolean',integer:item=>Number.isSafeInteger(item),number:item=>typeof item==='number'&&Number.isFinite(item)||item instanceof NumericLexeme,json:()=>true,'text[]':item=>Array.isArray(item)&&item.every(entry=>typeof entry==='string')};if(!checks[type]||!checks[type](value))fail('field type '+type);}
function pins(value){if(!object(value)||!Object.keys(value).length)fail('pins');for(const [path,digest]of Object.entries(value))if(!hex(digest)||path.startsWith('/')||path.split('/').some(part=>['','..','.'].includes(part)))fail('pin path');}
function evidence(rows){if(!Array.isArray(rows))fail('reused evidence');for(const row of rows){shape(row,'fileSHA256 rowIdentity field siteSHA256 frameSHA256','evidence');if(!hex(row.fileSHA256)||!hex(row.siteSHA256)||!hex(row.frameSHA256)||typeof row.rowIdentity!=='string'||typeof row.field!=='string')fail('evidence identity');}}
const kebab=value=>value.replace(/([a-z])([A-Z])/g,'$1-$2').toLowerCase();
function observedFrame(value,expected,session,label){shape(value,'sessionUser role searchPath timeZone readOnly',label);if(value.sessionUser!==session||value.role!==expected.role||value.searchPath!==expected.searchPath||value.timeZone!==expected.timeZone||value.readOnly!==true)fail(label);}

function validateContract(contract,manifest,contractRaw,batchFiles){
 shape(contract,'format status installable captureReady sourceFrameVersion compilerArtifactSHA256 compilerChecksum compiledSourceSHA256 sourceContractSHA256 closureSHA256 catalog1FileSHA256 frameEvidenceSHA256 contextPrerequisiteIds requiredPostgres requiredServerVersionNum pgcrypto variant sessionUser entryFrameId roleEntryPrecondition maxRows maxBytes executionFrames phases rules reusedEvidence sourcePins','contract');
 if(contract.format!=='ordered-current-complete-capture-contract-v2'||contract.status!=='REFERENCE-CAPTURE-ONLY'||contract.installable!==false||contract.captureReady!==true||contract.sourceFrameVersion!==2||contract.requiredServerVersionNum!=='180003'||contract.pgcrypto!=='1.4'||!['A','B'].includes(contract.variant)||contract.sessionUser!==(contract.variant==='A'?'zasp_test':'zasp_e2e')||typeof contract.requiredPostgres!=='string'||!contract.requiredPostgres)fail('contract boundary');
 if(contract.maxRows!==captureMaxRows||contract.maxBytes!==captureMaxBytes)fail('contract ceiling');
 for(const key of ['compilerArtifactSHA256','compilerChecksum','compiledSourceSHA256','sourceContractSHA256','closureSHA256','catalog1FileSHA256','frameEvidenceSHA256'])if(!hex(contract[key]))fail('contract provenance');
 if(!same(contract.contextPrerequisiteIds,contextPrerequisiteIds))fail('context prerequisites');
 shape(contract.roleEntryPrecondition,'sessionUser superuser','role entry precondition');if(contract.roleEntryPrecondition.sessionUser!==contract.sessionUser||contract.roleEntryPrecondition.superuser!==true)fail('role entry precondition');
 if(contract.entryFrameId!=='collectorDiscoveryCatalog'||!same(sorted(Object.keys(contract.executionFrames)),frameIds))fail('frame coverage');
 const expectedFrames={collectorDiscoveryCatalog:['zasp_discovery_authority','pg_catalog','collector',null],sourceDiscoveryPublic:['zasp_discovery_authority','pg_catalog, public','source-proof','hex'],sourceInventoryPublic:['zasp_inventory_authority','pg_catalog, public','source-proof','hex']};
 for(const id of frameIds){const frame=contract.executionFrames[id],expected=expectedFrames[id];shape(frame,'role searchPath timeZone derivation sourceFrameProofSHA256','execution frame');if(frame.role!==expected[0]||frame.searchPath!==expected[1]||frame.timeZone!=='UTC'||frame.derivation!==expected[2]||(expected[3]===null?frame.sourceFrameProofSHA256!==null:!hex(frame.sourceFrameProofSHA256)||frame.sourceFrameProofSHA256!==contract.frameEvidenceSHA256))fail('execution frame '+id);}
 shape(manifest,'format source files','manifest');if(manifest.format!==2||typeof manifest.source!=='string'||!manifest.source)fail('manifest');pins(manifest.files);pins(contract.sourcePins);evidence(contract.reusedEvidence);
 if(manifest.files['services/platform/migrations/ordered_current/consolidated-capture-contract-v2.json']!==sha(contractRaw))fail('manifest contract binding');
 for(const [path,digest] of Object.entries(contract.sourcePins))if(manifest.files[path]!==digest)fail('manifest source binding');
 if(!object(batchFiles))fail('batch files');
 const assigned=new Set(),referencedFrames=new Set(),batchByRule=new Map(),batchPaths=[];
 if(!Array.isArray(contract.phases)||contract.phases.length!==5||!object(contract.rules)||!Object.keys(contract.rules).length)fail('phase coverage');
 contract.phases.forEach((phase,index)=>{
  shape(phase,'id batches','phase contract');if(phase.id!==phases[index]||!Array.isArray(phase.batches)||!phase.batches.length)fail('phase contract');
  const seenFrames=new Set();
  for(const batch of phase.batches){
   shape(batch,'id executionFrameId file sqlSHA256 ruleIds','batch contract');if(batch.id!==`${phase.id}:${batch.executionFrameId}`||!frameIds.includes(batch.executionFrameId)||seenFrames.has(batch.executionFrameId)||!hex(batch.sqlSHA256)||!Array.isArray(batch.ruleIds)||!batch.ruleIds.length)fail('batch contract');seenFrames.add(batch.executionFrameId);referencedFrames.add(batch.executionFrameId);
   const expectedFile=`services/platform/migrations/ordered_current/consolidated-capture-${phase.id}-${kebab(batch.executionFrameId)}.sql`;if(batch.file!==expectedFile)fail('batch file');
   const raw=batchFiles[batch.file];if(!Buffer.isBuffer(raw)||sha(raw)!==batch.sqlSHA256||manifest.files[batch.file]!==batch.sqlSHA256)fail('batch file binding');batchPaths.push(batch.file);
   for(const id of batch.ruleIds){if(typeof id!=='string'||assigned.has(id)||!Object.hasOwn(contract.rules,id)||contract.rules[id].phase!==phase.id||contract.rules[id].executionFrameId!==batch.executionFrameId)fail('batch rule coverage');assigned.add(id);batchByRule.set(id,batch.id);}
  }
 });
 if(assigned.size!==Object.keys(contract.rules).length||referencedFrames.size!==3||!same(sorted(Object.keys(batchFiles)),sorted(batchPaths)))fail('rule or frame coverage');
 for(const [id,rule] of Object.entries(contract.rules)){
  shape(rule,'kind section phase executionFrameId fields fieldTypes sourceMaxRows refusalMaxRows bag rosterRuleId demandRuleId','rule');
  if(typeof rule.kind!=='string'||!['demand','roster',...sections].includes(rule.section)||!phases.includes(rule.phase)||!frameIds.includes(rule.executionFrameId)||!Array.isArray(rule.fields)||rule.fields.some(field=>typeof field!=='string')||new Set(rule.fields).size!==rule.fields.length||!object(rule.fieldTypes)||!same(sorted(rule.fields),sorted(Object.keys(rule.fieldTypes)))||typeof rule.bag!=='boolean'||!(rule.sourceMaxRows===null||integer(rule.sourceMaxRows))||!integer(rule.refusalMaxRows)||rule.refusalMaxRows===0||rule.refusalMaxRows>contract.maxRows)fail('rule shape '+id);
  for(const type of Object.values(rule.fieldTypes))if(typeof type!=='string'||!/^(?:text|boolean|integer|number|json|text\[\])\??$/.test(type))fail('rule type');
  if(rule.section==='roster'&&(rule.phase!=='keys'||rule.executionFrameId!=='collectorDiscoveryCatalog'||rule.fields.length||rule.bag||rule.rosterRuleId!==null))fail('roster rule');
  if(rule.section==='demand'&&(rule.phase!=='demand'||rule.executionFrameId==='collectorDiscoveryCatalog'||rule.fields.length||rule.bag||rule.rosterRuleId!==null||rule.demandRuleId!==null))fail('demand rule');
  if(rule.section==='roster'&&(typeof rule.demandRuleId!=='string'||contract.rules[rule.demandRuleId]?.section!=='demand')||rule.section!=='roster'&&rule.demandRuleId!==null)fail('demand linkage');
  if(rule.rosterRuleId!==null&&(!Object.hasOwn(contract.rules,rule.rosterRuleId)||contract.rules[rule.rosterRuleId].section!=='roster'||rule.phase!=='original'||rule.bag))fail('roster binding');
  if(rule.section==='witnesses'&&rule.phase!=='witness'||rule.section==='resolutions'&&rule.phase!=='resolution')fail('rule section phase');
 }
 for(const [id,rule] of Object.entries(contract.rules))if(rule.section==='demand'){const roster=Object.values(contract.rules).find(candidate=>candidate.demandRuleId===id);if(!roster||roster.executionFrameId!=='collectorDiscoveryCatalog')fail('demand consumer');const original=Object.values(contract.rules).find(candidate=>candidate.rosterRuleId&&candidate.rosterRuleId===Object.keys(contract.rules).find(key=>contract.rules[key]===roster));if(!original||original.executionFrameId!==rule.executionFrameId)fail('demand frame binding');}
 return {batchByRule};
}

export function readOrderedConsolidatedReferenceEnvelopeV2(raw,{contractRaw,manifestRaw,batchFiles}){
 if(!Buffer.isBuffer(raw)||raw.length>captureMaxBytes||raw.at(-1)!==10||raw.at(-2)!==125)fail('publisher byte framing');
 const contract=parse(contractRaw),manifest=parse(manifestRaw),validated=validateContract(contract,manifest,contractRaw,batchFiles),envelope=parse(raw,true);
 shape(envelope,'format status installable sourceFrameVersion packetManifestSHA256 contractSHA256 closureSHA256 compilerArtifactSHA256 compilerChecksum compiledSourceSHA256 sourceContractSHA256 catalog1FileSHA256 frameEvidenceSHA256 contextPrerequisiteIds sourcePins variant sessionUser entryFrame postgres serverVersionNum pgcrypto readOnly preAdmission postAdmission rolledBack frameRestored phases counts rawInputs normalizationObservations resolutions witnesses reusedEvidence','envelope');
 const bound={format:'ordered-current-complete-reference-v2',status:'REFERENCE-CAPTURE-ONLY',installable:false,sourceFrameVersion:2,packetManifestSHA256:sha(manifestRaw),contractSHA256:sha(contractRaw),closureSHA256:contract.closureSHA256,compilerArtifactSHA256:contract.compilerArtifactSHA256,compilerChecksum:contract.compilerChecksum,compiledSourceSHA256:contract.compiledSourceSHA256,sourceContractSHA256:contract.sourceContractSHA256,catalog1FileSHA256:contract.catalog1FileSHA256,frameEvidenceSHA256:contract.frameEvidenceSHA256,contextPrerequisiteIds:contract.contextPrerequisiteIds,sourcePins:contract.sourcePins,postgres:contract.requiredPostgres,serverVersionNum:contract.requiredServerVersionNum,pgcrypto:contract.pgcrypto,readOnly:true,preAdmission:true,postAdmission:true,rolledBack:true,frameRestored:true,reusedEvidence:contract.reusedEvidence};
 for(const [key,value]of Object.entries(bound))if(!same(envelope[key],value))fail('provenance '+key);
 if(envelope.variant!==contract.variant||envelope.sessionUser!==contract.sessionUser)fail('fixture owner');
 observedFrame(envelope.entryFrame,contract.executionFrames[contract.entryFrameId],contract.sessionUser,'entry frame');
 shape(envelope.counts,'streamRows expandedRows streamBytes demandRows rosterRows ruleRows','counts');if(!object(envelope.counts.ruleRows)||!same(sorted(Object.keys(envelope.counts.ruleRows)),sorted(Object.keys(contract.rules))))fail('rule count coverage');for(const key of ['streamRows','expandedRows','streamBytes','demandRows','rosterRows'])if(!integer(envelope.counts[key]))fail('count type');if(envelope.counts.expandedRows>contract.maxRows||envelope.counts.streamBytes>contract.maxBytes)fail('global ceiling');
 const ruleCounts=Object.fromEntries(Object.keys(contract.rules).map(id=>[id,0])),phaseRows=Object.fromEntries(phases.map(id=>[id,0])),phaseExpanded=Object.fromEntries(phases.map(id=>[id,0])),batchRows=new Map(),batchExpanded=new Map();let demand=0,roster=0;
 for(const section of sections){
  if(!Array.isArray(envelope[section]))fail('section array');const seen=new Set();let previous=null;
  for(const row of envelope[section]){shape(row,'ruleId identity multiplicity fact','row');const rule=contract.rules[row.ruleId];if(!rule||rule.section!==section)fail('row section');if(typeof row.identity!=='string'||!row.identity||!integer(row.multiplicity)||row.multiplicity<1||!rule.bag&&row.multiplicity!==1)fail('row multiplicity count');const key=JSON.stringify([row.ruleId,row.identity]);if(seen.has(key))fail('duplicate fact key');seen.add(key);if(previous&&(Buffer.compare(Buffer.from(previous[0]),Buffer.from(row.ruleId))>0||previous[0]===row.ruleId&&Buffer.compare(Buffer.from(previous[1]),Buffer.from(row.identity))>=0))fail('row order');previous=[row.ruleId,row.identity];if(!object(row.fact)||!same(sorted(Object.keys(row.fact)),sorted(rule.fields)))fail('selected fields');for(const field of rule.fields)typed(row.fact[field],rule.fieldTypes[field]);ruleCounts[row.ruleId]+=row.multiplicity;phaseRows[rule.phase]++;phaseExpanded[rule.phase]+=row.multiplicity;const batch=validated.batchByRule.get(row.ruleId);batchRows.set(batch,(batchRows.get(batch)??0)+1);batchExpanded.set(batch,(batchExpanded.get(batch)??0)+row.multiplicity);}
 }
 for(const [id,rule]of Object.entries(contract.rules)){const count=envelope.counts.ruleRows[id];if(!integer(count)||count>rule.refusalMaxRows||rule.sourceMaxRows!==null&&count>rule.sourceMaxRows)fail('rule count bound');const batch=validated.batchByRule.get(id);if(rule.section==='roster'){ruleCounts[id]=count;roster+=count;phaseRows.keys+=count;phaseExpanded.keys+=count;batchRows.set(batch,(batchRows.get(batch)??0)+count);batchExpanded.set(batch,(batchExpanded.get(batch)??0)+count);}else if(rule.section==='demand'){ruleCounts[id]=count;demand+=count;phaseRows.demand+=count;phaseExpanded.demand+=count;batchRows.set(batch,(batchRows.get(batch)??0)+count);batchExpanded.set(batch,(batchExpanded.get(batch)??0)+count);}else if(ruleCounts[id]!==count)fail('rule count');if(rule.rosterRuleId!==null&&count!==envelope.counts.ruleRows[rule.rosterRuleId])fail('roster count join');if(rule.demandRuleId!==null&&count!==envelope.counts.ruleRows[rule.demandRuleId])fail('demand count join');}
 if(envelope.counts.demandRows!==demand||envelope.counts.rosterRows!==roster||envelope.counts.streamRows!==Object.values(phaseRows).reduce((sum,value)=>sum+value,0)||envelope.counts.expandedRows!==Object.values(phaseExpanded).reduce((sum,value)=>sum+value,0))fail('global counts');
 if(!Array.isArray(envelope.phases)||envelope.phases.length!==5)fail('phase observations');let bytes=0;
 envelope.phases.forEach((phase,index)=>{const expected=contract.phases[index];shape(phase,'id batches rowCount expandedRows streamBytes','phase observation');if(phase.id!==expected.id||!Array.isArray(phase.batches)||phase.batches.length!==expected.batches.length)fail('phase provenance');let rows=0,expanded=0,streamBytes=0;phase.batches.forEach((batch,batchIndex)=>{const wanted=expected.batches[batchIndex],definition=contract.executionFrames[wanted.executionFrameId];shape(batch,'id executionFrameId sqlSHA256 beforeFrame afterFrame restoredFrame rowCount expandedRows streamBytes','batch observation');for(const key of ['id','executionFrameId','sqlSHA256'])if(batch[key]!==wanted[key])fail('batch provenance');observedFrame(batch.beforeFrame,definition,contract.sessionUser,'batch before frame');observedFrame(batch.afterFrame,definition,contract.sessionUser,'batch after frame');observedFrame(batch.restoredFrame,contract.executionFrames[contract.entryFrameId],contract.sessionUser,'batch restored frame');if(batch.rowCount!==(batchRows.get(batch.id)??0)||batch.expandedRows!==(batchExpanded.get(batch.id)??0)||!integer(batch.streamBytes)||batch.rowCount===0&&batch.streamBytes!==0||batch.rowCount>0&&batch.streamBytes===0)fail('batch count');rows+=batch.rowCount;expanded+=batch.expandedRows;streamBytes+=batch.streamBytes;});if(phase.rowCount!==rows||phase.expandedRows!==expanded||phase.streamBytes!==streamBytes||rows!==phaseRows[phase.id]||expanded!==phaseExpanded[phase.id])fail('phase count');bytes+=streamBytes;});
 if(bytes!==envelope.counts.streamBytes)fail('stream byte count');
 return envelope;
}

export function checkOrderedConsolidatedReferenceEnvelopeV2(raw,inputs){readOrderedConsolidatedReferenceEnvelopeV2(raw,inputs);}

export function admitOrderedConsolidatedReferenceV2(){throw Error('complete reference v2 admission closed; no accepted file pin');}
