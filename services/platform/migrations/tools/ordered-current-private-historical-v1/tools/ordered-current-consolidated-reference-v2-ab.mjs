// Offline application-fact comparison for the two fixed frame-v2 captures.
// This is evidence admission, not an install or runtime consumer.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {NumericLexeme,readOrderedConsolidatedReferenceEnvelopeV2} from './ordered-current-consolidated-reference-v2.mjs';

const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const fail=message=>{throw Error(`A/B fact equivalence ${message}`);};
const capturePins={A:'87b56d3510860ea97fc0fd3459a8f4d2e736e114026ddc397648721a0010fd73',B:'070c505dc48c14b9f98e2d54265bcca99e2e4d041153495ee532d0e431c9829e'};
const packetPins={A:{manifest:'87c197bb01b0e816035a7d976760348e6c86424175e43cb9b4d985a24b551a62',contract:'dc98ace441d12eccfe5a3ddc77747ec89e31835be65261015d81e9caf13cd716'},B:{manifest:'0f72335919caca1c9d1a05aa639a666bff71d2f02cc253ecb7d799856fd35617',contract:'4ed2d9c7795ac16c4f485d1e891b34cf7364f9cdb4f90647d2b58dafbeb894db'}};
const coveragePin='67e214f69821c113b58078b5fc38e7504e33fb5748d7ad56de1fce01f85ed5c4';
const principals={A:'zasp_test',B:'zasp_e2e'};
const sections=['rawInputs','normalizationObservations','resolutions','witnesses'];
const canonical=value=>Array.isArray(value)?value.map(canonical):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort((a,b)=>Buffer.compare(Buffer.from(a),Buffer.from(b))).map(key=>[key,canonical(value[key])])):value;
const encoded=value=>JSON.stringify(canonical(value),(_,item)=>item instanceof NumericLexeme?{$numericLexeme:item.token}:item);
const equal=(left,right)=>encoded(left)===encoded(right);

const definitions=[
 ['rawInputs','authorization80:data-controls-policy',{roles:'policyRoles',using:'policyExpr',check:'policyExpr'}],
 ['rawInputs','authorization80:data-controls-relation',{owner:'exact',acl:'acl'}],
 ['rawInputs','authorization80:function',{owner:'exact',acl:'acl'}],
 ['rawInputs','authorization80:hierarchy-column',{acl:'acl'}],
 ['rawInputs','authorization80:hierarchy-relation',{owner:'exact',acl:'acl'}],
 ['rawInputs','authorization80:hierarchy-trigger',{arguments:'hex',definition:'triggerSQL'}],
 ['rawInputs','authorization80:risk-relation',{owner:'exact',acl:'acl'}],
 ['rawInputs','materialized:sa-multistep-prior:function',{raw_owner:'exact',raw_acl:'acl'}],
 ['rawInputs','prior:compliance:function',{owner:'exact',raw_acl:'acl'}],
 ['rawInputs','prior:compliance:normalization-relation',{owner:'exact',raw_acl:'acl'}],
 ['rawInputs','prior:compliance:routine-acl',{owner:'exact',grantor:'exact',grantee:'exact'}],
 ['rawInputs','prior:run-context:function',{owner:'exact',raw_acl:'acl'}],
 ['rawInputs','prior:run-context:normalization-relation',{owner:'exact',raw_acl:'acl'}],
 ['rawInputs','prior:run-context:routine-acl',{owner:'exact',grantor:'exact',grantee:'exact'}],
 ['rawInputs','public:inventory:function',{owner:'exact',acl_raw:'acl','acl_grants[*][0]':'atom','acl_grants[*][3]':'atom'}],
 ['rawInputs','public:inventory:function:core-owner',{owner:'exact'}],
 ['rawInputs','ready78:saved-current:bindings',{owner:'exact',acl:'acl'}],
 ['rawInputs','ready78:saved-current:routines',{owner:'exact',acl_raw:'acl'}],
 ['rawInputs','saved-input:zasp_sa_export_prior.functions',{owner_name:'exact',acl:'acl'}],
 ['rawInputs','saved-input:zasp_temporal72.predecessor_functions',{owner_name:'exact',acl:'acl'}],
 ['rawInputs','wrapper:audit-source-acl',{'before_state.owner':'atom','before_state.grants[*].grantor':'atom','before_state.grants[*].grantee':'atom','after_state.owner':'atom','after_state.grants[*].grantor':'atom','after_state.grants[*].grantee':'atom','workflow_state.owner':'atom','workflow_state.grants[*].grantor':'atom','workflow_state.grants[*].grantee':'atom'}],
 ['rawInputs','wrapper:audit-source:relation',{owner:'exact',raw_acl:'acl'}],
 ['rawInputs','wrapper:audit-source:relation-acl',{owner:'exact',grantor:'exact',grantee:'exact'}],
 ['rawInputs','wrapper:audit-workflow:relation',{owner:'exact',raw_acl:'acl'}],
 ['rawInputs','wrapper:audit-workflow:relation-acl',{owner:'exact',grantor:'exact',grantee:'exact'}],
 ['rawInputs','wrapper:migration-helper:relations',{owner:'exact'}],
 ['rawInputs','wrapper:migration-helper:routine-acl',{owner:'exact',grantor:'exact',grantee:'exact'}],
 ['rawInputs','wrapper:migration-helper:routines',{owner:'exact',raw_acl:'acl'}],
 ['rawInputs','wrapper:scope-authority:relation',{owner:'exact'}],
 ['rawInputs','wrapper:scope-authority:routine-acl',{owner:'exact',grantor:'exact',grantee:'exact'}],
 ['rawInputs','wrapper:scope-authority:routines',{owner:'exact',raw_acl:'acl'}],
 ['normalizationObservations','wrapper:audit-source:expected',{'normalized_acl.owner':'atom','normalized_acl.grants[*].grantor':'atom','normalized_acl.grants[*].grantee':'atom'}],
 ['normalizationObservations','wrapper:audit-source:snapshot',{'normalized_acl.owner':'atom','normalized_acl.grants[*].grantor':'atom','normalized_acl.grants[*].grantee':'atom'}],
 ['normalizationObservations','wrapper:audit-workflow:snapshot',{'normalized_acl.owner':'atom','normalized_acl.grants[*].grantor':'atom','normalized_acl.grants[*].grantee':'atom'}],
 ['witnesses','prior:audit:metadata',{value:'token'}],
 ['witnesses','prior:audit:metadata-principal-login',{principal_name:'exact'}],
 ['witnesses','prior:audit:metadata-principals',{principal_name:'exact'}],
 ['witnesses','recursive:schema-metadata:normalization-input',{value:'token'}],
];
const allowances=new Map(definitions.map(([section,ruleId,paths])=>[`${section}\0${ruleId}`,paths]));
const factDerived=new Set(definitions.filter(([,id])=>['prior:compliance:routine-acl','prior:run-context:routine-acl','ready78:saved-current:bindings','saved-input:zasp_sa_export_prior.functions','saved-input:zasp_temporal72.predecessor_functions','wrapper:audit-source-acl','wrapper:audit-source:relation-acl','wrapper:audit-workflow:relation-acl','wrapper:migration-helper:routine-acl','wrapper:scope-authority:routine-acl','wrapper:audit-source:expected','wrapper:audit-source:snapshot','wrapper:audit-workflow:snapshot','prior:audit:metadata','prior:audit:metadata-principal-login','prior:audit:metadata-principals','recursive:schema-metadata:normalization-input'].includes(id)).map(([,id])=>id));
const physicalIdentity=new Set(['materialized:sa-multistep-prior:foreign-key-trigger','public:sa_multistep:foreign-key-trigger','temporal:75.fingerprint:foreign-key-trigger','temporal:78.predecessor73_fingerprint:foreign-key-trigger','temporal:78.predecessor76_fingerprint:foreign-key-trigger','temporal:78.predecessor77_fingerprint:foreign-key-trigger','worker:projected68:foreign-key-trigger','worker:projected69:foreign-key-trigger','worker:projected72:foreign-key-trigger','worker:projected78:foreign-key-trigger','worker:projected_domain:foreign-key-trigger']);

function packet(root,variant){
 const contractPath=path.join(root,'services/platform/migrations/ordered_current/consolidated-capture-contract-v2.json'),manifestPath=path.join(root,'snapshot-manifest.json'),coveragePath=path.join(root,'services/platform/migrations/ordered_current/consolidated-capture-coverage-v2.json');
 const contractRaw=fs.readFileSync(contractPath),manifestRaw=fs.readFileSync(manifestPath),coverageRaw=fs.readFileSync(coveragePath);
 if(sha(contractRaw)!==packetPins[variant].contract||sha(manifestRaw)!==packetPins[variant].manifest||sha(coverageRaw)!==coveragePin)fail(`fixed ${variant} packet`);
 const contract=JSON.parse(contractRaw),batchFiles=Object.fromEntries(contract.phases.flatMap(phase=>phase.batches).map(batch=>[batch.file,fs.readFileSync(path.join(root,batch.file))]));
 return {contractRaw,manifestRaw,batchFiles,contract,coverage:JSON.parse(coverageRaw)};
}

function sourceBindings(coverage,contract){
 if(definitions.length!==38)fail('allowance count');
 for(const [section,ruleId,paths] of definitions){
  const source=coverage.rawRules.find(rule=>rule.id===ruleId)??coverage.liveWitnesses?.find(rule=>rule.id===ruleId)??coverage.entries.find(rule=>rule.id===ruleId);
  const rule=contract.rules[ruleId];if(!source||!rule||rule.section!==section||source.sourceSite?.siteSHA256===undefined)fail(`source binding ${ruleId}`);
  for(const [field,mode] of Object.entries(paths)){const top=field.split(/[.[]/)[0],index=source.fields.indexOf(top),projection=source.projections?.[index]??'';if(index<0||!Object.hasOwn(rule.fieldTypes,top))fail(`source field ${ruleId}/${field}`);if(mode==='acl'&&!/(acl|proacl|relacl|array_to_string)/i.test(projection)&&!/(acl|grant)/i.test(top))fail(`ACL source ${ruleId}/${field}`);if(mode==='hex'&&!/encode\([^)]*tgargs[^)]*,'hex'\)/.test(projection))fail(`trigger argument source ${ruleId}/${field}`);if(mode==='triggerSQL'&&!/pg_get_triggerdef/.test(projection))fail(`trigger definition source ${ruleId}/${field}`);if(mode.startsWith('policy')&&!/(polroles|pg_get_expr)/.test(projection))fail(`policy source ${ruleId}/${field}`);}
 }
 for(const id of physicalIdentity){const source=coverage.rawRules.find(rule=>rule.id===id),rule=contract.rules[id],nameIndex=source?.fields.indexOf('name')??-1;if(!source||source.kind!=='foreign_key_trigger'||rule.bag||nameIndex<0||!/conname/.test(source.projections[nameIndex])||source.projections.some(value=>/tgname/.test(value)))fail(`physical identity source ${id}`);}
}

const escape=value=>value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
function principal(value,mode,from){
 if(value===null)return value;if(typeof value!=='string')fail('principal syntax type');const marker='$FIXTURE_PRINCIPAL';
 if(mode==='hex'){if(!/^(?:[0-9a-f]{2})*$/.test(value))fail('trigger argument bytes');const raw=Buffer.from(value,'hex'),wanted=Buffer.from(from),replacement=Buffer.from(marker),parts=[];let start=0,changed=false;for(let index=0;index<=raw.length;index++)if(index===raw.length||raw[index]===0){const item=raw.subarray(start,index);parts.push(item.equals(wanted)?(changed=true,replacement):item);if(index<raw.length)parts.push(Buffer.from([0]));start=index+1;}return changed?Buffer.concat(parts).toString('hex'):value;}
 if(!value.includes(from))return value;
 if(mode==='acl'&&/^\s*(?:\[|\{")/.test(value)){try{JSON.parse(value);}catch{fail('principal syntax JSON ACL');}const pattern=new RegExp(`("(?:owner|grantor|grantee)"\\s*:\\s*")${escape(from)}(")`,'g'),mapped=value.replace(pattern,`$1${marker}$2`);if(mapped.includes(from)||mapped===value)fail('principal syntax JSON ACL token');return mapped;}
 if(mode==='exact'||mode==='atom'){if(value!==from)fail('principal syntax exact');return marker;}
 if(mode==='policyRoles'){const pattern=new RegExp(`(^|[{,])${escape(from)}(?=[,}])`,'g'),mapped=value.replace(pattern,(match,prefix)=>prefix+marker);if(!/^\{[A-Za-z0-9_$,-]+\}$/.test(mapped)||mapped.includes(from)||mapped===value)fail('policy role syntax');return mapped;}
 if(mode==='policyExpr'){const expected=`(CURRENT_USER = '${from}'::name)`;if(value!==expected)fail('policy role syntax');return `(CURRENT_USER = '${marker}'::name)`;}
 if(mode==='triggerSQL'){const relation='(?:zasp_authorized_scopes|zasp_core_payloads|zasp_environments|zasp_workspaces)',expected=new RegExp(`^CREATE TRIGGER zasp_authorization80_hierarchy_write_guard BEFORE INSERT OR DELETE OR UPDATE OR TRUNCATE ON public\\.${relation} FOR EACH STATEMENT EXECUTE FUNCTION zasp_authorization80\\.hierarchy_write_guard\\('${escape(from)}'\\)$`);if(!expected.test(value))fail('trigger SQL role syntax');return value.replace(`'${from}'`,`'${marker}'`);}
 let pattern;if(mode==='acl')pattern=new RegExp(`(^|[,{/])${escape(from)}(?==|[,}])`,'g');else pattern=new RegExp(`(^|[^A-Za-z0-9_])${escape(from)}(?=$|[^A-Za-z0-9_])`,'g');
 const mapped=value.replace(pattern,(match,prefix)=>prefix+marker);if(mapped.includes(from)||mapped===value)fail('principal syntax embedded');return mapped;
}
function parts(pattern){return pattern.replace(/\[(\*|\d+)\]/g,'.$1').split('.');}
function normalizePath(value,tokens,mode,from,stats){if(!tokens.length){const mapped=principal(value,mode,from);if(!equal(value,mapped))stats.count++;return mapped;}const [head,...tail]=tokens;if(head==='*'){if(!Array.isArray(value))fail('principal syntax array');return value.map(item=>normalizePath(item,tail,mode,from,stats));}if(value===null||typeof value!=='object'||!Object.hasOwn(value,head))fail('principal syntax path');const out=Array.isArray(value)?value.slice():{...value};out[head]=normalizePath(value[head],tail,mode,from,stats);return out;}
function normalizedFact(row,section,variant,stats){let fact=row.fact,paths=allowances.get(`${section}\0${row.ruleId}`);if(!paths)return fact;fact=structuredClone(fact);for(const [field,mode] of Object.entries(paths)){const before=stats.count;try{fact=normalizePath(fact,parts(field),mode,principals[variant],stats);}catch(error){fail(`${error.message}; ${row.ruleId}/${field}`);}if(stats.count!==before)stats.rules[row.ruleId]=(stats.rules[row.ruleId]??0)+stats.count-before;}return fact;}
function rowsByRule(envelope,section){const out=new Map();for(const row of envelope[section]){if(!out.has(row.ruleId))out.set(row.ruleId,[]);out.get(row.ruleId).push(row);}return out;}
function multiset(rows,section,variant,ignoreIdentity,stats){return rows.map(row=>encoded({...(ignoreIdentity?{}:{identity:row.identity}),multiplicity:row.multiplicity,fact:normalizedFact(row,section,variant,stats)})).sort();}

function compareFrames(a,b){if(a?.sessionUser!==principals.A||b?.sessionUser!==principals.B)fail('frame session user');const clean=value=>{const copy=structuredClone(value);copy.sessionUser='$FIXTURE_PRINCIPAL';return copy;};return equal(clean(a),clean(b));}
function compareEnvelopeBoundary(a,b){
 const skip=new Set(['packetManifestSHA256','contractSHA256','sourcePins','variant','sessionUser','entryFrame','phases','counts','rawInputs','normalizationObservations','resolutions','witnesses']);
 if(!equal(Object.keys(a).sort(),Object.keys(b).sort()))fail('envelope fields');for(const key of Object.keys(a))if(!skip.has(key)&&!equal(a[key],b[key]))fail(`envelope ${key}`);
 if(a.variant!=='A'||b.variant!=='B'||a.sessionUser!==principals.A||b.sessionUser!==principals.B)fail('fixture variants');
 if(!compareFrames(a.entryFrame,b.entryFrame))fail('entry frame');
 const aCounts={...a.counts,streamBytes:0},bCounts={...b.counts,streamBytes:0};if(!equal(aCounts,bCounts))fail('counts');
 if(a.phases.length!==b.phases.length)fail('phase count');for(let index=0;index<a.phases.length;index++){const ap=structuredClone(a.phases[index]),bp=structuredClone(b.phases[index]);if(!['original','witness'].includes(ap.id)&&ap.streamBytes!==bp.streamBytes)fail('phase stream bytes');ap.streamBytes=bp.streamBytes=0;if(ap.batches.length!==bp.batches.length)fail('batch count');for(let batch=0;batch<ap.batches.length;batch++){for(const frame of ['beforeFrame','afterFrame','restoredFrame']){if(!compareFrames(ap.batches[batch][frame],bp.batches[batch][frame]))fail('batch frame');ap.batches[batch][frame].sessionUser=bp.batches[batch][frame].sessionUser='$FIXTURE_PRINCIPAL';}if(!['original','witness'].includes(ap.id)&&ap.batches[batch].streamBytes!==bp.batches[batch].streamBytes)fail('batch stream bytes');ap.batches[batch].streamBytes=bp.batches[batch].streamBytes=0;}if(!equal(ap,bp))fail(`phase ${ap.id}`);}
}

export function compareAdmittedOrderedConsolidatedReferencePairV2({a,b}){
 compareEnvelopeBoundary(a,b);const aStats={count:0,rules:{}},bStats={count:0,rules:{}};
 for(const section of sections){const ar=rowsByRule(a,section),br=rowsByRule(b,section),ids=new Set([...ar.keys(),...br.keys()]);for(const id of ids){const left=ar.get(id)??[],right=br.get(id)??[];if(id==='recursive:authorization80:registration'){let aIdentity,bIdentity;try{aIdentity=JSON.parse(left[0]?.identity);bIdentity=JSON.parse(right[0]?.identity);}catch{fail('registration identity');}if(left.length!==1||right.length!==1||left[0].multiplicity!==right[0].multiplicity||!equal(aIdentity,left[0].fact)||!equal(bIdentity,right[0].fact)||left[0].fact.checksum!==right[0].fact.checksum)fail('registration checksum');continue;}const ignore=factDerived.has(id)||physicalIdentity.has(id),l=multiset(left,section,'A',ignore,aStats),r=multiset(right,section,'B',ignore,bStats);if(!equal(l,r))fail(physicalIdentity.has(id)?`physical identity fact multiset ${id}`:`row ${section}/${id}`);}}
 if(aStats.count!==350||bStats.count!==350)fail(`principal leaf coverage ${aStats.count}/${bStats.count}`);return {status:'APPLICATION-FACT-EQUIVALENT',rules:1862,physicalRows:39090,expandedRows:52764,principalLeaves:aStats.count,physicalIdentityRows:408,conditionalDerivedFields:1};
}

export function readAdmittedOrderedConsolidatedReferenceObservationV2(raw,packetInputs){return readOrderedConsolidatedReferenceEnvelopeV2(raw,packetInputs);}

export function readFixedOrderedConsolidatedReferencePairV2({aRaw,bRaw,aPacketRoot,bPacketRoot}){
 if(!Buffer.isBuffer(aRaw)||sha(aRaw)!==capturePins.A)fail('fixed A capture');if(!Buffer.isBuffer(bRaw)||sha(bRaw)!==capturePins.B)fail('fixed B capture');
 const aPacket=packet(aPacketRoot,'A'),bPacket=packet(bPacketRoot,'B');sourceBindings(aPacket.coverage,aPacket.contract);sourceBindings(bPacket.coverage,bPacket.contract);
 const a=readAdmittedOrderedConsolidatedReferenceObservationV2(aRaw,aPacket),b=readAdmittedOrderedConsolidatedReferenceObservationV2(bRaw,bPacket),comparison=compareAdmittedOrderedConsolidatedReferencePairV2({a,b});
 return {a,b,comparison,allowanceMetadata:{definitions:definitions.length,factDerivedRules:factDerived.size,physicalIdentityRules:physicalIdentity.size}};
}

export function admitFixedOrderedConsolidatedReferencePairV2(input){return readFixedOrderedConsolidatedReferencePairV2(input).comparison;}
