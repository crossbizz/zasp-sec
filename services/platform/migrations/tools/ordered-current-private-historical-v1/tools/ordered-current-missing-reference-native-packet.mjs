import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {buildOrderedCurrentMissingReferenceContractV1} from './ordered-current-missing-reference-contract-v1.mjs';

const fail=message=>{throw Error(`ordered-current missing reference native packet ${message}`);};
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const freeze=value=>{if(value&&typeof value==='object'&&!Object.isFrozen(value)){for(const child of Object.values(value))freeze(child);Object.freeze(value);}return value;};
const contractModuleSHA256='2a304799618b0ca70b18df1f63f04c7bc450aab83b0bfcc19b779aead5b3af90';
const contractSHA256='262728237a748a512b98e499a9b0335c13cabcf39a372fd3eaf65261e8f1449d';
const limits=freeze({maxRules:12,maxRows:204,maxBytes:16777216,outerSeconds:300,sqlSeconds:10,lockSeconds:3,cleanupSeconds:3});

function exactInput(input){return input&&typeof input==='object'&&JSON.stringify(Object.keys(input).sort())===JSON.stringify(['catalogRaw','compiledReleaseRaw','sourceContractRaw'])&&Object.values(input).every(Buffer.isBuffer);}
function verifyContractModule(){if(sha(fs.readFileSync(new URL('./ordered-current-missing-reference-contract-v1.mjs',import.meta.url)))!==contractModuleSHA256)fail('contract module identity');}
const sqlIdentity=sql=>({sql,sqlSHA256:sha(sql)});
const frameName=rule=>rule.projectionFrame.owner==='zasp_inventory_authority'?'sourceInventoryPublic':'sourceDiscoveryPublic';

function baselineRule(rule){
 const [projectionIdentities,rosterIdentities,comparison]=rule.membershipProgram.steps;
 const observationSQL=`SELECT pg_catalog.jsonb_build_object('identity',capture_identity,'fields',to_jsonb(projected)-'capture_identity') FROM (${rule.projectionSQL}) projected ORDER BY capture_identity`;
 const stages=[
  {id:'capture-projection',action:'query-jsonb-rows',frame:'projectionFrame',...sqlIdentity(observationSQL)},
  {...projectionIdentities,sqlSHA256:sha(projectionIdentities.sql)},
  {...rosterIdentities,sqlSHA256:sha(rosterIdentities.sql)},
  {...comparison,sqlSHA256:sha(comparison.sql)},
 ];
 return freeze({id:rule.id,kind:rule.kind,exactRows:rule.exactRows,fields:rule.fields,fieldTypes:rule.fieldTypes,projectionFrame:{owner:rule.projectionFrame.owner,searchPath:rule.projectionFrame.searchPath},canonicalRosterFrame:rule.canonicalRosterFrame,sourceSitesSHA256:sha(JSON.stringify(rule.sourceSites)),ruleSHA256:sha(JSON.stringify(rule)),sqlIdentities:stages.map(stage=>stage.sqlSHA256),stages});
}

function probe(id,frame,setup,sql,expected){return freeze({id,transaction:'separate-read-write-rollback',frame,stages:[{id:'capture-pre-state',action:'capture-exact-session-and-selected-object-state'},{id:'mutate',action:'execute-fixed-sql',...sqlIdentity(setup)},{id:'probe',action:'execute-fixed-query',...sqlIdentity(sql),expected},{id:'rollback',action:'rollback-transaction-bounded'},{id:'verify-restoration',action:'compare-exact-pre-state'}],cleanup:'rollback-and-verify-exact-state'});}

const temporalTarget='public.zasp_execution_claim_jobs(text,text,integer,integer)';
const temporalSavedSignature='zasp_execution_claim_jobs(text,text,integer,integer)';
const temporalExpression=String.raw`SELECT regexp_replace(btrim(CASE WHEN p.oid='${temporalTarget}'::regprocedure THEN (SELECT split_part(definition,chr(36)||'function'||chr(36),2) FROM zasp_temporal72.predecessor_functions WHERE signature='${temporalSavedSignature}') ELSE p.prosrc END),E'\s+',' ','g') FROM pg_catalog.pg_proc p WHERE p.oid='${temporalTarget}'::regprocedure`;
const precisionTarget='public.zasp_production_runtime_precision_live_fingerprint()';
const precisionSavedSignature='zasp_production_runtime_precision_live_fingerprint()';
const precisionExpression=`SELECT CASE WHEN p.oid='${precisionTarget}'::regprocedure THEN (SELECT definition FROM zasp_temporal72.predecessor_functions WHERE signature='${precisionSavedSignature}') ELSE pg_get_functiondef(p.oid) END FROM pg_catalog.pg_proc p WHERE p.oid='${precisionTarget}'::regprocedure`;
const unselectedInsert="ALTER TABLE zasp_temporal72.predecessor_functions DROP CONSTRAINT predecessor_functions_pkey; INSERT INTO zasp_temporal72.predecessor_functions(signature,definition,owner_name,acl) VALUES ('zasp_missing_reference_unselected()','SELECT 1','zasp_discovery_authority','{}'),('zasp_missing_reference_unselected()','SELECT 2','zasp_discovery_authority','{}')";
const duplicateTemporal=`ALTER TABLE zasp_temporal72.predecessor_functions DROP CONSTRAINT predecessor_functions_pkey; INSERT INTO zasp_temporal72.predecessor_functions(signature,definition,owner_name,acl) SELECT signature,definition,owner_name,acl FROM zasp_temporal72.predecessor_functions WHERE signature='${temporalSavedSignature}'`;
const duplicatePrecision=`ALTER TABLE zasp_temporal72.predecessor_functions DROP CONSTRAINT predecessor_functions_pkey; INSERT INTO zasp_temporal72.predecessor_functions(signature,definition,owner_name,acl) SELECT signature,definition,owner_name,acl FROM zasp_temporal72.predecessor_functions WHERE signature='${precisionSavedSignature}'`;
const deleteSaved=signature=>`ALTER TABLE zasp_temporal72.predecessor_functions DISABLE TRIGGER immutable; DELETE FROM zasp_temporal72.predecessor_functions WHERE signature='${signature}'; ALTER TABLE zasp_temporal72.predecessor_functions ENABLE TRIGGER immutable`;

function baselineWitness(id,sql,frame='sourceDiscoveryPublic',expected='capture-boolean-or-null',ruleId){return freeze({id,...(ruleId?{ruleId}:{}),frame,...sqlIdentity(sql),expected});}
function witnessProgram(contract,rules){
 const witness=new Map(contract.witnesses.map(item=>[item.id,item])),rule=new Map(rules.map(item=>[item.id,item]));
 const exactWitness=id=>{const item=witness.get(id);if(!item?.sql)fail(`witness SQL ${id}`);return baselineWitness(id,item.sql);};
 const config=id=>{
  const item=rule.get(id),procAlias=id.startsWith('temporal72:')?'p':'procedure';
  const identityExpression=id.startsWith('temporal72:')?"p.proname||'('||pg_get_function_identity_arguments(p.oid)||')'":"procedure.proname||'('||pg_get_function_identity_arguments(procedure.oid)||')'";
  const sql=`WITH selected AS MATERIALIZED (${item.projectionSQL}) SELECT pg_catalog.jsonb_build_object('identity',selected.capture_identity,'raw',${procAlias}.proconfig::text,'is_null',${procAlias}.proconfig IS NULL,'dimensions',pg_catalog.array_ndims(${procAlias}.proconfig),'lower',pg_catalog.array_lower(${procAlias}.proconfig,1),'upper',pg_catalog.array_upper(${procAlias}.proconfig,1),'projected',selected.execution_config_text) FROM selected JOIN pg_catalog.pg_proc ${procAlias} ON selected.capture_identity=${identityExpression} JOIN pg_catalog.pg_namespace config_namespace ON config_namespace.oid=${procAlias}.pronamespace AND config_namespace.nspname='public' ORDER BY selected.capture_identity`;
  return baselineWitness(`${id}:raw-config-array`,sql,frameName(item),'capture-jsonb-rows',id);
 };
 const managed=id=>{const item=rule.get(id),role=id.startsWith('temporal72:')?'r':'role',sql=`WITH selected AS MATERIALIZED (${item.projectionSQL}) SELECT pg_catalog.jsonb_build_object('identity',selected.capture_identity,'database',current_database(),'database_oid',(SELECT oid::text FROM pg_catalog.pg_database WHERE datname=current_database()),'shared_comment',pg_catalog.shobj_description(${role}.oid,'pg_authid'),'projected',to_jsonb(selected)) FROM selected JOIN pg_catalog.pg_roles ${role} ON ${role}.rolname=selected.name ORDER BY selected.capture_identity`;return baselineWitness(`${id}:managed-current-database`,sql,frameName(item),'capture-jsonb-rows',id);};
 const nativeMembership=witness.get('role-profile:native-roles:membership');
 const inventoryProjection=rule.get('inventory-fields:function').projectionSQL;
 const families=[
  {id:'role-profile:current-profile:aggregate',baseline:[exactWitness('role-profile:current-profile:aggregate')],probes:[]},
  {id:'role-profile:native-roles:aggregate',baseline:[exactWitness('role-profile:native-roles:aggregate')],probes:[]},
  {id:'role-profile:native-roles:membership',baseline:[exactWitness('role-profile:native-roles:membership')],probes:[probe('native-role-missing-regrole','sourceDiscoveryPublic','ALTER ROLE zasp_temporal_accounting RENAME TO zasp_missing_reference_temporal_accounting',`WITH membership AS MATERIALIZED (${nativeMembership.sql}) SELECT membership.*, 'zasp_temporal_accounting'::pg_catalog.regrole AS missing_role FROM membership`,{outcome:'error',sqlState:'42704'})]},
  {id:'routine-config-array-shape',baseline:[config('temporal72:function'),config('inventory-fields:function')],probes:[]},
  {id:'saved-scalar-case-demand',baseline:[],probes:[
   probe('temporal-lazy-unselected','sourceDiscoveryPublic',unselectedInsert,temporalExpression,{outcome:'one-non-null-row'}),
   probe('temporal-zero-row-null','sourceDiscoveryPublic',deleteSaved(temporalSavedSignature),temporalExpression,{outcome:'one-null-row'}),
   probe('temporal-multiple-row','sourceDiscoveryPublic',duplicateTemporal,temporalExpression,{outcome:'error',sqlState:'21000'}),
   probe('temporal-missing-regprocedure','sourceDiscoveryPublic',`ALTER FUNCTION ${temporalTarget} RENAME TO zasp_missing_reference_claim_jobs`,temporalExpression,{outcome:'error',sqlState:'42883'}),
   probe('precision-lazy-unselected','sourceDiscoveryPublic',unselectedInsert,precisionExpression,{outcome:'one-non-null-row'}),
   probe('precision-zero-row-null','sourceDiscoveryPublic',deleteSaved(precisionSavedSignature),precisionExpression,{outcome:'one-null-row'}),
   probe('precision-multiple-row','sourceDiscoveryPublic',duplicatePrecision,precisionExpression,{outcome:'error',sqlState:'21000'}),
   probe('precision-missing-regprocedure','sourceDiscoveryPublic',`ALTER FUNCTION ${precisionTarget} RENAME TO zasp_missing_reference_precision_fingerprint`,precisionExpression,{outcome:'error',sqlState:'42883'}),
  ]},
  {id:'managed-role-current-database',baseline:[managed('temporal72:role'),managed('inventory-fields:role')],probes:[]},
  {id:'inventory-core-owner-resolution',baseline:[],probes:[
   probe('inventory-core-shadow-resolution','sourceInventoryPublic','CREATE TEMP TABLE zasp_core_payloads(probe integer)',`SELECT pg_catalog.jsonb_build_object('resolved','zasp_core_payloads'::regclass::text,'temporary','zasp_core_payloads'::regclass=pg_catalog.to_regclass('pg_temp.zasp_core_payloads'),'projection',(SELECT pg_catalog.jsonb_agg(to_jsonb(projected)) FROM (${inventoryProjection}) projected))`,{outcome:'one-json-row'}),
   probe('inventory-core-missing-regclass','sourceInventoryPublic','ALTER TABLE public.zasp_core_payloads RENAME TO zasp_missing_reference_core_payloads',inventoryProjection,{outcome:'error',sqlState:'42P01'}),
  ]},
 ];
 if(families.length!==7||families.some(family=>!witness.has(family.id)))fail('witness family closure');
 return freeze({limits:{sqlSeconds:10,lockSeconds:3,cleanupSeconds:3},families});
}

export function buildOrderedCurrentMissingReferenceNativePacket(input){
 verifyContractModule();
 if(!exactInput(input))fail('fixed source input required');
 let contract;try{contract=buildOrderedCurrentMissingReferenceContractV1(input);}catch(error){fail(`contract (${error.message})`);}
 if(contract.contractSHA256!==contractSHA256||contract.installable!==false||contract.captureStatus!=='NOT-CAPTURED'||contract.rules.length!==12||contract.maxRows!==204)fail('accepted contract identity');
 const baselineRules=contract.rules.map(baselineRule),sourceSites=contract.rules.reduce((sum,rule)=>sum+rule.sourceSites.length,0);
 const packet={format:'ordered-current-missing-reference-native-v1',status:'NATIVE-UNVERIFIED',installable:false,captureStatus:'NOT-CAPTURED',sourceAuthority:'accepted-recovery80-source-2ca-missing-reference-capture-only',sourcePins:{...contract.sourceAuthority,contractModuleSHA256,contractJSONSHA256:sha(JSON.stringify(contract))},limits,counts:{rules:12,rows:204,sourceSites,witnessFamilies:7},contract,baseline:{transaction:{isolation:'repeatable-read',access:'read-only',snapshot:'single'},rules:baselineRules},witnessProgram:witnessProgram(contract,contract.rules),output:{format:'ordered-current-missing-reference-capture-v1',status:'NATIVE-OBSERVED-NOT-ACCEPTED',installable:false,fileName:'missing-reference-capture.json',mode:'0600',publish:'exclusive-after-all-controls',sections:['observations','canonicalIdentities','controls','provenance']}};
 if(sourceSites!==21||baselineRules.reduce((sum,rule)=>sum+rule.exactRows,0)!==204)fail('packet bounds');
 return freeze(packet);
}

export function serializeOrderedCurrentMissingReferenceNativePacket(packet){
 if(!packet||packet.format!=='ordered-current-missing-reference-native-v1')fail('packet object');
 const raw=Buffer.from(JSON.stringify(packet)+'\n');if(raw.length>limits.maxBytes)fail('packet bytes');return {raw,sha256:sha(raw),bytes:raw.length};
}

export function materializeOrderedCurrentMissingReferenceNativePacket(packet,directory){
 if(typeof directory!=='string'||!path.isAbsolute(directory)||path.normalize(directory)!==directory)fail('materializer directory');
 fs.mkdirSync(directory,{recursive:true,mode:0o700});
 const output=path.join(directory,'missing-reference-native-packet.json'),serialized=serializeOrderedCurrentMissingReferenceNativePacket(packet);
 try{fs.writeFileSync(output,serialized.raw,{flag:'wx',mode:0o600});}catch(error){
  if(error?.code!=='EEXIST')fail(`materializer write (${error.message})`);
  let existing;try{existing=fs.readFileSync(output);}catch(readError){fail(`materializer read (${readError.message})`);}
  if(!existing.equals(serialized.raw))fail('materializer refuses overwrite');
 }
 return {path:output,sha256:serialized.sha256,bytes:serialized.bytes};
}

// This is intentionally a shape-and-pin verifier, rather than another packet
// builder: the intake receives only the independently reviewed fixed bytes.
export function assertOrderedCurrentMissingReferenceNativePacketV1(packet){
 const same=(left,right)=>JSON.stringify(left)===JSON.stringify(right);
 if(!packet||typeof packet!=='object'||Array.isArray(packet)||!same(Object.keys(packet).sort(),['baseline','captureStatus','contract','counts','format','installable','limits','output','sourceAuthority','sourcePins','status','witnessProgram']))fail('packet envelope');
 if(packet.format!=='ordered-current-missing-reference-native-v1'||packet.status!=='NATIVE-UNVERIFIED'||packet.installable!==false||packet.captureStatus!=='NOT-CAPTURED'||packet.sourceAuthority!=='accepted-recovery80-source-2ca-missing-reference-capture-only')fail('packet status');
 if(!same(packet.counts,{rules:12,rows:204,sourceSites:21,witnessFamilies:7})||packet.contract?.contractSHA256!==contractSHA256||packet.sourcePins?.contractModuleSHA256!==contractModuleSHA256||packet.contract?.installable!==false||packet.contract?.captureStatus!=='NOT-CAPTURED')fail('packet pins');
 if(!Array.isArray(packet.contract.rules)||packet.contract.rules.length!==12||packet.contract.rules.reduce((sum,rule)=>sum+rule.exactRows,0)!==204||!Array.isArray(packet.baseline?.rules)||packet.baseline.rules.length!==12||!Array.isArray(packet.witnessProgram?.families)||packet.witnessProgram.families.length!==7)fail('packet counts');
 return true;
}
