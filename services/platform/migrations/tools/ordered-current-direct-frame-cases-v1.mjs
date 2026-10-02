import crypto from 'node:crypto';
import {compileOrderedCollector,compileOrderedDirectFrameCollectorV1} from './ordered-current-catalog.mjs';
import {directFrameAdaptersV1,directFrameAdmissionSQL,directFrameRuleFieldMatrixV1,directFrameRulesV1} from './ordered-current-direct-frame-v1.mjs';
import {buildOrderedTransformAcceptance} from './build-ordered-current-transform-acceptance.mjs';
import {lowerOrderedTemporalTransforms} from './ordered-current-temporal-transforms.mjs';
import {lowerOrderedPublicFunctionTransforms} from './ordered-current-public-function-transforms.mjs';
import {compileOrderedTransforms} from './ordered-current-transform-compiler.mjs';

const fail=message=>{throw Error(`ordered-current direct-frame cases v1 ${message}`);};
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const same=(left,right)=>JSON.stringify(left)===JSON.stringify(right);
const plain=value=>value!==null&&typeof value==='object'&&!Array.isArray(value)&&Object.getPrototypeOf(value)===Object.prototype;
const freeze=value=>{if(value&&typeof value==='object'&&!Object.isFrozen(value)){for(const child of Object.values(value))freeze(child);Object.freeze(value);}return value;};
const exact=(value,keys)=>plain(value)&&same(Object.keys(value).sort(),keys.slice().sort());
const quote=value=>"'"+value.replaceAll("'","''")+"'";
const namespace='zasp_authorization80_ordered_current';
const successorProgramSHA256='692e7fa9f1be3338a9ca78b7229681134b3d21bc8c33c888c455651f472dc85b';
const sourcePins=freeze({
 compilerArtifactSHA256:'2ca5e151e304df622167ab5a313135acd28d8a010bc29638dd0e9c83f968395c',
 compilerChecksum:'f53752f15df1875e7c08ab6db39e91f08efdf5cf23bb2d6f86015fb22615a214',
 compiledSourceSHA256:'e04af1ed6cdaf40add80196b59214cc64f7f126c1d3f64801352a4bc20923b6e',
 sourceContractSHA256:'02b13c54ff1a543a4ca3a8f43fd2aa71e0334b04efea90afcf61cccf6a74e5cb',
 coverageSHA256:'67e214f69821c113b58078b5fc38e7504e33fb5748d7ad56de1fce01f85ed5c4',
 catalogSHA256:'9cda05aa8d51f32b0b86d7997930e768b0b050308db26837093ff4fc6f6f35df',
});
const limits=freeze({caseSeconds:10,cleanupSeconds:3,observerSeconds:30,lockSeconds:3,maxRows:1600,maxBytes:33554432});
const frames=freeze({
 mutation:{role:'zasp_test',searchPath:'pg_catalog, public',timeZone:'UTC'},
 sourceDiscoveryPublic:{role:'zasp_discovery_authority',searchPath:'pg_catalog, public',timeZone:'UTC'},
 canonicalCollector:{role:'zasp_discovery_authority',searchPath:'pg_catalog',timeZone:'UTC'},
});
const signature=adapter=>`${adapter.name}(${adapter.args.map(argument=>argument[1]).join(',')})`;
const declaration=(adapter,body,args=adapter.args)=>`CREATE OR REPLACE FUNCTION ${adapter.name}(${args.map(([name,type])=>name+' '+type).join(', ')})\nRETURNS pg_catalog.text LANGUAGE plpgsql STABLE SECURITY INVOKER PARALLEL UNSAFE\nSET search_path=pg_catalog,public SET TimeZone='UTC'\nAS $body$${body}$body$;`;
const poisonBody="\nBEGIN\n RAISE EXCEPTION USING ERRCODE='ZX001', MESSAGE='ordered direct frame poison';\nEND\n";
const invocation=adapter=>`SELECT ${adapter.name}(${adapter.args.map(([,type])=>`NULL::${type}`).join(',')})`;
const collectorOutcomes=freeze([{collector:'direct',outcome:'success',rows:0,forbiddenSQLState:'ZX001'},{collector:'transform',outcome:'success',rows:0,forbiddenSQLState:'ZX001'}]);
const reachabilityAssignments=freeze([
 ['function_definition_public','worker-edge:runtime_projected50_binding:3','definition'],
 ['function_identity_arguments_public','worker-edge:runtime_projected50_binding:3','identity_arguments'],
 ['function_identity_public','worker:projected_domain:foreign-key-trigger','function'],
 ['relation_identity_public','worker-edge:runtime_projected40:5','relation'],
 ['type_identity_public','worker-edge:gateway_projected24:3','type_identity'],
 ['format_type_public','worker-edge:runtime_projected40:5','type'],
 ['column_default_public','worker-edge:gateway_projected24:3','default_text_or_empty'],
 ['constraint_definition_public','worker-edge:runtime_projected40:4','definition'],
 ['constraint_definition_pretty_public','worker-edge:gateway_projected24:4','definition_pretty'],
 ['index_definition_public','worker-edge:gateway_projected24:5','definition'],
 ['trigger_definition_public','worker-edge:runtime_projected50_search:9','definition'],
 ['trigger_definition_pretty_public','worker-edge:runtime_projected50_binding:4','definition_pretty'],
 ['trigger_when_public','worker:projected_domain:foreign-key-trigger','when_text_or_empty'],
 ['policy_using_public','worker-edge:gateway_projected27:11','using'],
 ['policy_check_public','worker-edge:gateway_projected27:11','check'],
 ['policy_view_using_public','worker-edge:runtime_projected40:6','using'],
 ['policy_view_check_public','worker-edge:runtime_projected40:6','check'],
 ['index_view_definition_public','worker-edge:runtime_projected40:7','definition'],
]);
function reachabilityBindings(coverage){
 const byRule=new Map(directFrameRulesV1.map(rule=>[rule.id,rule])),byMatrix=new Map(directFrameRuleFieldMatrixV1.map(rule=>[rule.id,rule]));
 return reachabilityAssignments.map(([short,ruleId,field])=>{
  const adapter=directFrameAdaptersV1.find(item=>item.name===namespace+'.'+short),rule=byRule.get(ruleId),matrix=byMatrix.get(ruleId),leaf=matrix?.fields.find(item=>item.name===field);
  if(!adapter||!rule||matrix?.kind!==rule.kind||leaf?.adapter!==short)fail('reachability assignment');
  if(coverage){
   const matches=coverage.rawRules.filter(item=>item.id===ruleId),captured=matches[0],index=rule.fields.indexOf(field);
   if(matches.length!==1||index<0||!same(captured.originRule,rule)||captured.sourceSite?.siteSHA256!==matrix.siteSHA256||captured.projections?.[index]!==leaf.source||captured.executionFrameId!=='sourceDiscoveryPublic')fail(`${short} reachability source binding`);
  }
  const selectorWitnessSQL=`SELECT identity FROM (${compileOrderedCollector([rule]).sql}) selector_witness ORDER BY identity`,binding={adapter:adapter.name,ruleId,kind:rule.kind,field,sourceExpression:leaf.source,sourceSiteSHA256:matrix.siteSHA256};
  return freeze({...binding,minimumRows:1,selectedKeyAuthority:'requiredAcceptance.directExpectedRows',expectedKeyComparison:'exact-rule-canonical-key-set',selectorWitnessSQL,selectorWitnessSQLSHA256:sha(selectorWitnessSQL),callBindingSHA256:sha(JSON.stringify(binding))});
 });
}
function commonStages(reachability){return [
 {id:'capture-pre-state',action:'capture-exact-object-and-session-state',frame:'mutation',expectedOutcome:'success',timeoutSeconds:10},
 {id:'mutate',action:'execute-fixed-mutation',frame:'mutation',expectedOutcome:'success',timeoutSeconds:10},
 {id:'positive-invocation',action:'execute-fixed-sql-in-savepoint',frame:'sourceDiscoveryPublic',expectedOutcome:'error',expectedSQLState:'ZX001',timeoutSeconds:10},
 {id:'rollback-positive-invocation',action:'rollback-savepoint',frame:'sourceDiscoveryPublic',expectedOutcome:'success',timeoutSeconds:3},
 {id:'admission-probe',action:'execute-fixed-admission-scalar',frame:'canonicalCollector',expectedOutcome:'success',expectedAdmission:false,timeoutSeconds:10},
 {id:'selector-reachability-probe',action:'execute-fixed-selector-witness',frame:'canonicalCollector',expectedOutcome:'exact-key-set',minimumRows:reachability.minimumRows,selectedKeyAuthority:reachability.selectedKeyAuthority,timeoutSeconds:10},
 {id:'direct-gated-collector',action:'execute-direct-collector',frame:'canonicalCollector',expectedOutcome:'success',expectedRows:0,forbiddenSQLState:'ZX001',timeoutSeconds:10},
 {id:'transform-gated-collector',action:'execute-transform-collector',frame:'canonicalCollector',expectedOutcome:'success',expectedRows:0,forbiddenSQLState:'ZX001',timeoutSeconds:10},
 {id:'assert-noninvocation',action:'assert-reachable-poison-did-not-raise',frame:'canonicalCollector',expectedOutcome:'no-ZX001',timeoutSeconds:10},
 {id:'rollback-case',action:'rollback-transaction',frame:'mutation',expectedOutcome:'success',timeoutSeconds:3},
 {id:'verify-restoration',action:'compare-exact-pre-state-and-session-state',frame:'mutation',expectedOutcome:'equal',timeoutSeconds:3},
];}
function poisonCases(reachability){return directFrameAdaptersV1.map((adapter,index)=>freeze({
 id:`poison:${signature(adapter)}`,
 target:{name:adapter.name,signature:signature(adapter),argumentTypes:adapter.args.map(item=>item[1]),bodySHA256:sha(adapter.body)},
 mutation:{frame:'mutation',sql:declaration(adapter,poisonBody)},
 positiveInvocation:{sql:invocation(adapter),expectedSQLState:'ZX001',isolation:'savepoint'},
 expectedAdmission:false,
 collectorOutcomes,
 reachability:reachability[index],
 nonInvocation:{mode:'reachable-poison-no-error',forbiddenSQLState:'ZX001',affectedCollector:'direct',basis:'fixed-source-selected-key-set-plus-positive-poison-control'},
 stages:commonStages(reachability[index]),
 rollback:'required',
 restoration:{object:'exact-pre-case-definition-owner-acl-config-properties-and-overload-roster',session:'role-search_path-timezone-readonly',beforeNextCase:true},
 limits:{caseSeconds:10,cleanupSeconds:3},
}));}

function propertyCases(reachability=reachabilityBindings().find(item=>item.adapter===namespace+'.relation_identity_public')){
 const adapter=directFrameAdaptersV1.find(item=>item.name===namespace+'.relation_identity_public');
 const sig=signature(adapter),altered="\nBEGIN\n RETURN 'altered-body';\nEND\n";
 const cases=[
  ['adapter-owner',`ALTER FUNCTION ${sig} OWNER TO zasp_test; GRANT EXECUTE ON FUNCTION ${sig} TO zasp_discovery_authority`],
  ['adapter-acl',`REVOKE ALL ON FUNCTION ${sig} FROM zasp_discovery_authority`],
  ['adapter-config',`ALTER FUNCTION ${sig} SET search_path TO public`],
  ['adapter-body-signature',declaration(adapter,altered)],
  ['adapter-exact-arity',`DROP FUNCTION ${sig}; ${declaration(adapter,adapter.body,[...adapter.args,['extra','pg_catalog.oid','26']])}`],
 ['adapter-extra-overload',`CREATE FUNCTION ${adapter.name}(value pg_catalog.text) RETURNS pg_catalog.text LANGUAGE plpgsql STABLE SECURITY INVOKER PARALLEL UNSAFE SET search_path=pg_catalog,public SET TimeZone='UTC' AS $body$ BEGIN RETURN value; END $body$`],
 ];
 return cases.map(([id,sql])=>{
  const directError=id==='adapter-acl'?'42501':id==='adapter-exact-arity'?'42883':null;
  const outcomes=directError?freeze([{collector:'direct',outcome:'error',expectedSQLState:directError},{collector:'transform',outcome:'success',rows:0}]):collectorOutcomes;
  const directStage=directError?{id:'direct-gated-collector',expectedOutcome:'error',expectedSQLState:directError,frame:'canonicalCollector',timeoutSeconds:10}:{id:'direct-gated-collector',expectedOutcome:'success',expectedRows:0,frame:'canonicalCollector',timeoutSeconds:10};
  const collectorStages=directError?[{id:'begin-direct-savepoint',expectedOutcome:'success',frame:'canonicalCollector',timeoutSeconds:10},directStage,{id:'rollback-direct-savepoint',expectedOutcome:'success',frame:'canonicalCollector',timeoutSeconds:3},{id:'transform-gated-collector',expectedOutcome:'success',expectedRows:0,frame:'canonicalCollector',timeoutSeconds:10}]:[directStage,{id:'transform-gated-collector',expectedOutcome:'success',expectedRows:0,frame:'canonicalCollector',timeoutSeconds:10}];
  return freeze({id,target:signature(adapter),mutation:{frame:'mutation',sql},expectedAdmission:false,collectorOutcomes:outcomes,reachability,stages:[
  {id:'capture-pre-state',expectedOutcome:'success',frame:'mutation',timeoutSeconds:10},
  {id:'mutate',expectedOutcome:'success',frame:'mutation',timeoutSeconds:10},
  {id:'admission-probe',expectedOutcome:'success',expectedAdmission:false,frame:'canonicalCollector',timeoutSeconds:10},
  {id:'selector-reachability-probe',expectedOutcome:'exact-key-set',minimumRows:reachability.minimumRows,selectedKeyAuthority:reachability.selectedKeyAuthority,frame:'canonicalCollector',timeoutSeconds:10},
  ...collectorStages,
  {id:'rollback-case',expectedOutcome:'success',frame:'mutation',timeoutSeconds:3},
  {id:'verify-restoration',expectedOutcome:'equal',frame:'mutation',timeoutSeconds:3},
 ],rollback:'required',restoration:'exact-before-next-case',limits:{caseSeconds:10,cleanupSeconds:3}});
 });
}

function semanticProbes(){
 const call=(name,args)=>`${namespace}.${name}(${args})`;
 const tableSetup=['CREATE TABLE public.__ordered_frame_probe_parent(id integer PRIMARY KEY)','CREATE TABLE public.__ordered_frame_probe_child(id integer REFERENCES public.__ordered_frame_probe_parent(id))','GRANT SELECT ON public.__ordered_frame_probe_parent,public.__ordered_frame_probe_child TO zasp_discovery_authority'];
 const triggerSetup=[...tableSetup,"CREATE FUNCTION public.__ordered_frame_probe_trigger() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN RETURN NEW; END $f$","CREATE TRIGGER __ordered_frame_probe_trigger BEFORE INSERT ON public.__ordered_frame_probe_child FOR EACH ROW WHEN (NEW.id IS NOT NULL) EXECUTE FUNCTION public.__ordered_frame_probe_trigger()",'GRANT EXECUTE ON FUNCTION public.__ordered_frame_probe_trigger() TO zasp_discovery_authority'];
 const policySetup=['CREATE TABLE public.__ordered_frame_probe_policy(id integer, owner_name text)','ALTER TABLE public.__ordered_frame_probe_policy ENABLE ROW LEVEL SECURITY',"CREATE POLICY __ordered_frame_probe_policy ON public.__ordered_frame_probe_policy USING (owner_name = CURRENT_USER) WITH CHECK (id > 0)",'GRANT SELECT ON public.__ordered_frame_probe_policy TO zasp_discovery_authority'];
 const indexSetup=['CREATE TABLE public.__ordered_frame_probe_index(id integer)','CREATE INDEX __ordered_frame_probe_index_idx ON public.__ordered_frame_probe_index(id)','GRANT SELECT ON public.__ordered_frame_probe_index TO zasp_discovery_authority'];
 const make=(id,originalSQL,adapterSQL,expectedOutcome='equal-text',expectedSQLState=null,setupSQL=[])=>freeze({id,setupSQL,originalSQL,adapterSQL,expectedOutcome,expectedSQLState,originalFrame:'sourceDiscoveryPublic',adapterFrame:'canonicalCollector',comparison:'exact-postgresql-value-type-and-error',rollback:'required',limits:{caseSeconds:10,cleanupSeconds:3}});
 return [
  make('routine-definition',`SELECT pg_catalog.pg_get_functiondef(${quote(signature(directFrameAdaptersV1[0]))}::pg_catalog.regprocedure)`,`SELECT ${directFrameAdaptersV1[0].name}(${quote(signature(directFrameAdaptersV1[0]))}::pg_catalog.regprocedure::pg_catalog.oid)`),
  make('routine-identity-arguments',`SELECT pg_catalog.pg_get_function_identity_arguments(${quote(signature(directFrameAdaptersV1[1]))}::pg_catalog.regprocedure)`,`SELECT ${directFrameAdaptersV1[1].name}(${quote(signature(directFrameAdaptersV1[1]))}::pg_catalog.regprocedure::pg_catalog.oid)`),
  make('routine-identity',`SELECT ${quote(signature(directFrameAdaptersV1[2]))}::pg_catalog.regprocedure::pg_catalog.text`,`SELECT ${directFrameAdaptersV1[2].name}(${quote(signature(directFrameAdaptersV1[2]))}::pg_catalog.regprocedure::pg_catalog.oid)`),
  make('null-regclass','SELECT NULL::pg_catalog.oid::pg_catalog.regclass::pg_catalog.text',`SELECT ${call('relation_identity_public','NULL::pg_catalog.oid')}`,'equal-null'),
  make('null-regtype','SELECT NULL::pg_catalog.oid::pg_catalog.regtype::pg_catalog.text',`SELECT ${call('type_identity_public','NULL::pg_catalog.oid')}`,'equal-null'),
  make('format-type-modifier',"SELECT pg_catalog.format_type('pg_catalog.varchar'::pg_catalog.regtype,14)",`SELECT ${call('format_type_public',"'pg_catalog.varchar'::pg_catalog.regtype::pg_catalog.oid,14")}`),
  make('missing-column-default','SELECT (SELECT pg_catalog.pg_get_expr(d.adbin,d.adrelid) FROM pg_catalog.pg_attrdef d WHERE d.oid=0)','SELECT '+call('column_default_public','0::pg_catalog.oid'),'equal-null'),
  make('regclass-selected-error',"SELECT CASE WHEN true THEN 'public.__ordered_missing_frame_relation'::pg_catalog.regclass::pg_catalog.text ELSE 'safe' END",`SELECT CASE WHEN true THEN ${call('relation_identity_public',"'public.__ordered_missing_frame_relation'::pg_catalog.regclass::pg_catalog.oid")} ELSE 'safe' END`,'equal-error','42P01'),
  make('regprocedure-selected-error',"SELECT 'public.__ordered_missing_frame_routine()'::pg_catalog.regprocedure::pg_catalog.text",`SELECT ${directFrameAdaptersV1[2].name}('public.__ordered_missing_frame_routine()'::pg_catalog.regprocedure::pg_catalog.oid)`,'equal-error','42883'),
  make('regtype-selected-error',"SELECT 'public.__ordered_missing_frame_type'::pg_catalog.regtype::pg_catalog.text",`SELECT ${call('type_identity_public',"'public.__ordered_missing_frame_type'::pg_catalog.regtype::pg_catalog.oid")}`,'equal-error','42704'),
  make('regclass-unselected-lazy',"SELECT CASE WHEN false THEN (CURRENT_USER||'.__ordered_missing_frame_relation')::pg_catalog.regclass::pg_catalog.text ELSE 'safe' END",`SELECT CASE WHEN false THEN ${call('relation_identity_public',"(CURRENT_USER||'.__ordered_missing_frame_relation')::pg_catalog.regclass::pg_catalog.oid")} ELSE 'safe' END`),
  make('missing-column-default-empty',"SELECT COALESCE((SELECT pg_catalog.pg_get_expr(d.adbin,d.adrelid) FROM pg_catalog.pg_attrdef d WHERE d.oid=0),'')",`SELECT COALESCE(${call('column_default_public','0::pg_catalog.oid')},'')`,'equal-empty'),
  make('constraint-pretty-false',"SELECT pg_catalog.pg_get_constraintdef(oid) FROM pg_catalog.pg_constraint WHERE conname='__ordered_frame_probe_child_id_fkey'",`SELECT ${call('constraint_definition_public','oid')} FROM pg_catalog.pg_constraint WHERE conname='__ordered_frame_probe_child_id_fkey'`,'equal-text',null,tableSetup),
  make('constraint-pretty-true',"SELECT pg_catalog.pg_get_constraintdef(oid,true) FROM pg_catalog.pg_constraint WHERE conname='__ordered_frame_probe_child_id_fkey'",`SELECT ${call('constraint_definition_pretty_public','oid')} FROM pg_catalog.pg_constraint WHERE conname='__ordered_frame_probe_child_id_fkey'`,'equal-text',null,tableSetup),
  make('index-core-definition',"SELECT pg_catalog.pg_get_indexdef(c.oid) FROM pg_catalog.pg_class c WHERE c.relname='__ordered_frame_probe_index_idx'",`SELECT ${call('index_definition_public','c.oid')} FROM pg_catalog.pg_class c WHERE c.relname='__ordered_frame_probe_index_idx'`,'equal-text',null,indexSetup),
  make('trigger-pretty-false',"SELECT pg_catalog.pg_get_triggerdef(oid) FROM pg_catalog.pg_trigger WHERE tgname='__ordered_frame_probe_trigger'",`SELECT ${call('trigger_definition_public','oid')} FROM pg_catalog.pg_trigger WHERE tgname='__ordered_frame_probe_trigger'`,'equal-text',null,triggerSetup),
  make('trigger-pretty-true',"SELECT pg_catalog.pg_get_triggerdef(oid,true) FROM pg_catalog.pg_trigger WHERE tgname='__ordered_frame_probe_trigger'",`SELECT ${call('trigger_definition_pretty_public','oid')} FROM pg_catalog.pg_trigger WHERE tgname='__ordered_frame_probe_trigger'`,'equal-text',null,triggerSetup),
  make('trigger-when-null-and-value',"SELECT pg_catalog.pg_get_expr(tgqual,tgrelid) FROM pg_catalog.pg_trigger WHERE tgname='__ordered_frame_probe_trigger'",`SELECT ${call('trigger_when_public','oid')} FROM pg_catalog.pg_trigger WHERE tgname='__ordered_frame_probe_trigger'`,'error','22023',triggerSetup),
  make('policy-core-using',"SELECT pg_catalog.pg_get_expr(polqual,polrelid) FROM pg_catalog.pg_policy WHERE polname='__ordered_frame_probe_policy'",`SELECT ${call('policy_using_public','oid')} FROM pg_catalog.pg_policy WHERE polname='__ordered_frame_probe_policy'`,'equal-text',null,policySetup),
  make('policy-core-check',"SELECT pg_catalog.pg_get_expr(polwithcheck,polrelid) FROM pg_catalog.pg_policy WHERE polname='__ordered_frame_probe_policy'",`SELECT ${call('policy_check_public','oid')} FROM pg_catalog.pg_policy WHERE polname='__ordered_frame_probe_policy'`,'equal-text',null,policySetup),
  make('policy-view-computed-text',"SELECT qual::pg_catalog.text||E'\\n'||with_check::pg_catalog.text FROM pg_catalog.pg_policies WHERE schemaname='public' AND tablename='__ordered_frame_probe_policy' AND policyname='__ordered_frame_probe_policy'",`SELECT ${call('policy_view_using_public',"'public','__ordered_frame_probe_policy','__ordered_frame_probe_policy'")}||E'\\n'||${call('policy_view_check_public',"'public','__ordered_frame_probe_policy','__ordered_frame_probe_policy'")}`,'equal-text',null,policySetup),
  make('index-view-computed-text',"SELECT indexdef::pg_catalog.text FROM pg_catalog.pg_indexes WHERE schemaname='public' AND tablename='__ordered_frame_probe_index' AND indexname='__ordered_frame_probe_index_idx'",`SELECT ${call('index_view_definition_public',"'public','__ordered_frame_probe_index','__ordered_frame_probe_index_idx'")}`,'equal-text',null,indexSetup),
 ];
}

function parseFixed(input){
 if(!exact(input,['compiledReleaseRaw','sourceContractRaw','coverageRaw','catalogRaw']))fail('fixed input fields');
 for(const key of Object.keys(input))if(!Buffer.isBuffer(input[key]))fail(`fixed input ${key} bytes`);
 if(sha(input.compiledReleaseRaw)!==sourcePins.compilerArtifactSHA256)fail('compiled release identity');
 if(sha(input.sourceContractRaw)!==sourcePins.sourceContractSHA256)fail('source contract identity');
 if(sha(input.coverageRaw)!==sourcePins.coverageSHA256)fail('coverage identity');
 if(sha(input.catalogRaw)!==sourcePins.catalogSHA256)fail('catalog identity');
 let release,contract,coverage,catalog;try{release=JSON.parse(input.compiledReleaseRaw);contract=JSON.parse(input.sourceContractRaw);coverage=JSON.parse(input.coverageRaw);catalog=JSON.parse(input.catalogRaw);}catch{fail('fixed input JSON');}
 if(release.format!=='zasp-worker-compiled-release-v1'||release.checksum!==sourcePins.compilerChecksum||release.source_sha256!==sourcePins.compiledSourceSHA256||sha(Buffer.from(release.source))!==sourcePins.compiledSourceSHA256)fail('compiled source binding');
 if(contract.format!=='ordered-current-effective-contract-v1'||!Array.isArray(contract.nodes))fail('source contract shape');
 if(coverage.sourceFrameVersion!==2||!Array.isArray(coverage.rawRules))fail('coverage shape');
 if(catalog.format!=='zasp-worker-effective-catalog-v2'||catalog.compiled_checksum!==sourcePins.compilerChecksum)fail('catalog shape');
 return {contract,coverage};
}

function transformCaseStages(item,allRuleIDs){
 const ruleIDs=item.ruleIDs.length?item.ruleIDs:allRuleIDs,stages=[
  {id:'capture-pre-state',action:'capture-exact-case-object-and-session-state',frame:'mutation',expectedOutcome:'success',timeoutSeconds:10},
  {id:'apply-mutations',action:'execute-fixed-mutationSQL',frame:'mutation',expectedOutcome:'success',statementCount:item.setup.length,timeoutSeconds:10},
 ];
 if(item.witnessSQL){
  stages.push({id:'run-config-witness',action:'execute-fixed-witnessSQL',frame:'sourceDiscoveryPublic',expectedOutcome:'success',timeoutSeconds:10});
  stages.push({id:'validate-config-witness',action:'validate-fixed-config-shape-and-text',frame:'sourceDiscoveryPublic',expectedOutcome:item.expectNonstandard?'refuse-nonstandard':'equal-original-text',timeoutSeconds:10});
 }
 if(item.probeSQL){
  stages.push({id:'begin-probe-error-savepoint',action:'begin-savepoint',frame:'mutation',expectedOutcome:'success',timeoutSeconds:10});
  stages.push({id:'run-expected-error-probe',action:'execute-fixed-probeSQL',frame:'mutation',expectedOutcome:'error',expectedSQLState:item.sqlState,timeoutSeconds:10});
  stages.push({id:'rollback-probe-error-savepoint',action:'rollback-savepoint',frame:'mutation',expectedOutcome:'success',timeoutSeconds:3});
 }
 stages.push({id:'run-roster-probes',action:'execute-fixed-rule-rosterSQL',ruleIDs,frame:'canonicalCollector',expectedOutcome:'success',comparison:'exact-canonical-roster',timeoutSeconds:10});
 if(item.sqlState&&!item.probeSQL){
  stages.push({id:'begin-original-error-savepoint',action:'begin-savepoint',frame:'sourceDiscoveryPublic',expectedOutcome:'success',timeoutSeconds:10});
  stages.push({id:'run-original-aggregates',action:'execute-fixed-rule-originalAggregateSQL',ruleIDs,frame:'sourceDiscoveryPublic',expectedOutcome:'error',expectedSQLState:item.sqlState,timeoutSeconds:10});
  stages.push({id:'rollback-original-error-savepoint',action:'rollback-savepoint',frame:'sourceDiscoveryPublic',expectedOutcome:'success',timeoutSeconds:3});
  stages.push({id:'begin-candidate-error-savepoint',action:'begin-savepoint',frame:'canonicalCollector',expectedOutcome:'success',timeoutSeconds:10});
  stages.push({id:'run-candidate-aggregates',action:'execute-fixed-rule-candidateAggregateSQL',ruleIDs,frame:'canonicalCollector',expectedOutcome:'error',expectedSQLState:item.sqlState,timeoutSeconds:10});
  stages.push({id:'rollback-candidate-error-savepoint',action:'rollback-savepoint',frame:'canonicalCollector',expectedOutcome:'success',timeoutSeconds:3});
  stages.push({id:'compare-error-sqlstates',action:'compare-exact-original-candidate-sqlstate',ruleIDs,frame:'mutation',expectedOutcome:'equal',expectedSQLState:item.sqlState,timeoutSeconds:10});
 }else{
  stages.push({id:'run-original-aggregates',action:'execute-fixed-rule-originalAggregateSQL',ruleIDs,frame:'sourceDiscoveryPublic',expectedOutcome:'success',timeoutSeconds:10});
  stages.push({id:'run-candidate-aggregates',action:'execute-fixed-rule-candidateAggregateSQL',ruleIDs,frame:'canonicalCollector',expectedOutcome:'success',timeoutSeconds:10});
  stages.push({id:'compare-exact-aggregates',action:'compare-exact-unnormalized-original-candidate-and-roster',ruleIDs,frame:'mutation',expectedOutcome:'equal',timeoutSeconds:10});
 }
 stages.push({id:'rollback-case',action:'rollback-case-transaction',frame:'mutation',expectedOutcome:'success',timeoutSeconds:3});
 stages.push({id:'verify-restoration',action:'compare-exact-object-session-and-roster-pre-state',frame:'mutation',expectedOutcome:'equal',timeoutSeconds:3});
 return stages;
}

function successorTransform(contract,coverage){
 const temporal=lowerOrderedTemporalTransforms(contract),pub=lowerOrderedPublicFunctionTransforms(contract),recipes=[...temporal.recipes,...pub.recipes],sites=[...temporal.sites,...pub.sites];
 if(recipes.length!==13)fail('successor transform recipe coverage');
 const sourceFrame={role:'zasp_discovery_authority',searchPath:'pg_catalog, public',timeZone:'UTC',derivation:'source-proof',sourceFrameProofSHA256:'6c09fd7b1981d3a0e74cadb7a324b29cb3d4a5a5c3fee4b61a6e90ef6c0c8124'};
 if(!same(coverage.framePlan?.executionFrames?.sourceDiscoveryPublic,sourceFrame))fail('successor transform source frame');
 const accepted=buildOrderedTransformAcceptance(contract),compiled=compileOrderedTransforms(recipes,{definitionFrame:'pg_catalog, public'});
 const rules=recipes.map(recipe=>{
  const prior=accepted.rules.find(item=>item.id===recipe.ruleId),site=sites.find(item=>item.sha256===recipe.siteSHA256),captured=coverage.rawRules.filter(item=>item.id===recipe.ruleId);
  if(!prior||!site||captured.length!==1||captured[0].executionFrameId!=='sourceDiscoveryPublic'||coverage.framePlan?.ruleFrames?.[recipe.ruleId]!=='sourceDiscoveryPublic')fail(`${recipe.ruleId} successor source coverage`);
  const proof=captured[0].sourceSite;
  if(!proof||proof.sourceIdentity!==recipe.sourceIdentity||proof.sourceSHA256!==recipe.sourceSHA256||proof.definitionSHA256!==recipe.definitionSHA256||proof.siteSHA256!==recipe.siteSHA256||proof.start!==site.start||proof.end!==site.end)fail(`${recipe.ruleId} successor source site`);
  const candidate=compileOrderedTransforms([recipe],{definitionFrame:'pg_catalog, public'});
  const aggregateField=field=>prior.fieldTypes[field]==='boolean'?`(fact->>${quote(field)})::boolean`:prior.fieldTypes[field]==='string'?`fact->>${quote(field)}`:fail(`${recipe.ruleId} aggregate field type ${field}`);
  return freeze({id:recipe.ruleId,kind:'routine',fields:Object.keys(recipe.fields),fieldTypes:prior.fieldTypes,sourceSite:proof,executionFrame:'sourceDiscoveryPublic',candidateFrame:'canonicalCollector',originalSQL:prior.originalSQL,candidateSQL:candidate.sql,rosterSQL:prior.rosterSQL,witnessSQL:prior.witnessSQL,originalAggregateSQL:prior.originalAggregateSQL,candidateAggregateSQL:`SELECT pg_catalog.string_agg(line,E'\\n' ORDER BY line) FROM (SELECT kind,identity,fact,pg_catalog.concat_ws('|',${quote(site.type)},${Object.keys(recipe.fields).map(aggregateField).join(',')}) AS line FROM (${candidate.sql}) projected) candidate_lines`,compiledSQLSHA256:candidate.sourceSHA256});
 });
 const allRuleIDs=rules.map(rule=>rule.id),cases=accepted.cases.map(item=>freeze({id:item.id,ruleIDs:item.ruleIDs,mutationSQL:item.setup,mode:item.mode,expectedOutcome:item.sqlState?'error':'success',expectedSQLState:item.sqlState||null,mustChange:item.mustChange,expectNonstandard:item.expectNonstandard,probeSQL:item.probeSQL,witnessSQL:item.witnessSQL,mutationFrame:'mutation',originalFrame:'sourceDiscoveryPublic',candidateFrame:'canonicalCollector',stages:transformCaseStages(item,allRuleIDs),rollback:'required',limits:{caseSeconds:10,cleanupSeconds:3}}));
 const gatedSQL=`WITH complete_adapter_admission AS MATERIALIZED (${directFrameAdmissionSQL}) SELECT transformed.* FROM (${compiled.sql}) transformed CROSS JOIN complete_adapter_admission WHERE complete_adapter_admission.admitted IS TRUE`,compiledSQLSHA256=sha(gatedSQL);
 return freeze({rules,compiled:{...compiled,ungatedSQL:compiled.sql,ungatedSourceSHA256:compiled.sourceSHA256,sql:gatedSQL,sourceSHA256:compiledSQLSHA256},compiledSQLSHA256,cases,rawRules:compiled.rawRules,sourceDisposition:'independent-successor-compilation-from-pinned-contract-and-sites; historical packet is not authority'});
}

function validatePoison(item,index,reachability){
 const adapter=directFrameAdaptersV1[index],reachabilityKeys=['adapter','ruleId','kind','field','sourceExpression','sourceSiteSHA256','minimumRows','selectedKeyAuthority','expectedKeyComparison','selectorWitnessSQL','selectorWitnessSQLSHA256','callBindingSHA256'];
 if(!exact(item,['id','target','mutation','positiveInvocation','expectedAdmission','collectorOutcomes','reachability','nonInvocation','stages','rollback','restoration','limits'])||!exact(item.target,['name','signature','argumentTypes','bodySHA256'])||!exact(item.mutation,['frame','sql'])||!exact(item.positiveInvocation,['sql','expectedSQLState','isolation'])||!exact(item.reachability,reachabilityKeys)||!same(item.reachability,reachability)||!exact(item.nonInvocation,['mode','forbiddenSQLState','affectedCollector','basis'])||item.nonInvocation.mode!=='reachable-poison-no-error'||item.nonInvocation.forbiddenSQLState!=='ZX001'||item.nonInvocation.affectedCollector!=='direct'||!exact(item.restoration,['object','session','beforeNextCase'])||!exact(item.limits,['caseSeconds','cleanupSeconds'])||item.id!==`poison:${signature(adapter)}`||item.target.signature!==signature(adapter)||item.target.bodySHA256!==sha(adapter.body)||item.expectedAdmission!==false||item.rollback!=='required'||item.mutation.sql!==declaration(adapter,poisonBody)||item.positiveInvocation.sql!==invocation(adapter)||item.positiveInvocation.expectedSQLState!=='ZX001'||!same(item.collectorOutcomes,collectorOutcomes)||!same(item.stages,commonStages(reachability))||item.limits.caseSeconds!==10||item.limits.cleanupSeconds!==3)fail('poison case');
}
function validateSuccessorTransform(value){
 const digest=sha(JSON.stringify(value));
 if(digest!==successorProgramSHA256)fail(`successor transform authority ${digest}`);
 if(!exact(value,['rules','compiled','compiledSQLSHA256','cases','rawRules','sourceDisposition'])||!Array.isArray(value.rules)||value.rules.length!==13||!Array.isArray(value.cases)||value.cases.length!==19||!Array.isArray(value.rawRules)||value.rawRules.length!==13||typeof value.sourceDisposition!=='string')fail('successor transform');
 if(!exact(value.compiled,['sql','recipes','rawRules','definitionFrame','frameVersion','admissionSQL','sourceSHA256','ungatedSQL','ungatedSourceSHA256'])||value.compiled.recipes!==13||value.compiled.definitionFrame!=='pg_catalog, public'||value.compiled.frameVersion!==2||sha(value.compiled.sql)!==value.compiledSQLSHA256||value.compiled.sourceSHA256!==value.compiledSQLSHA256||sha(value.compiled.ungatedSQL)!==value.compiled.ungatedSourceSHA256)fail('successor transform');
 const ruleKeys=['id','kind','fields','fieldTypes','sourceSite','executionFrame','candidateFrame','originalSQL','candidateSQL','rosterSQL','witnessSQL','originalAggregateSQL','candidateAggregateSQL','compiledSQLSHA256'];
 const ids=new Set();
 for(const rule of value.rules){
  if(!exact(rule,ruleKeys)||ids.has(rule.id)||rule.kind!=='routine'||rule.executionFrame!=='sourceDiscoveryPublic'||rule.candidateFrame!=='canonicalCollector'||!Array.isArray(rule.fields)||!exact(rule.fieldTypes,rule.fields)||!exact(rule.sourceSite,['sourceIdentity','sourceSHA256','definitionSHA256','siteSHA256','start','end','frame'])||typeof rule.originalSQL!=='string'||typeof rule.candidateSQL!=='string'||typeof rule.rosterSQL!=='string'||sha(rule.candidateSQL)!==rule.compiledSQLSHA256)fail('successor transform rule');
  ids.add(rule.id);
 }
 const caseKeys=['id','ruleIDs','mutationSQL','mode','expectedOutcome','expectedSQLState','mustChange','expectNonstandard','probeSQL','witnessSQL','mutationFrame','originalFrame','candidateFrame','stages','rollback','limits'];
 for(const item of value.cases)if(!exact(item,caseKeys)||!Array.isArray(item.ruleIDs)||!Array.isArray(item.mutationSQL)||!Array.isArray(item.stages)||!item.stages.length||!['success','error'].includes(item.expectedOutcome)||item.expectedSQLState!==null&&typeof item.expectedSQLState!=='string'||item.mutationFrame!=='mutation'||item.originalFrame!=='sourceDiscoveryPublic'||item.candidateFrame!=='canonicalCollector'||item.rollback!=='required'||!exact(item.limits,['caseSeconds','cleanupSeconds'])||item.limits.caseSeconds!==10||item.limits.cleanupSeconds!==3)fail('successor transform case');
}

export function assertOrderedCurrentDirectFrameCasesV1(value){
 const keys=['format','status','installable','sourcePins','limits','frames','directCollector','poisonCases','propertyCases','semanticProbes','successorTransform','requiredAcceptance','driverContract','blockingDependencies'];
 if(!exact(value,keys)||value.format!=='ordered-current-direct-frame-cases-v1'||value.status!=='NATIVE-UNVERIFIED'||value.installable!==false||!same(value.sourcePins,sourcePins)||!same(value.limits,limits)||!same(value.frames,frames))fail('program envelope');
 const fixedDirect=compileOrderedDirectFrameCollectorV1(structuredClone(directFrameRulesV1));
 if(!exact(value.directCollector,['rules','adapters','sql','sqlSHA256','installSQL','admissionSQL'])||value.directCollector.rules!==50||value.directCollector.adapters!==18||value.directCollector.sql!==fixedDirect.sql||value.directCollector.sqlSHA256!==fixedDirect.sourceSHA256||value.directCollector.installSQL!==fixedDirect.installSQL||value.directCollector.admissionSQL!==fixedDirect.admissionSQL)fail('direct collector');
 const reachability=reachabilityBindings();
 if(!Array.isArray(value.poisonCases)||value.poisonCases.length!==18)fail('poison case');for(let index=0;index<18;index++)validatePoison(value.poisonCases[index],index,reachability[index]);
 if(!Array.isArray(value.propertyCases)||!same(value.propertyCases,propertyCases()))fail('property cases');
 if(!Array.isArray(value.semanticProbes)||!same(value.semanticProbes,semanticProbes()))fail('semantic probes');
 validateSuccessorTransform(value.successorTransform);
 const acceptance={rules:63,rows:1600,directRules:50,directRows:1220,transformRules:13,transformRows:380,comparison:'exact-unnormalized-facts-and-canonical-keys',oldUniverse:'byte-identical-before-and-after-all-cases'};
 if(!same(value.requiredAcceptance,acceptance))fail('required acceptance');
 if(!exact(value.driverContract,['transactionPerCase','positiveInvocationIsolation','cleanupDeadlineSeconds','caseDeadlineSeconds','capturePreState','verifyAfterRollback','publishBeforeRestoration','unknownFieldPolicy','restoreSQLAfterRollback','integerComparison'])||value.driverContract.transactionPerCase!==true||value.driverContract.unknownFieldPolicy!=='refuse'||value.driverContract.publishBeforeRestoration!==false)fail('driver contract');
 if(!Array.isArray(value.blockingDependencies)||value.blockingDependencies.some(item=>!exact(item,['id','required']))||!same(value.blockingDependencies.map(item=>item.id),['independent-expected-rows','original-universe-query','successor-installation-proof','native-execution']))fail('blocking dependencies');
 return value;
}

export function buildOrderedCurrentDirectFrameCasesV1(input){
 const {contract,coverage}=parseFixed(input),direct=compileOrderedDirectFrameCollectorV1(structuredClone(directFrameRulesV1)),reachability=reachabilityBindings(coverage),transform=successorTransform(contract,coverage);
 if(direct.ruleFieldMatrix.length!==50||directFrameAdaptersV1.length!==18)fail('direct inventory');
 const value={
  format:'ordered-current-direct-frame-cases-v1',status:'NATIVE-UNVERIFIED',installable:false,sourcePins,limits,frames,
  directCollector:{rules:50,adapters:18,sql:direct.sql,sqlSHA256:direct.sourceSHA256,installSQL:direct.installSQL,admissionSQL:direct.admissionSQL},
  poisonCases:poisonCases(reachability),propertyCases:propertyCases(reachability.find(item=>item.adapter===namespace+'.relation_identity_public')),semanticProbes:semanticProbes(),successorTransform:transform,
  requiredAcceptance:{rules:63,rows:1600,directRules:50,directRows:1220,transformRules:13,transformRows:380,comparison:'exact-unnormalized-facts-and-canonical-keys',oldUniverse:'byte-identical-before-and-after-all-cases'},
  driverContract:{transactionPerCase:true,positiveInvocationIsolation:'savepoint-with-immediate-rollback',cleanupDeadlineSeconds:3,caseDeadlineSeconds:10,capturePreState:'exact-object-and-session-state',verifyAfterRollback:'before-next-case',publishBeforeRestoration:false,unknownFieldPolicy:'refuse',restoreSQLAfterRollback:false,integerComparison:'lossless-json-number'},
  blockingDependencies:[
   {id:'independent-expected-rows',required:'Consume the separately source-bound 63-rule/1600-row expected facts; this program contains no expected truth.'},
   {id:'original-universe-query',required:'Bind the reviewed old-universe queries before native execution; no source-bound query is present in the admitted inputs.'},
   {id:'successor-installation-proof',required:'Byte-prove the fixed compiled successor was installed before any case.'},
   {id:'native-execution',required:'Run every fixed case and semantic probe; this offline program makes no native claim.'},
  ],
 };
 return freeze(assertOrderedCurrentDirectFrameCasesV1(value));
}
