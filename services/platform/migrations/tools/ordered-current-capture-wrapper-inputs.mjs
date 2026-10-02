import fs from 'node:fs';
import crypto from 'node:crypto';

const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const base=new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/',import.meta.url);
const generatedBase=new URL('./ordered-current-worker-source-closure-v1-artifacts/',import.meta.url);
const generatedNames=Object.freeze({'ordered-current-effective-contract3.json':'effective-contract3.json','ordered-current-effective-catalog1.json':'effective-catalog1.json','ordered-current-inventory-compiled.json':'inventory-compiled.json','ordered-current-supplementary-reference1.json':'supplementary-reference1.json','ordered-current-remaining-reference1.json':'remaining-reference1.json','ordered-current-private-reference-alias1.json':'private-reference-alias1.json'});
const fixed={
 source:['ordered-current-effective-contract3.json','be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6'],
 catalog:['ordered-current-effective-catalog1.json','b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077']
};
const same=(left,right)=>JSON.stringify(left)===JSON.stringify(right);
function pinned([name,digest]){
 const primary=new URL(name,base),fallback=new URL(generatedNames[name]??name,generatedBase);
 let raw;
 try{raw=fs.readFileSync(primary);}catch(error){if(error.code!=='ENOENT')throw error;raw=fs.readFileSync(fallback);}
 if(sha(raw)!==digest)throw Error('wrapper capture fixed pin '+name);
 return JSON.parse(raw);
}
function admit(sourceContract,catalog){
 const source=pinned(fixed.source),fixedCatalog=pinned(fixed.catalog);
 if(!same(sourceContract,source))throw Error('wrapper capture source pin');
 if(!same(catalog,fixedCatalog))throw Error('wrapper capture catalog pin');
 return {source,catalog:fixedCatalog};
}
function frame(node){
 return Object.fromEntries(['owner','acl','config','language','security_definer','volatility','parallel','strict','leakproof','cost','rows','arguments','result'].map(key=>[key,node[key]]));
}
function sourceSite(source,identity,start=0,end=null){
 const matches=source.nodes.filter(node=>node.identity===identity);
 if(matches.length!==1)throw Error('wrapper capture source identity '+identity);
 const node=matches[0],body=Buffer.from(node.source),finish=end??body.length;
 if(start<0||finish<start||finish>body.length)throw Error('wrapper capture source span '+identity);
 return {sourceIdentity:identity,sourceSHA256:node.sourceSHA256,definitionSHA256:node.definitionSHA256,siteSHA256:sha(body.subarray(start,finish)),start,end:finish,frame:frame(node)};
}
function topLevelSelect(source){
 const select=source.match(/^\s*SELECT\s+/i);
 if(!select)throw Error('wrapper capture SELECT source');
 const begin=select[0].length;
 let depth=0,quote=false;
 for(let index=begin;index<source.length;index++){
  const character=source[index];
  if(character==="'"){
   if(quote&&source[index+1]==="'"){index++;continue;}
   quote=!quote;continue;
  }
  if(quote)continue;
  if(character==='(')depth++;
  else if(character===')')depth--;
  else if(depth===0&&/^FROM\b/i.test(source.slice(index))&&/\s/.test(source[index-1]))return {projection:source.slice(begin,index).trim(),from:source.slice(index).trim()};
 }
 return {projection:source.slice(begin).trim(),from:null};
}
const quotedList=values=>values.map(value=>"'"+value.replaceAll("'","''")+"'").join(',');
const literal=value=>"'"+value.replaceAll("'","''")+"'";
const resolutionFields=['literal','cast','sourceSite','demandPath','resolvedIdentity'];
const resolutionTypes=nullable=>({literal:'text',cast:'text',sourceSite:'text',demandPath:'text[]',resolvedIdentity:nullable?'text?':'text'});
const helperSignatures=['zasp_valid_product_id(text)','zasp_workflow_replay(text,text,text,text,text,text,jsonb)'];
const helperDemand=`s.signature IN(${quotedList(helperSignatures)})`;
const scopeRoutines=['zasp_sa_multistep_prior.lock_scope(text,text,text,text)','zasp_sa_multistep_prior.pricing_lock_scope(text,text,text,text)'];
const role=name=>`CASE WHEN ${name}=0 THEN 'PUBLIC' ELSE ${name}::regrole::text END`;

export function buildOrderedWrapperCaptureInputs(sourceContract,catalogInput) {
 const {source,catalog}=admit(sourceContract,catalogInput);
 const entries=[],rawRules=[],runtimeAlgebra=[],unresolved=[];
 const identities={
  scope:'zasp_temporal67.scope_authority_ready()',
  migration:'zasp_temporal72.migration_helper_identity(text,text,text)',
  runtime:'zasp_authorization80.runtime_audit_ready()',
  expected:'public.zasp_audit_export_source_acl_expected(jsonb)',
  sourceReady:'public.zasp_audit_export_source_acl_ready()',
  sourceSnapshot:'public.zasp_audit_export_source_acl_snapshot()',
  catalogACL:'public.zasp_audit_export_source_catalog_acl(aclitem[],oid)',
  catalogRole:'public.zasp_audit_export_source_catalog_role(oid,oid)',
  workflowReady:'public.zasp_audit_export_workflow_acl_ready()',
  workflowSnapshot:'public.zasp_audit_export_workflow_acl_snapshot()'
 };
 const sites=Object.fromEntries(Object.entries(identities).map(([name,identity])=>[name,sourceSite(source,identity)]));
 const addRule=rule=>{
  if(rule.fields.length!==rule.projections.length||new Set(rule.fields).size!==rule.fields.length)throw Error('wrapper capture field shape '+rule.id);
  const complete={sourceMaxRows:null,refusalMaxRows:10000,...rule};
  rawRules.push(complete);
  complete.fields.forEach((field,expressionOrdinal)=>entries.push({
   ...complete.sourceSite,
   expressionOrdinal,
   field,
   sourceExpression:complete.projections[expressionOrdinal],
   selector:structuredClone(complete.selector),
   demandPath:[...complete.demandPath],
   disposition:'capture',
   evidence:{phase:complete.sqlPhase??'original',ruleId:complete.id,field}
  }));
  return complete;
 };
 const addAlgebra=(name,children)=>runtimeAlgebra.push({...sites[name],ruleId:'wrapper-algebra:'+identities[name],disposition:'runtime-algebra-required',children});
 const children=(ruleID,fields)=>fields.map(field=>({ruleId:ruleID,field}));

 const scopePath=[identities.scope];
 addRule({
  id:'wrapper:scope-authority:relation',kind:'relation',fields:['relation_identity','owner'],fieldTypes:{relation_identity:'text',owner:'text'},sourceSite:sites.scope,
  sourceMaxRows:1,projections:['c.oid::regclass::text','c.relowner::regrole::text'],from:"FROM pg_class c WHERE c.oid='public.zasp_authorized_scopes'::regclass",
  canonicalClass:'pg_class',handleExpression:"'pg_class:'||c.oid::text||':0'",selector:{identities:['public.zasp_authorized_scopes']},demandPath:scopePath
 });
 const scopeRoutineFrom=`FROM pg_proc p WHERE p.oid IN(${scopeRoutines.map(value=>`'${value}'::regprocedure`).join(',')})`;
 addRule({
  id:'wrapper:scope-authority:routines',kind:'routine',fields:['routine_identity','owner','raw_acl'],fieldTypes:{routine_identity:'text',owner:'text',raw_acl:'text?'},sourceSite:sites.scope,
  sourceMaxRows:2,projections:['p.oid::regprocedure::text','p.proowner::regrole::text','p.proacl::text'],from:scopeRoutineFrom,
  canonicalClass:'pg_proc',handleExpression:"'pg_proc:'||p.oid::text||':0'",selector:{identities:scopeRoutines},demandPath:scopePath
 });
 addRule({
  id:'wrapper:scope-authority:routine-acl',kind:'routine_acl_bag',fields:['routine_identity','owner','grantor','grantee','privilege','grantable'],fieldTypes:{routine_identity:'text',owner:'text',grantor:'text',grantee:'text',privilege:'text',grantable:'boolean'},sourceSite:sites.scope,
  projections:['p.oid::regprocedure::text','p.proowner::regrole::text',role('a.grantor'),role('a.grantee'),'a.privilege_type::text','a.is_grantable'],
  from:`FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a WHERE p.oid IN(${scopeRoutines.map(value=>`'${value}'::regprocedure`).join(',')})`,
  bag:true,selector:{identities:scopeRoutines,acl:'raw-proacl'},demandPath:scopePath
 });
 addRule({
  id:'wrapper:scope-authority:relation-resolution',kind:'fixed_resolution_bag',fields:resolutionFields,fieldTypes:resolutionTypes(false),sourceSite:sites.scope,
  sourceMaxRows:1,projections:[literal('public.zasp_authorized_scopes'),literal('regclass'),literal(sites.scope.siteSHA256),`ARRAY[${quotedList(scopePath)}]::text[]`,"'public.zasp_authorized_scopes'::regclass::text"],
  from:'FROM (VALUES(1)) AS demanded(one)',bag:true,sqlPhase:'resolution',section:'resolutions',selector:{inputs:['public.zasp_authorized_scopes'],cast:'regclass'},demandPath:scopePath
 });
 addRule({
  id:'wrapper:scope-authority:routine-resolution',kind:'fixed_resolution_bag',fields:resolutionFields,fieldTypes:resolutionTypes(false),sourceSite:sites.scope,
  sourceMaxRows:2,projections:['d.literal::text',literal('regprocedure'),literal(sites.scope.siteSHA256),`ARRAY[${quotedList(scopePath)}]::text[]`,'d.literal::regprocedure::text'],
  from:`FROM (VALUES (${scopeRoutines.map(value=>literal(value)).join('),(')})) AS d(literal)`,bag:true,sqlPhase:'resolution',section:'resolutions',selector:{inputs:scopeRoutines,cast:'regprocedure'},demandPath:scopePath
 });
 addAlgebra('scope',[
  ...children('wrapper:scope-authority:relation',['relation_identity','owner']),
  ...children('wrapper:scope-authority:routines',['routine_identity','owner','raw_acl']),
  ...children('wrapper:scope-authority:routine-acl',['grantor','grantee','privilege','grantable']),
  ...children('wrapper:scope-authority:relation-resolution',['literal','resolvedIdentity']),
  ...children('wrapper:scope-authority:routine-resolution',['literal','resolvedIdentity'])
 ]);

 const migrationPath=['saved-input:zasp_temporal72.predecessor_functions',identities.migration];
 addRule({
  id:'wrapper:migration-helper:relations',kind:'relation',fields:['relation_identity','owner'],fieldTypes:{relation_identity:'text',owner:'text'},sourceSite:sites.migration,
  sourceMaxRows:2,projections:['c.oid::regclass::text','c.relowner::regrole::text'],from:`FROM pg_class c WHERE c.oid IN(SELECT CASE WHEN EXISTS(SELECT 1 FROM zasp_temporal72.predecessor_functions s WHERE ${helperDemand}) THEN d.identity::regclass ELSE NULL END FROM (VALUES ('public.zasp_core_payloads'),('public.zasp_authorized_scopes')) AS d(identity))`,
  canonicalClass:'pg_class',handleExpression:"'pg_class:'||c.oid::text||':0'",selector:{identities:['public.zasp_core_payloads','public.zasp_authorized_scopes'],demandedSignatures:helperSignatures},demandPath:migrationPath
 });
 const demandedHelper=`EXISTS(SELECT 1 FROM zasp_temporal72.predecessor_functions s WHERE ${helperDemand} AND p.oid=CASE WHEN ${helperDemand} THEN to_regprocedure('public.'||s.signature) ELSE NULL END)`;
 addRule({
  id:'wrapper:migration-helper:routines',kind:'routine',fields:['routine_identity','owner','raw_acl'],fieldTypes:{routine_identity:'text',owner:'text',raw_acl:'text?'},sourceSite:sites.migration,
  sourceMaxRows:2,projections:['p.oid::regprocedure::text','p.proowner::regrole::text','p.proacl::text'],from:`FROM pg_proc p WHERE ${demandedHelper}`,
  canonicalClass:'pg_proc',handleExpression:"'pg_proc:'||p.oid::text||':0'",selector:{savedTable:'zasp_temporal72.predecessor_functions',signatures:helperSignatures},demandPath:migrationPath
 });
 addRule({
  id:'wrapper:migration-helper:routine-acl',kind:'routine_acl_bag',fields:['routine_identity','owner','grantor','grantee','privilege','grantable'],fieldTypes:{routine_identity:'text',owner:'text',grantor:'text',grantee:'text',privilege:'text',grantable:'boolean'},sourceSite:sites.migration,
  projections:['p.oid::regprocedure::text','p.proowner::regrole::text',role('x.grantor'),role('x.grantee'),'x.privilege_type::text','x.is_grantable'],
  from:`FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) x WHERE ${demandedHelper}`,bag:true,
  selector:{savedTable:'zasp_temporal72.predecessor_functions',signatures:helperSignatures,acl:'raw-proacl'},demandPath:migrationPath
 });
 const migrationDemandProjection=`ARRAY[${literal(migrationPath[0])},${literal(migrationPath[1])},s.signature::text]::text[]`;
 addRule({
  id:'wrapper:migration-helper:relation-resolution',kind:'demanded_resolution_bag',fields:resolutionFields,fieldTypes:resolutionTypes(false),sourceSite:sites.migration,
  projections:['d.literal::text',literal('regclass'),literal(sites.migration.siteSHA256),migrationDemandProjection,`CASE WHEN ${helperDemand} THEN d.literal::regclass::text ELSE NULL END`],
  from:`FROM zasp_temporal72.predecessor_functions s CROSS JOIN (VALUES ('public.zasp_core_payloads'),('public.zasp_authorized_scopes')) AS d(literal) WHERE ${helperDemand}`,bag:true,sqlPhase:'resolution',section:'resolutions',
  selector:{savedTable:'zasp_temporal72.predecessor_functions',signatures:helperSignatures,inputs:['public.zasp_core_payloads','public.zasp_authorized_scopes'],cast:'regclass'},demandPath:migrationPath
 });
 addRule({
  id:'wrapper:migration-helper:routine-resolution',kind:'demanded_resolution_bag',fields:resolutionFields,fieldTypes:resolutionTypes(true),sourceSite:sites.migration,
  projections:["'public.'||s.signature",literal('to_regprocedure'),literal(sites.migration.siteSHA256),migrationDemandProjection,`CASE WHEN ${helperDemand} THEN to_regprocedure('public.'||s.signature)::text ELSE NULL END`],
  from:`FROM zasp_temporal72.predecessor_functions s WHERE ${helperDemand}`,bag:true,sqlPhase:'resolution',section:'resolutions',
  selector:{savedTable:'zasp_temporal72.predecessor_functions',signatures:helperSignatures,cast:'to_regprocedure'},demandPath:migrationPath
 });
 addAlgebra('migration',[
  ...children('saved-input:zasp_temporal72.predecessor_functions',['signature','owner_name','acl']),
  ...children('wrapper:migration-helper:relations',['relation_identity','owner']),
  ...children('wrapper:migration-helper:routines',['routine_identity','owner','raw_acl']),
  ...children('wrapper:migration-helper:routine-acl',['grantor','grantee','privilege','grantable']),
  ...children('wrapper:migration-helper:relation-resolution',['literal','resolvedIdentity']),
  ...children('wrapper:migration-helper:routine-resolution',['literal','resolvedIdentity'])
 ]);

 const runtimeResolutionSite=sourceSite(source,identities.runtime,514,680);
 const noneSite=sourceSite(source,identities.runtime,230,461),nonePath=['wrapper:runtime-profile',identities.runtime,'none'];
 const noneDemand="(SELECT count(*) FROM zasp_authorization80.runtime_profile)=1 AND rp.singleton AND rp.audit_mode='none'",noneFrom=`FROM zasp_authorization80.runtime_profile rp WHERE ${noneDemand}`;
 const noneRelation=`(CASE WHEN ${noneDemand} THEN 'public.zasp_admin_audit' ELSE NULL END)::regclass`;
 addRule({
  id:'wrapper:runtime-audit:none-namespace',kind:'namespace_witness',fields:['namespace_identity'],fieldTypes:{namespace_identity:'text?'},sourceSite:noneSite,
  sourceMaxRows:1,projections:[`CASE WHEN ${noneDemand} THEN to_regnamespace('zasp_authorization80_audit')::text ELSE NULL END`],from:noneFrom,
  bag:true,sqlPhase:'witness',section:'witnesses',selector:{auditMode:'none',count:1,singleton:true,namespace:'zasp_authorization80_audit',cast:'to_regnamespace'},demandPath:nonePath
 });
 addRule({
  id:'wrapper:runtime-audit:none-relation-resolution',kind:'conditional_resolution_bag',fields:resolutionFields,fieldTypes:resolutionTypes(false),sourceSite:noneSite,
  sourceMaxRows:1,projections:[literal('public.zasp_admin_audit'),literal('regclass'),literal(noneSite.siteSHA256),`ARRAY[${quotedList(nonePath)}]::text[]`,noneRelation+'::text'],from:noneFrom,
  bag:true,sqlPhase:'resolution',section:'resolutions',selector:{auditMode:'none',count:1,singleton:true,relation:'public.zasp_admin_audit',cast:'regclass'},demandPath:nonePath
 });
 addRule({
  id:'wrapper:runtime-audit:none-trigger-inputs',kind:'trigger_witness',fields:['relation_identity','name'],fieldTypes:{relation_identity:'text',name:'text'},sourceSite:noneSite,
  sourceMaxRows:1,sourceMaxRowsBasis:'one selected runtime profile row; pg_trigger unique (tgrelid,tgname)',projections:['t.tgrelid::regclass::text','t.tgname::text'],
  from:`FROM zasp_authorization80.runtime_profile rp CROSS JOIN pg_trigger t WHERE ${noneDemand} AND t.tgrelid=${noneRelation} AND t.tgname='zasp_authorization80_audit_write_guard'`,
  bag:true,sqlPhase:'witness',section:'witnesses',selector:{auditMode:'none',count:1,singleton:true,relation:'public.zasp_admin_audit',triggerName:'zasp_authorization80_audit_write_guard'},demandPath:nonePath
 });
 const noneChildren=[...children('wrapper:runtime-profile',['singleton','audit_mode']),...children('wrapper:runtime-audit:none-namespace',['namespace_identity']),...children('wrapper:runtime-audit:none-relation-resolution',['literal','resolvedIdentity']),...children('wrapper:runtime-audit:none-trigger-inputs',['relation_identity','name'])];
 runtimeAlgebra.push({...noneSite,ruleId:'wrapper:runtime-audit:none-branch',disposition:'runtime-algebra-required',children:noneChildren,sourceExpression:Buffer.from(source.nodes.find(n=>n.identity===identities.runtime).source).subarray(230,461).toString(),equivalenceGate:'profile count guard and non-STRICT SELECT INTO precede branch demand; SQL AND evaluation order and caught errors remain live; no saved ready Boolean'});
 const runtimePath=['wrapper:runtime-profile',identities.runtime],runtimeFrom="FROM zasp_authorization80.runtime_profile rp WHERE (SELECT count(*) FROM zasp_authorization80.runtime_profile)=1 AND rp.singleton AND rp.audit_mode='source52-canonical61-audit-v1'";
 addRule({
  id:'wrapper:runtime-audit:registration-resolution',kind:'conditional_resolution_bag',fields:resolutionFields,fieldTypes:resolutionTypes(true),sourceSite:runtimeResolutionSite,
  sourceMaxRows:1,projections:[literal('zasp_authorization80_audit.registration'),literal('to_regclass'),literal(runtimeResolutionSite.siteSHA256),`ARRAY[${quotedList(runtimePath)}]::text[]`,"CASE WHEN rp.audit_mode='source52-canonical61-audit-v1' THEN to_regclass('zasp_authorization80_audit.registration')::text ELSE NULL END"],
  from:runtimeFrom,bag:true,sqlPhase:'resolution',section:'resolutions',selector:{savedBag:'wrapper:runtime-profile',auditMode:'source52-canonical61-audit-v1',count:1,singleton:true,cast:'to_regclass'},demandPath:runtimePath
 });
 addRule({
  id:'wrapper:runtime-audit:catalog-resolution',kind:'conditional_resolution_bag',fields:resolutionFields,fieldTypes:resolutionTypes(true),sourceSite:runtimeResolutionSite,
  sourceMaxRows:1,projections:[literal('zasp_authorization80_audit.catalog_ready()'),literal('to_regprocedure'),literal(runtimeResolutionSite.siteSHA256),`ARRAY[${quotedList(runtimePath)}]::text[]`,"CASE WHEN rp.audit_mode='source52-canonical61-audit-v1' THEN to_regprocedure('zasp_authorization80_audit.catalog_ready()')::text ELSE NULL END"],
  from:runtimeFrom,bag:true,sqlPhase:'resolution',section:'resolutions',selector:{savedBag:'wrapper:runtime-profile',auditMode:'source52-canonical61-audit-v1',count:1,singleton:true,cast:'to_regprocedure'},demandPath:runtimePath
 });
 addAlgebra('runtime',[
  ...noneChildren,
  ...children('wrapper:runtime-profile',['singleton','name','audit_mode']),
  ...children('wrapper:runtime-audit:registration-resolution',['literal','resolvedIdentity']),
  ...children('wrapper:runtime-audit:catalog-resolution',['literal','resolvedIdentity'])
 ]);

 const addAuditFamily=({prefix,relation,siteName,columnCount})=>{
  const site=sites[siteName],path=[site.sourceIdentity],relationLiteral=`'${relation}'::regclass`;
  addRule({
   id:`wrapper:${prefix}:relation`,kind:'relation',fields:['relation_identity','owner','raw_acl'],fieldTypes:{relation_identity:'text',owner:'text',raw_acl:'text?'},sourceSite:site,
   sourceMaxRows:1,projections:['c.oid::regclass::text','c.relowner::regrole::text','c.relacl::text'],from:`FROM pg_class c WHERE c.oid=${relationLiteral}`,
   canonicalClass:'pg_class',handleExpression:"'pg_class:'||c.oid::text||':0'",selector:{identities:[relation],catalog1Owner:catalog.relations.find(row=>row.identity===relation)?.owner},demandPath:path
  });
  addRule({
   id:`wrapper:${prefix}:columns`,kind:'column',fields:['relation_identity','number','name','raw_acl'],fieldTypes:{relation_identity:'text',number:'integer',name:'text',raw_acl:'text?'},sourceSite:site,
   projections:['a.attrelid::regclass::text','a.attnum','a.attname::text','a.attacl::text'],from:`FROM pg_attribute a WHERE a.attrelid=${relationLiteral} AND a.attnum>0 AND NOT a.attisdropped`,
   canonicalClass:'pg_attribute',handleExpression:"'pg_attribute:'||a.attrelid::text||':'||a.attnum::text",selector:{relation,attnum:{greaterThan:0},attisdropped:false,catalog1ColumnCount:columnCount},demandPath:path
  });
  addRule({
   id:`wrapper:${prefix}:relation-acl`,kind:'relation_acl_bag',fields:['relation_identity','owner','acl_defaulted','grantor','grantee','privilege','grantable'],fieldTypes:{relation_identity:'text',owner:'text',acl_defaulted:'boolean',grantor:'text',grantee:'text',privilege:'text',grantable:'boolean'},sourceSite:site,
   projections:['c.oid::regclass::text','c.relowner::regrole::text','c.relacl IS NULL',role('x.grantor'),role('x.grantee'),'x.privilege_type::text','x.is_grantable'],
   from:`FROM pg_class c CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) x WHERE c.oid=${relationLiteral}`,bag:true,
   selector:{relation,acl:'raw-or-acldefault-r',multiplicity:'expanded-tuple'},demandPath:path
  });
  addRule({
   id:`wrapper:${prefix}:column-acl`,kind:'column_acl_bag',fields:['relation_identity','number','name','owner','grantor','grantee','privilege','grantable'],fieldTypes:{relation_identity:'text',number:'integer',name:'text',owner:'text',grantor:'text',grantee:'text',privilege:'text',grantable:'boolean'},sourceSite:site,
   projections:['a.attrelid::regclass::text','a.attnum','a.attname::text','c.relowner::regrole::text',role('x.grantor'),role('x.grantee'),'x.privilege_type::text','x.is_grantable'],
   from:`FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped CROSS JOIN LATERAL aclexplode(a.attacl) x WHERE c.oid=${relationLiteral}`,bag:true,
   selector:{relation,attnum:{greaterThan:0},attisdropped:false,acl:'raw-attacl',multiplicity:'expanded-tuple'},demandPath:path
  });
  const node=source.nodes.find(row=>row.identity===site.sourceIdentity),parsed=topLevelSelect(node.source);
  addRule({
   id:`wrapper:${prefix}:snapshot`,kind:'normalization_observation_bag',fields:['normalized_acl'],fieldTypes:{normalized_acl:'json'},sourceSite:site,
   sourceMaxRows:1,projections:[parsed.projection],from:parsed.from,bag:true,sqlPhase:'witness',section:'normalizationObservations',selector:{relation,expression:'pinned-source-inline'},demandPath:path
  });
 };
 addAuditFamily({prefix:'audit-source',relation:'public.zasp_admin_audit',siteName:'sourceSnapshot',columnCount:10});
 const sourceReadySite=sourceSite(source,identities.sourceReady,281,429);
 addRule({
  id:'wrapper:audit-source:ready-relation',kind:'relation',fields:['relation_identity','kind','row_security','forced_row_security'],fieldTypes:{relation_identity:'text',kind:'text',row_security:'boolean',forced_row_security:'boolean'},sourceSite:sourceReadySite,
  sourceMaxRows:1,projections:['c.oid::regclass::text','c.relkind::text','c.relrowsecurity','c.relforcerowsecurity'],from:"FROM pg_class c WHERE c.oid='public.zasp_admin_audit'::regclass",
  canonicalClass:'pg_class',handleExpression:"'pg_class:'||c.oid::text||':0'",selector:{identities:['public.zasp_admin_audit']},demandPath:['wrapper:audit-source-acl',identities.sourceReady]
 });
 const expectedNode=source.nodes.find(row=>row.identity===identities.expected),expected=topLevelSelect(expectedNode.source);
 if(expected.from!==null)throw Error('wrapper capture expected transform source');
 addRule({
  id:'wrapper:audit-source:expected',kind:'normalization_observation_bag',fields:['normalized_acl'],fieldTypes:{normalized_acl:'json'},sourceSite:sites.expected,
  projections:[expected.projection.replace(/\bbefore_value\b/g,'s.before_state')],from:'FROM public.zasp_audit_export_source_acl s',bag:true,sqlPhase:'witness',section:'normalizationObservations',
  selector:{savedBag:'wrapper:audit-source-acl',field:'before_state',expression:'pinned-source-inline'},demandPath:['wrapper:audit-source-acl',identities.expected]
 });
 addAuditFamily({prefix:'audit-workflow',relation:'public.zasp_workflow_audit',siteName:'workflowSnapshot',columnCount:11});

 addAlgebra('sourceReady',[
  ...children('wrapper:audit-source-acl',['singleton','before_state','after_state']),
  ...children('wrapper:audit-source:ready-relation',['relation_identity','kind','row_security','forced_row_security']),
  ...children('wrapper:audit-source:expected',['normalized_acl']),
  ...children('wrapper:audit-source:snapshot',['normalized_acl'])
 ]);
 addAlgebra('sourceSnapshot',[
  ...children('wrapper:audit-source:relation',['relation_identity','owner','raw_acl']),
  ...children('wrapper:audit-source:columns',['relation_identity','number','name','raw_acl']),
  ...children('wrapper:audit-source:relation-acl',['acl_defaulted','grantor','grantee','privilege','grantable']),
  ...children('wrapper:audit-source:column-acl',['number','name','grantor','grantee','privilege','grantable'])
 ]);
 addAlgebra('catalogACL',[
  ...children('wrapper:audit-source:relation',['owner','raw_acl']),
  ...children('wrapper:audit-source:columns',['number','raw_acl']),
  ...children('wrapper:audit-source:relation-acl',['grantor','grantee','privilege','grantable']),
  ...children('wrapper:audit-source:column-acl',['number','grantor','grantee','privilege','grantable']),
  ...children('wrapper:audit-workflow:relation',['owner','raw_acl']),
  ...children('wrapper:audit-workflow:columns',['number','raw_acl']),
  ...children('wrapper:audit-workflow:relation-acl',['grantor','grantee','privilege','grantable']),
  ...children('wrapper:audit-workflow:column-acl',['number','grantor','grantee','privilege','grantable'])
 ]);
 addAlgebra('catalogRole',[
  ...children('wrapper:audit-source:relation',['owner']),
  ...children('wrapper:audit-workflow:relation',['owner'])
 ]);
 addAlgebra('workflowReady',[
  ...children('wrapper:audit-source-acl',['singleton','workflow_state']),
  ...children('wrapper:audit-workflow:snapshot',['normalized_acl'])
 ]);
 addAlgebra('workflowSnapshot',[
  ...children('wrapper:audit-workflow:relation',['relation_identity','owner','raw_acl']),
  ...children('wrapper:audit-workflow:columns',['relation_identity','number','name','raw_acl']),
  ...children('wrapper:audit-workflow:relation-acl',['acl_defaulted','grantor','grantee','privilege','grantable']),
  ...children('wrapper:audit-workflow:column-acl',['number','name','grantor','grantee','privilege','grantable'])
 ]);
 return {entries,rawRules,runtimeAlgebra,unresolved};
}
