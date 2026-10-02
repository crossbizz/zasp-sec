import crypto from 'node:crypto';

const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const frameFields=['owner','acl','config','language','security_definer','volatility','parallel','strict','leakproof','cost','rows','arguments','result'];
const authority='zasp_discovery_authority';
const authorityACL='{zasp_discovery_authority=X/zasp_discovery_authority}';
const frame=(language,security_definer,argumentsText,result)=>({owner:authority,acl:authorityACL,config:['search_path=pg_catalog, public'],language,security_definer,volatility:'s',parallel:'u',strict:false,leakproof:false,cost:100,rows:0,arguments:argumentsText,result});
const specs={
 'zasp_temporal68.predecessor_ready(text,text)':{sourceSHA256:'dd0f5fe44a5f0eb1c5853f555adce40e13e43e5fcd70cb3c0f5361a6f4afac4c',definitionSHA256:'c6eed3d3fd1aad9eb53690e2a1e364dc576e1910224af2fec91813189c944bb6',frame:frame('plpgsql',true,'c text, f text','boolean'),recipes:[[108454,115016]]},
 'zasp_temporal77.base67_fingerprint()':{sourceSHA256:'2e205ba34a6d5267f51b8436d1b5021c9fc7161f776b3b525a085615ae6f556c',definitionSHA256:'ae6456305a2ffc9aa054dd32e085fd7595859714c1cdf56946c8d837c082e907',frame:frame('sql',false,'','text'),recipes:[[96716,103278],[103627,110189],[110542,117104]]},
 'zasp_authorization80_worker.ordered_writer_definition(oid)':{sourceSHA256:'59ea633911328f4f05136e7b9818ed5e45e449c0b4f1705f02191233b0e04696',definitionSHA256:'c93753702e031b6fd99de4bf73a8c4514df60b5412d76e646f3475428781486b',frame:frame('sql',false,'value oid','text')},
 'zasp_authorization80_worker.ordered_writer_normalized_identity(oid)':{sourceSHA256:'e00f962acc31dbafd16bbba545f1e7c4f5c1efeb33aeea148d8b2703c2a5f16e',definitionSHA256:'66005303302bba2a0556d0f8199c2ef7116bee7ed66aef319e235afe8ae3fa65',frame:frame('sql',false,'value oid','text')}
};
const labels=['saved','legacy-approval-fence','legacy-action-fence','schema','function','table','column','constraint','index','trigger','foreign-key-trigger','policy'];
const branchPins={
 saved:'896cf4c6ca461438efdc8d2072732648daa97d5639bd61a80ca266e5c1d4413f','legacy-approval-fence':'51eb24269fc9ed1657a6f3020e24f5364f6eff1bf876cd19862e289bd3ed39e7','legacy-action-fence':'4b5e628134405d0deb24cc7d5372ce4c87e784c75c2ad285b2b15ef2e4ff44a0',schema:'be3549b7d4044edfb648c11846e0125fd8dbbea0038b546706b68469d92f3faf',function:'6d018f1ceb22996f8a4120e661b71d90a8089cbb59cb0155d06cf20a23a45161',table:'eaee4a4e227826501bdd7843c878ac9a4abcb0ed67b259bf0235f2ad4e7672bf',column:'2ff1e3bfbf3fc934d4c8d66968f53b07cb9d92ea07c2917af0973914dafcaea0',constraint:'fb33f6f11807f8c5158ea69a1b4147e844204a2d04117332b39b704f8bf661fd',index:'7ff0ae2ab21cb7fb9a053e125d2150c8a0eaaf129c02d63864a757de790937f6',trigger:'b6f57c516be7ce586f73a7b273fad525f901d8dfe5b67c3c5375fa756a6ddc95','foreign-key-trigger':'eee5ba05bff4fff480c63e73ecc24aec142d68777d2c5302fd563f6bc3e206d0',policy:'5e172040ea207cd381fc610778a20a04634ab360af73620fed3c5629844c6de7'
};
const recipeSHA256='73a57356b9f058b94a2c4cde0343ccfb41543e9f788fde78445b2da5a33d7fa2';
const savedStart="SELECT concat_ws('|','saved',signature,replace(replace(definition,'033bf2";
const recipeEnd="\n ) SELECT encode(digest(convert_to(string_agg(value,E'\\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities";
const unionPrefix='\n UNION ALL ';
const refs=(ruleId,fields)=>fields.map(field=>({ruleId,field}));
const fullRoutineFields=['routine_identity','definition','source_body','owner','raw_acl','language','volatility','security_definer','strict','parallel','leakproof','config_json','config_raw','config_dims','config_ndims','config_bounds','identity_arguments','result','cost','rows'];
const fullRoutineTypes={routine_identity:'text',definition:'text',source_body:'text',owner:'text',raw_acl:'text?',language:'text',volatility:'text',security_definer:'boolean',strict:'boolean',parallel:'text',leakproof:'boolean',config_json:'json?',config_raw:'text?',config_dims:'text?',config_ndims:'integer?',config_bounds:'json?',identity_arguments:'text',result:'text',cost:'number',rows:'number'};
const fullRoutineProjections=['p.oid::regprocedure::text','pg_get_functiondef(p.oid)','p.prosrc::text','p.proowner::regrole::text','p.proacl::text','l.lanname::text','p.provolatile::text','p.prosecdef','p.proisstrict','p.proparallel::text','p.proleakproof','to_jsonb(p.proconfig)','p.proconfig::text','array_dims(p.proconfig)','array_ndims(p.proconfig)','(SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,d),array_upper(p.proconfig,d)) ORDER BY d) FROM generate_series(1,array_ndims(p.proconfig)) d)','pg_get_function_identity_arguments(p.oid)','pg_get_function_result(p.oid)','p.procost','p.prorows'];
const resolutionFields=['literal','cast','sourceSite','demandPath','resolvedIdentity'];
const resolutionTypes=Object.fromEntries(resolutionFields.map(field=>[field,'text']));
const deploymentCompileIdentity='zasp_sa_multistep_prior.deployment_compile(jsonb,boolean)';

function selectedNode(contract,identity){
 if(!contract||!Array.isArray(contract.nodes))throw Error('materialized source pin');
 const matches=contract.nodes.filter(node=>node.identity===identity),spec=specs[identity];
 if(!spec||matches.length!==1)throw Error('materialized source pin '+identity);
 const node=matches[0];
 if(typeof node.source!=='string'||typeof node.definition!=='string'||node.sourceSHA256!==spec.sourceSHA256||sha(node.source)!==spec.sourceSHA256||node.definitionSHA256!==spec.definitionSHA256||sha(node.definition)!==spec.definitionSHA256)throw Error('materialized source pin '+identity);
 const actual=Object.fromEntries(frameFields.map(field=>[field,node[field]]));
 if(JSON.stringify(actual)!==JSON.stringify(spec.frame))throw Error('materialized source frame '+identity);
 return node;
}

function sourceSite(node,start=0,end=Buffer.byteLength(node.source)){
 const bytes=Buffer.from(node.source),text=bytes.subarray(start,end).toString('utf8');
 return {sourceIdentity:node.identity,sourceSHA256:node.sourceSHA256,definitionSHA256:node.definitionSHA256,siteSHA256:sha(text),start,end,frame:Object.fromEntries(frameFields.map(field=>[field,structuredClone(node[field])]))};
}

function recipes(node){
 const expected=specs[node.identity].recipes,found=[];
 let cursor=0;
 while(true){
  const start=node.source.indexOf(savedStart,cursor);if(start<0)break;
  const end=node.source.indexOf(recipeEnd,start);if(end<0)throw Error('materialized recipe end '+node.identity);
  const recipeSite=sourceSite(node,start,end);
  if(recipeSite.siteSHA256!==recipeSHA256)throw Error('materialized recipe pin '+node.identity);
  const starts=[start];
  for(let union=node.source.indexOf(unionPrefix,start);union>=0&&union<end;union=node.source.indexOf(unionPrefix,union+1))starts.push(union+unionPrefix.length);
  if(starts.length!==labels.length)throw Error('materialized recipe branch count '+node.identity);
  const branches=starts.map((branchStart,index)=>{
   const branchEnd=index+1<starts.length?starts[index+1]-unionPrefix.length:end,site=sourceSite(node,branchStart,branchEnd);
   const label=siteText(node,site).match(/concat_ws\('\|','([^']+)'/)?.[1];
   if(label!==labels[index]||site.siteSHA256!==branchPins[label])throw Error('materialized recipe branch '+node.identity+' '+index);
   return {...site,label,text:siteText(node,site)};
  });
  found.push({site:recipeSite,branches});cursor=end+1;
 }
 if(JSON.stringify(found.map(row=>[row.site.start,row.site.end]))!==JSON.stringify(expected))throw Error('materialized recipe coverage '+node.identity);
 return found;
}

function siteText(node,site){return Buffer.from(node.source).subarray(site.start,site.end).toString('utf8');}

function childSite(node,branch,text){
 const relative=branch.text.indexOf(text);if(relative<0)throw Error('materialized source child '+branch.label);
 return sourceSite(node,branch.start+Buffer.byteLength(branch.text.slice(0,relative)),branch.start+Buffer.byteLength(branch.text.slice(0,relative+text.length)));
}

function validateCatalog(catalog,nodes){
 if(!catalog||!Array.isArray(catalog.functions)||!Array.isArray(catalog.relations)||!Array.isArray(catalog.columns))throw Error('materialized catalog pin');
 for(const [identity,node] of nodes){
  const rows=catalog.functions.filter(row=>row.identity===identity);
  if(rows.length!==1||sha(rows[0].definition)!==node.definitionSHA256||frameFields.some(field=>JSON.stringify(rows[0][field])!==JSON.stringify(node[field])))throw Error('materialized catalog pin '+identity);
 }
 const shapes={
  'zasp_sa_multistep_prior.functions':[['signature','text'],['definition','text'],['owner_name','text'],['acl','jsonb']],
  'zasp_temporal77.predecessor_functions':[['signature','text'],['definition','text'],['owner_name','text'],['acl','text']],
  'zasp_authorization80_worker.predecessor_functions':[['signature','text'],['definition','text'],['owner_name','text'],['acl','text']]
 };
 for(const [relation,shape] of Object.entries(shapes)){
  if(catalog.relations.filter(row=>row.identity===relation).length!==1)throw Error('materialized catalog pin '+relation);
  const columns=catalog.columns.filter(row=>row.relation===relation).sort((a,b)=>a.position-b.position);
  if(columns.length!==shape.length||columns.some((row,index)=>row.position!==index+1||row.name!==shape[index][0]||row.type!==shape[index][1]||row.not_null!==true))throw Error('materialized catalog pin '+relation);
 }
}

export function buildOrderedMaterializedCaptureInputs(sourceContract,catalog){
 const nodes=new Map(Object.keys(specs).map(identity=>[identity,selectedNode(sourceContract,identity)]));
 validateCatalog(catalog,nodes);
 const predecessor=nodes.get('zasp_temporal68.predecessor_ready(text,text)'),base67=nodes.get('zasp_temporal77.base67_fingerprint()');
 const copied=[...recipes(predecessor),...recipes(base67)],first=new Map(copied[0].branches.map(branch=>[branch.label,branch]));
 const entries=[],rawRules=[],runtimeAlgebra=[],unresolved=[];
 const addRule=(rule,demandPath)=>{
  rawRules.push(rule);
  rule.fields.forEach((field,expressionOrdinal)=>entries.push({...rule.sourceSite,expressionOrdinal,field,sourceExpression:rule.projections[expressionOrdinal],selector:structuredClone(rule.selector),demandPath:[...demandPath],disposition:'capture',evidence:{phase:rule.sqlPhase??'original',ruleId:rule.id,field}}));
 };
 const canonical=(id,kind,fields,types,projections,from,label,canonicalClass,handleExpression,selector)=>addRule({id,kind,fields,fieldTypes:Object.fromEntries(fields.map((field,index)=>[field,types[index]])),projections,from,sourceSite:first.get(label),sourceMaxRows:label==='schema'?1:null,refusalMaxRows:10000,canonicalClass,handleExpression,selector},['materialized-sa-multistep-prior',label]);
 const routineFields=['name','identity_arguments','raw_owner','security_definer','volatility','parallel','strict','leakproof','config_raw','raw_acl','definition'];
 const routineTypes=['text','text','text','boolean','text','text','boolean','boolean','text?','text?','text'];
 const routineProjections=['p.proname::text','pg_get_function_identity_arguments(p.oid)','p.proowner::regrole::text','p.prosecdef','p.provolatile::text','p.proparallel::text','p.proisstrict','p.proleakproof','p.proconfig::text','p.proacl::text','pg_get_functiondef(p.oid)'];
 const approvalNames=['zasp_security_agent_decide_approval','zasp_security_agent_decide_approval_v22','zasp_security_agent_decide_approval_v23','zasp_security_agent_decide_approval_v24','zasp_security_agent_expire_approvals_v28'];
 const actionNames=['zasp_security_agent_claim_temporary_policy_effects','zasp_security_agent_heartbeat_temporary_policy_effect','zasp_security_agent_dispatch_temporary_policy_run','zasp_security_agent_finish_temporary_policy_effect','zasp_security_agent_store_temporary_policy_target','zasp_security_agent_store_temporary_policy_target_v27','zasp_policy_deployment_store_temporary_source','zasp_security_agent_execute_run','zasp_security_agent_execute_run_v21','zasp_security_agent_execute_run_v22','zasp_security_agent_execute_run_v23','zasp_security_agent_execute_run_v24'];
 const names=values=>values.map(value=>`'${value}'`).join(',');
 addRule({id:'saved-input:zasp_sa_multistep_prior.functions',kind:'saved_bag',fields:['signature','definition','owner_name','acl'],fieldTypes:{signature:'text',definition:'text',owner_name:'text',acl:'json'},projections:['signature::text','definition::text','owner_name::text','acl'],from:'FROM zasp_sa_multistep_prior.functions',sourceSite:first.get('saved'),sourceMaxRows:null,refusalMaxRows:10000,bag:true,selector:{table:'zasp_sa_multistep_prior.functions',predicate:null}},['materialized-sa-multistep-prior','saved']);
 canonical('materialized:sa-multistep-prior:legacy-approval-fence','routine',routineFields,routineTypes,routineProjections,`FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname IN(${names(approvalNames)})`,'legacy-approval-fence','pg_proc',"'pg_proc:'||p.oid::text||':0'",{namespace:'public',names:approvalNames});
 canonical('materialized:sa-multistep-prior:legacy-action-fence','routine',routineFields,routineTypes,routineProjections,`FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname IN(${names(actionNames)})`,'legacy-action-fence','pg_proc',"'pg_proc:'||p.oid::text||':0'",{namespace:'public',names:actionNames});
 canonical('materialized:sa-multistep-prior:schema','namespace',['name','owner','raw_acl'],['text','text','text?'],['n.nspname::text','n.nspowner::regrole::text','n.nspacl::text'],"FROM pg_namespace n WHERE n.nspname='zasp_sa_multistep_prior'",'schema','pg_namespace',"'pg_namespace:'||n.oid::text||':0'",{name:'zasp_sa_multistep_prior'});
 canonical('materialized:sa-multistep-prior:function','routine',routineFields,routineTypes,routineProjections,"FROM pg_proc p WHERE p.pronamespace='zasp_sa_multistep_prior'::regnamespace",'function','pg_proc',"'pg_proc:'||p.oid::text||':0'",{namespace:'zasp_sa_multistep_prior'});
 canonical('materialized:sa-multistep-prior:table','relation',['name','kind','persistence','owner','row_security','forced_row_security','raw_acl'],['text','text','text','text','boolean','boolean','text?'],['c.relname::text','c.relkind::text','c.relpersistence::text','c.relowner::regrole::text','c.relrowsecurity','c.relforcerowsecurity','c.relacl::text'],"FROM pg_class c WHERE c.relnamespace='zasp_sa_multistep_prior'::regnamespace AND c.relkind IN('r','v','m','p','S')",'table','pg_class',"'pg_class:'||c.oid::text||':0'",{namespace:'zasp_sa_multistep_prior',relationKinds:['r','v','m','p','S']});
 canonical('materialized:sa-multistep-prior:column','column',['relation_name','position','name','type','not_null','identity','generated','collation','default_expression','raw_acl'],['text','integer','text','text','boolean','text','text','text','text?','text?'],['c.relname::text','a.attnum','a.attname::text','format_type(a.atttypid,a.atttypmod)','a.attnotnull','a.attidentity::text','a.attgenerated::text','a.attcollation::regcollation::text','pg_get_expr(d.adbin,d.adrelid)','a.attacl::text'],"FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_sa_multistep_prior'::regnamespace AND c.relkind IN('r','p') AND a.attnum>0 AND NOT a.attisdropped",'column','pg_attribute',"'pg_attribute:'||a.attrelid::text||':'||a.attnum::text",{namespace:'zasp_sa_multistep_prior',relationKinds:['r','p'],positiveAttributes:true,excludeDropped:true});
 canonical('materialized:sa-multistep-prior:constraint','constraint',['relation_name','name','definition','validated'],['text','text','text','boolean'],['c.relname::text','k.conname::text','pg_get_constraintdef(k.oid)','k.convalidated'],"FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_sa_multistep_prior'::regnamespace",'constraint','pg_constraint',"'pg_constraint:'||k.oid::text||':0'",{namespace:'zasp_sa_multistep_prior'});
 canonical('materialized:sa-multistep-prior:index','index',['relation_name','definition','valid','ready','live'],['text','text','boolean','boolean','boolean'],['c.relname::text','pg_get_indexdef(i.indexrelid)','i.indisvalid','i.indisready','i.indislive'],"FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_sa_multistep_prior'::regnamespace",'index','pg_class',"'pg_class:'||i.indexrelid::text||':0'",{namespace:'zasp_sa_multistep_prior'});
 canonical('materialized:sa-multistep-prior:trigger','trigger',['relation_name','name','enabled','definition'],['text','text','text','text'],['c.relname::text','t.tgname::text','t.tgenabled::text','pg_get_triggerdef(t.oid)'],"FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_sa_multistep_prior'::regnamespace",'trigger','pg_trigger',"'pg_trigger:'||t.oid::text||':0'",{namespace:'zasp_sa_multistep_prior',internal:false});
 canonical('materialized:sa-multistep-prior:foreign-key-trigger','foreign_key_trigger',['relation','name','referenced_relation','trigger_relation','constraint_relation','function','event_bits','enabled','deferrable','deferred','argument_count','arguments','columns_text','when_text_or_empty'],['text','text','text','text','text','text','integer','text','boolean','boolean','integer','text','text','text'],['k.conrelid::regclass::text','k.conname::text','k.confrelid::regclass::text','t.tgrelid::regclass::text','t.tgconstrrelid::regclass::text','t.tgfoid::regprocedure::text','t.tgtype','t.tgenabled::text','t.tgdeferrable','t.tginitdeferred','t.tgnargs','encode(t.tgargs,\'hex\')','t.tgattr::text',"COALESCE(pg_get_expr(t.tgqual,t.tgrelid),'')"],"FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='zasp_sa_multistep_prior'::regnamespace",'foreign-key-trigger','pg_trigger',"'pg_trigger:'||t.oid::text||':0'",{namespace:'zasp_sa_multistep_prior',internal:true,constraintType:'f'});
 canonical('materialized:sa-multistep-prior:policy','policy',['relation_name','name','command','permissive','roles','using','check'],['text','text','text','boolean','text?','text?','text?'],['c.relname::text','p.polname::text','p.polcmd::text','p.polpermissive','p.polroles::regrole[]::text','pg_get_expr(p.polqual,p.polrelid)','pg_get_expr(p.polwithcheck,p.polrelid)'],"FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_sa_multistep_prior'::regnamespace",'policy','pg_policy',"'pg_policy:'||p.oid::text||':0'",{namespace:'zasp_sa_multistep_prior'});
 addRule({id:'materialized:sa-multistep-prior:deployment-compile-saved',kind:'saved_bag',fields:['signature','definition'],fieldTypes:{signature:'text',definition:'text'},projections:['signature::text','definition::text'],from:"FROM zasp_temporal77.predecessor_functions WHERE signature='zasp_sa_multistep_prior.deployment_compile(jsonb,boolean)'",sourceSite:first.get('function'),sourceMaxRows:null,refusalMaxRows:10000,bag:true,selector:{table:'zasp_temporal77.predecessor_functions',signature:'zasp_sa_multistep_prior.deployment_compile(jsonb,boolean)'}},['materialized-sa-multistep-prior','function','deployment-compile-saved-scalar']);

 const addHelperRoutine=(id,identity)=>{
  const node=nodes.get(identity);
  addRule({id,kind:'routine',fields:[...fullRoutineFields],fieldTypes:{...fullRoutineTypes},projections:[...fullRoutineProjections],from:`FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='${identity}'::regprocedure`,sourceSite:sourceSite(node),sourceMaxRows:1,refusalMaxRows:10000,canonicalClass:'pg_proc',handleExpression:"'pg_proc:'||p.oid::text||':0'",selector:{identity,cardinality:'exactly-one-canonical-routine',frame:'pg_catalog, public'}},[identity,'source-routine-input']);
 };
 addHelperRoutine('materialized:ordered-writer-definition:routine','zasp_authorization80_worker.ordered_writer_definition(oid)');
 addHelperRoutine('materialized:ordered-writer-normalized-identity:routine','zasp_authorization80_worker.ordered_writer_normalized_identity(oid)');

 const writer=nodes.get('zasp_authorization80_worker.ordered_writer_definition(oid)');
 const helperMatches=[...writer.source.matchAll(/'((?:[^']|'')*)'::regprocedure/g)];
 if(helperMatches.length!==15||new Set(helperMatches.map(match=>match[1])).size!==15)throw Error('materialized writer helper bindings');
 const helperBindings=helperMatches.map(match=>match[1]);
 const helperLiteralSites=helperMatches.map(match=>sourceSite(writer,Buffer.byteLength(writer.source.slice(0,match.index)),Buffer.byteLength(writer.source.slice(0,match.index+match[0].length))));
 const resolution=(id,literal,origin,raw,demandPath,selector,demand='p.oid IS NOT NULL')=>{
  const projections=[`'${literal}'`,"'regprocedure'",`'${origin.siteSHA256}'`,`'${demandPath}'`,`((CASE WHEN ${demand} THEN '${literal}' ELSE NULL END)::regprocedure)::text`];
  const from=raw.from+(/\bWHERE\b/.test(raw.from)?' AND ':' WHERE ')+`(${demand})`;
  addRule({id,kind:'resolution',fields:[...resolutionFields],fieldTypes:{...resolutionTypes},projections,from,sourceSite:origin,sourceMaxRows:null,refusalMaxRows:10000,bag:true,sqlPhase:'resolution',section:'resolutions',selector:{...selector,callerDemandPath:demandPath,literal,cast:'regprocedure',selectedRowDemand:demand}},[demandPath,literal]);
  return refs(id,resolutionFields);
 };

 const rawByLabel=new Map([['saved',rawRules[0]],...labels.slice(1).map(label=>[label,rawRules.find(rule=>rule.id===`materialized:sa-multistep-prior:${label}`)])]);
 for(const recipe of copied)for(const branch of recipe.branches){
  const raw=rawByLabel.get(branch.label),children=refs(raw.id,raw.fields),sourceChildren=[];
  if(branch.label==='function')children.push(...refs('materialized:sa-multistep-prior:deployment-compile-saved',['signature','definition']));
  if(['legacy-approval-fence','legacy-action-fence','function'].includes(branch.label)){
   const call=branch.label==='function'?'zasp_authorization80_worker.ordered_writer_normalized_identity(p.oid)':'zasp_authorization80_worker.ordered_writer_definition(p.oid)',target=branch.label==='function'?'zasp_authorization80_worker.ordered_writer_normalized_identity(oid)':'zasp_authorization80_worker.ordered_writer_definition(oid)',site=childSite(nodes.get(branch.sourceIdentity),branch,call),demandPath=`${branch.sourceIdentity}:${branch.start}:${branch.label}`;
   const helperRoutineId=branch.label==='function'?'materialized:ordered-writer-normalized-identity:routine':'materialized:ordered-writer-definition:routine';
   children.push(...refs(helperRoutineId,fullRoutineFields));
   let helperDemand='p.oid IS NOT NULL';
   if(branch.label==='function'){
    const guardMatches=[...branch.text.matchAll(new RegExp("'"+deploymentCompileIdentity.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+"'::regprocedure",'g'))];
    if(guardMatches.length!==1)throw Error('materialized deployment compile guard '+branch.sourceIdentity+' '+branch.start);
    const match=guardMatches[0],origin=sourceSite(nodes.get(branch.sourceIdentity),branch.start+Buffer.byteLength(branch.text.slice(0,match.index)),branch.start+Buffer.byteLength(branch.text.slice(0,match.index+match[0].length)));
    children.push(...resolution(`materialized:${branch.sourceIdentity}:${branch.start}:${branch.label}:branch-resolution:0`,deploymentCompileIdentity,origin,raw,demandPath,{outerRuleId:raw.id,branchGuard:'deployment-compile-saved-arm'}));
    helperDemand=`p.oid<>'${deploymentCompileIdentity}'::regprocedure`;
   }
   helperBindings.forEach((literal,ordinal)=>children.push(...resolution(`materialized:${branch.sourceIdentity}:${branch.start}:${branch.label}:helper-resolution:${ordinal}`,literal,helperLiteralSites[ordinal],raw,demandPath,{outerRuleId:raw.id,helperIdentity:target,helperSourceSite:helperLiteralSites[ordinal]},helperDemand)));
   const scopeMatches=[...branch.text.matchAll(/'(zasp_sa_multistep_prior\.(?:lock_scope|pricing_lock_scope)\(text,text,text,text\))'::regprocedure/g)];
   if(scopeMatches.length!==4)throw Error('materialized scope owner bindings '+branch.sourceIdentity+' '+branch.start);
   scopeMatches.forEach((match,ordinal)=>{
    const relativeStart=match.index,origin=sourceSite(nodes.get(branch.sourceIdentity),branch.start+Buffer.byteLength(branch.text.slice(0,relativeStart)),branch.start+Buffer.byteLength(branch.text.slice(0,relativeStart+match[0].length)));
    children.push(...resolution(`materialized:${branch.sourceIdentity}:${branch.start}:${branch.label}:scope-resolution:${ordinal}`,match[1],origin,raw,demandPath,{outerRuleId:raw.id,scopeOwnerMarker:true,physicalOccurrence:ordinal}));
   });
   sourceChildren.push({sourceIdentity:target,sourceSite:site,required:'exact selected helper frame, caller definition input, saved CASE bag, 15 helper-local literal resolutions and four physical scope-owner cast resolutions',execution:'selected original row only; helper result is not an expected fact'});
  }
  runtimeAlgebra.push({...branch,ruleId:`materialized:${branch.sourceIdentity}:${branch.start}:${branch.label}`,branch:branch.label,disposition:'materialized-legacy-branch-algebra',children,sourceChildren,expectedFact:false,cardinality:'preserve original UNION ALL multiset, concat_ws NULL skipping, empty aggregate NULL, scalar zero/NULL/multiple-row behavior and original cast errors',normalization:branch.label==='saved'?{replacements:[['033bf2ffa9d4a60121d4f20436ff7de36d1421b62f849254a09048caf75998e6','<compiled-checksum>'],['2941a7ee76eb6af211f0329a9f16bace0b63dbdd22023280a98a4baa55529d98','<compiled-fingerprint>']]}:['legacy-approval-fence','legacy-action-fence','function'].includes(branch.label)?{scopeOwnerMarkers:true,rawOwnerACLRequired:true}:undefined});
 }

 runtimeAlgebra.push({...sourceSite(writer),ruleId:'materialized:ordered-writer-definition:algebra',disposition:'selected-helper-source-algebra',children:[...refs('materialized:ordered-writer-definition:routine',fullRoutineFields),...refs('saved-input:zasp_authorization80_worker.predecessor_functions',['signature','definition','owner_name','acl'])],sourceChildren:[],helperBindings,argument:'caller-selected pg_proc oid',fallback:'caller raw pg_get_functiondef value',expectedFact:false,cardinality:'saved scalar zero rows => NULL; multiple rows => error; ELSE definition remains the caller-selected current definition'});
 const normalized=nodes.get('zasp_authorization80_worker.ordered_writer_normalized_identity(oid)'),normalizedCall='zasp_authorization80_worker.ordered_writer_definition(value)',normalizedCallStart=normalized.source.indexOf(normalizedCall),normalizedCallSite=sourceSite(normalized,normalizedCallStart,normalizedCallStart+Buffer.byteLength(normalizedCall));
 runtimeAlgebra.push({...sourceSite(normalized),ruleId:'materialized:ordered-writer-normalized-identity:algebra',disposition:'selected-helper-source-algebra',children:refs('materialized:ordered-writer-normalized-identity:routine',fullRoutineFields),sourceChildren:[{sourceIdentity:'zasp_authorization80_worker.ordered_writer_definition(oid)',sourceSite:normalizedCallSite,required:'all source-selected raw children under the original helper-local frame',execution:'selected original caller row only'}],replacements:[{from:'033bf2ffa9d4a60121d4f20436ff7de36d1421b62f849254a09048caf75998e6',to:'<compiled-checksum>'},{from:'2941a7ee76eb6af211f0329a9f16bace0b63dbdd22023280a98a4baa55529d98',to:'<compiled-fingerprint>'},{from:'6b6a74cba9ee791d8b23c08df2f3d08949a339e23460694bc0e2d2d3f25c8e92',to:'<registered-fingerprint>'}],expectedFact:false});

 return {entries,rawRules,runtimeAlgebra,unresolved};
}
