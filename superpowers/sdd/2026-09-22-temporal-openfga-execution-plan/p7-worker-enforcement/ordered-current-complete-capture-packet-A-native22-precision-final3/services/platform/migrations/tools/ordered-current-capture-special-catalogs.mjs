import crypto from 'node:crypto';

const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const frameFields=['owner','acl','config','language','security_definer','volatility','parallel','strict','leakproof','cost','rows','arguments','result'];
const operator='zasp_security_agent_global_operator';
const globalIdentity='public.zasp_production_security_agent_existing_tests_global_fingerprin()';
const complianceIdentity='public.zasp_compliance_jobs_catalog()';
const globalRelations=['public.zasp_security_agent_global_control_receipts','public.zasp_security_agent_kill_switches','public.zasp_security_agent_audit','public.zasp_discovery_principal_bindings','zasp_existing_tests_predecessor.global_control_triggers'];
const relationSelector={relationLiterals:globalRelations};
const complianceRelationSelector={namespace:'public',relationName:{startsWith:'zasp_compliance_export_',orEquals:'zasp_compliance_worker_bindings'}};
const complianceGlobalSelector={relationName:{startsWith:'zasp_compliance_export_',orEquals:'zasp_compliance_worker_bindings'},namespaceRestriction:null};

const sourcePins={
  [globalIdentity]:{
    sourceSHA256:'76ccb7e1f7f530c9d371ab9f9ccf43a9587d1fb927086fc6aefc9384664a9045',
    definitionSHA256:'f6a27f7e6f19d841d305c9be19a205d900643c2eb93687b156572745b12a197b',
    sites:[
      [0,642,'05e994aad7c81155970d7e27d00a00adda45e105c2ab69496877d1957f0721d3'],
      [642,906,'6b4c4233243cb366892782d2ef324794e7330b51a20ee2177e5b0b8b7d352bb3'],
      [906,1127,'293ad57fe6ea984b9ec280d9dcd93c19bfd2625febee227d843784cbb3c7bb15'],
      [1127,1289,'787259376c2590ac3887e8187d63c2c4bb946f6136c006f1a58ee6dcbc795aa7'],
      [1289,1425,'7b5991f0ebfd9997086d66a9154d05cc977d2313b9edf6340d461626815de861'],
      [1425,1560,'930fd03a4872ce8780c13858a532e61c8d3cf37246b573838b35435c8667dd94'],
      [1560,1895,'4d9fb8b395db04512b19d0f22428c422a9eb1405dd0adc691b754b4324e45067'],
      [1895,2168,'61aaa033ddcc6b0f7f139e6e040818aa4d60981fe16e5895930aa9097f40435f'],
      [2168,2614,'0c7d8f3155dd2124431016365bf769128abe7286506ff8e8ab0830ab6140ccea'],
      [2614,2801,'a115a20256f5d45bd9bd290c2e9bf2e4391e6557e99f6824a4b52d6e6e2937cb'],
      [2801,3013,'6fea542d707530f43fa762c4bc9ad6ae49adafbacd57817f050ddadef4dcc8c5'],
      [3013,3326,'5c40ac65ea8095c562ece1825946f5854cfe7163eee9b19b2983421d301a5418'],
      [3326,3546,'e6847477c3118da8753811bf13e569ab139a166f466e1e28465d9c5959df8d7e'],
      [3546,3788,'ac3549a0c0d0ea3413f568c25b45eb0d6e28a6d3a3afddee501911fa3a27623a'],
      [3788,4038,'90c41daf88c0c00e9e1d67e5231b9a300fbaacaf29ac866cefbd74bb3dd39290'],
      [4038,4305,'3452dbd579dddbc90e0d9bed495ade00b0fe521a046cd8a7e06e19d270a38f41'],
      [4305,4558,'4ef7fe80bbc7c61ab632b608f530b8eb7882a22d39e328a141cd26a4c521d5eb'],
      [4558,4798,'000d80ed226ec0716e291c5e1b074341c9e18318bc066f3c1473fe87220e9cfe']
    ]
  },
  [complianceIdentity]:{
    sourceSHA256:'40c581b50272ca9e174fd8ee45af64a7d06b0ce9660df1028b5e05283c92529b',
    definitionSHA256:'f4a0b4d00f6b30c7eace177c9f3b3a5afdc0739f105a2d9e1f426a6c4f91adc9',
    sites:[
      [0,363,'e698cd462666ec01e377d9ca8643f02487a9d053fad22b06940f62e7086f7cc8'],
      [363,1085,'89211c012c7dd69b9581ba5138d524c556d868622e9e5a04162a631e16941b9a'],
      [1085,1353,'8a5d40b6a98c8c7f6fccc1182a0ddf44f9dc441c6087d342e851455d382afe5e'],
      [1353,1614,'dadd034a1e9c4f40b6db9723b833e06177059ebcfd5927b52a31a43e17a08740'],
      [1614,2023,'ec4acb6f4655821d578ba9c908f5c50a2206dad8023c81cfc95f2bce6da8b7f8'],
      [2023,2302,'677cd42b55f9554aefb9fed0ff2408e83f062d63ed3191418bfbeb22e9ec7fa9'],
      [2302,2594,'22876952f6e74b0ba9aef7cd3ec9a981664f4dee12244ac8699e2c9ff2a40608'],
      [2594,2685,'c0cba462618504d87022e9e81784d8d3e1f44bc16d51eefc977c811401967e74']
    ]
  }
};

const types=(fields,values)=>Object.fromEntries(fields.map((field,index)=>[field,values[index]]));
const spec=(label,kind,fields,wireTypes,selector,extra={})=>({label,kind,fields,fieldTypes:types(fields,wireTypes),selector,...extra});
const configFields=['config_json','config_raw','config_dims','config_ndims','config_bounds'];
const configTypes=['json?','text?','text?','integer?','json?'];
const configProjections=['to_jsonb(rolconfig)','rolconfig::text','array_dims(rolconfig)','array_ndims(rolconfig)','(SELECT jsonb_agg(jsonb_build_array(array_lower(rolconfig,d),array_upper(rolconfig,d)) ORDER BY d) FROM generate_series(1,array_ndims(rolconfig)) d)'];
const globalSpecs=[
  spec('role','role',['name','superuser','inherit','create_role','create_db','login','replication','bypass_rls','connection_limit','valid_until_text_or_empty','config_raw_text_or_empty',...configFields],['text','boolean','boolean','boolean','boolean','boolean','boolean','boolean','integer','text','text',...configTypes],{roleName:operator},{sourceMaxRows:1,canonicalClass:'pg_authid',handleExpression:"'pg_authid:'||oid::text||':0'",extraProjections:configProjections}),
  spec('membership','membership_bag',['granted_role','member_role','grantor_role','admin_option'],['text','text','text','boolean'],{eitherRole:operator},{bag:true}),
  spec('owned-function','routine',['original_identity','security_definer','acl_text_or_empty','definition'],['text','boolean','text','text'],{ownerRole:operator},{canonicalClass:'pg_proc',handleExpression:"'pg_proc:'||p.oid::text||':0'"}),
  spec('owned-relation','relation',['original_identity','relation_kind'],['text','text'],{ownerRole:operator},{canonicalClass:'pg_class',handleExpression:"'pg_class:'||c.oid::text||':0'"}),
  spec('owned-schema','namespace',['name'],['text'],{ownerRole:operator},{canonicalClass:'pg_namespace',handleExpression:"'pg_namespace:'||oid::text||':0'"}),
  spec('owned-database','database',['name'],['text'],{ownerRole:operator},{canonicalClass:'pg_database',handleExpression:"'pg_database:'||oid::text||':0'"}),
  spec('default-acl','default_acl',['role','namespace','object_type','acl_text'],['text','text?','text','text?'],{roleOrAclGrantee:operator},{canonicalClass:'pg_default_acl',handleExpression:"'pg_default_acl:'||oid::text||':0'"}),
  spec('table','relation',['original_identity','relation_kind','persistence','row_security','force_row_security','owner','acl_text_or_empty','options_text_or_empty'],['text','text','text','boolean','boolean','text','text','text'],relationSelector,{sourceMaxRows:5,canonicalClass:'pg_class',handleExpression:"'pg_class:'||c.oid::text||':0'",usesRelationsCte:true}),
  spec('column','column',['relation_identity','physical_position','name','type','not_null','identity','generated','collation','default_text_or_empty','acl_text_or_empty'],['text','integer','text','text','boolean','text','text','text','text','text'],relationSelector,{canonicalClass:'pg_attribute',handleExpression:"'pg_attribute:'||a.attrelid::text||':'||a.attnum::text",usesRelationsCte:true}),
  spec('constraint','constraint',['relation_identity','name','validated','definition_pretty'],['text','text','boolean','text'],relationSelector,{canonicalClass:'pg_constraint',handleExpression:"'pg_constraint:'||oid::text||':0'",usesRelationsCte:true}),
  spec('index','index',['relation_identity','index_identity','valid','ready','live','definition'],['text','text','boolean','boolean','boolean','text'],relationSelector,{canonicalClass:'pg_class',handleExpression:"'pg_class:'||indexrelid::text||':0'",usesRelationsCte:true}),
  spec('policy','policy',['relation_identity','name','permissive','command','roles_csv','using_expression','check_expression'],['text','text','boolean','text','text?','text?','text?'],relationSelector,{canonicalClass:'pg_policy',handleExpression:"'pg_policy:'||oid::text||':0'",usesRelationsCte:true}),
  spec('trigger','trigger',['relation_identity','name','enabled','definition_pretty','routine_identity'],['text','text','text','text','text'],relationSelector,{canonicalClass:'pg_trigger',handleExpression:"'pg_trigger:'||oid::text||':0'",usesRelationsCte:true}),
  spec('saved-trigger','saved_trigger',['relation_name','trigger_name','definition','enabled'],['text','text','text','text'],{table:'zasp_existing_tests_predecessor.global_control_triggers',predicate:null},{bag:true}),
  spec('relation-grant','acl_bag',['relation_identity','privilege','grantable','grantor_role'],['text','text','boolean','text'],{aclGrantee:operator},{bag:true}),
  spec('column-grant','acl_bag',['relation_identity','column_name','privilege','grantable','grantor_role'],['text','text','text','boolean','text'],{aclGrantee:operator},{bag:true}),
  spec('function-grant','acl_bag',['routine_identity','privilege','grantable','grantor_role'],['text','text','boolean','text'],{aclGrantee:operator},{bag:true}),
  spec('schema-grant','acl_bag',['namespace_name','privilege','grantable','grantor_role'],['text','text','boolean','text'],{aclGrantee:operator},{bag:true})
];
const complianceSpecs=[
  spec('relation','relation',['name','owner','relation_kind','row_security','force_row_security','acl_text_or_empty'],['text','text','text','boolean','boolean','text'],complianceRelationSelector,{canonicalClass:'pg_class',handleExpression:"'pg_class:'||c.oid::text||':0'"}),
  spec('column','column',['relation_name','normalized_position','name','type','not_null','default_text_or_empty','acl_text_or_empty','identity','generated','collation'],['text','integer','text','text','boolean','text','text','text','text','text'],complianceRelationSelector,{canonicalClass:'pg_attribute',handleExpression:"'pg_attribute:'||a.attrelid::text||':'||a.attnum::text"}),
  spec('constraint','constraint',['relation_name','name','definition','validated'],['text','text','text','boolean'],complianceGlobalSelector,{canonicalClass:'pg_constraint',handleExpression:"'pg_constraint:'||k.oid::text||':0'"}),
  spec('index','index',['relation_name','definition','valid','ready'],['text','text','boolean','boolean'],complianceGlobalSelector,{canonicalClass:'pg_class',handleExpression:"'pg_class:'||i.indexrelid::text||':0'"}),
  spec('policy','policy',['relation_name','name','command','permissive','roles_csv','using_expression','check_expression'],['text','text','text','boolean','text?','text?','text?'],complianceGlobalSelector,{canonicalClass:'pg_policy',handleExpression:"'pg_policy:'||p.oid::text||':0'"}),
  spec('trigger','trigger',['relation_name','name','enabled','definition'],['text','text','text','text'],complianceGlobalSelector,{canonicalClass:'pg_trigger',handleExpression:"'pg_trigger:'||t.oid::text||':0'"}),
  spec('role','role',['name','login','inherit','superuser','create_db','create_role','replication','bypass_rls','connection_limit','config_raw_text_or_empty','valid_until_text_or_empty',...configFields],['text','boolean','boolean','boolean','boolean','boolean','boolean','boolean','integer','text','text',...configTypes],{roleNames:['zasp_compliance_worker','zasp_compliance_cleanup']},{sourceMaxRows:2,canonicalClass:'pg_authid',handleExpression:"'pg_authid:'||oid::text||':0'",extraProjections:configProjections})
];

const releaseValues={revision:'compliance-limits-v1',controls:500,records_per_control:100,format_bytes:4194304,package_bytes:8388608,snapshot_bytes:4194304,scope_active:2,deployment_active:100,attempts:5,lease_seconds:60,retry_seconds:30,retention_seconds:86400,scope_bytes:268435456,deployment_bytes:17179869184,scope_jobs:100,deployment_jobs:10000,job_grants:5,principal_grants:20};
const releaseFields=Object.keys(releaseValues);
const releaseTypes=Object.fromEntries(releaseFields.map(field=>[field,field==='revision'?'text':'integer']));

function selectedNode(contract,identity) {
  if(!contract||!Array.isArray(contract.nodes))throw Error('special catalog source contract missing');
  const prefix=identity.slice(0,identity.indexOf('(')+1);
  const candidates=contract.nodes.filter(node=>typeof node?.identity==='string'&&node.identity.startsWith(prefix));
  if(candidates.length!==1||candidates[0].identity!==identity)throw Error('special catalog source identity '+identity);
  const node=candidates[0],pin=sourcePins[identity];
  const expectedFrame={owner:'zasp_discovery_authority',acl:'{zasp_discovery_authority=X/zasp_discovery_authority}',config:['search_path=pg_catalog, public'],language:'sql',security_definer:false,volatility:'s',parallel:'u',strict:false,leakproof:false,cost:100,rows:0,arguments:'',result:'text'};
  if(typeof node.source!=='string'||typeof node.definition!=='string'||sha(node.source)!==pin.sourceSHA256||node.sourceSHA256!==pin.sourceSHA256||sha(node.definition)!==pin.definitionSHA256||node.definitionSHA256!==pin.definitionSHA256||frameFields.some(field=>JSON.stringify(node[field])!==JSON.stringify(expectedFrame[field])))throw Error('special catalog source pin or frame '+identity);
  return node;
}

function anchor(node,start,end,siteSHA256) {
  const text=Buffer.from(node.source).subarray(start,end);
  if(sha(text)!==siteSHA256)throw Error('special catalog source site '+node.identity+' '+start);
  return {sourceIdentity:node.identity,sourceSHA256:node.sourceSHA256,definitionSHA256:node.definitionSHA256,siteSHA256,start,end,frame:Object.fromEntries(frameFields.map(field=>[field,structuredClone(node[field])]))};
}

function concatProjection(text,label) {
  const marker='concat_ws(',start=text.indexOf(marker);
  if(start<0)throw Error('special catalog source projection '+label);
  const parts=[];let begin=start+marker.length,depth=0,quote=false;
  for(let index=begin;index<text.length;index++){
    const char=text[index];
    if(char==="'"){
      if(quote&&text[index+1]==="'"){index++;continue;}
      quote=!quote;continue;
    }
    if(quote)continue;
    if(char==='('){depth++;continue;}
    if(char===')'){
      if(depth>0){depth--;continue;}
      parts.push(text.slice(begin,index).trim());
      const from=text.slice(index+1).replace(/\n\s*--[\s\S]*$/,'').trim();
      if(parts[0]!=="'|'"||parts[1]!==`'${label}'`||!from.startsWith('FROM '))throw Error('special catalog source projection '+label);
      return {projections:parts.slice(2),from};
    }
    if(char===','&&depth===0){parts.push(text.slice(begin,index).trim());begin=index+1;}
  }
  throw Error('special catalog source projection '+label);
}

function releasePolicyBinding(catalog) {
  if(!catalog||!Array.isArray(catalog.columns)||!Array.isArray(catalog.constraints)||!Array.isArray(catalog.relations))throw Error('special catalog policy catalog missing');
  const relation='public.zasp_compliance_export_policy';
  const columns=catalog.columns.filter(row=>row.relation===relation).sort((a,b)=>a.position-b.position);
  const expectedColumnTypes=['text','integer','integer','bigint','bigint','bigint','integer','integer','integer','integer','integer','integer','bigint','bigint','integer','integer','integer','integer'];
  if(columns.length!==releaseFields.length||columns.some((row,index)=>row.name!==releaseFields[index]||row.type!==expectedColumnTypes[index]||row.not_null!==true||row.position!==index+1))throw Error('special catalog policy columns');
  const constraints=catalog.constraints.filter(row=>row.relation===relation).sort((a,b)=>Buffer.compare(Buffer.from(a.name),Buffer.from(b.name)));
  if(constraints.length!==37||constraints.some(row=>row.validated!==true||row.deferrable!==false||row.deferred!==false))throw Error('special catalog policy constraints');
  const byName=new Map(constraints.map(row=>[row.name,row]));
  for(const field of releaseFields){
    const notNull=byName.get(`zasp_compliance_export_policy_${field}_not_null`),check=byName.get(`zasp_compliance_export_policy_${field}_check`),value=releaseValues[field];
    const rhs=field==='revision'?"'compliance-limits-v1'::text":field==='deployment_bytes'?"'17179869184'::bigint":String(value);
    if(notNull?.definition!==`NOT NULL ${field}`||check?.definition!==`CHECK ((${field} = ${rhs}))`)throw Error('special catalog policy constraint '+field);
  }
  if(byName.get('zasp_compliance_export_policy_pkey')?.definition!=='PRIMARY KEY (revision)')throw Error('special catalog policy primary key');
  const relations=catalog.relations.filter(row=>row.identity===relation);
  if(relations.length!==1||relations[0].kind!=='r'||relations[0].owner!=='zasp_discovery_authority'||relations[0].row_security!==true||relations[0].forced_row_security!==true||relations[0].acl!=='{zasp_discovery_authority=arwdDxtm/zasp_discovery_authority}')throw Error('special catalog policy relation');
  return constraints.map(row=>structuredClone(row));
}

function addRule(result,node,siteTuple,prefix,metadata,projection,extra={}) {
  const [start,end,siteSHA256]=siteTuple,sourceSite=anchor(node,start,end,siteSHA256);
  if(metadata.extraProjections)projection={...projection,projections:[...projection.projections,...metadata.extraProjections]};
  if(projection.projections.length!==metadata.fields.length)throw Error('special catalog source field mapping '+metadata.label);
  const id=`special:${prefix}:${metadata.label}`;
  const raw={id,kind:metadata.kind,fields:[...metadata.fields],fieldTypes:{...metadata.fieldTypes},projections:[...projection.projections],from:projection.from,sourceSite,sourceMaxRows:metadata.sourceMaxRows??null,refusalMaxRows:10000,selector:structuredClone(metadata.selector),...extra};
  if(metadata.bag)raw.bag=true;
  if(metadata.canonicalClass){raw.canonicalClass=metadata.canonicalClass;raw.handleExpression=metadata.handleExpression;}
  result.rawRules.push(raw);
  metadata.fields.forEach((field,expressionOrdinal)=>result.entries.push({...sourceSite,expressionOrdinal,field,sourceExpression:projection.projections[expressionOrdinal],selector:structuredClone(raw.selector),demandPath:[id],disposition:'capture',evidence:{phase:'original',ruleId:id,field}}));
  result.runtimeAlgebra.push({...sourceSite,ruleId:id,disposition:'runtime-algebra-required',children:metadata.fields.map(field=>({ruleId:id,field}))});
}

export function buildOrderedSpecialCatalogCapture(sourceContract,catalog) {
  const globalNode=selectedNode(sourceContract,globalIdentity),complianceNode=selectedNode(sourceContract,complianceIdentity);
  const constraintBindings=releasePolicyBinding(catalog),result={entries:[],rawRules:[],runtimeAlgebra:[],unresolved:[]};
  const cteStart=globalNode.source.indexOf('WITH relations AS ('),cteEnd=globalNode.source.indexOf('), identities(value) AS (');
  if(cteStart<0||cteEnd<0)throw Error('special catalog source relations CTE');
  const sqlPrefix=globalNode.source.slice(cteStart,cteEnd+1);
  globalSpecs.forEach((metadata,index)=>{
    const site=sourcePins[globalIdentity].sites[index],text=Buffer.from(globalNode.source).subarray(site[0],site[1]).toString('utf8');
    addRule(result,globalNode,site,'global-control',metadata,concatProjection(text,metadata.label),metadata.usesRelationsCte?{sqlPrefix}:{});
  });
  complianceSpecs.forEach((metadata,index)=>{
    const site=sourcePins[complianceIdentity].sites[index],text=Buffer.from(complianceNode.source).subarray(site[0],site[1]).toString('utf8');
    addRule(result,complianceNode,site,'compliance-jobs',metadata,concatProjection(text,metadata.label));
  });
  const limitsMetadata={label:'limits',kind:'release_policy',fields:releaseFields,fieldTypes:releaseTypes,selector:{table:'public.zasp_compliance_export_policy',columns:releaseFields,primaryKey:'revision',releaseValues,constraintBindings},sourceMaxRows:1,bag:true};
  addRule(result,complianceNode,sourcePins[complianceIdentity].sites[7],'compliance-jobs',limitsMetadata,{projections:releaseFields.map(field=>`p.${field}`),from:'FROM public.zasp_compliance_export_policy p'});
  return result;
}
