import crypto from 'node:crypto';
// Finite pinned public recipes; unresolved transformations never become raw equality.
const pins={
"attack_lab_execution":["6ba4b44f5881673ddf439f0aa80aeb9ca2bfca2b3b007c4030dcc810916938a3","1a6bd021b3661048d6888e8b1eb5f7d860c1c2781b52674bbf62634dd27034ec",8],
"discovery_schedule_replay":["8ed5df9ba2dc68a3f03b50c6a7087425673789290b2b857cc30be19bcdfeea51","436b3586e2d2e2238c82520b3b238ebc89df78d3b3de79d3e7e5e4568aab5231",8],
"execution":["f1d736c4922a17308f45c4f37099374f9d6a2f5304b8f828f81a169a605f6eda","4a69fac36145097b86491b3ae71a13072ead01656ac59813f4b4ca0c7294a0d6",0],
"inventory":["b51e2a21f46dafe49b964619b91c379ca84fbc660c9d8c7e8a470f036f95cc20","194d87f2a5c6e2638e989c61a65a15181cb7383f1e4058469ba705afc50acc9b",9],
"policy_deployment_execution":["f8e351130849bcd3b18ce1ed28e16fc87e7dba53255be5f642ef8fdbf0841513","b4ab27589016a77049e2a3b0eed86a99339d473a1cfde22492ddaa3a3457c6d1",0],
"recovery_execution":["d67773464f945932cc767caabc6b2c56cd0fde13faee305c9fbfd3dc82af0767","8379bf47ecbbc21d65b2c917d5356a371f4d706dda869be5bb4dc03e5153cc73",0],
"red_team_execution":["652f15e3b144df685eea3f74616c63ad399a934378136715d39e6910b3112cb6","bfda00f6de43c5ac7d0d63ccd3b2627773bf62fad881d0a655b33e45890e6306",7],
"sa_attack_lab":["be2d5847ed9683838c4bd34c2f2c197242c2b1e39a147cace8f9c004c34ef448","2c9d57d5cd0cfef9a53da1333a16e59681fac38704ce78d0d4f54f0346d695dc",8],
"sa_export":["bbd093c72bd6dd9a28d0f5101780aade9a921f8513a386ac4e5449203fcbd836","fef446bc77b30ebc75533eb324c7032584b6ca498b66951ad5ecbf13eb894b8e",9],
"sa_multistep":["4968d2b98f8992b95ec7a213d7ae16c9c3891a8913395fa6551308c7f0be496e","df660cad163b9ef904f4bed917e5df793d0be4e2f009ac5d763b511cbf6a3c4a",7],
"sa_webhook":["32a078415bb62510f2eefabecc9c3c3ca3adbd1a5f09aacac731a3520e3c4bbe","65b8dfe698e8b1b4b454b99a764839e3da43162898063b4a208503a4cd84513c",10],
"security_agent_connector_revocation":["1581b96a76eb3370f4fbd4090de24aae144ba0c8c996813be54ecd16fa17d3e5","f6e0ef1c9960688ef088ce3ed9652462e67a6d5f65388fb1e42990896ddc22cb",6],
"security_agent_session_isolation":["1758a218a35d1fb67def7c9e958b4f7f2e5549b42881f1e565eee5b5bb94d7da","b4f922737ac4e6cea06e28cb373c26f0f14fc6337015c1617d0a016fbcd20a9b",0],
};

const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const eq=(field,value)=>({field,equals:value});
const any=(field,values)=>values.length===1?eq(field,values[0]):{any:values.map(v=>eq(field,v))};
const all=(...children)=>({all:children});
const strings=s=>[...s.matchAll(/'([^']*)'/g)].map(m=>m[1]);
const capture=(text,re)=>{const m=text.match(re);if(!m)throw Error('public source selector mismatch');return m[1];};
const list=(text,re)=>strings(capture(text,re));
const pub=eq('namespace','public');
const starts=(field,value)=>({field,startsWith:value});
const like=(field,value)=>({field,like:value});
const calls=text=>[...text.replace(/--[^\n]*/g,m=>' '.repeat(m.length)).replace(/'(?:[^']|'')*'/g,m=>' '.repeat(m.length)).matchAll(/\b((?:public\.)?zasp[a-z0-9_]+(?:\.[a-z0-9_]+)?)\(([^()]*)\)/g)].map(m=>(m[1].includes('.')?'':'public.')+m[1]+'('+m[2]+')');
const fkFields=['relation','name','referenced_relation','trigger_relation','constraint_relation','function','event_bits','enabled','deferrable','deferred','argument_count','arguments','columns_text','when_text_or_empty'];

function selectorFor(family,branch,text) {
  const relationField=branch==='table'?'name':'relation_name';
  if(branch==='schema')return eq('name',capture(text,/nspname='([^']+)'/));
  if(branch==='saved'||branch==='saved-table')return null;
  if(branch==='role')return any('name',text.includes('rolname IN(')?list(text,/rolname IN\(([^)]+)\)/):[capture(text,/rolname='([^']+)'/)]);
  if(branch==='membership')return all(any('namespace',list(text,/granted\.rolname IN\(([^)]+)\)/)),eq('member','zasp_discovery_authority'));
  if(family==='inventory') {
    if(['table','column','constraint','policy'].includes(branch))return all(pub,any(relationField,list(text,/class\.relname=ANY\(ARRAY\[([^\]]+)\]\)/)));
    if(branch==='index')return all(pub,any('name',list(text,/index_value\.relname IN\(([^)]+)\)/)));
    if(branch==='function')return all(pub,{any:[like('name','zasp_inventory_%'),...list(capture(text,/(FROM pg_proc procedure[\s\S]+)$/),/procedure\.proname IN\(([^)]+)\)/).map(n=>eq('name',n))]},{not:eq('name','zasp_inventory_live_fingerprint')});
    if(branch==='trigger')return all(pub,eq('relation_name','zasp_core_payloads'),eq('name','zasp_core_inventory_write_fence'));
    if(branch==='rule'||branch==='restore')return null;
  }
  if(['attack_lab_execution','red_team_execution'].includes(family)){
    const prefix=family==='attack_lab_execution'?'zasp_attack_lab_%':'zasp_red_team_%';
    if(branch==='function')return all(pub,family==='red_team_execution'?{any:[like('name',prefix),eq('name','zasp_effective_scope_permissions')]}:like('name',prefix));
    if(branch==='index')return all(pub,like('name',prefix),eq('relation_kind','i'));
    if(branch==='table')return all(pub,like('name',prefix),any('relation_kind',['r','i']));
    if(branch==='column')return all(pub,like('relation_name',prefix));
    if(['constraint','policy'].includes(branch))return like('relation_name',prefix);
  }
  if(family==='security_agent_connector_revocation'){
    const relation='public.zasp_security_agent_connector_revocations';
    if(branch==='table')return all(pub,eq('name','zasp_security_agent_connector_revocations'),any('relation_kind',['r','i']));
    if(branch==='function')return all(pub,any('name',list(text,/procedure\.proname=ANY\(ARRAY\[([^\]]+)\]\)/)));
    if(branch==='constraint')return all(eq('relation','public.zasp_security_agent_definitions'),eq('name','zasp_security_agent_connector_revocation_supervised_check'));
    return eq('relation',relation);
  }
  if(family==='discovery_schedule_replay'){
    if(branch==='function')return null; // The original saved-signature subquery is not a frozen identity list.
    const union={any:[eq('namespace','zasp_schedule_replay_prior'),eq(branch==='table'?'identity':'relation','public.zasp_discovery_schedule_runs')]};
    return branch==='table'?all(union,eq('relation_kind','r')):union;
  }
  if(family==='sa_multistep'){
    const base=all(pub,starts(branch==='function'?'name':relationField,'zasp_sa_multistep_'));
    if(branch==='table')base.all.push(any('relation_kind',['r','v','m','p','S']));
    if(branch==='column')base.all.push(any('relation_kind',['r','p']));
    return base;
  }
  if(family==='sa_attack_lab'){
    if(branch==='function')return {any:[eq('namespace','zasp_sa_attack_lab_prior'),all(pub,starts('name','zasp_sa_attack_lab_'))]};
    const prefix=starts(relationField,'zasp_sa_attack_lab_');
    if(branch==='table')return all(pub,prefix,eq('relation_kind','r'));
    return branch==='column'?all(pub,prefix):prefix;
  }
  if(family==='sa_export'||family==='sa_webhook'){
    const schema='zasp_'+family+'_prior',prefix='zasp_'+family+'_';
    if(branch==='function')return {any:[eq('namespace',schema),all(pub,{any:[starts('name',prefix),family==='sa_export'?starts('name','zasp_sa_manual_'):like('name','%security_agent_webhook%')]})]};
    const target=family==='sa_webhook'?{any:[eq(relationField,'zasp_security_agent_webhook_deliveries'),starts(relationField,prefix)]}:starts(relationField,prefix);
    if(branch==='policy'||(family==='sa_webhook'&&branch==='trigger'))return target;
    const union={any:[eq('namespace',schema),all(pub,target)]};
    return branch==='table'?all(union,eq('relation_kind','r')):union;
  }
  throw Error('public source branch selection unknown');
}

function lowerBranch(family,branch,text) {
  const selector=selectorFor(family,branch,text);
  if(branch==='membership')return {type:'membership-cardinality',selector,required:'Preserve original role/member/admin rows as a bag, including duplicate selected values from different unselected grantors. Do not introduce grantor identity equality or deduplicate rows.'};
  if(branch==='saved-table')return {type:'nested-aggregate',selector:eq('identity','zasp_sa_attack_lab_prior.functions'),required:'Preserve correlated column/constraint sorted aggregates, original NULL/empty results, physical order and parent relation cardinality under original frame; no flat row-equality substitute.'};
  if(family==='inventory'&&['rule','restore'].includes(branch))return {type:'live-metadata',selector:null,required:'Preserve the exact original live inventory metadata row universe, JSON key removal or digest encoding, row identity/cardinality and original frame. No product-row export or captured constants.'};
  if((branch==='function'&&['discovery_schedule_replay','sa_attack_lab','sa_export','sa_multistep','sa_webhook','inventory'].includes(family))||(family==='inventory'&&['table','policy','role'].includes(branch))||(family==='sa_export'&&branch==='saved'))return {type:'original-transformation',selector,required:'Preserve exact original JSON/ACL/body/owner normalization and identity helper calls, registered-login relationships, saved-signature dynamic selection and scalar zero/multiple-row errors. Do not freeze a login or substitute raw body/ACL equality; literal role tags cannot impersonate registered identity.'};
  let kind=branch,fields,predicate,namespaces=[];
  const projection=text.slice(0,text.indexOf(' FROM '));
  if(branch==='function'){kind='routine';fields=['name','identity_arguments','owner','security_definer','config_text_or_empty','acl_text_or_empty','definition'];}
  else if(branch==='role')fields=['name','superuser','inherit','create_role','create_db','login','replication','bypass_rls'];
  else if(branch==='schema'){kind='namespace';fields=['name','owner','acl_text_or_empty'];}
  else if(branch==='saved'){
    kind='saved_function';namespaces=[capture(text,/FROM (zasp_[a-z0-9_]+)\.functions/)];fields=['signature','definition','owner','acl'];
  }
  else if(branch==='table'){
    kind='relation';fields=[...(projection.includes('n.nspname')?['namespace_name']:[]),'name',...(family==='sa_multistep'?['kind','persistence']:[]),'owner','row_security','forced_row_security','acl_text_or_empty'];
  }
  else if(branch==='column'){
    const named=['attack_lab_execution','red_team_execution','discovery_schedule_replay','inventory','security_agent_connector_revocation'].includes(family);
    kind=named?'column_name':'column';
    fields=family==='inventory'?['type','not_null','default_pretty_text_or_empty']:[...(projection.includes('n.nspname')?['namespace_name']:[]),...(family!=='security_agent_connector_revocation'?['relation_name']:[]),...(!named?['position']:[]),'name',text.includes('::regtype::text')?'type_identity':'type','not_null',...(['sa_multistep','security_agent_connector_revocation'].includes(family)?['identity','generated']:[]),...(family==='sa_multistep'?['collation']:[]),'default_text_or_empty',...(text.includes('a.attacl')?['acl_text_or_empty']:[])];
  }
  else if(branch==='constraint'||branch==='table_constraint'){
    kind='constraint';
    fields=family==='inventory'?['definition_pretty']:family==='security_agent_connector_revocation'?(branch==='table_constraint'?['name','constraint_type','validated','deferrable','deferred','definition_pretty']:['name','validated','definition_pretty']):['relation_name','name',...(['attack_lab_execution','red_team_execution'].includes(family)?['constraint_type','validated','definition_pretty']:['definition',...(text.includes('k.convalidated')?['validated']:[])])];
  }
  else if(branch==='index'){
    if(['inventory','attack_lab_execution'].includes(family)){kind='class_index';fields=family==='inventory'?['definition']:['name','definition'];}
    else fields=family==='security_agent_connector_revocation'?['name','valid','ready','unique','primary','definition']:['relation_name','definition','valid','ready',...(family==='sa_multistep'?['live']:[])];
  }
  else if(branch==='policy'){
    if(family==='security_agent_connector_revocation')fields=['name','command','permissive','roles_csv_public_sorted','using_text_or_empty','check_text_or_empty'];
    else fields=['relation_name','name',...(text.includes('p.polcmd')?['command']:[]),...(text.includes('.polpermissive')?['permissive']:[]),...(text.includes('p.polroles')?['roles']:[]),'using','check'];
  }
  else if(branch==='trigger'){
    fields=family==='inventory'?['definition_pretty']:[...(projection.includes('n.nspname')?['namespace_name']:[]),'relation_name','name','enabled','definition'];
    predicate='user-triggers';
  }
  else if(branch==='foreign-key-trigger'){kind='foreign_key_trigger';fields=[...fkFields];}
  else throw Error('public source branch not handled');
  const base={id:'public:'+family+':'+branch,kind,namespaces,identities:[],fields};
  return {...base,...(selector?{selector}:{}),...(predicate?{predicate}:{})};
}

export function lowerOrderedPublicCatalog(contract) {
  if(!contract||!Array.isArray(contract.nodes))throw Error('public source contract missing');
  const rules=[],sites=[],obligations=[],unsupported=[];
  for(const [family,[sourcePin,definitionPin,count]] of Object.entries(pins)){
    const identity='public.zasp_'+family+'_live_fingerprint()',ns=contract.nodes.filter(n=>typeof n?.identity==='string'&&n.identity.startsWith(identity.slice(0,-2)+'('));
    if(ns.length!==1||ns[0].identity!==identity)throw Error('public source missing, duplicate or overloaded');
    const n=ns[0],inventory=family==='inventory',frame={owner:inventory?'zasp_inventory_authority':'zasp_discovery_authority',acl:inventory?'{zasp_inventory_authority=X/zasp_inventory_authority,zasp_discovery_authority=X/zasp_inventory_authority}':'{zasp_discovery_authority=X/zasp_discovery_authority}',security_definer:inventory||family==='execution',language:'sql',volatility:'s',parallel:'u',strict:false,leakproof:false,cost:100,rows:0,result:'text',arguments:''};
    if(typeof n.source!=='string'||typeof n.definition!=='string'||sha(n.source)!==sourcePin||n.sourceSHA256!==sourcePin||sha(n.definition)!==definitionPin||n.definitionSHA256!==definitionPin||Object.entries(frame).some(([k,v])=>n[k]!==v)||JSON.stringify(n.config)!=='["search_path=pg_catalog, public"]')throw Error('public source pin or frame mismatch');
    const site=(start,end,type)=>{const text=n.source.slice(start,end),s={family,identity,type,start:Buffer.byteLength(n.source.slice(0,start)),end:Buffer.byteLength(n.source.slice(0,end)),text,sha256:sha(text),sourceSHA256:sourcePin,definitionSHA256:definitionPin,...frame,config:[...n.config]};sites.push(s);return s;};
    const unresolved=(s,type,required,extra={})=>{const x={family,branch:s.type,type,siteSHA256:s.sha256,source:s.text,required,...extra};obligations.push(x);unsupported.push({...x,reason:required,disposition:'required original obligation; no waiver or installable claim'});};
    if(!count){const s=site(0,n.source.length,'conditional-wrapper');unresolved(s,'conditional-wrapper','Preserve exact conditional registration/catalog checks, original frame, outgoing call demand and NULL versus empty-text/error results.',{targets:calls(s.text),fallback:s.text.includes("ELSE ''")?'':null});continue;}
    let begin=0;
    if(family==='sa_export'){
      begin=n.source.indexOf("\n SELECT concat_ws('|','prior'");
      if(begin<0)throw Error('public source export CTE boundary missing');
      const s=site(0,begin,'registered-migration-binding');
      unresolved(s,'registered-migration-binding','Retain exact two saved signatures, live principal binding and role MEMBER relationship to saved owner, original query scope and NULL behavior. Preserve literal versus registered identity tags; no fixture login alias.');
    }
    const starts=[begin,...[...n.source.matchAll(/\n +UNION ALL /g)].map(m=>m.index)],digest=n.source.match(/\n +\) SELECT encode\(digest/);
    if(starts.length!==count+1||!digest||digest.index<starts.at(-1))throw Error('public source coverage mismatch');
    for(let i=0;i<starts.length;i++){
      const text=n.source.slice(starts[i],starts[i+1]??digest.index),branch=text.match(/concat_ws\('\|','([a-z_-]+)'/)?.[1]??text.match(/SELECT '([a-z_-]+)'(?:::text)?(?: kind)?,/)?.[1];
      if(!branch)throw Error('public source branch missing');
      const s=site(starts[i],starts[i+1]??digest.index,branch);
      if(['prior','webhook','execution'].includes(branch)){unresolved(s,'predecessor','Preserve exact original framed outgoing result and concat_ws NULL behavior; no recursive original collector call.',{targets:calls(text)});continue;}
      const lowered=lowerBranch(family,branch,text);
      if(lowered.type){unresolved(s,lowered.type,lowered.required,{selector:lowered.selector,targets:calls(text)});continue;}
      rules.push(lowered);
      const reasons=[];
      if(/'[^']+'::reg(namespace|class|procedure|role)/.test(text))reasons.push('preserve original reg-object resolution and missing-object error, not empty selection');
      if(['class_index','foreign_key_trigger','saved_function'].includes(lowered.kind))reasons.push('exact source-kind row universe, original projected values/cardinality and independent reference required; no joined-view approximation');
      if(lowered.kind==='role'||(lowered.kind==='trigger'&&lowered.fields.includes('relation_name')))reasons.push('exact original role name or trigger parent relation-name projection and independent reference fields required');
      if(lowered.fields.some(f=>['namespace_name','type_identity','default_pretty_text_or_empty','definition_pretty','roles_csv_public_sorted'].includes(f)))reasons.push('exact original framed descriptor/deparse/role encoding and independent reference fields required');
      if(reasons.length)unresolved(s,'descriptor-reference',reasons.join('; '),{ruleId:lowered.id});
    }
    const s=site(digest.index,n.source.length,'digest');
    obligations.push({family,type:'digest-semantics',siteSHA256:s.sha256,encoding:inventory?'jsonb-array':'sorted-lines',required:inventory?'Retain original JSON names/types/NULL, identities and bag cardinality, kind/identity/definition sort and empty [] fallback before UTF8 SHA256; no old-digest equality claim.':'Retain exact concat_ws NULL skipping, field-specific coalescing, UNION ALL bag cardinality, sorted newline aggregation/NULL empty aggregate and UTF8 SHA256; no old-digest equality claim.'});
  }
  return {rules,sites,obligations,unsupported};
}
