import crypto from 'node:crypto';
// This is a bounded compiler for eleven pinned effective recipes, not a SQL parser.
const pins={
  acceptance:['d431ecc57e280c8fc6174f0a47c8d4706c8515d0ac2cc17d4494f4acaa5edc9b','c4eb62cc0365f869fee4fff41cb01f5f613e9bb01930fb10e6961e67af49eecd',1],
  candidate_authority:['70a37e815d11cc6c3cda98dbbe5785f90625acb734816449c1fae4225f1d29e5','2ee7365d6d576656fdc18643ded3b317f9fc59e27a6260d0e6df7f629feb4df0',7],
  correlation_routing:['3bbd0f4ef0bcadb1583d5661bb23f75c718e622e6c9ff1ce0b3e8f6284a437f7','abface23b685a3085c70ce0dd1bd4466f2167cfb2eb8af65392fe45c4b88effd',2],
  enrollment_pairing:['dc52bfd60b97d0c0abe65350de4f6157fd28d99f2209a57b5cf36b64fea20a4d','45baaa1e8e7bb71c265490cba0638db5de276b559afbff69be84dfcdd0a6d87f',6],
  precision:['b6f6310ddee97053ec8dbb36b2e18a0604bdf8272d5bc0e1faeaadfb02118892','2540e996d735a54a96a1fd3add0c1ff3bdd034b5f0d67825ab9fee137603c797',0],
  queue_replay:['1783f14f02de63688cee1d4b1c3f1adea0e7cde92e1a4b73325c9f1859b3df56','dffd80d7ba89678e85fdd7a61fa7211a17842ce175c17585b989cf60fef177f7',1],
  session_evidence:['198275cf2c10977f1e98ea9da6afe4f56bd00952f9f2b8cccaa0043f799d97b5','ad4c99b4c03b1f3a520e7fa2b5431ae18d869d745b8cfcebc58e3f2d1eba227d',1],
  session_query:['fb2e2700987e01048bce1bef5c0b4de3ac8696ce8c539b3599bbc862d84f287e','0cd3d849e94541e0528b4e97e12bf39f0e0d591a5f2cd5186ec9a73d4b80879b',1],
  session_reads:['74a7fdf8b833a8586150990601e682eacdab96b0eaf80d8182b8f93992ec2336','a18b7c5b1c902d7a8ae2ec6e9d7c571c8321e5b1d3740807027f540c27d45713',7],
  session_search:['b951c37aa8c62b0ccd4901f9818cc92a95c1c3f30c515f5db123f3a074ed88a8','dbf7b0deb04824e1c6301cdba64eb3f7d0fa0d04f0eee752dfd1138420f7b057',7],
  sessions:['83a869dbeb2ad0a8129879b270a54de4692730f5bfb9c5eef450ee201e9ed04b','12857815bf14d231369905b7528434d2f528f7ec2dacbdfc65b124bf6df0ca0b',0]
};
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const signature=name=>`public.zasp_production_runtime_${name}_live_fingerprint()`;
const eq=(field,value)=>({field,equals:value});
const any=(field,values)=>values.length===1?eq(field,values[0]):{any:values.map(v=>eq(field,v))};
const publicNames=names=>({all:[eq('namespace','public'),any('name',names)]});
const strings=text=>[...text.matchAll(/'([^']*)'/g)].map(m=>m[1]);
const inNames=(text,field)=>{
  const match=text.match(new RegExp('\\b'+field+" IN\\(([^)]+)\\)"));
  if(!match)throw Error('runtime source selector mismatch');
  return strings(match[1]);
};
const regclasses=text=>[...new Set([...text.matchAll(/'(public\.[a-z0-9_]+)'::regclass/g)].map(m=>m[1]))];

function lowerBranch(family,branch,text) {
  const id=`runtime:${family}:${branch}`;
  const base={id,kind:branch,namespaces:[],identities:[]};
  if(branch==='function') {
    const names=inNames(text,'proname');
    const selector=family==='session_search'?{all:[eq('namespace','public'),{any:[{field:'name',like:'zasp_runtime_session_search_%'},...names.map(n=>eq('name',n))]}]}:publicNames(names);
    return {...base,kind:'routine',selector,fields:['name','identity_arguments','owner','security_definer','config_text_or_empty','acl_text_or_empty','definition']};
  }
  if(branch==='table') {
    const fields=['name','owner',...(family==='candidate_authority'?['kind']:[]),'row_security','forced_row_security','acl_text_or_empty',...(family==='candidate_authority'?['options_text_or_empty']:[])];
    const refs=regclasses(text);
    return {...base,kind:'relation',...(refs.length?{identities:refs}:{selector:publicNames(inNames(text,'relname'))}),fields};
  }
  if(branch==='column') {
    if(family==='enrollment_pairing')return {...base,kind:'information_column',selector:{all:[eq('namespace','public'),any('relation_name',inNames(text,'table_name'))]},fields:['relation_name','name','data_type','is_nullable','default_text_or_empty']};
    return {...base,kind:'column_name',selector:any('relation',regclasses(text)),fields:family==='candidate_authority'?['relation','name','normalized_position','type','not_null','identity','generated','acl_text_or_empty','default_text_or_empty']:['name','type','not_null',...(family==='session_search'?['default_text_or_empty']:[])]};
  }
  if(branch==='constraint') {
    if(family==='enrollment_pairing')return {...base,kind:'global_constraint',selector:{any:[any('relation',regclasses(text)),any('name',inNames(text,'conname'))]},fields:['relation','name','definition_pretty']};
    return {...base,selector:any('relation',regclasses(text)),fields:[...(family==='candidate_authority'?['relation']:[]),'name',...(family==='candidate_authority'?['validated','definition_pretty']:['definition','validated'])]};
  }
  if(branch==='policy') {
    const table=text.match(/tablename='([^']+)'/);
    const names=table?[table[1]]:inNames(text,'tablename');
    return {...base,kind:'policy_view',selector:{all:[eq('namespace','public'),any('relation_name',names)]},fields:[...(['candidate_authority','enrollment_pairing'].includes(family)?['relation_name']:[]),'name','roles_text',...(family==='candidate_authority'?['permissive']:[]),'command','using','check']};
  }
  if(branch==='index') {
    if(family==='candidate_authority')return {...base,selector:any('relation',regclasses(text)),fields:['valid','ready','live','definition']};
    const table=text.match(/tablename='([^']+)'/);
    if(!table)throw Error('runtime source index selector mismatch');
    return {...base,kind:'index_view',selector:{all:[eq('namespace','public'),eq('relation_name',table[1])]},fields:['name','definition']};
  }
  if(branch==='trigger') {
    const refs=regclasses(text);
    let selector=refs.length?any('relation',refs):any('name',inNames(text,'tgname'));
    if(family==='correlation_routing')selector={all:[selector,eq('name','zasp_runtime_correlation_claim_version')]};
    return {...base,selector,...(text.includes('NOT tgisinternal')?{predicate:'user-triggers'}:{}),fields:[...(family==='candidate_authority'?['relation']:[]),'name','enabled',text.includes('oid,true)')?'definition_pretty':'definition']};
  }
  throw Error('runtime source branch unsupported');
}

export function lowerOrderedRuntimeCatalog(contract) {
  if(!contract||!Array.isArray(contract.nodes))throw Error('runtime source contract missing');
  const rules=[],sites=[],obligations=[],unsupported=[];
  for(const [family,[sourcePin,definitionPin,count]] of Object.entries(pins)) {
    const identity=signature(family), candidates=contract.nodes.filter(n=>typeof n?.identity==='string'&&n.identity.startsWith(identity.slice(0,-2)+'('));
    if(candidates.length!==1||candidates[0].identity!==identity)throw Error('runtime source missing, duplicate or overloaded');
    const node=candidates[0];
    if(typeof node.source!=='string'||typeof node.definition!=='string'||sha(node.source)!==sourcePin||node.sourceSHA256!==sourcePin||sha(node.definition)!==definitionPin||node.definitionSHA256!==definitionPin||node.owner!=='zasp_discovery_authority'||node.acl!=='{zasp_discovery_authority=X/zasp_discovery_authority}'||JSON.stringify(node.config)!=='["search_path=pg_catalog, public"]'||node.language!=='sql'||node.security_definer!==false||node.volatility!=='s'||node.strict!==false||node.result!=='text'||node.arguments!=='')throw Error('runtime source pin or frame mismatch');
    const site=(start,end,type)=>{
      const text=node.source.slice(start,end);
      const value={family,identity,type,start:Buffer.byteLength(node.source.slice(0,start)),end:Buffer.byteLength(node.source.slice(0,end)),text,sha256:sha(text),sourceSHA256:sourcePin,definitionSHA256:definitionPin,owner:node.owner,acl:node.acl,config:[...node.config],security_definer:node.security_definer};
      sites.push(value);return value;
    };
    if(!count) {
      const s=site(0,node.source.length,'conditional-wrapper');
      const targets=family==='sessions'?['zasp_authorization80_worker.catalog_ready()','zasp_authorization80_worker.runtime_projected40()']:['zasp_temporal72.fingerprint()','zasp_temporal72.retained_precision_fingerprint()'];
      obligations.push({family,type:'conditional-wrapper',targets,siteSHA256:s.sha256,source:s.text,required:'Preserve original CASE/EXISTS comparisons, NULL result and conditional call execution; lower predecessor graph without recursive original calls.'});
      unsupported.push({family,branch:'conditional-wrapper',siteSHA256:s.sha256,reason:'conditional predecessor lowering belongs to evaluator; original guard and NULL semantics remain required'});
      continue;
    }
    const starts=[...node.source.matchAll(/\n UNION ALL /g)].map(m=>m.index);
    const digestStart=node.source.lastIndexOf('\n ) SELECT');
    if(starts.length!==count||digestStart<starts.at(-1))throw Error('runtime source branch coverage mismatch');
    const prior=site(0,starts[0],'predecessor');
    const target=prior.text.match(/concat_ws\('\|','prior',([a-z0-9_]+)\(\)\)/)?.[1];
    if(!target)throw Error('runtime source predecessor mismatch');
    obligations.push({family,type:'predecessor',target:'public.'+target+'()',siteSHA256:prior.sha256,required:'Lower exact predecessor result including NULL/empty and missing facts; no recursive original collector call.'});
    for(let i=0;i<starts.length;i++) {
      const text=node.source.slice(starts[i],starts[i+1]??digestStart);
      const branch=text.match(/concat_ws\('\|','([a-z]+)'/)?.[1];
      if(!branch)throw Error('runtime source unknown fact branch');
      const s=site(starts[i],starts[i+1]??digestStart,branch), rule=lowerBranch(family,branch,text);
      rules.push(rule);
      const reasons=[];
      if(rule.kind==='policy_view')reasons.push('exact pg_policies roles::text/command/expressions require source-view reference descriptors, not pg_policy approximation');
      if(rule.kind==='information_column')reasons.push('information_schema visible-row/data_type/is_nullable/default semantics require actual original-frame reference descriptors');
      if(rule.kind==='global_constraint')reasons.push('global conname addition universe must include conrelid=0 via LEFT JOIN; reference input must not omit domain constraints');
      if(rule.fields.includes('definition_pretty'))reasons.push('actual pg_get_*def(...,true) reference bytes are required; non-pretty deparse is not a substitute');
      if(rule.fields.includes('normalized_position'))reasons.push('exact sandbox_id live-count normalization and independently derived reference value required');
      if(reasons.length)unsupported.push({family,branch,kind:rule.kind,siteSHA256:s.sha256,source:s.text,reason:reasons.join('; '),disposition:'exact proposed rule; descriptor/reference integration unresolved'});
    }
    const digest=site(digestStart,node.source.length,'digest');
    obligations.push({family,type:'digest-semantics',siteSHA256:digest.sha256,required:'Original concat_ws NULL skipping, field coalescing, UNION ALL cardinality, sorted newline aggregation, UTF8 and SHA256 remain source obligations; typed comparison is not a claim of byte-identical old digest.'});
  }
  return {rules,sites,obligations,unsupported};
}
