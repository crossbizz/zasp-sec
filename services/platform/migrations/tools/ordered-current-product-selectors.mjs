import crypto from 'node:crypto';

// A finite translation of nine pinned effective recipes, not a general SQL parser.
const pins={
  approval_notification:['442c82e65615ba99addbdeaea52cc2c767da812af1ecb843eed1e6c613a8f70e','919a1534578fc77548d65c70682111ef1224265c0e448f089adbcd1b4731edc6',7],
  home_attention:['6337a8151081e2f68a773ba4ce68024f9f47af5b6db7e44fa10847e446b0580f','043f501a18318b900177a4ae0879352e9e9764f4834323aece9404be08f62c96',1],
  integration_setup:['a658f796c31c955db26a859151885b63b0e53cbc47db8a5229ad3d67fafa513e','5068f01ec463c11cebaa181cb2b5b744499f32a1bc9b749f46251c5c75ec3625',2],
  integration_webhook:['1c15bc54f536113727aff8942cdf041737e8d91f33a51a69c95032570a7f1219','45aa864f09bf795a9a373cde1a7570e0204a6354984cf1bfd0308eb1d5a146a3',6],
  reconciliation_lane_plan:['bab1d34ab132c902729f29fab6562bf44e1576d22c16b21d616d8376402b2408','6c7d78391bfcf01d264b987af78bac4bdde2db2b4008440deb2948404c357ac1',1],
  red_team_artifacts:['8c5df3ff67223b74e07e5055dd29d63712af78f7ca321ccd6d4aae456025a787','275050efb45a97647e60d2eac203689e43a86e22f56bf58397c1660085cc0d43',3],
  red_team_invocation:['5d02e3969ada5446071a95551ea96f4e661a17f66b56d6d2040c47e9df866861','47fc2cd08b3b135e998eedd2f3e7bb505d7265bc17fa4f1ddc9221c02037decc',1],
  red_team_safety:['7aae1418fdd0a8a8ade28ce35d6624d1ea6695b7ae05d95cc4eb407c5913012e','a3a436f12b092c8d85379fad1c1199acce1c32a02579cc0faeba2d396a97d042',1],
  workflow_compatibility:['65b31911c14fa07698e66ee8274a96361cbab8564e2fe93d92a10d0edc01b126','5c28af675dfbdc91752944281f1da5b0697743e21b05f725b9d0dffbd0e8a36b',1]
};
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const eq=(field,value)=>({field,equals:value});
const any=(field,values)=>values.length===1?eq(field,values[0]):{any:values.map(v=>eq(field,v))};
const publicNames=names=>({all:[eq('namespace','public'),any('name',names)]});
const approval='public.zasp_security_agent_approval_notifications';
const strings=text=>[...text.matchAll(/'([^']*)'/g)].map(m=>m[1]);
const regclass=text=>{
  const refs=[...new Set([...text.matchAll(/'(public\.[a-z0-9_]+)'::regclass/g)].map(m=>m[1]))];
  if(refs.length!==1)throw Error('product source relation selector mismatch');
  return refs[0];
};

function branchRule(family,branch,text) {
  const base={id:`product:${family}:${branch}`,kind:branch,namespaces:[],identities:[]};
  if(branch==='function') {
    const match=text.match(/\bproname(?: IN\(([^)]+)\)|=ANY\(ARRAY\[([^\]]+)\]\))/);
    if(!match)throw Error('product source routine selector mismatch');
    return {...base,kind:'routine',selector:publicNames(strings(match[1]??match[2])),fields:['name','identity_arguments','owner','security_definer','config_text_or_empty','acl_text_or_empty','definition']};
  }
  if(branch==='table')return {...base,kind:'relation',selector:family==='approval_notification'?{all:[eq('namespace','public'),eq('name',approval.slice(7)),any('relation_kind',['r','i'])]}:eq('identity',regclass(text)),fields:['name','owner','row_security','forced_row_security','acl_text_or_empty']};
  const selector=eq('relation',family==='approval_notification'&&branch==='column'?approval:regclass(text));
  if(branch==='column')return {...base,kind:family==='red_team_artifacts'?'column_name':'column',selector,fields:family==='red_team_artifacts'?['name','type','not_null']:[...(family==='approval_notification'?['relation_name']:[]),'position','name','type','not_null','default_text_or_empty']};
  if(branch==='constraint')return {...base,selector,fields:family==='approval_notification'?['name','constraint_type','validated','definition_pretty']:family==='integration_webhook'?['name','definition_pretty']:['name','definition','validated']};
  if(branch==='index')return {...base,selector,fields:[...(family==='approval_notification'?['name']:[]),'definition']};
  if(branch==='policy')return {...base,selector,fields:family==='approval_notification'?['name','permissive','roles_csv_public_sorted','using_text_or_empty','check_text_or_empty']:['name','command','permissive','roles_named_array_text','using','check']};
  if(branch==='trigger') {
    const name=text.match(/\btgname='([^']+)'/)?.[1];
    if(!name||!text.includes('NOT trigger_value.tgisinternal'))throw Error('product source trigger selector mismatch');
    return {...base,selector:{all:[selector,eq('name',name)]},predicate:'user-triggers',fields:['name','definition_pretty']};
  }
  throw Error('product source unknown branch');
}

export function lowerOrderedProductCatalog(contract) {
  if(!contract||!Array.isArray(contract.nodes))throw Error('product source contract missing');
  const rules=[],sites=[],obligations=[],unsupported=[];
  for(const [family,[sourcePin,definitionPin,count]] of Object.entries(pins)) {
    const identity=`public.zasp_production_${family}_live_fingerprint()`;
    const candidates=contract.nodes.filter(n=>typeof n?.identity==='string'&&n.identity.startsWith(identity.slice(0,-2)+'('));
    if(candidates.length!==1||candidates[0].identity!==identity)throw Error('product source missing, duplicate or overloaded');
    const n=candidates[0];
    const frame={owner:'zasp_discovery_authority',acl:'{zasp_discovery_authority=X/zasp_discovery_authority}',language:'sql',security_definer:false,volatility:'s',parallel:'u',strict:false,leakproof:false,cost:100,rows:0,result:'text',arguments:''};
    if(typeof n.source!=='string'||typeof n.definition!=='string'||sha(n.source)!==sourcePin||n.sourceSHA256!==sourcePin||sha(n.definition)!==definitionPin||n.definitionSHA256!==definitionPin||Object.entries(frame).some(([k,v])=>n[k]!==v)||JSON.stringify(n.config)!=='["search_path=pg_catalog, public"]')throw Error('product source pin or frame mismatch');
    const site=(start,end,type)=>{
      const text=n.source.slice(start,end),s={family,identity,type,start:Buffer.byteLength(n.source.slice(0,start)),end:Buffer.byteLength(n.source.slice(0,end)),text,sha256:sha(text),sourceSHA256:sourcePin,definitionSHA256:definitionPin,owner:n.owner,acl:n.acl,config:[...n.config],security_definer:n.security_definer};
      sites.push(s);return s;
    };
    const predecessor=s=>{
      const target=s.text.match(/concat_ws\('\|','(?:prior|compatibility)',([a-z0-9_]+)\(\)\)/)?.[1];
      if(!target)throw Error('product source predecessor mismatch');
      obligations.push({family,type:'predecessor',target:'public.'+target+'()',siteSHA256:s.sha256,required:'Preserve exact original framed predecessor result, NULL and missing facts; no recursive original collector call.'});
    };
    const starts=[...n.source.matchAll(/\n +UNION ALL /g)].map(m=>m.index),digestStart=n.source.lastIndexOf('\n ) SELECT');
    if(starts.length!==count||digestStart<starts.at(-1))throw Error('product source branch coverage mismatch');
    const prior=site(0,starts[0],family==='integration_setup'?'live-metadata-scalar':'predecessor');
    if(family==='integration_setup') {
      const obligation={family,type:'live-metadata-scalar',relation:'public.zasp_schema_metadata',key:'production_security_agent_attack_path_fingerprint',siteSHA256:prior.sha256,source:prior.text,required:'Preserve original framed scalar lookup: zero rows yields NULL, multiple-row lookup raises, concat_ws skips NULL; do not freeze a product-row value or move lookup into the direct catalog collector.'};
      obligations.push(obligation);unsupported.push({...obligation,reason:'live framed metadata obligation requires evaluator integration'});
    } else predecessor(prior);
    for(let i=0;i<starts.length;i++) {
      const text=n.source.slice(starts[i],starts[i+1]??digestStart),branch=text.match(/concat_ws\('\|','([a-z]+)'/)?.[1];
      if(!branch)throw Error('product source branch missing');
      const s=site(starts[i],starts[i+1]??digestStart,branch);
      if(branch==='compatibility'){predecessor(s);continue;}
      const rule=branchRule(family,branch,text);rules.push(rule);
      const reasons=[];
      if(text.includes('::regclass')) {
        obligations.push({family,branch,type:'relation-resolution',relation:regclass(text),siteSHA256:s.sha256,required:'Resolve the exact original regclass in its original frame; absent relation raises rather than silently selecting zero rows. Preserve this obligation outside the direct collector.'});
        reasons.push('exact original regclass existence/error obligation must be discharged by evaluator, not replaced by empty selector output');
      }
      if(branch==='policy')reasons.push(family==='approval_notification'?'pg_policy name; exact sorted CSV with PUBLIC for OID 0 and LEFT JOIN NULL omission; coalesced using/check required':'pg_policy name; exact sorted pg_roles ARRAY::text omits OID 0; raw nullable using/check required');
      if(family==='approval_notification'&&branch==='column')reasons.push('physical column descriptor needs class.relname field without ordinal normalization');
      if(family==='approval_notification'&&branch==='index')reasons.push('pg_index descriptor needs index pg_class.relname, not pg_indexes view substitution');
      if(rule.fields.includes('definition_pretty'))reasons.push('independent original-frame pretty deparse reference bytes required, not non-pretty approximation');
      if(reasons.length)unsupported.push({family,branch,kind:rule.kind,siteSHA256:s.sha256,source:s.text,reason:reasons.join('; '),disposition:'exact proposed rule; descriptor/reference integration unresolved'});
    }
    const digest=site(digestStart,n.source.length,'digest');
    obligations.push({family,type:'digest-semantics',siteSHA256:digest.sha256,required:'Preserve concat_ws NULL skipping and exact per-field coalescing, UNION ALL row cardinality, string_agg sorted newline UTF8 SHA256 (including empty/NULL aggregate); typed comparison does not establish byte-identical original digest.'});
  }
  return {rules,sites,obligations,unsupported};
}
