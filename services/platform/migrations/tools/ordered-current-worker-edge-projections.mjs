import crypto from 'node:crypto';
export const orderedWorkerEdgeSourceClosureCountsV1=Object.freeze({sourceBodies:6,branches:54,digestTails:6,conditionals:7,membershipBags:2,delegates:6});
// Source-only companion. No reference facts or executable helper fallback.
const pins={
  gateway_projected24:['a47b0b44fecc9639b73018c2e044fe3fc05fdc81b993b4dc632088427b69d758','94a4fd079f82b064794fe16b46248373d5675911701db5e28cdbff228297ca1a',7],
  gateway_projected27:['9cb5fa4453d0a725d6fde54e7744c884e031bc325d8c96463be67315344a3c4e','fe8d3216de591bdb1264a9da97f982eb6cb2ac45115a3484c0fc544d2a76019c',13],
  ordered_projected28:['9a0ec7f8b07dacc0e1d254ae127ad259652984824f6a5c621233b14a49c6fbba','ac79cf296f7e2e7add00e130e18eb30940672680aaf7941ae6d6a05bf4a02876',10],
  runtime_projected40:['71f42f79d5c0076532863576afc4e53d91ae0a774ed0ad8b4b8a0606f5763c02','1cf20efba843fbc52f138373fd3b222037a7479d32a07260f3e23ac2e54fb119',7],
  runtime_projected50_binding:['42a2a6244f89cce465d9ee30f23d0bf686ed53e502462d533d298e61d31d6019','bb6b74424533e5a216d1721bd8e0bad9f789864d0084d73ad60345a90d0b34c1',8],
  runtime_projected50_search:['42cae24d2fac1b87580d5ad6648b05d992c48665589f073a07a42f2608d55c7f','184f584b545fbc92c765f1c31a67c29bd2b63679c20d2523c75f9482cd5bec72',9],
};
const helperPin=['59ea633911328f4f05136e7b9818ed5e45e449c0b4f1705f02191233b0e04696','c93753702e031b6fd99de4bf73a8c4514df60b5412d76e646f3475428781486b'];
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const frame={owner:'zasp_discovery_authority',acl:'{zasp_discovery_authority=X/zasp_discovery_authority}',config:['search_path=pg_catalog, public'],language:'sql',security_definer:false,volatility:'s',parallel:'u',strict:false,leakproof:false,cost:100,rows:0,result:'text',arguments:''};
const eq=(field,equals)=>({field,equals}),like=(field,value)=>({field,like:value});
const all=(...children)=>({all:children}),any=(...children)=>({any:children});
const oneOf=(field,values)=>values.length===1?eq(field,values[0]):any(...values.map(v=>eq(field,v)));
const literals=s=>[...s.matchAll(/'((?:[^']|'')*)'/g)].map(m=>m[1].replaceAll("''","'"));
const bindings=s=>[...s.matchAll(/'([^']+)'::(regclass|regprocedure|regrole|regnamespace)/g)].map(m=>({identity:m[1],cast:m[2]}));
const tableFields=['name','owner','row_security','forced_row_security','acl_text_or_empty'];
const routineFields=['name','identity_arguments','owner','security_definer','config_text_or_empty','acl_text_or_empty','definition'];
const roleFields=['name','superuser','inherit','create_role','create_db','login','replication','bypass_rls'];
function pinned(contract,family,pin,argumentsValue=''){
  const stem='zasp_authorization80_worker.'+family+'(',found=contract.nodes.filter(n=>n.identity?.startsWith(stem)),identity=stem+(argumentsValue?'oid':'')+')';
  const expected={...frame,arguments:argumentsValue};
  if(found.length!==1||found[0].identity!==identity)throw Error('worker edge source identity');
  const n=found[0];
  if(sha(n.source)!==pin[0]||n.sourceSHA256!==pin[0]||sha(n.definition)!==pin[1]||n.definitionSHA256!==pin[1]||Object.entries(expected).some(([k,v])=>JSON.stringify(n[k])!==JSON.stringify(v)))throw Error('worker edge source/frame pin');
  return {node:n,frame:expected};
}
// Bounded first-concat lexer, used only after full immutable body admission.
// Outer FROM starts after its closing parenthesis; saved subquery WHERE never
// supplies a catalog selector.
function projection(text){
  const marker='concat_ws(',start=text.indexOf(marker);if(start<0)throw Error('worker edge projection');
  let quoted=false,depth=1,part=start+marker.length;const args=[];
  for(let i=part;i<text.length;i++){
    const c=text[i];if(c==="'"){if(quoted&&text[i+1]==="'"){i++;continue;}quoted=!quoted;continue;}if(quoted)continue;
    if(c==='(')depth++;else if(c===')'&&--depth===0){args.push(text.slice(part,i).trim());if(args[0]!=="'|'"||!/^'[a-z_-]+'$/.test(args[1]))throw Error('worker edge header');return {branch:args[1].slice(1,-1),fields:args.slice(2),from:text.slice(i+1).trim()};}
    else if(c===','&&depth===1){args.push(text.slice(part,i).trim());part=i+1;}
  }throw Error('worker edge projection boundary');
}
function ruleFor(family,ordinal,p){
  const where=p.from.split(/\bWHERE\s+/).at(-1),values=literals(where),reg=bindings(where).map(b=>b.identity),branch=p.branch;
  const publicScope=s=>all(eq('namespace','public'),s),relation=()=>oneOf('relation',reg);
  const rule=(kind,fields,selector,extra={})=>({id:`worker-edge:${family}:${ordinal}`,kind,namespaces:[],identities:[],fields,selector,...extra});
  const recovery=family==='gateway_projected27',deployment=family==='ordered_projected28',pattern=recovery?'zasp_recovery_%':'zasp_policy_deployment_%';
  if(branch==='function'){
    // Preserve PostgreSQL's original literal cast (including alias resolution
    // and missing-object errors); never compare the alias to canonical text.
    if(family==='runtime_projected50_binding'&&ordinal===7)return rule('routine',routineFields,any(...reg.map(regprocedureEquals=>({field:'identity',regprocedureEquals}))));
    if(p.fields.at(-1)!=='pg_get_functiondef(p.oid)')return null;
    return rule('routine',routineFields,where.includes('n.nspname')?publicScope(oneOf('name',values.slice(1))):oneOf('identity',reg));
  }
  if(branch==='role')return rule('role',roleFields,oneOf('name',values));
  if(branch==='table')return rule('relation',tableFields,reg.length?oneOf('identity',reg):publicScope(all(recovery||deployment?like('name',pattern):eq('name','zasp_security_agent_temporary_policy_targets'),oneOf('relation_kind',['r','i']))));
  if(branch==='runtime_gateway_column')return rule('column_all',['relation_name','name','type_identity','not_null','default_text_or_empty'],publicScope(all(eq('relation_name','zasp_runtime_gateway_events'),eq('name','policy_ids'))));
  if(branch==='runtime_gateway_index')return rule('index',['name','owner','valid','ready','unique','primary','definition'],all(eq('relation','public.zasp_runtime_gateway_events'),oneOf('name',['zasp_runtime_gateway_events_policy_ids_v27_idx','zasp_runtime_gateway_events_policy_history_v27_idx'])));
  if(family==='runtime_projected40'&&branch==='policy')return rule('policy_view',['namespace_name','table_name','name','roles_text','command','using','check'],publicScope(oneOf('table_name',['zasp_runtime_session_events','zasp_runtime_session_projection_receipts'])));
  if(branch==='column'){
    let fields,selector;
    if(family==='gateway_projected24'){fields=['name','type_identity','not_null','identity','generated','default_text_or_empty'];selector=relation();}
    else if(recovery||deployment){fields=['relation_name','name','type_identity','not_null',...(deployment?['identity','generated']:[]),'default_text_or_empty'];selector=publicScope(deployment?any(like('relation_name',pattern),oneOf('relation_name',['zasp_security_agent_temporary_policy_targets','zasp_security_agent_session_policy_targets'])):like('relation_name',pattern));}
    else{fields=[...(family==='runtime_projected40'?['relation']:[]),'name','type','not_null',...(family==='runtime_projected50_search'?['acl_text_or_empty','default_text_or_empty']:[])];selector=relation();}
    return rule('column_name',fields,selector);
  }
  if(branch==='session-column-acl')return rule('column_name',['name','acl_text_or_empty'],relation());
  if(['constraint','table_constraint','runtime_gateway_constraint'].includes(branch)){
    if(recovery||deployment)return rule('constraint',['relation_name','name','constraint_type','validated','definition_pretty'],branch==='runtime_gateway_constraint'?all(eq('relation_name','zasp_runtime_gateway_events'),eq('name','zasp_runtime_gateway_events_policy_ids_v27_ck')):like('relation_name',pattern));
    if(family==='gateway_projected24')return rule('constraint',branch==='table_constraint'?['name','constraint_type','validated','deferrable','deferred','definition_pretty']:['name','validated','definition_pretty'],branch==='table_constraint'?relation():all(relation(),eq('name','zasp_security_agent_session_isolation_supervised_check')));
    return rule('constraint',['name','definition','validated'],relation());
  }
  if(branch==='index'){
    if(recovery||deployment)return rule('class_index',['name','definition'],publicScope(all(like('name',pattern),eq('relation_kind','i'))));
    if(family==='gateway_projected24')return rule('index',['name','valid','ready','unique','primary','definition'],any(all(eq('relation','public.zasp_runtime_gateway_events'),eq('name','zasp_runtime_gateway_events_session_v24_idx')),eq('relation','public.zasp_security_agent_temporary_policy_targets')));
    return rule('index_view',['name','definition'],publicScope(oneOf('table_name',values.slice(1))));
  }
  if(branch==='policy')return recovery||deployment?rule('policy',['relation_name','name','permissive','using','check'],like('relation_name',pattern)):rule('policy_view',['name','roles_text','command','using','check'],publicScope(eq('table_name','zasp_runtime_sandbox_search_outbox')));
  if(branch==='trigger'){
    if(recovery)return rule('trigger',['relation_name','name','definition_pretty'],publicScope(like('name','%_recovery_hold')),{predicate:'user-triggers'});
    if(deployment)return rule('trigger',['relation_name','name','definition_pretty'],any(...['%policy_deployment%','%policy_sequence','%policy_verify'].map(x=>like('name',x))));
    if(family==='runtime_projected50_binding')return rule('trigger',['name','enabled','definition_pretty'],all(relation(),eq('name','zasp_runtime_session_claim_version')));
    return rule('trigger',['relation','name','enabled','definition'],relation(),{predicate:'user-triggers'});
  }
  return null;
}
export function lowerOrderedWorkerEdgeProjections(contract){
  if(!Array.isArray(contract?.nodes))throw Error('worker edge contract');
  const h=pinned(contract,'ordered_writer_definition',helperPin,'value oid');
  const helper={identity:h.node.identity,source:h.node.source,sourceSHA256:helperPin[0],definitionSHA256:helperPin[1],frame:h.frame,bindings:bindings(h.node.source),demand:'selected original helper-call arm only'};
  const rules=[],recipes=[],sites=[],obligations=[],unsupported=[],referenceNeeds=[];
  for(const [family,pin]of Object.entries(pins)){
    const {node:n,frame:f}=pinned(contract,family,pin),starts=[0,...[...n.source.matchAll(/\n[ \t]+UNION ALL /g)].map(m=>m.index)],tail=n.source.lastIndexOf(') SELECT encode('),digest=n.source.lastIndexOf('\n',tail);
    if(starts.length!==pin[2]||digest<=starts.at(-1))throw Error('worker edge branch coverage');
    const site=(start,end,type,ordinal)=>{const text=n.source.slice(start,end),s={family,identity:n.identity,type,ordinal,start:Buffer.byteLength(n.source.slice(0,start)),end:Buffer.byteLength(n.source.slice(0,end)),text,sha256:sha(text),sourceSHA256:pin[0],definitionSHA256:pin[1],frame:structuredClone(f)};sites.push(s);return s;};
    for(let i=0;i<starts.length;i++){
      const text=n.source.slice(starts[i],starts[i+1]??digest),p=projection(text),s=site(starts[i],starts[i+1]??digest,p.branch,i+1),ruleId=`worker-edge:${family}:${i+1}`;
      const base={ruleId,sourceIdentity:n.identity,sourceSHA256:pin[0],definitionSHA256:pin[1],siteSHA256:s.sha256,start:s.start,end:s.end,frame:structuredClone(f),branch:p.branch,projections:p.fields,from:p.from,source:text,bindings:bindings(text)};
      if(['prior','prior_live','sandbox-search'].includes(p.branch)){
        const o={...base,type:'original-delegate',required:'Complete source-derived delegated recipe and original invocation frame, live facets, NULL and error behavior remain required. No collector helper call, fixture result or new historical-call exception.'};obligations.push(o);unsupported.push(o);continue;
      }
      if(p.branch==='membership'){
        const o={...base,type:'membership-bag',required:'Fresh exact role/member/admin projection with original UNION ALL duplicate cardinality. Grantor is not selected and cannot become an expected-key discriminator. No generic membership set substitution.'};obligations.push(o);unsupported.push(o);continue;
      }
      const rule=ruleFor(family,i+1,p);
      if(rule){
        rules.push(rule);unsupported.push({...base,type:'independent-reference-and-native',required:'Exact independent field/universe evidence and original frame, deparse, cardinality and aggregate parity required before integration.'});
        // Only these three finite maxima follow from the original selectors
        // and PostgreSQL object keys. LIKE/global/name-only routine universes
        // have no honest source-derived maximum; capture must supply an
        // explicitly reviewed refusal cap, never infer one from fixture rows.
        const attribute=family==='gateway_projected27'&&i===7,index=family==='gateway_projected27'&&i===9,resolvedPair=family==='runtime_projected50_binding'&&i===6;
        const sourceMaxRows=attribute?1:index||resolvedPair?2:null;
        if(rule.fields.length!==p.fields.length)throw Error('worker edge selected field correspondence');
        referenceNeeds.push({...base,kind:rule.kind,fields:[...rule.fields],selector:structuredClone(rule.selector),...(rule.predicate?{predicate:rule.predicate}:{}),
          selectedFields:rule.fields.map((field,position)=>({field,expression:p.fields[position]})),
          keyFrame:'pg_catalog',captureFrame:'original-source-frame',referenceStatus:'missing-independent-reference',sourceMaxRows,
          sourceMaxRowsBasis:attribute?'unique relation/attribute name':index?'two index names on one relation':resolvedPair?'two resolved routine OIDs':null,
          captureBoundStatus:sourceMaxRows===null?'requires-reviewed-refusal-cap':'source-maximum-refuse-excess',
          resolution:resolvedPair?'independent-regprocedure-resolution-required':'original-source-bindings-retained',
          ...(attribute?{universe:{positiveAttributes:false,excludeDropped:true}}:{})});
      }
      else{
        const type=family==='runtime_projected50_binding'&&i===6?'routine-identity-resolution':p.branch==='runtime_gateway_column'?'attribute-universe':p.branch==='runtime_gateway_index'?'index-owner':p.branch==='policy'?'policy-schema':'conditional-routine';
        const recipe={...base,type,disposition:'source-pinned representation only',...(type==='attribute-universe'?{universe:{positiveAttributes:false,excludeDropped:true}}:{})};recipes.push(recipe);
        const o={...base,type,required:type==='conditional-routine'?'Preserve original ordered CASE, selected helper demand/frame, saved signature or to_regprocedure matching, literal binding, scalar zero/NULL/multiple-row behavior. No raw definition fallback or copied expected helper truth.':'Descriptor/source projection absent: retain every original field and FROM/WHERE universe; do not narrow or add raw fields.'};obligations.push(o);unsupported.push(o);
        if(text.includes('zasp_authorization80_worker.ordered_writer_definition('))obligations.push({...base,type:'helper-demand-frame',helperIdentity:helper.identity,helperSourceSHA256:helper.sourceSHA256,helperDefinitionSHA256:helper.definitionSHA256,helperFrame:structuredClone(helper.frame),required:'Helper-local literal resolution occurs only on the original selected helper-call arm. Outer-query binding is not equivalent. Keep original helper frame, saved scalar and inner CASE ordering.'});
      }
      if(base.bindings.length)obligations.push({...base,type:'original-reg-object-binding',required:'Preserve exact literal cast resolution/error at its original frame and demand boundary. Missing objects are not empty selectors; do not move helper-local literals to outer query entry.'});
    }
    const s=site(digest,n.source.length,'digest',pin[2]+1);obligations.push({family,sourceIdentity:n.identity,sourceSHA256:pin[0],definitionSHA256:pin[1],frame:structuredClone(f),type:'original-aggregate-digest',siteSHA256:s.sha256,source:s.text,required:'Preserve concat_ws NULL skipping and selected coalesces, field order, UNION ALL bags, sorted newline string_agg including empty NULL, UTF8 and digest. Typed field equality alone is not whole original digest proof.'});
  }
  return {installable:false,rules,recipes,sites,obligations,unsupported,referenceNeeds,helpers:[helper]};
}
