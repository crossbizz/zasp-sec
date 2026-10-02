import crypto from 'node:crypto';
export const orderedWorkerOpaqueBranchesV1=Object.freeze(['schema','column','index','policy','trigger','owner-policy','mutation-trigger','saved']);
export const orderedWorkerSourceClosureCountsV1=Object.freeze({sourceBodies:9,branches:103,digestTails:9,recipes:28,unavailableUniverses:2,retainedOpaque:8});
// Nine immutable source bodies only. Proposed rules still need independent
// reference, original aggregate/frame and current native integration evidence.
const pins={
  projected_domain:['f4aa1fbb16bbe2cee3d15f7ddd83946bc09e2e51982da5e429090e5b9eed018f','f3c159b6d3f5ee0e8bcf389dc2d6be4f23447ba00c04e93b20f992b26c272d75',7,'public',true],
  projected_temporal_profile:['3ecfc291a5f440d142a5fad18a70ed9a15ae9b887ec236d9d3dd7633f71e8355','0414eae6a45f19b0944682ab812462d12658f575ecc35174a36f03f1c851dac6',8,'zasp_authorization80_temporal',true],
  projected62:['70a15652d021961e9431d2e440819ab546d0e5bad86bc46aa3321fd46c9490c6','497b2c57e960a831046b08e5e66c682e7a488ac9878938e113c99fe6ced8e831',8,'zasp_ordered_public62',false],
  projected68:['c30a31d1cf3bc8c68d080de927fd96d92fac0ebe13e6b57cf55187cd41b8b4bc','792e4e098c839ad6bc037b92b6483859d38f6ac27f7d10ad8f3d3b5aeb0fc6ca',10,'zasp_temporal68',false],
  projected69:['7defc1df49352cbb625839fbf7116f8a3ddabe620700fe2266c0122d5220913b','c500d010433f0e7a9a58e3582322b66d18de8c58354ff324710afd55ee56eaff',10,'zasp_temporal69',false],
  projected72:['32a325a28612f7055f39b44a3537dbe32d669807d306c3687ec0acb1b93978f6','3cf6bae8961260b198b6e8933b7989286745eb3a5f56203978350c66922b5fbf',14,'zasp_temporal72',false],
  projected74:['2ef9a3b9274d9df23e9e7322b6183b2e4241c458bae10a5db4240db2b9f8f2e8','9aaa13c14b0a3e5bbef6b30e1b808de14addfe5f8aaeff71dd24d0355301a8c1',25,'zasp_temporal74',false],
  projected78:['47216eab1003503ed9ed86f463ab45cdcf2a634b65118e0a7c77bd4658cbc275','4d818d9c032431c2a27fb4d74e05ed6bf9258dde49e8fa470c824e84ac8972b3',13,'zasp_temporal78',false],
  projected79:['82643ea7e1976d99f0772678d787c5f8fe731897f3add31c425ee82790964657','434a681f3b48a3afc196aa95389ee0cf4a87a57ecb97119c6d1f8b362e5948ed',8,'zasp_authorization79',false],
};
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const eq=(field,equals)=>({field,equals});
const any=(field,values)=>({any:values.map(value=>eq(field,value))});
const all=(...children)=>({all:children});
const not=value=>({not:value});
const strings=value=>[...value.matchAll(/'([^']*)'/g)].map(m=>m[1]);
const fkFields=['relation','name','referenced_relation','trigger_relation','constraint_relation','function','event_bits','enabled','deferrable','deferred','argument_count','arguments','columns_text','when_text_or_empty'];
// A bounded lexer splits only the first concat_ws in an already fully pinned
// branch. Nested CASE/scalars and their original spelling remain untouched.
function projections(source){
  const marker="concat_ws(",start=source.indexOf(marker);
  if(start<0)throw Error('worker projection absent');
  let depth=1,quoted=false,part=start+marker.length;const args=[];
  for(let i=part;i<source.length;i++){
    const c=source[i];
    if(c==="'"){if(quoted&&source[i+1]==="'"){i++;continue;}quoted=!quoted;continue;}
    if(quoted)continue;
    if(c==='(')depth++;
    else if(c===')'){if(--depth===0){args.push(source.slice(part,i).trim());if(args[0]!=="'|'"||!/^'[a-z-]+'$/.test(args[1]))throw Error('worker concat header');return args.slice(2);}}
    else if(c===','&&depth===1){args.push(source.slice(part,i).trim());part=i+1;}
  }
  throw Error('worker projection boundary');
}
function staticRule(family,branch,source,namespace,domainNames){
  const transforms=['function','view','effective-predecessor','precision-handoff','bulk-handoff','approval-dependency','approval-read-dependency','predecessor-compatibility'];
  if(transforms.includes(branch)||family==='projected_domain'&&branch==='trigger'||family==='projected74'&&branch==='constraint'||family==='projected72'&&branch==='saved'||branch.startsWith('lock-')||['delivery-role-membership','public-effect-security','public-effect-column-acl'].includes(branch))return null;
  const p=projections(source).join(','),base={id:'worker:'+family+':'+branch,kind:branch,namespaces:[],identities:[],fields:[]};
  let selector=eq('namespace',namespace);
  if(family==='projected_domain')selector=all(eq('namespace','public'),any(branch==='table'?'name':'relation_name',domainNames));
  if(branch==='schema'){base.kind='namespace';base.fields=[...(p.includes('nspname')?['name']:[]),'owner',p.includes('COALESCE')?'acl_text_or_empty':'acl'];}
  else if(branch==='table'||branch==='relation'){base.kind='relation';base.fields=['name','kind',...(p.includes('c.relpersistence')?['persistence']:[]),'owner',...(p.includes("COALESCE(c.relacl")?['row_security','forced_row_security','acl_text_or_empty']:['acl','row_security','forced_row_security'])];}
  else if(branch==='column'){
    base.kind='column';base.fields=['relation_name','position','name','type','not_null'];
    if(family==='projected_temporal_profile')base.fields.push('acl','default');
    else base.fields.push(p.includes('COALESCE(pg_get_expr')?'default_text_or_empty':'default',...(p.includes('a.attacl')?['acl_text_or_empty']:[]));
  }
  else if(branch==='constraint'){base.fields=['relation_name','name','definition','validated'];}
  else if(branch==='index')base.fields=['relation_name','definition','valid','ready'];
  else if(branch==='policy'||branch==='owner-policy'){
    base.kind='policy';base.fields=[p.includes('p.polrelid::regclass')?'relation':'relation_name','name'];
    // Field order is documented by the original projections; comparison keys
    // preserve the same selected set without adding absent command/permissive.
    if(p.includes('p.polcmd'))base.fields.push('command');if(p.includes('p.polpermissive'))base.fields.push('permissive');base.fields.push('roles','using','check');
    if(branch==='owner-policy')selector=all(any('name',strings(source.match(/p\.polname IN\(([^)]+)\)/)[1])),any('relation',[...source.matchAll(/'([^']+)'::regclass/g)].map(m=>m[1])));
  }
  else if(branch==='foreign-key-trigger'){base.kind='foreign_key_trigger';base.fields=[...fkFields];}
  else if(branch==='saved'){base.kind='saved_function';base.fields=['signature','definition','owner','acl'];base.namespaces=[namespace];return base;}
  else if(['trigger','mutation-trigger','finding-ownership-trigger','finding-decision-trigger'].includes(branch)){
    base.kind='trigger';base.fields=[...(p.includes('t.tgrelid::regclass')?['relation']:p.includes('c.relname')?['relation_name']:[]),...(p.includes('t.tgname')?['name']:[]),'enabled','definition'];
    if(source.includes('NOT t.tgisinternal'))base.predicate='user-triggers';
    if(family==='projected68')selector=all(selector,not(all(eq('relation','zasp_temporal68.deliveries'),any('name',['ordered_policy_capture','ordered_policy_no_truncate']))));
    if(family==='projected72')selector=all(selector,not(all(any('name',['zasp_authorization80_worker_discovery_source','zasp_authorization80_worker_discovery_no_truncate']),any('relation',['zasp_temporal72.runs','zasp_temporal72.schedules']))));
    if(family==='projected_temporal_profile')selector={any:[selector,all(eq('name','zasp_authorization79_capture'),any('relation',['public.zasp_integrations','public.zasp_integration_connections','public.zasp_discovery_syncs','public.zasp_inventory_entities']))]};
    if(family==='projected79')selector=eq('name','zasp_authorization79_capture');
    if(branch!=='trigger'){
      const name=source.match(/t\.tgname='([^']+)'/)?.[1],relations=[...source.matchAll(/'([^']+)'::regclass/g)].map(m=>m[1]);
      if(!name||!relations.length)throw Error('worker trigger selector');selector=all(eq('name',name),any('relation',relations));
    }
  }else throw Error('worker branch not accounted');
  return {...base,selector};
}
export function lowerOrderedWorkerProjections(contract){
  if(!Array.isArray(contract?.nodes))throw Error('worker source contract');
  const rules=[],recipes=[],sites=[],obligations=[],unsupported=[];
  for(const [family,[sourcePin,definitionPin,count,namespace,definer]]of Object.entries(pins)){
    const identity='zasp_authorization80_worker.'+family+'()',found=contract.nodes.filter(n=>n.identity?.startsWith(identity.slice(0,-2)+'('));
    if(found.length!==1||found[0].identity!==identity)throw Error('worker source identity coverage');
    const n=found[0],frame={owner:'zasp_discovery_authority',acl:'{zasp_discovery_authority=X/zasp_discovery_authority}',config:['search_path=pg_catalog, public'],language:'sql',security_definer:definer,volatility:'s',parallel:'u',strict:false,leakproof:false,cost:100,rows:0,result:'text',arguments:''};
    if(sha(n.source)!==sourcePin||n.sourceSHA256!==sourcePin||sha(n.definition)!==definitionPin||n.definitionSHA256!==definitionPin||Object.entries(frame).some(([k,v])=>JSON.stringify(n[k])!==JSON.stringify(v)))throw Error('worker source/frame pin');
    const starts=[0,...[...n.source.matchAll(/\n +UNION ALL /g)].map(m=>m.index)],digest=n.source.lastIndexOf('\n ) SELECT');
    if(starts.length!==count||digest<=starts.at(-1))throw Error('worker branch coverage');
    const domainNames=family==='projected_domain'?strings(n.source.match(/c\.relname=ANY\(ARRAY\[([\s\S]*?)\]\)/)[1]):[];
    if(family==='projected_domain'&&domainNames.length!==23)throw Error('worker domain universe');
    const site=(start,end,type)=>{const text=n.source.slice(start,end),row={family,identity,type,start:Buffer.byteLength(n.source.slice(0,start)),end:Buffer.byteLength(n.source.slice(0,end)),text,sha256:sha(text),sourceSHA256:sourcePin,definitionSHA256:definitionPin,frame:structuredClone(frame)};sites.push(row);return row;};
    for(let i=0;i<starts.length;i++){
      const text=n.source.slice(starts[i],starts[i+1]??digest),branch=text.match(/concat_ws\('\|','([^']+)'/)?.[1]??text.match(/SELECT '([a-z-]+)\|'\|\|/)?.[1];
      if(!branch)throw Error('worker unknown original branch');
      const s=site(starts[i],starts[i+1]??digest,branch),ruleId='worker:'+family+':'+branch;
      const binding={ruleId,siteSHA256:s.sha256,sourceIdentity:identity,sourceSHA256:sourcePin,definitionSHA256:definitionPin,frame:structuredClone(frame)};
      if(['domain-catalog','inventory-catalog'].includes(branch)){
        const obligation={...binding,type:'original-delegate',source:text,required:'Preserve original selected delegate identity, invocation frame, NULL concatenation and digest dependency without recursive collector calls or frozen expected truth.'};obligations.push(obligation);unsupported.push({...obligation});continue;
      }
      const rule=staticRule(family,branch,text,namespace,domainNames);
      if(rule){rules.push(rule);unsupported.push({...binding,type:'independent-reference-and-native',required:'Source-selected direct rule requires exact independent projected values, universe/key cardinality, original frame/deparse and aggregate equivalence. No source-selected field or live relationship is discharged by representation.'});}
      else{
        const whole=family==='projected72'&&branch==='saved',recipe={...binding,source:text,projectionMode:whole?'whole-case-value':'ordered-concat-fields',projections:whole?[text]:projections(text),disposition:'source-pinned representation only'};
        recipes.push(recipe);const obligation={...binding,type:'original-transformation-or-live-projection',source:text,required:'Preserve every ordered source expression, saved membership and reg-object cast, scalar zero/NULL/multiple-row behavior, original conditional demand and helper frame. Parent-lock role/grant/member/default-namespace inputs remain fresh source-selected obligations; zero application callees is not proof of static status. No raw definition, owner/ACL alias, saved restoration or target-derived result substitution.'};obligations.push(obligation);unsupported.push({...obligation});
      }
      const bindings=[...text.matchAll(/'([^']+)'::(regclass|regnamespace|regprocedure|regrole)/g)].map(m=>({identity:m[1],cast:m[2]}));
      if(bindings.length)obligations.push({...binding,type:'original-reg-object-binding',bindings,required:'Preserve each original resolution/error and frame boundary; a missing object is not an empty selector. Source-specific unqualified names retain their original resolution obligations.'});
    }
    const d=site(digest,n.source.length,'digest');obligations.push({family,sourceIdentity:identity,type:'original-aggregate-digest',siteSHA256:d.sha256,source:d.text,required:'Preserve original concat_ws NULL skipping and coalesces, UNION ALL bag cardinality, source field order, sorted newline aggregate including empty NULL, UTF8 and SHA256. Direct typed equality is not original digest proof.'});
  }
  return {installable:false,rules,recipes,sites,obligations,unsupported};
}
