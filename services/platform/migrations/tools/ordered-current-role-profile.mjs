import crypto from 'node:crypto';

// Closed source translation. Aggregate execution remains an evaluator obligation.
const pins=[
  ['zasp_temporal68.predecessor_ready(text,text)','dd0f5fe44a5f0eb1c5853f555adce40e13e43e5fcd70cb3c0f5361a6f4afac4c','c6eed3d3fd1aad9eb53690e2a1e364dc576e1910224af2fec91813189c944bb6',[74702,103533,105803],[]],
  ['zasp_temporal68.ready(text,text)','fe58995a0e48312eb5c54cca509a217a471c1464129f09c7475933a8d2f1dab9','f9557bcb94debad45801d1715181e4592c47be92fa79005b3c811b6281757f83',[4350],[5113,6160,7211]],
  ['zasp_temporal78.ready(text,text)','06023c0cf59ce604e0585d8b182f1c2ec094ca1c34aa6a9052201ecae66abc76','a6a988fd4b42b6c63dc66b34a2de51476a0bfe9452ef4536b061206d120999ac',[17469,21417],[18327]],
  ['zasp_temporal77.base67_fingerprint()','2e205ba34a6d5267f51b8436d1b5021c9fc7161f776b3b525a085615ae6f556c','ae6456305a2ffc9aa054dd32e085fd7595859714c1cdf56946c8d837c082e907',[2709],[]]
];
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const profileText="(SELECT count(*)=1 AND bool_and(singleton AND name='canonical61-temporal78-authorization79-80-v1') FROM zasp_authorization80.runtime_profile)";
const roleText="(SELECT count(*)=3 AND bool_and(NOT(rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) FROM pg_roles WHERE rolname IN('zasp_temporal_executor','zasp_temporal_compensation','zasp_temporal_accounting'))\n AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE roleid='zasp_temporal_accounting'::regrole OR member IN('zasp_temporal_executor'::regrole,'zasp_temporal_compensation'::regrole,'zasp_temporal_accounting'::regrole))";
const roles=['zasp_temporal_executor','zasp_temporal_compensation','zasp_temporal_accounting'];
const flags=['login','superuser','create_db','create_role','replication','bypass_rls'];
const owner='zasp_discovery_authority';
const fail=()=>{throw Error('role-profile source, frame or annotation mismatch');};

export function lowerOrderedRoleProfileCatalog(contract) {
  if(!Array.isArray(contract?.nodes)||!Array.isArray(contract?.materializedObligations))fail();
  const sites=[],obligations=[];
  for(const [identity,sourceSHA256,definitionSHA256,profileStarts,roleStarts] of pins){
    const nodes=contract.nodes.filter(n=>typeof n?.identity==='string'&&n.identity.startsWith(identity.slice(0,identity.indexOf('(')+1)));
    const entries=contract.materializedObligations.filter(n=>n.identity===identity);
    if(nodes.length!==1||nodes[0].identity!==identity||entries.length!==1)fail();
    const node=nodes[0],entry=entries[0],base=identity==='zasp_temporal77.base67_fingerprint()';
    const acl=identity==='zasp_temporal68.ready(text,text)'?'{zasp_discovery_authority=X/zasp_discovery_authority,zasp_temporal_executor=X/zasp_discovery_authority,zasp_temporal_compensation=X/zasp_discovery_authority,zasp_security_agent_api=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}':'{zasp_discovery_authority=X/zasp_discovery_authority}';
    const frame={owner,acl,config:['search_path=pg_catalog, public'],result:base?'text':'boolean',arguments:base?'':'c text, f text',language:identity.includes('predecessor_ready')?'plpgsql':'sql',parallel:'u',volatility:'s',strict:false,leakproof:false,security_definer:!base,cost:100,rows:0};
    if(typeof node.source!=='string'||typeof node.definition!=='string'||sha(node.source)!==sourceSHA256||sha(node.definition)!==definitionSHA256||node.sourceSHA256!==sourceSHA256||node.definitionSHA256!==definitionSHA256)fail();
    for(const [key,value] of Object.entries(frame))if(JSON.stringify(node[key])!==JSON.stringify(value))fail();
    for(const key of ['sourceSHA256','definitionSHA256','owner','config','security_definer'])if(JSON.stringify(entry[key])!==JSON.stringify(node[key]))fail();
    const spans=entry.structuralInvariantSpans;
    if(!Array.isArray(spans)||spans.length!==profileStarts.length+roleStarts.length)fail();
    for(const [index,start] of [...profileStarts,...roleStarts].entries()){
      const profile=index<profileStarts.length,text=profile?profileText:roleText;
      const kind=profile?'fixed-current-profile':'fixed-native-role-shape-and-membership',end=start+Buffer.byteLength(text),digest=sha(text),span=spans[index];
      if(!span||span.kind!==kind||span.start!==start||span.end!==end||span.text!==text||span.sha256!==digest||span.disposition!=='fresh-structural-invariant-not-customer-input'||Buffer.from(node.source).subarray(start,end).toString()!==text)fail();
      const site={identity,kind,start,end,text,sha256:digest,sourceSHA256,definitionSHA256,frame:structuredClone(frame)};
      sites.push(site);
      const obligation={identity,start,end,siteSHA256:digest,preserveSQLNulls:true};
      if(profile)obligations.push({...obligation,type:'profile-aggregate',ruleId:'role-profile:current-profile',expression:{count:1,boolAnd:{all:[{field:'singleton',equals:true},{field:'name',equals:'canonical61-temporal78-authorization79-80-v1'}]}}});
      else obligations.push({...obligation,type:'native-role-aggregate',ruleId:'role-profile:native-roles',expression:{count:3,boolAnd:{notAny:[...flags]}},membership:{role:'zasp_temporal_accounting',members:[...roles],operation:'not-exists',join:'or',missingRegrole:'error'}});
    }
  }
  return {
    rules:[
      {id:'role-profile:current-profile',kind:'fixed_runtime_profile',namespaces:['zasp_authorization80'],identities:[],fields:['singleton','name']},
      {id:'role-profile:native-roles',kind:'role',namespaces:[],identities:[],selector:{any:roles.map(name=>({field:'name',equals:name}))},fields:[...flags]}
    ],sites,obligations,
    unsupported:[
      {kind:'fixed_runtime_profile',reason:'Direct unfiltered singleton/name descriptor and independent reference required; do not substitute registration checksum/profile_name.'},
      {kind:'aggregate-semantics',reason:'Evaluator must preserve original count/bool_and/SQL NULL semantics at all eleven sites; projection equality alone is not aggregate equivalence.'},
      {kind:'membership-boundary',reason:'Bind four original OR negative universes to existing native membership rule and preserve missing-regrole error behavior; no duplicate or broadened membership rule.'}
    ]
  };
}
