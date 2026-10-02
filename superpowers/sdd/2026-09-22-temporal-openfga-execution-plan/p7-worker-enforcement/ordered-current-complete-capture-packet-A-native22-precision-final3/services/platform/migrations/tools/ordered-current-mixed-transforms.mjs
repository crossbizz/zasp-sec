// Source representation only. Neither original live condition is a portable
// fixture boolean, an approved primitive exception, or executable collector SQL.
import crypto from 'node:crypto';
import {lowerOrderedPublicCatalog} from './ordered-current-public-selectors.mjs';
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const field=field=>({op:'field',field});
const literal=value=>({op:'literal',value});
const frame={owner:'zasp_discovery_authority',acl:'{zasp_discovery_authority=X/zasp_discovery_authority}',config:['search_path=pg_catalog, public'],language:'sql',volatility:'s',parallel:'u',strict:false,leakproof:false,cost:100,rows:0};
const inputPins={
  'zasp_temporal72.fingerprint()':['1ec25170f7d2d2451c8dfb16ffefec0fbc7330eca7221638cb4c18ecdf74d41d','43b3d082bbec543ee3ba1717a090d2c4fef3305fdb41006a2338ff4422554725',false,'text'],
  'zasp_authorization80_temporal.catalog_ready()':['332f99b997ef4b3d38ac58402a6219ae993d030b8d4dc1566aae46356bc5efda','0cdbc2dc8b017422fd116b9c1dd47a922bcc27458888af30b1ff8ecd50b9fb09',true,'boolean'],
  'zasp_authorization80_temporal.projected72()':['829710c308583f54d55fe97f34a931bce24a9a30b4353aa48f52b319bbc5e8fd','854710213d0c79dbdd21954527f8c60606fab88dc6f5e9a276d053c03a377710',true,'text'],
  'zasp_authorization80_worker.projected72()':['32a325a28612f7055f39b44a3537dbe32d669807d306c3687ec0acb1b93978f6','3cf6bae8961260b198b6e8933b7989286745eb3a5f56203978350c66922b5fbf',false,'text'],
};
function pinned(contract,identity,sourceSHA256,definitionSHA256,security_definer,result,argumentsText=''){
  const found=contract.nodes.filter(node=>node.identity===identity);
  if(found.length!==1)throw Error('mixed source identity cardinality');
  const node=found[0];
  if(node.sourceSHA256!==sourceSHA256||node.definitionSHA256!==definitionSHA256||sha(node.source)!==sourceSHA256||sha(node.definition)!==definitionSHA256)throw Error('mixed source pin');
  const required={...frame,security_definer,result,arguments:argumentsText};
  for(const [key,value]of Object.entries(required))if(JSON.stringify(node[key])!==JSON.stringify(value))throw Error('mixed source frame pin');
  return {identity,sourceSHA256,definitionSHA256,source:node.source,frame:required};
}
function sitePart(parent,type,start,end){
  const text=parent.source.slice(start,end);
  return {identity:parent.identity,type,start:Buffer.byteLength(parent.source.slice(0,start)),end:Buffer.byteLength(parent.source.slice(0,end)),text,sha256:sha(text),sourceSHA256:parent.sourceSHA256,definitionSHA256:parent.definitionSHA256,frame:parent.frame};
}
export function lowerOrderedMixedTransforms(contract){
  const accepted=lowerOrderedPublicCatalog(contract);
  const scheduleSites=accepted.sites.filter(site=>site.family==='discovery_schedule_replay'&&site.type==='function');
  const exportSites=accepted.sites.filter(site=>site.family==='sa_export'&&site.type==='saved');
  if(scheduleSites.length!==1||exportSites.length!==1)throw Error('mixed original branch coverage');
  const helper=pinned(contract,'public.zasp_discovery_schedule_replay_function_identity(oid)','658281859af2c84dcc18fae084b3d1dc4b27b8297ba84ae8e594daa1e77a6ec0','4c75452af242fa7e9dd28cf5d1555ddd1343bce9fa1db494d40512f4479679e0',false,'text','value oid');
  const guardInputs=Object.entries(inputPins).map(([identity,pins])=>pinned(contract,identity,...pins));
  const helperSite=sitePart(helper,'schedule-helper',0,helper.source.length);
  const identityMatch=helper.source.match(/CASE WHEN value IN\((.+?)\) THEN CASE WHEN (EXISTS\(.+?) THEN \(SELECT definition FROM zasp_temporal72\.predecessor_functions WHERE to_regprocedure\(signature\)=value\) ELSE NULL END ELSE pg_get_functiondef\(value\) END/s);
  if(!identityMatch)throw Error('mixed helper expression boundary');
  const identities=[...identityMatch[1].matchAll(/'([^']+)'::regprocedure/g)].map(match=>match[1]);
  if(identities.length!==2)throw Error('mixed helper literal coverage');
  const guard={op:'original72-guard',condition:identityMatch[2],conditionSHA256:sha(identityMatch[2]),frame:structuredClone(helper.frame),primitiveException:false,outsideCollectorAuthorized:false,
    then:{op:'saved-oid-scalar',schema:'zasp_temporal72',table:'predecessor_functions',field:'definition',signatureResolution:'to_regprocedure',argument:'original-helper-value'},else:literal(null)};
  let expression={op:'identity-membership-case',argument:'original-helper-value',identities,cast:'regprocedure',then:guard,else:field('definition')};
  const replacements=[...helper.source.matchAll(/,'([a-f0-9]{64})','(<[a-z-]+>)'\)/g)];
  if(replacements.length!==2)throw Error('mixed helper replacement coverage');
  for(const[,from,to]of replacements)expression={op:'replace',input:expression,from,to};
  const scheduleFields={};
  for(const name of ['namespace_name','name','identity_arguments','owner','security_definer','volatility','parallel','strict','leakproof','config_text_or_empty'])scheduleFields[name]=field(name);
  scheduleFields.acl={op:'coalesce',args:[field('acl'),literal('')]};
  scheduleFields.definition={op:'original-helper-demand',helper,argument:'actual-pg-proc-oid',expression};
  const schedule={ruleId:'public:discovery_schedule_replay:function',kind:'routine',siteSHA256:scheduleSites[0].sha256,
    selector:{op:'saved-signature-universe',schema:'zasp_schedule_replay_prior',table:'functions',field:'signature',cast:'regprocedure',namespace:'zasp_schedule_replay_prior',publicNamePrefix:'zasp_discovery_schedule_replay_',source:scheduleSites[0].text.slice(scheduleSites[0].text.indexOf(' WHERE ')+7)},fields:scheduleFields};

  const exportParent=pinned(contract,'public.zasp_sa_export_live_fingerprint()','bbd093c72bd6dd9a28d0f5101780aade9a921f8513a386ac4e5449203fcbd836','fef446bc77b30ebc75533eb324c7032584b6ca498b66951ad5ecbf13eb894b8e',false,'text');
  const start=exportParent.source.indexOf(' WITH saved AS ('),end=exportParent.source.indexOf(', identities(value) AS (');
  if(start<0||end<=start)throw Error('mixed export CTE boundary');
  const savedSite=sitePart(exportParent,'export-saved-cte',start,end);
  if(savedSite.sha256!=='cccedfae3423eaa6cccd392960fc79cf8b64148b2974028d5f883ff5ebb45a84')throw Error('mixed export CTE source');
  const predicate=savedSite.text.slice(savedSite.text.indexOf('s.signature IN('),savedSite.text.indexOf(' AS migration_owned'));
  const signatures=[...predicate.slice(0,predicate.indexOf('\n AND')).matchAll(/'([^']+)'/g)].map(match=>match[1]);
  if(signatures.length!==2)throw Error('mixed export signature coverage');
  const exported={ruleId:'public:sa_export:saved',kind:'export_saved',sourceTable:'zasp_sa_export_prior.functions',siteSHA256:exportSites[0].sha256,frame:exportParent.frame,
    bindings:{migration_owned:{op:'registered-migration-owner',signatures,bindingTable:'public.zasp_discovery_principal_bindings',role:'zasp_discovery_authority',roleTest:'MEMBER',ownerField:'owner_name',source:predicate,sourceSHA256:sha(predicate)}},
    fields:{signature:field('signature'),definition:field('definition'),owner:{op:'registered-owner-case',condition:'migration_owned',registered:'<registered-migration-principal>',literalPrefix:'owner:',field:'owner_name'},
      acl:{op:'registered-acl-case',condition:'migration_owned',field:'acl',ownerField:'owner_name',registeredTag:'registered-migration-principal',literalTag:'literal',removeOnly:'grantee',order:'original-ordinality',result:'original-jsonb-text',emptyAggregate:null}}};
  const obligations=[
    {ruleId:schedule.ruleId,type:'original72-lowering',required:'Preserve the complete selected original72 registration EXISTS and fingerprint equality, SQL NULL/AND behavior, and helper invocation frame. Do not add an outside-collector fingerprint exception. Lower the source-selected structural inputs and retain fresh live registration/cardinality, authorization readiness, runtime audit/profile and trigger checks with original frames before discharging this guard.',inputIdentities:guardInputs.map(node=>node.identity)},
    {ruleId:schedule.ruleId,type:'saved-universe-demand',required:'Preserve all saved-signature regprocedure casts in the outer selector, helper-local two-literal resolution on actual invocation, original to_regprocedure saved scalar comparison with zero rows NULL and multiple rows error, and all syntactic relation/column binding and privilege failures. Scalar row demand is conditional; parse/binding obligations are not waived. Original concat_ws/UNION ALL/sort/newline/UTF8/digest and every selected routine field remain required.'},
    {ruleId:exported.ruleId,type:'fresh-registered-identity',required:'Evaluate only the two original signatures, fresh binding principal_name=owner_name and authority_role, pg_roles join, and MEMBER eligibility. EXISTS preserves its original duplicate semantics; SQL false or NULL selects literal owner and ACL. No fixed migration login, role alias, inferred LOGIN condition or target-derived expected boolean.'},
    {ruleId:exported.ruleId,type:'acl-array-and-independent-reference',required:'Preserve original jsonb_array_elements errors/NULL behavior, scalar aggregate empty NULL, original ordinality and all ACL fields/grant options. Registered and literal tags are outside each original entry; remove only grantee for the matching owner. Preserve exact original jsonb text and raw ELSE, source row multiplicity and aggregate/digest behavior. Independent normalized owner/ACL projection evidence is required before expected fields can be generated.'},
  ];
  const unsupported=[{ruleId:schedule.ruleId,type:'mixed-guard-compilation',reason:'Original72 condition, saved-signature universe, helper demand and live/structural equivalence are not compiled.'},{ruleId:exported.ruleId,type:'mixed-owner-acl-compilation',reason:'Fresh principal/MEMBER and ordered tagged ACL projection require exact compilation plus independent normalized reference and native parity.'}];
  return {installable:false,recipes:[schedule,exported],sites:[scheduleSites[0],helperSite,exportSites[0],savedSite],guardInputs,obligations,unsupported};
}
