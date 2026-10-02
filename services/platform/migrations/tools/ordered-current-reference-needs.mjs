// Finite reference-only inputs. Raw transform rows are intermediate inputs,
// never substitutes for the original normalized comparison fields.
import {lowerOrderedTemporalCatalog} from './ordered-current-temporal-selectors.mjs';
import {lowerOrderedPublicCatalog} from './ordered-current-public-selectors.mjs';
import {lowerOrderedTemporal72Catalog} from './ordered-current-temporal72.mjs';
import {orderedReferenceInput,inspectOrderedReferenceRules,countOrderedReferenceCandidates} from './ordered-current-catalog.mjs';
const capturedKinds=new Set(['namespace','relation','column','column_name','constraint','global_constraint','index','policy','trigger','saved_function','saved_constraint','role','routine']);
const rawFields=['namespace_name','name','identity_arguments','owner','acl','definition','source','security_definer','config','volatility','parallel','strict','leakproof'];
export function buildOrderedWorkerNativeReferenceContractV1({workerRecipes,edgeConditionals,membershipBags}){
  if(arguments.length!==1||!Array.isArray(workerRecipes)||workerRecipes.length!==28||!Array.isArray(edgeConditionals)||edgeConditionals.length!==7||!Array.isArray(membershipBags)||membershipBags.length!==2)throw Error('worker native reference closure');
  const membershipMaxRows={'worker-edge:gateway_projected27:3':2,'worker-edge:ordered_projected28:3':1};
  const rules=[...workerRecipes,...edgeConditionals,...membershipBags].map(row=>{
    const membership=Object.hasOwn(membershipMaxRows,row.ruleId),maxRows=membership?membershipMaxRows[row.ruleId]:1024,maxBytes=membership?65536:16777216;
    return {ruleId:row.ruleId,sourceIdentity:row.sourceIdentity,siteSHA256:row.siteSHA256,frame:structuredClone(row.frame),disposition:row.disposition,maxRows,maxBytes,capBasis:membership?'membership source fixes the selected granted/member role pairs; refuse duplicate or excess rows':'fixed source-site safety cap: at most 1024 selected rows and 16 MiB per rule; this is a refusal ceiling, never expected truth'};
  });
  if(new Set(rules.map(row=>row.ruleId)).size!==37||rules.some(row=>Object.hasOwn(row,'expectedFacts')||Object.hasOwn(row,'expectedRows')))throw Error('worker native reference rule coverage');
  return {format:'ordered-current-worker-native-observation-pending-v1',required:true,installable:false,captureReady:false,rules,limits:{maxRules:37,maxRows:35843,maxBytes:67108864,overflow:'abort-and-publish-nothing'},capDerivation:{recipeRows:'35 fixed source sites x 1024-row refusal ceiling',membershipRows:'two exact role pairs plus one exact role pair',totalRows:'35*1024+2+1',ruleBytes:'16 MiB for each recipe source site; 64 KiB for each fixed membership bag',totalBytes:'64 MiB whole-packet refusal ceiling independent of per-rule ceilings'},requiredEvidence:'bounded fixed native capture with exact original frames, NULLs, multiplicity, errors and aggregates; no log promotion'};
}

export function assertOrderedWorkerNativeObservationBoundsV1(observation,contract){
  if(arguments.length!==2||!contract||contract.format!=='ordered-current-worker-native-observation-pending-v1'||contract.installable!==false||contract.captureReady!==false||!Array.isArray(contract.rules)||contract.rules.length!==37||!Number.isSafeInteger(contract.limits?.maxRows)||contract.limits.maxRows<=0||!Number.isSafeInteger(contract.limits?.maxBytes)||contract.limits.maxBytes<=0||contract.limits.overflow!=='abort-and-publish-nothing')throw Error('worker native observation contract bounds');
  if(!observation||Object.keys(observation).sort().join(',')!=='rules,totalBytes,totalRows,truncated'||observation.truncated!==false||!Array.isArray(observation.rules)||observation.rules.length!==contract.rules.length)throw Error('worker native observation shape');
  const caps=new Map();for(const rule of contract.rules){if(caps.has(rule.ruleId)||!Number.isSafeInteger(rule.maxRows)||rule.maxRows<=0||!Number.isSafeInteger(rule.maxBytes)||rule.maxBytes<=0)throw Error('worker native observation rule cap');caps.set(rule.ruleId,rule);}
  const seen=new Set();let rows=0,bytes=0;
  for(const observed of observation.rules){if(!observed||Object.keys(observed).sort().join(',')!=='bytes,rows,ruleId'||seen.has(observed.ruleId)||!caps.has(observed.ruleId)||!Number.isSafeInteger(observed.rows)||observed.rows<0||!Number.isSafeInteger(observed.bytes)||observed.bytes<0)throw Error('worker native observation rule coverage');seen.add(observed.ruleId);const cap=caps.get(observed.ruleId);if(observed.rows>cap.maxRows||observed.bytes>cap.maxBytes)throw Error('worker native observation rule overflow');rows+=observed.rows;bytes+=observed.bytes;}
  if(rows!==observation.totalRows||bytes!==observation.totalBytes||rows>contract.limits.maxRows||bytes>contract.limits.maxBytes)throw Error('worker native observation total overflow');
}
export function buildOrderedReferenceNeeds(contract,catalog){
  if(catalog.domain_constraints.length)throw Error('domain reference metadata requires exact adapter');
  const temporal=lowerOrderedTemporalCatalog(contract),pub=lowerOrderedPublicCatalog(contract),special=lowerOrderedTemporal72Catalog(contract);
  const input=orderedReferenceInput(catalog),allRules=[...temporal.rules,...pub.rules];
  const available=inspectOrderedReferenceRules(allRules,input,capturedKinds);
  const pendingIds=new Set(available.pending.map(p=>p.id));
  const rules=[...allRules.filter(r=>pendingIds.has(r.id)),...special.rules];
  const sites=[...temporal.sites,...pub.sites],obligations=[...temporal.obligations,...pub.obligations,...special.obligations];
  if(catalog.relations.filter(r=>r.identity==='public.zasp_core_payloads').length!==1)throw Error('inventory original regclass reference identity absent');
  const inventorySource=contract.nodes.find(n=>n.identity==='public.zasp_inventory_live_fingerprint()');
  if(JSON.stringify(inventorySource?.config)!=='["search_path=pg_catalog, public"]')throw Error('inventory original reference frame differs');
  obligations.push({type:'original-regclass-resolution',sourceIdentity:inventorySource.identity,sourceSHA256:inventorySource.sourceSHA256,originalLiteral:'zasp_core_payloads',originalFrame:inventorySource.config,collectorLiteral:'public.zasp_core_payloads',referenceIdentity:'public.zasp_core_payloads',required:'The reference collector alone qualifies this one literal under its pg_catalog frame. Preserve original missing-object/error and pg_catalog shadow-resolution behavior under the original source frame in runtime/native parity; do not waive that obligation or rewrite function definition fields.'});
  const inventoryShapes={
    table:['relation',['name','owner','row_security','forced_row_security','execution_acl_text']],
    policy:['policy',['relation_name','name','permissive','command','execution_roles_text','using','check']],
    function:['routine',['name','identity_arguments','inventory_owner','security_definer','execution_config_text','inventory_acl_text','inventory_body']],
    role:['role',['name','login','inherit','superuser','create_db','create_role','replication','bypass_rls','inventory_v1_managed_here']]
  };
  for(const [branch,[kind,fields]] of Object.entries(inventoryShapes)){
    const site=pub.obligations.find(o=>o.family==='inventory'&&o.branch===branch&&o.type==='original-transformation');
    if(!site?.selector)throw Error('inventory original source selector absent');
    rules.push({id:'inventory-fields:'+branch,kind,namespaces:[],identities:[],fields,selector:structuredClone(site.selector)});
  }
  for(const site of temporal.obligations.filter(o=>o.type==='original-transformation'&&!o.family.startsWith('72.'))){
    if(!site.selector)throw Error('temporal raw input selector absent');
    rules.push({id:'raw-transform:temporal:'+site.family+':'+site.branch,kind:'routine',namespaces:[],identities:[],fields:[...rawFields],selector:structuredClone(site.selector)});
  }
  for(const site of pub.obligations.filter(o=>o.type==='original-transformation'&&o.branch==='function'&&o.family!=='inventory')){
    let selector=site.selector;
    if(site.family==='discovery_schedule_replay'){
      // Capture-only expansion from independently pinned saved rows. The later
      // original dynamic universe and regprocedure error semantics stay live.
      const identities=catalog.saved_functions.filter(r=>r.schema==='zasp_schedule_replay_prior').map(row=>{
        const found=catalog.functions.filter(f=>f.identity===row.signature||f.identity==='public.'+row.signature);
        if(found.length!==1)throw Error('schedule saved signature cannot resolve in reference');
        return found[0].identity;
      });
      if(!identities.length)throw Error('schedule saved reference universe absent');
      selector={any:[{field:'namespace',equals:'zasp_schedule_replay_prior'},...identities.map(identity=>({field:'identity',equals:identity})),{all:[{field:'namespace',equals:'public'},{field:'name',startsWith:'zasp_discovery_schedule_replay_'}]}]};
    }
    if(!selector)throw Error('public raw input selector absent');
    rules.push({id:'raw-transform:public:'+site.family,kind:'routine',namespaces:[],identities:[],fields:[...rawFields],selector:structuredClone(selector)});
  }
  const metadata=[...input,...input.filter(row=>row.kind==='relation').map(row=>({...row,kind:'class_index'}))];
  const ruleMaxRows=countOrderedReferenceCandidates(rules,metadata),categoryMaxRows={};
  const internalTriggerBound=catalog.triggers.filter(t=>t.internal===true).length;
  for(const rule of rules){
    if(rule.kind==='foreign_key_trigger')ruleMaxRows[rule.id]=internalTriggerBound;
    if(!Number.isSafeInteger(ruleMaxRows[rule.id])||ruleMaxRows[rule.id]<1)throw Error('missing positive finite reference bound '+rule.id);
    categoryMaxRows[rule.kind]=(categoryMaxRows[rule.kind]??0)+ruleMaxRows[rule.id];
  }
  const maxRows=Object.values(ruleMaxRows).reduce((sum,n)=>sum+n,0);
  if(maxRows>10000)throw Error('combined reference exceeds approved row ceiling');
  return {rules,sites,obligations,pending:available.pending,resolvedRules:available.resolved,ruleMaxRows,categoryMaxRows,maxRows,
    boundNotes:{foreign_key_trigger:'Each of seven selected constraint-source universes is bounded by all 1028 internal triggers in pinned independent catalog1; no expected joined fields are inferred.',rawTransforms:'Intermediate source inputs only. Never compare these raw rows in place of normalized original fields.',schedule:'Saved signature capture identities come solely from pinned catalog1. Original dynamic selector and missing-reg-object errors remain obligations.'}};
}
