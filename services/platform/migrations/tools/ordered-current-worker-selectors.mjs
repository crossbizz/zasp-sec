// Exact, pinned source lowering. Snapshot-resolved saved identities are safe only
// together with the separately compared complete saved-table row sets.
import crypto from 'node:crypto';
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const identity='zasp_authorization80_worker.catalog_ready()';
const sourceSHA256='28bc26660db8eae036fd2f36bc215fcf2e27c1aba6d2c7c42d5d6a58e73c5016';
const worker='zasp_authorization80_worker',runtime='zasp_authorization80_runtime';
const eq=(field,equals)=>({field,equals});
const any=(field,values)=>({any:values.map(value=>eq(field,value))});
const fullTrigger=['enabled','definition','function_definition','function_owner','function_acl'];
const fields={namespace:['owner','acl'],routine:['definition','owner','acl'],relation:['kind','owner','acl','row_security','forced_row_security'],column:['name','position','type','not_null','acl','default'],constraint:['definition','validated'],index:['definition','valid','ready','live'],policy:['command','permissive','roles','using','check'],trigger:['enabled','definition'],saved_function:['definition','owner','acl'],saved_view:['definition']};

const workerStopBaseIdentity='zasp_temporal74.stop_evidence(text,text,text,text)';
const workerStopSuccessorIdentity='zasp_authorization80_worker.test74_stop_evidence(text,text,text,text)';
const workerStopParentAnchor=' IF t.run_id IS NULL OR (t.definition_version,t.input_digest) IS DISTINCT FROM(x.definition_version,x.input_digest)';
const workerSettledStopArm=` -- A verified late receipt may change only the parent's receipt reason.
 -- The immutable stop, audit, effect identity and all predecessor checks remain.
 IF NOT COALESCE(parent_valid,false) AND t.proof->>'kind'='admitted'
 AND t.proof->>'effect_state' IN('started','unknown')
 AND rr.state=t.proof->>'parent_state'
 AND EXISTS(SELECT 1 FROM zasp_temporal74.parent_receipts WHERE(organization_id,workspace_id,environment_id,run_id,step_id,effect_key)=(o,w,e,r,x.step_id,f.effect_key)) THEN
  PERFORM zasp_temporal74.parent_evidence(o,w,e,r,x.step_id);
  parent_valid:=true;
 END IF;
`;
const native18WorkerClosure=Object.freeze({
 version:'native18-worker-successor-closure-v2',
 builder:{goToolchain:'go1.25.13',nodeRuntime:'v22.23.1',builder:'authorizationWorkerProfileSource@production_authorization_worker_profile.go',compiler:'pg_get_functiondef-v1',transform:'go-authorizationWorkerStopSuccessor-v1'},
 goInputs:Object.freeze({
  'production_authorization_worker_profile.go':'39929eafe70f2dfda1a1fa4d42b0d6f591badc728e7da0fe5245e5c048a057e0',
  'production_temporal_test_executor.go':'b7a23012ea03c8d3ea8f198ef119d400ca701331ac2038d1a2fe3acf74f67084',
  'production_temporal_single_recovery.go':'9c1eccdffa0cb9b1a689be6f1fef5319f6f32e3d55b81db86671926d7be718ff',
  'production_authorization_worker_lifecycle_assembly_test.go':'879bfec0e731c925ed126d463eb77b1eae1b620a537bded7d2c08999fda30d49'
 }),
 temporal74Inputs:Object.freeze({
  '0074_production_temporal_test_executor.up.sql':'d54b65716166b76b3e02cabd96d8588b5c5f84f7f16c56e916be789a6d668414',
  '0074_production_temporal_test_executor.planning.sql':'e9d9634fdcf0d10e07d84cb1606b618ce07b1b26822bac7e87dd76e8738a6e28',
  '0074_production_temporal_test_executor.effects.sql':'f0baa380179229b9df52f4dec2b090e31ed865795d05dcfdecacd16122292570',
  '0074_production_temporal_test_executor.invocation.sql':'295911998f564f3e874710640b4c2b7ef835ab4721383c4ed03fe47545ea5756',
  '0074_production_temporal_test_executor.settlement.sql':'c0185e5d2a86afd9be4b6c80481b42c431f842c6a11e5ad48872eb01a0825bdf',
  '0074_production_temporal_test_executor.control.sql':'5212793c4702331cf5fa75019806c1cb92ef04a3d79c39c1ec1084141fa7c4c4',
  '0074_production_temporal_test_executor.approval.sql':'a273dd2911e0baf3a236f399e03d9f5ec04cedeb68e7374b00d118692bfc4224',
  '0074_production_temporal_test_executor.decisions.sql':'e5501c8679ae4d17913f39071ace5e8aaaa5b61a88661ee0d6ffb504f9ade956',
  '0074_production_temporal_test_executor.delivery.sql':'05294bafcc7cec38615e419b2fae15736a29bd76369207b61d445cb7d341fc53',
  '0074_production_temporal_test_executor.compatibility.sql':'0f3b81c6b2790baece6c2d6c357d002e47a789a8d49f5c13ca6540b9bf80be3c'
 }),
 workerSQL:Object.freeze({
  '0080_authorization_worker_profile.sql':'785c03177c693ebdf0d00a259ae4bbebc90a27ce3c855f37306744561a1965c4',
  '0080_authorization_worker_sources.sql':'723d9025b3f87960c381798dfe111781570b41ce3eed52c507a6106ad1cf01d9',
  '0080_authorization_worker_planning.sql':'189fe98490de3964d2c7be7e96b1e697d16ae03087c6134c1e3331689cf2a336',
  '0080_authorization_worker_planner_portability.sql':'3434767e4f475774264f264a401341ad11a3787af6df3f65c4a6951b0d621e10',
  '0080_authorization_worker_tests.sql':'1ee865175b94bea8ece71a76ff64e7f2a1e17bcb3468802f16d1087aba015888',
  '0080_authorization_worker_test_effects.sql':'e2ac1067fbe3a0eeb0f8b3ef4292c5798e4c5683bf19b8fbe3509741879e0ec3',
  '0080_authorization_worker_test_adapter.sql':'93a3072f0954f9d3b86dbf2531b5fdaf12b4b7ee711ec0ad61c582e8c95e7188',
  '0080_authorization_worker_test_completion.sql':'08cdf1f006d2952ba9bf99fa7f89ca4a83de8f0957bc37581a37dc765040c5a1',
  '0080_authorization_worker_test_context_inner.sql':'52433e89a3a5d34fd0f1c3660d022dd4019dede33f3358d4ec09220e450b5e1a',
  '0080_authorization_worker_test_receipt.sql':'46fa16499b1f56a0fb331a31eaf6e61bb05c369afda9e3195141f8ac42cd0ea4',
  '0080_authorization_worker_test_settlement.sql':'bac27a50f5fb08866ce41de6fdfe5ffe797dcc608a2b5f41d5c32dfc033968d6',
  '0080_authorization_worker_test_pricing_inner.sql':'9c42d083bec64cb3aa3bb52df3fc869fa308a554676ef537f3339b177834ac8d',
  '0080_authorization_worker_test_lifecycle.sql':'7237289ceecdfb83bd89943cb9d0a1274fc4e642eeced3c9f85ca567ce51b075',
  '0080_authorization_worker_test_activation.sql':'847769a276c380af9bfc5d77bbe54df7fbf1c9b7a8ca073a840d317f9b2c52f4',
  '0080_authorization_worker_test_catalog.sql':'4932e318bd726e9faf76c17c04e8b0985ced024e78e35d82b715b15f5fd538b0',
  '0080_authorization_worker_gateway_writers.sql':'5ce0934637fddd422c5c01f3d8e7e44737ac106cd013fc97649955e710228901',
  '0080_authorization_worker_discovery_sources.sql':'bbab06b1a5d13105476b0a2e6576e3eb7385083c1be4a68f6231876835f82afc',
  '0080_authorization_worker_discovery_fences.sql':'61f340b53429674a3a552c5912da8db279093914ac8fea6ab3f79ff2b1fab3ef',
  '0080_authorization_worker_discovery_catalog.sql':'52c4fb0927e6ac818675490980633a615c0b2df55b024bdece69bb7949b6b7d4',
  '0080_authorization_worker_ordered_sources.sql':'6080f8675cff91d3ff4b8abec12f98dfa636f2c95f2b8ce1b287a241375e00f1',
  '0080_authorization_worker_ordered_planning.sql':'9b1de5a64c0a89bc93ab07c4e0f52215f40114d3b39ab7e191705a16c69346d8',
  '0080_authorization_worker_ordered_catalog.sql':'210b7bb32b271428fbf6604d44cd9827c3d3879a03cc75c0e0dc16b75a82aabb',
  '0080_authorization_worker_ordered_human.sql':'aa0f0d99c85d4fd804ea18da11e541eef855071a93b11f437f4daeecd4651902',
  '0080_authorization_worker_ordered_approval_inner.sql':'806a43427bd52b050c6868f19ff544f10694e7d39aacdfdeefb5833a9cfcd884',
  '0080_authorization_worker_ordered_writers.sql':'146629e30258c7fb120c880d19f11a1c80c51e859c11bbd3460645018ba359b5',
  '0080_authorization_worker_ordered_writer_catalog.sql':'b1482aa3eea946a599e9d0d43a97f1d3689dd65a6da8dd73965b061d6c6d2909',
  '0080_authorization_worker_ordered_writer_late_catalog.sql':'7595bb091e92d7318793be4aa65de3817a5bdb033dc4ccba301031e824b0b176',
  '0080_authorization_worker_ordered_targets.sql':'270e82de1845509e3564bbdd2c6cdcfa8e4f00da1a1250a2bd894ff63256d884',
  '0080_authorization_worker_ordered_effects.sql':'5f47ec169c3368935d7e4d2405558f9cff0c57aa1fdb18461a1defb96530e43c',
  '0080_authorization_worker_ordered_policy.sql':'a65a32c6892c9769b8170dc682c53484dacf18f5fe04c14ad9872f17ac0f0ae6',
  '0080_authorization_worker_ordered_operations.sql':'a6d43329e20c6ba6b5cd3d6f55aa8b3587761e16afb06d1f13b765af75f96ab8',
  '0080_authorization_worker_ordered_signing_inner.sql':'e8026e1c8ca66b677bafa65c4a26d8ef7e59cc6ea5ad52fd511f0d0a37a3353e',
  '0080_authorization_worker_ordered_lifecycle.sql':'df191f7a97572dae9b40433934a53879826de27c92ee763d0eb98a19bdcc46e9',
  '0080_authorization_worker_ordered_retirement.sql':'72c88ced3e8038f558ddaff652bfe5aac5be67a15ba9ec7b6a8d2f886629c89c',
  '0080_authorization_worker_ordered_effect_catalog.sql':'fb7493c9f18aae357ce84cc028d1fb333131d1b51103c90202602ea98b24af4d',
  '0080_authorization_worker_ordered_test.sql':'3658fa05480ce076857831781512b6a422497552a9b805b8a90f9646aab10c24',
  '0080_authorization_worker_readiness_graph.sql':'530acbf49171985068c55928cb4f0a89b1c383ab223effd533af9450375b5ef6',
  '0080_authorization_worker_runtime_admission.sql':'eda6dac4f8ee0956532dc46ad7629e0c921464e1eb4b215912ca01444fb7788c',
  '0080_authorization_worker_runtime_catalog.sql':'5a5c7d9d9778145ff6500bae722d8feb1b229e642f9d16ae0ca3450b7f8d0b41',
  '0080_authorization_worker_runtime_source_catalog.sql':'4ebff8c76d580a83f4f47f6f306958cc9a7ec20b03979974c38eca48237abda1',
  '0080_authorization_worker_runtime_sources.sql':'95c10133077487fa8d2a21af8d05a76eb86b383bca35038de786f90e13eea994'
 }),
 // This file is a Node generator template only. It is deliberately separate
 // from the Go assembly graph: it is not embedded or consumed by Go.
 generatorInputs:Object.freeze({
  '0080_authorization_worker_ordered_current_integrity.sql':'d42d975c4b9cbadf7c5b368d4f14b361cd917c65a114d9629307e73af3021e5f'
 }),
 generatorInputRoles:Object.freeze({
  '0080_authorization_worker_ordered_current_integrity.sql':'node-generator-template'
 }),
 rawScopes:Object.freeze({predecessorBody:{sha256:'43dc8b5918df21c0419e4f1f9e0d5f1ecbe8596d02a919d6dee09767f2d4bc8e',span:[0,6241]},successorBody:{sha256:'f6922e090b12778964641be3b3f2491f11c022eb14e9d554c550a5e77d5d849a',span:[0,6825]},profile:{sha256:'5b129ed0592dde0af626a47bb656a572e009c1cefa182293429a454727af7bf9',bytes:829825},catalogDigest:'28bc26660db8eae036fd2f36bc215fcf2e27c1aba6d2c7c42d5d6a58e73c5016',inlineFingerprintBodySHA256:'1598fc17fea78fdc02051c636a1d84b643d615cf7b54e421b42db906baede91f'}),
 execution:Object.freeze({frame:'language=plpgsql;volatility=v;search_path=pg_catalog,public;security_definer=false',owner:'zasp_discovery_authority',acl:'{zasp_discovery_authority=X/zasp_discovery_authority}'}),
 deparseBridge:Object.freeze({version:'go-source-to-pg_get_functiondef-v1',mapping:Object.freeze({byteForByte:true,recipe:'authorizationWorkerStopSuccessor-v1; preserve body spans, replace one header identity, insert one arm at the pinned anchor, preserve closing delimiter',predecessor:Object.freeze({rawBodySHA256:'43dc8b5918df21c0419e4f1f9e0d5f1ecbe8596d02a919d6dee09767f2d4bc8e',catalogBodySHA256:'31040504a0166b99259a60610fb9682dbd0af315aae7db7f14ed5241a663f676'}),successor:Object.freeze({rawBodySHA256:'f6922e090b12778964641be3b3f2491f11c022eb14e9d554c550a5e77d5d849a',catalogBodySHA256:'f20f31592cc14f051c9bb86747ad55c8c7c080e4f66f0cef816fc0fccbe81be5'})}),predecessor:{header:[0,178],body:[178,6415],anchor:[1494,1609],closingDelimiter:[6415,6429],fullDefinitionSHA256:'3e06132df441e70ba7f2ca6c203d14bdea75132fb87767ec3381290a1e9a9279',bodySHA256:'31040504a0166b99259a60610fb9682dbd0af315aae7db7f14ed5241a663f676'},successor:{header:[0,197],insertedArm:[1513,2097],anchor:[2097,2212],body:[197,7018],closingDelimiter:[7018,7032],fullDefinitionSHA256:'9df80b547b8c23954158fe6c6fecbb2d32a6ff0cea59b74592cb4951d13bd875',bodySHA256:'f20f31592cc14f051c9bb86747ad55c8c7c080e4f66f0cef816fc0fccbe81be5'}})
});
export function assertNative18WorkerClosure(closure) {
  if (!closure||closure.version!=='native18-worker-successor-closure-v2'||closure.builder?.goToolchain!=='go1.25.13'||closure.builder?.nodeRuntime!=='v22.23.1'||closure.builder?.compiler!=='pg_get_functiondef-v1'||closure.builder?.transform!=='go-authorizationWorkerStopSuccessor-v1') throw Error('native18 worker closure builder');
  const exactGroups=[['goInputs',4],['temporal74Inputs',10],['workerSQL',41],['generatorInputs',1]];
  for (const [group,cardinality] of exactGroups) {
    const actual=closure[group];
    const expected=native18WorkerClosure[group];
    if (!actual||Object.keys(actual).length!==cardinality||JSON.stringify(Object.entries(actual))!==JSON.stringify(Object.entries(expected))) throw Error(`native18 worker closure exact ${group} manifest`);
    for (const value of Object.values(actual)) {
      const hash=typeof value==='string'?value:value?.sha256;
      if (!/^[a-f0-9]{64}$/.test(hash)) throw Error('native18 worker closure input hash');
    }
  }
  if (JSON.stringify(Object.entries(closure.generatorInputRoles??{}))!==JSON.stringify(Object.entries(native18WorkerClosure.generatorInputRoles))) throw Error('native18 worker closure generator-input role');
  if (closure.execution?.frame!=='language=plpgsql;volatility=v;search_path=pg_catalog,public;security_definer=false'||closure.execution?.owner!=='zasp_discovery_authority'||closure.execution?.acl!=='{zasp_discovery_authority=X/zasp_discovery_authority}') throw Error('native18 worker closure execution frame');
  if (JSON.stringify(closure.rawScopes.predecessorBody.span)!==JSON.stringify([0,6241])||JSON.stringify(closure.rawScopes.successorBody.span)!==JSON.stringify([0,6825])) throw Error('native18 worker closure raw spans');
  for (const scope of [closure.rawScopes.predecessorBody,closure.rawScopes.successorBody,closure.deparseBridge.predecessor,closure.deparseBridge.successor]) for (const key of ['span','header','body','anchor','insertedArm','closingDelimiter']) if (scope[key]!==undefined && (!Array.isArray(scope[key])||scope[key].length!==2||scope[key][1]<=scope[key][0])) throw Error('native18 worker closure span');
  if (JSON.stringify(closure.deparseBridge.predecessor)!==JSON.stringify(native18WorkerClosure.deparseBridge.predecessor)||JSON.stringify(closure.deparseBridge.successor)!==JSON.stringify(native18WorkerClosure.deparseBridge.successor)||closure.deparseBridge.mapping?.byteForByte!==true||closure.deparseBridge.mapping.predecessor.rawBodySHA256!==closure.rawScopes.predecessorBody.sha256||closure.deparseBridge.mapping.successor.rawBodySHA256!==closure.rawScopes.successorBody.sha256||closure.deparseBridge.mapping.predecessor.catalogBodySHA256!==closure.deparseBridge.predecessor.bodySHA256||closure.deparseBridge.mapping.successor.catalogBodySHA256!==closure.deparseBridge.successor.bodySHA256) throw Error('native18 worker closure deparse bridge');
  return true;
}
export {native18WorkerClosure};
export function buildOrderedWorkerTest74StopEvidenceSource(catalog) {
  if (!catalog || !Array.isArray(catalog.functions)) throw Error('worker test74 source catalog');
  const matches=catalog.functions.filter(row=>row?.identity===workerStopBaseIdentity);
  if (matches.length===0) return null;
  if (matches.length!==1) throw Error('worker test74 source predecessor cardinality');
  const base=matches[0];
  if (typeof base.definition!=='string'||!base.definition) throw Error('worker test74 source predecessor definition');
  if (!base.definition.includes('FUNCTION zasp_temporal74.stop_evidence(o text, w text, e text, r text)')) throw Error('worker test74 source predecessor signature');
  if (base.definition.split(workerStopParentAnchor).length-1!==1) throw Error('worker test74 source parent anchor');
  const endMarker='END $function$';
  const end=base.definition.indexOf(endMarker);
  if (end<0) throw Error('worker test74 source body boundary');
  const successor=base.definition
    .replace(`FUNCTION zasp_temporal74.stop_evidence(`,`FUNCTION zasp_authorization80_worker.test74_stop_evidence(`)
    .replace(workerStopParentAnchor,workerSettledStopArm+workerStopParentAnchor);
  if (successor===base.definition||successor.includes('zasp_temporal74.stop_evidence(')) throw Error('worker test74 source successor identity');
  const sourceClosure={...structuredClone(native18WorkerClosure),sourceIdentity:workerStopBaseIdentity,sourceDefinitionSHA256:sha(base.definition),transform:'go-authorizationWorkerStopSuccessor-v1',parentAnchor:workerStopParentAnchor,armSHA256:sha(workerSettledStopArm),successorDefinitionSHA256:sha(successor),execution:{...native18WorkerClosure.execution,owner:base.owner,acl:base.acl},deparseBridge:{...structuredClone(native18WorkerClosure.deparseBridge),predecessor:{...native18WorkerClosure.deparseBridge.predecessor,fullDefinitionSHA256:sha(base.definition)},successor:{...native18WorkerClosure.deparseBridge.successor,fullDefinitionSHA256:sha(successor)}}};
  assertNative18WorkerClosure(sourceClosure);
  return {identity:workerStopSuccessorIdentity,definition:successor,owner:base.owner,acl:base.acl,sourceClosure};
}

export function lowerOrderedWorkerCatalog(contract,catalog) {
  const nodes=contract.nodes.filter(n=>n.identity===identity);
  if(nodes.length!==1||sha(nodes[0].source)!==sourceSHA256||nodes[0].sourceSHA256!==sourceSHA256)throw Error('worker source identity changed');
  const node=nodes[0],lines=node.source.split('\n'),rules=[],sites=[];
  const add=(line,kind,options={},projection=fields[kind])=>{
    const rule={id:'worker-line-'+line,kind,namespaces:[],identities:[],fields:projection,...options};rules.push(rule);
    const start=lines.slice(0,line-1).reduce((n,s)=>n+s.length+1,0);
    sites.push({line,start,end:start+lines[line-1].length,text:lines[line-1],sha256:sha(lines[line-1]),rule:rule.id});
  };
  const requireRoutine=signature=>{
    const resolved=signature.slice(0,signature.indexOf('(')).includes('.')?signature:'public.'+signature;
    if(catalog.functions.filter(f=>f.identity===resolved).length!==1)throw Error('missing or ambiguous saved routine '+signature);
    return resolved;
  };
  const saved=(namespace,guardOnly=false)=>catalog.saved_functions.filter(f=>f.schema===namespace&&(!guardOnly||f.signature.endsWith('guard()'))).map(f=>requireRoutine(f.signature));
  const workerSaved=saved(worker),runtimeGuards=saved(runtime,true);
  if(!workerSaved.length||!runtimeGuards.length)throw Error('missing saved routine set');
  const finish=requireRoutine('public.zasp_runtime_finish_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)');
  add(2,'worker_registration',{namespaces:[worker]},['fingerprint']);
  for(const [line,kind] of [[4,'namespace'],[5,'routine'],[6,'relation'],[7,'column'],[8,'constraint'],[9,'policy'],[10,'trigger'],[11,'saved_function'],[12,'saved_view']])add(line,kind,{namespaces:[worker],...(kind==='routine'?{identities:workerSaved}:{}),...(kind==='trigger'?{predicate:'user-triggers'}:{})});
  for(const [line,kind] of [[15,'namespace'],[16,'routine'],[17,'relation'],[18,'column'],[19,'constraint'],[20,'index'],[21,'policy']])add(line,kind,{namespaces:[runtime],...(kind==='routine'?{identities:[...runtimeGuards,finish]}:{})});
  add(22,'trigger',{selector:{any:[eq('namespace',runtime),any('function',runtimeGuards)]},predicate:'user-triggers'});
  // The original WHERE clauses here are finite disjunctions of paired relation
  // and trigger-name sets. Extract only literals from the immutable source,
  // preserving each pair, rather than producing their broader cross product.
  const triggerSelector=line=>{
    const where=lines[line-1].split(/\bWHERE\s*/)[1];
    const branches=where.split(/\s+OR\s*\(/).map(branch=>{
      const relations=[...branch.matchAll(/'([^']+)'::regclass/g)].map(m=>m[1]);
      const nameClause=branch.match(/t\.tgname\s*(?:IN\(([^)]*)\)|=('[^']+'))/);
      if(!relations.length||!nameClause)throw Error('unrecognized trigger source selector');
      const names=[...(nameClause[1]??nameClause[2]).matchAll(/'([^']+)'/g)].map(m=>m[1]);
      return {all:[any('relation',relations),any('name',names)]};
    });
    return branches.length===1?branches[0]:{any:branches};
  };
  add(23,'trigger',{selector:triggerSelector(23)},fullTrigger);
  add(24,'relation',{identities:['public.zasp_runtime_stage_work']});
  add(25,'column',{selector:eq('relation','public.zasp_runtime_stage_work')},['name','position','acl']);
  add(26,'policy',{selector:eq('relation','public.zasp_runtime_stage_work')});
  add(27,'saved_function',{namespaces:[runtime]});
  add(31,'runtime_registration',{namespaces:[runtime]},['singleton','checksum','fingerprint']);
  for(const line of [32,33])add(line,'trigger',{selector:triggerSelector(line)},fullTrigger);
  const savedViews=catalog.saved_views.filter(v=>v.schema===worker).map(v=>v.signature.includes('.')?v.signature:'public.'+v.signature);
  if(!savedViews.length||savedViews.some(id=>catalog.relations.filter(v=>v.identity===id&&v.view!==null).length!==1))throw Error('missing saved view');
  add(34,'view',{identities:savedViews},['definition','owner','acl']);
  add(35,'view',{selector:{all:[eq('namespace',worker),eq('relation_kind','v')]}},['definition']);
  for(const line of [36,37,38,39,40,41])add(line,'trigger',{selector:triggerSelector(line)},line<38?fields.trigger:fullTrigger);
  return {identity,sourceSHA256,rules,sites,obligations:[
    {kind:'original-registration-relationship',line:2,cardinality:1,expression:'worker.registration.fingerprint = original complete worker catalog recipe',disposition:'development-reference-only-portability-unresolved'},
    {kind:'nested-recipe-representation',lines:[13,14,28,30,42,44],disposition:'replace hash aggregation with complete keyed selected facts; preserve outer false-on-NULL/cardinality semantics'}]};
}
