import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import {buildOrderedSpecialCatalogCapture} from './ordered-current-capture-special-catalogs.mjs';

const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const base=new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/',import.meta.url);
const contractRaw=fs.readFileSync(new URL('ordered-current-effective-contract3.json',base));
const catalogRaw=fs.readFileSync(new URL('ordered-current-effective-catalog1.json',base));
const mapRaw=fs.readFileSync(new URL('ordered-current-complete-capture-delegate-source-map.json',base));
assert.equal(sha(contractRaw),'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6');
assert.equal(sha(catalogRaw),'b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077');
assert.equal(sha(mapRaw),'f46635f66ce2666a4e8196d2c85548c9358704ee37926137a590b3ea7e55300d');
const contract=JSON.parse(contractRaw),catalog=JSON.parse(catalogRaw),sourceMap=JSON.parse(mapRaw);
const globalIdentity='public.zasp_production_security_agent_existing_tests_global_fingerprin()';
const complianceIdentity='public.zasp_compliance_jobs_catalog()';
const globalLabels=['role','membership','owned-function','owned-relation','owned-schema','owned-database','default-acl','table','column','constraint','index','policy','trigger','saved-trigger','relation-grant','column-grant','function-grant','schema-grant'];
const complianceLabels=['relation','column','constraint','index','policy','trigger','role','limits'];
const rule=(out,prefix,label)=>out.rawRules.find(x=>x.id===`special:${prefix}:${label}`);

test('the two exact installed source identities lower all 26 pinned UTF8 branch sites',()=>{
  const out=buildOrderedSpecialCatalogCapture(contract,catalog);
  assert.equal(out.rawRules.length,26);
  assert.equal(out.entries.length,162);
  assert.equal(out.runtimeAlgebra.length,26);
  assert.deepEqual(out.unresolved,[]);
  assert.deepEqual(out.rawRules.map(x=>x.id),[
    ...globalLabels.map(x=>`special:global-control:${x}`),
    ...complianceLabels.map(x=>`special:compliance-jobs:${x}`)
  ]);

  for(const [identity,prefix,labels] of [[globalIdentity,'global-control',globalLabels],[complianceIdentity,'compliance-jobs',complianceLabels]]){
    const node=contract.nodes.find(x=>x.identity===identity);
    const mapped=sourceMap.nodes.find(x=>x.identity===identity);
    assert.equal(mapped.branches.length,labels.length);
    labels.forEach((label,index)=>{
      const raw=rule(out,prefix,label),branch=mapped.branches[index];
      assert.deepEqual(raw.sourceSite,{
        sourceIdentity:identity,
        sourceSHA256:node.sourceSHA256,
        definitionSHA256:node.definitionSHA256,
        siteSHA256:branch.sha256,
        start:branch.start,
        end:branch.end,
        frame:{owner:node.owner,acl:node.acl,config:node.config,language:node.language,security_definer:node.security_definer,volatility:node.volatility,parallel:node.parallel,strict:node.strict,leakproof:node.leakproof,cost:node.cost,rows:node.rows,arguments:node.arguments,result:node.result}
      });
      assert.equal(sha(Buffer.from(node.source).subarray(branch.start,branch.end)),branch.sha256);
      const entries=out.entries.filter(x=>x.evidence.ruleId===raw.id);
      assert.equal(entries.length,raw.fields.length);
      entries.forEach((entry,ordinal)=>assert.deepEqual(entry,{
        ...raw.sourceSite,
        expressionOrdinal:ordinal,
        field:raw.fields[ordinal],
        sourceExpression:raw.projections[ordinal],
        selector:raw.selector,
        demandPath:[raw.id],
        disposition:'capture',
        evidence:{phase:'original',ruleId:raw.id,field:raw.fields[ordinal]}
      }));
    });
  }
});

test('global-control rules keep global universes, original text facts, pretty flags and true bag multiplicity',()=>{
  const out=buildOrderedSpecialCatalogCapture(contract,catalog);
  const role=rule(out,'global-control','role');
  assert.deepEqual(role.fields,['name','superuser','inherit','create_role','create_db','login','replication','bypass_rls','connection_limit','valid_until_text_or_empty','config_raw_text_or_empty','config_json','config_raw','config_dims','config_ndims','config_bounds']);
  assert.deepEqual(role.fieldTypes,{name:'text',superuser:'boolean',inherit:'boolean',create_role:'boolean',create_db:'boolean',login:'boolean',replication:'boolean',bypass_rls:'boolean',connection_limit:'integer',valid_until_text_or_empty:'text',config_raw_text_or_empty:'text',config_json:'json?',config_raw:'text?',config_dims:'text?',config_ndims:'integer?',config_bounds:'json?'});
  assert.equal(role.canonicalClass,'pg_authid');
  assert.equal(role.handleExpression,"'pg_authid:'||oid::text||':0'");
  assert.match(role.projections[10],/rolconfig::text/);
  assert.deepEqual(role.projections.slice(11),['to_jsonb(rolconfig)','rolconfig::text','array_dims(rolconfig)','array_ndims(rolconfig)','(SELECT jsonb_agg(jsonb_build_array(array_lower(rolconfig,d),array_upper(rolconfig,d)) ORDER BY d) FROM generate_series(1,array_ndims(rolconfig)) d)']);

  const membership=rule(out,'global-control','membership');
  assert.deepEqual(membership.fields,['granted_role','member_role','grantor_role','admin_option']);
  assert.equal(membership.bag,true);
  assert.equal('canonicalClass' in membership,false);
  assert.match(membership.from,/roleid=.*global_operator.* OR member=.*global_operator/);

  for(const label of ['owned-function','owned-relation','owned-schema','owned-database']){
    const raw=rule(out,'global-control',label);
    assert.match(raw.from,/global_operator/);
    assert.doesNotMatch(raw.from,/relations/);
  }
  assert.match(rule(out,'global-control','default-acl').from,/defaclrole=.* OR EXISTS/);
  assert.equal(rule(out,'global-control','default-acl').fieldTypes.namespace,'text?');

  const relations=['public.zasp_security_agent_global_control_receipts','public.zasp_security_agent_kill_switches','public.zasp_security_agent_audit','public.zasp_discovery_principal_bindings','zasp_existing_tests_predecessor.global_control_triggers'];
  for(const label of ['table','column','constraint','index','policy','trigger']){
    const raw=rule(out,'global-control',label);
    for(const relation of relations)assert.match(raw.sqlPrefix,new RegExp(relation.replaceAll('.','\\.')));
    assert.match(raw.from,/relations/);
  }
  assert.equal(rule(out,'global-control','constraint').projections.at(-1),'pg_get_constraintdef(oid,true)');
  assert.equal(rule(out,'global-control','trigger').projections[3],'pg_get_triggerdef(oid,true)');
  assert.deepEqual(rule(out,'global-control','policy').fieldTypes,{relation_identity:'text',name:'text',permissive:'boolean',command:'text',roles_csv:'text?',using_expression:'text?',check_expression:'text?'});

  const saved=rule(out,'global-control','saved-trigger');
  assert.equal(saved.bag,true);
  assert.deepEqual(saved.fields,['relation_name','trigger_name','definition','enabled']);
  assert.match(saved.from,/zasp_existing_tests_predecessor\.global_control_triggers/);
  for(const label of ['relation-grant','column-grant','function-grant','schema-grant']){
    const raw=rule(out,'global-control',label);
    assert.equal(raw.bag,true);
    assert.equal('canonicalClass' in raw,false);
    assert.equal(raw.fields.at(-1),'grantor_role');
    assert.match(raw.from,/a\.grantee='zasp_security_agent_global_operator'::regrole/);
  }
});

test('compliance rules preserve selector namespace omissions, normalized positions and original deparse modes',()=>{
  const out=buildOrderedSpecialCatalogCapture(contract,catalog);
  for(const label of ['relation','column'])assert.match(rule(out,'compliance-jobs',label).from,/n\.nspname='public'/);
  for(const label of ['constraint','index','policy','trigger']){
    const raw=rule(out,'compliance-jobs',label);
    assert.doesNotMatch(raw.from,/pg_namespace|nspname/);
    assert.match(raw.from,/starts_with\(c\.relname,'zasp_compliance_export_'\) OR c\.relname='zasp_compliance_worker_bindings'/);
  }
  const column=rule(out,'compliance-jobs','column');
  assert.equal(column.projections[1],"(SELECT count(*) FROM pg_attribute live WHERE live.attrelid=a.attrelid AND live.attnum>0 AND live.attnum<=a.attnum AND NOT live.attisdropped)");
  assert.deepEqual(column.fields,['relation_name','normalized_position','name','type','not_null','default_text_or_empty','acl_text_or_empty','identity','generated','collation']);
  assert.equal(column.canonicalClass,'pg_attribute');
  assert.equal(column.handleExpression,"'pg_attribute:'||a.attrelid::text||':'||a.attnum::text");

  const policy=rule(out,'compliance-jobs','policy');
  assert.equal(policy.projections[4],"(SELECT string_agg(r::regrole::text,',' ORDER BY r::regrole::text) FROM unnest(p.polroles) r)");
  assert.doesNotMatch(policy.projections[4],/PUBLIC|CASE/);
  assert.deepEqual(policy.fieldTypes,{relation_name:'text',name:'text',command:'text',permissive:'boolean',roles_csv:'text?',using_expression:'text?',check_expression:'text?'});
  assert.equal(rule(out,'compliance-jobs','constraint').projections[2],'pg_get_constraintdef(k.oid)');
  assert.equal(rule(out,'compliance-jobs','trigger').projections[3],'pg_get_triggerdef(t.oid)');
  assert.match(rule(out,'compliance-jobs','trigger').from,/NOT t\.tgisinternal/);
  assert.doesNotMatch(rule(out,'compliance-jobs','trigger').projections[3],/,true\)/);

  const role=rule(out,'compliance-jobs','role');
  assert.equal(role.sourceMaxRows,2);
  assert.deepEqual(role.fields,['name','login','inherit','superuser','create_db','create_role','replication','bypass_rls','connection_limit','config_raw_text_or_empty','valid_until_text_or_empty','config_json','config_raw','config_dims','config_ndims','config_bounds']);
  assert.match(role.projections[9],/rolconfig::text/);
  assert.deepEqual(role.projections.slice(11),['to_jsonb(rolconfig)','rolconfig::text','array_dims(rolconfig)','array_ndims(rolconfig)','(SELECT jsonb_agg(jsonb_build_array(array_lower(rolconfig,d),array_upper(rolconfig,d)) ORDER BY d) FROM generate_series(1,array_ndims(rolconfig)) d)']);
});

test('the compliance release-policy leaf is explicit and bound to every fixed column constraint',()=>{
  const out=buildOrderedSpecialCatalogCapture(contract,catalog),limits=rule(out,'compliance-jobs','limits');
  const fields=['revision','controls','records_per_control','format_bytes','package_bytes','snapshot_bytes','scope_active','deployment_active','attempts','lease_seconds','retry_seconds','retention_seconds','scope_bytes','deployment_bytes','scope_jobs','deployment_jobs','job_grants','principal_grants'];
  assert.deepEqual(limits.fields,fields);
  assert.deepEqual(limits.projections,fields.map(x=>`p.${x}`));
  assert.deepEqual(limits.fieldTypes,Object.fromEntries(fields.map(x=>[x,x==='revision'?'text':'integer'])));
  assert.equal(limits.sourceMaxRows,1);
  assert.equal(limits.bag,true);
  assert.equal(limits.from,'FROM public.zasp_compliance_export_policy p');
  assert.deepEqual(limits.selector.releaseValues,{revision:'compliance-limits-v1',controls:500,records_per_control:100,format_bytes:4194304,package_bytes:8388608,snapshot_bytes:4194304,scope_active:2,deployment_active:100,attempts:5,lease_seconds:60,retry_seconds:30,retention_seconds:86400,scope_bytes:268435456,deployment_bytes:17179869184,scope_jobs:100,deployment_jobs:10000,job_grants:5,principal_grants:20});
  assert.deepEqual(limits.selector.columns,fields);
  assert.equal(limits.selector.primaryKey,'revision');
  assert.equal(limits.selector.constraintBindings.length,37);
  assert.ok(limits.selector.constraintBindings.every(x=>x.validated===true&&x.relation==='public.zasp_compliance_export_policy'));
});

test('selected source, frame and release-policy catalog drift refuse without mutating inputs',()=>{
  const beforeSource=JSON.stringify(contract),beforeCatalog=JSON.stringify(catalog);
  const first=buildOrderedSpecialCatalogCapture(contract,catalog);
  assert.deepEqual(first,buildOrderedSpecialCatalogCapture(contract,catalog));
  assert.equal(JSON.stringify(contract),beforeSource);
  assert.equal(JSON.stringify(catalog),beforeCatalog);

  const changes=[
    ([source])=>source.nodes=source.nodes.filter(x=>x.identity!==globalIdentity),
    ([source])=>source.nodes.push({...source.nodes.find(x=>x.identity===globalIdentity)}),
    ([source])=>{source.nodes.find(x=>x.identity===globalIdentity).source+=' ';},
    ([source])=>{source.nodes.find(x=>x.identity===complianceIdentity).owner='other';},
    (([,cat])=>{cat.columns=cat.columns.filter(x=>!(x.relation==='public.zasp_compliance_export_policy'&&x.name==='job_grants'));}),
    (([,cat])=>{cat.constraints.find(x=>x.name==='zasp_compliance_export_policy_attempts_check').definition='CHECK ((attempts = 6))';})
  ];
  for(const change of changes){const inputs=[structuredClone(contract),structuredClone(catalog)];change(inputs);assert.throws(()=>buildOrderedSpecialCatalogCapture(...inputs),/special catalog (?:source|policy)/);}
  assert.throws(()=>buildOrderedSpecialCatalogCapture(null,catalog),/special catalog source/);
  assert.throws(()=>buildOrderedSpecialCatalogCapture(contract,null),/special catalog policy/);
});
