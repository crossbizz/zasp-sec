import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import * as manifest from './build-ordered-current-integrity.mjs';

test('reviewed static descriptors join typed projection without hiding missing or extra rows', () => {
  const rules=[['saved_view','definition'],['runtime_registration','fingerprint'],['worker_registration','fingerprint']].map(([kind,field])=>({id:kind,kind,namespaces:[kind==='runtime_registration'?'zasp_authorization80_runtime':'zasp_authorization80_worker'],identities:[],fields:[field]}));
  const input=rules.map(rule=>({kind:rule.kind,namespace:rule.namespaces[0],identity:JSON.stringify([rule.namespaces[0]+(rule.kind==='saved_view'?'.predecessor_views':'.registration'),rule.kind==='saved_view'?'public.v':true]),fact:{[rule.fields[0]]:'original'}}));
  assert.doesNotThrow(()=>manifest.compileOrderedCollector(rules));
  const rows=manifest.projectOrderedFacts(rules,input);
  assert.equal(rows.length,3);
  assert.equal(manifest.compareFacts(rows,manifest.projectOrderedFacts(rules,input.slice(1))),false);
  assert.equal(manifest.compareFacts(rows,manifest.projectOrderedFacts(rules,[...input,{...input[2],identity:'extra-key'}])),false);
  const changed=structuredClone(input);changed[1].fact.fingerprint=null;
  assert.equal(manifest.compareFacts(rows,manifest.projectOrderedFacts(rules,changed)),false);
  assert.throws(()=>manifest.compileOrderedCollector([{...rules[1],namespaces:['unreviewed']}]),/unsupported/);
});
test('source LIKE wildcards and exact view projections preserve their original universes',()=>{
  const rules=[{id:'like-source',kind:'routine',namespaces:[],identities:[],fields:['definition'],selector:{field:'name',like:'runtime_%'}}];
  assert.doesNotThrow(()=>manifest.compileOrderedCollector(rules));
  const rows=['runtime_foo','runtimeXfoo','runtime','other'].map(name=>({kind:'routine',identity:name+'()',namespace:'public',name,fact:{definition:'body'}}));
  assert.equal(manifest.projectOrderedFacts(rules,rows).length,2);
  assert.equal(manifest.projectOrderedFacts([{...rules[0],selector:{field:'name',like:'runtime\\_%'}}],rows).length,1);
  const projections=[['routine',['name','identity_arguments','config_text_or_empty','acl_text_or_empty']],['relation',['name','acl_text_or_empty','options_text_or_empty']],['column_name',['name','type','normalized_position','default_text_or_empty','acl_text_or_empty']],['global_constraint',['name','relation','definition_pretty']],['trigger',['definition_pretty']],['policy_view',['roles','command','using','check','permissive']],['index_view',['name','definition']],['information_column',['table_name','name','data_type','is_nullable','default_text_or_empty']]].map(([kind,fields])=>({id:kind,kind,namespaces:['public'],identities:[],fields}));
  assert.doesNotThrow(()=>manifest.compileOrderedCollector(projections));
  const sql=manifest.compileOrderedCollector(projections).sql;
  assert.match(sql,/FROM pg_catalog\.pg_constraint k LEFT JOIN/);
  assert.match(sql,/FROM information_schema\.columns/);
  assert.match(sql,/a\.attname='sandbox_id'/);
});
test('product policy role encodings stay separate and preserve explicit PUBLIC semantics',()=>{
  const rules=[['policy',['name','roles_csv_public_sorted','roles_named_array_text','using_text_or_empty','check_text_or_empty']],['column',['relation_name']],['index',['name']]].map(([kind,fields])=>({id:kind,kind,namespaces:['public'],identities:[],fields}));
  assert.doesNotThrow(()=>manifest.compileOrderedCollector(rules));
  const sql=manifest.compileOrderedCollector(rules).sql;
  assert.match(sql,/WHEN role_oid=0 THEN 'PUBLIC'/);
  assert.match(sql,/WHERE role_row\.oid=ANY\(p\.polroles\) ORDER BY role_row\.rolname/);
  const input=[{kind:'policy',namespace:'public',identity:'p',fact:{name:'p',roles_csv_public_sorted:'PUBLIC,owner',roles_named_array_text:'{owner}',using_text_or_empty:'',check_text_or_empty:''}}];
  const rows=manifest.projectOrderedFacts(rules,input);
  assert.equal(rows[0].fact.roles_csv_public_sorted,'PUBLIC,owner');
  assert.equal(rows[0].fact.roles_named_array_text,'{owner}');
});
test('closed negative selectors preserve SQL NULL and constrained-side FK trigger universes',()=>{
  const rule={id:'negative',kind:'global_constraint',namespaces:[],identities:[],fields:['name'],selector:{not:{field:'namespace',equals:'excluded'}}};
  assert.doesNotThrow(()=>manifest.compileOrderedCollector([rule]));
  const rows=[null,'excluded','included'].map((namespace,i)=>({kind:'global_constraint',identity:String(i),namespace,fact:{name:'c'}}));
  assert.equal(manifest.projectOrderedFacts([rule],rows).length,1);
  const fk={id:'fk',kind:'foreign_key_trigger',namespaces:['zasp_temporal68'],identities:[],fields:['relation','name','referenced_relation','trigger_relation','constraint_relation','function','event_bits','enabled','deferrable','deferred','argument_count','arguments','columns_text','when_text_or_empty']};
  assert.doesNotThrow(()=>manifest.compileOrderedCollector([fk]));
  const sql=manifest.compileOrderedCollector([fk]).sql;
  assert.match(sql,/c\.oid=k\.conrelid/);
  assert.match(sql,/t\.tgisinternal AND k\.contype='f'/);
  assert.doesNotMatch(sql,/t\.tgname/);
});

// Independent literals: none of the expected rows comes from the serializer.
const expected = [
  {kind: 'namespace', identity: 'release', fact: {owner: 'owner', acl: null}},
  {kind: 'routine', identity: 'release.entry(text)', fact: {owner: 'owner', acl: ['owner=X/owner'], definition: 'SELECT 1', security_definer: true, config: ['search_path=pg_catalog']}},
  {kind: 'relation', identity: 'release.items', fact: {kind: 'r', owner: 'owner', row_security: true, forced_row_security: true, acl: null}},
  {kind: 'column', identity: 'release.items/1', fact: {name: 'id', position: 1, type: 'text', not_null: true, default: null, acl: null}},
  {kind: 'constraint', identity: 'release.items/pk', fact: {definition: 'PRIMARY KEY (id)', validated: true}},
  {kind: 'index', identity: 'release.pk', fact: {definition: 'CREATE UNIQUE INDEX pk ON release.items USING btree (id)', valid: true, ready: true, live: true}},
  {kind: 'policy', identity: 'release.items/owner', fact: {command: '*', permissive: true, roles: ['owner'], using: 'true', check: null}},
  {kind: 'trigger', identity: 'release.items/guard', fact: {enabled: 'O', definition: 'CREATE TRIGGER guard BEFORE INSERT ON release.items FOR EACH ROW EXECUTE FUNCTION release.guard()'}},
  {kind: 'view', identity: 'release.visible', fact: {definition: 'SELECT id FROM release.items', owner: 'owner', acl: null}},
  {kind: 'rewrite', identity: 'release.visible/_RETURN', fact: {event: '1', enabled: 'O', instead: true, definition: 'CREATE RULE _RETURN AS ON SELECT TO release.visible DO INSTEAD SELECT id FROM release.items'}},
  {kind: 'type', identity: 'release.state', fact: {kind: 'e', owner: 'owner', labels: ['open', 'closed']}},
  {kind: 'operator', identity: 'release.==(text,text)', fact: {procedure: 'release.equal(text,text)'}},
  {kind: 'collation', identity: 'release.sort', fact: {provider: 'c', locale: 'C'}},
  {kind: 'default_acl', identity: 'owner/release/r', fact: {acl: ['owner=arwdDxt/owner']}},
  {kind: 'role', identity: 'owner', fact: {login: false, superuser: false, create_db: false, create_role: false, replication: false, bypass_rls: false}},
  {kind: 'membership', identity: 'owner/migration', fact: {admin: false, grantor: 'installer'}},
  {kind: 'role_setting', identity: 'owner/database', fact: {config: ['search_path=pg_catalog']}},
  {kind: 'saved_function', identity: 'release/previous(text)', fact: {definition: 'SELECT $1', owner: 'owner', acl: null}},
  {kind: 'saved_view', identity: 'release/previous', fact: {definition: 'SELECT 1'}},
  {kind: 'saved_constraint', identity: 'release/previous/check', fact: {definition: 'CHECK (id IS NOT NULL)'}},
  {kind: 'saved_trigger', identity: 'release/previous/guard', fact: {enabled: 'O', definition: 'CREATE TRIGGER guard BEFORE INSERT ON release.previous FOR EACH ROW EXECUTE FUNCTION release.guard()'}},
  {kind: 'registration', identity: 'release.registration', fact: {singleton: true, checksum: 'a'.repeat(64), fingerprint: 'b'.repeat(64)}},
  {kind: 'dependency', identity: 'release.items/id/release.state/n', fact: {object: 'release.items/id', referenced: 'release.state', dependency_kind: 'n'}},
  {kind: 'shared_dependency', identity: 'release.items/owner/o', fact: {object: 'release.items', referenced: 'owner', dependency_kind: 'o'}},
  {kind: 'extension', identity: 'pgcrypto', fact: {schema: 'public', version: '1.3'}}
];
const change = (rows, kind, field, value) => { rows.find(r => r.kind === kind).fact[field] = value; };
const changeBody = rows => change(rows, 'routine', 'definition', 'SELECT true');
const grantExecute = rows => change(rows, 'routine', 'acl', ['owner=X/owner', '=X/owner']);
const changeOwner = rows => change(rows, 'routine', 'owner', 'executor');
const disableTrigger = rows => change(rows, 'trigger', 'enabled', 'D');
const addRlsPolicy = rows => rows.push({kind: 'policy', identity: 'release.items/public', fact: {command: '*', permissive: true, roles: ['public'], using: 'true', check: null}});
const removeConstraint = rows => rows.splice(rows.findIndex(r => r.kind === 'constraint'), 1);
const changeSavedDefinition = rows => change(rows, 'saved_function', 'definition', 'SELECT true');
const addUnexpectedObject = rows => rows.push({kind: 'routine', identity: 'release.extra()', fact: {definition: 'SELECT true'}});
// Missing behavior is an assertion failure, not a module-loader error.
const compareFacts = (...args) => manifest.compareFacts?.(...args);
const normalizeEntry = (...args) => manifest.normalizeEntry?.(...args);
const buildManifest = (...args) => manifest.buildManifest?.(...args);

test('keyed facts compare complete sets, preserve NULL and reject each declared drift', () => {
  assert.equal(compareFacts(expected, structuredClone(expected)), true);
  assert.equal(compareFacts(expected, [...expected].reverse()), true);
  for (const mutate of [changeBody, grantExecute, changeOwner, disableTrigger, addRlsPolicy, removeConstraint, changeSavedDefinition, addUnexpectedObject]) {
    const live = structuredClone(expected); mutate(live);
    assert.equal(compareFacts(expected, live), false, mutate.name);
  }
  for (const kind of expected.map(r => r.kind)) {
    assert.equal(compareFacts(expected, expected.filter(r => r.kind !== kind)), false, kind + ' missing');
    const live = structuredClone(expected);
    live.push({...structuredClone(live.find(r => r.kind === kind)), identity: kind + '/unexpected'});
    assert.equal(compareFacts(expected, live), false, kind + ' addition');
  }
  const emptyAcl = structuredClone(expected); change(emptyAcl, 'namespace', 'acl', []);
  assert.equal(compareFacts(expected, emptyAcl), false);
  const emptyDefault = structuredClone(expected); change(emptyDefault, 'column', 'default', '');
  assert.equal(compareFacts(expected, emptyDefault), false);
  const reorderedConfig = structuredClone(expected);
  change(reorderedConfig, 'routine', 'config', ['search_path=pg_catalog', 'TimeZone=UTC']);
  const otherConfig = structuredClone(reorderedConfig); otherConfig.find(r => r.kind === 'routine').fact.config.reverse();
  assert.equal(compareFacts(reorderedConfig, otherConfig), false);
});

test('malformed, duplicate and undeclared fact fields refuse comparison', () => {
  for (const malformed of [null, {}, [...expected, expected[0]], [{kind: 'unknown', identity: 'x', fact: {owner: 'owner'}}], [{kind: 'routine', identity: 'x', fact: {owner: undefined}}], [{kind: 'role', identity: 'x', fact: {login: 'false'}}], [{kind: 'routine', identity: 'x', fact: {captured_ready: true}}]]) {
    assert.equal(compareFacts(expected, malformed), false);
  }
});

const zero = '0'.repeat(64);
const entryBody = `BEGIN PERFORM zasp_authorization80_ordered_current.require('${zero}'); END`;
const entry = {identity: 'release.entry(text)', definition: entryBody,
  manifestSpan: {start: entryBody.indexOf(zero), end: entryBody.indexOf(zero) + 64}};
const release = {format: 1, purpose: 'development-only', expectedFromTarget: false,
  profileChecksum: 'a'.repeat(64), compiledSourceSHA256: 'b'.repeat(64),
  contractSHA256: 'c'.repeat(64), referenceFileSHA256: 'd'.repeat(64),
  postgres: '17.6', pgcrypto: '1.3', generatorSHA256: 'e'.repeat(64),
  moduleSHA256: {'module.sql': 'f'.repeat(64)},
  facts: structuredClone(expected), entries: [entry]};
release.facts.find(r => r.kind === 'routine').fact.definition = entryBody;

test('one exact compiler span normalizes and retains every other byte', () => {
  const got = normalizeEntry(entry);
  assert.equal(got?.definition, "BEGIN PERFORM zasp_authorization80_ordered_current.require('@ordered-current-manifest@'); END");
  assert.equal(got?.manifestLiteral, zero);
  const twoManifestLiteralSites = {...entry, definition: entryBody + entryBody};
  assert.throws(() => normalizeEntry(twoManifestLiteralSites));
  assert.throws(() => normalizeEntry({...entry, manifestSpan: {start: 0, end: 64}}));
  assert.throws(() => normalizeEntry({...entry, definition: entryBody.replace(zero, 'x'.repeat(64))}));
});

test('two deterministic passes reach a fixed point and distinguish payloadSHA from fileSHA', () => {
  const built = buildManifest(release);
  assert.equal(typeof built?.payloadSHA256, 'string');
  assert.notEqual(built.payloadSHA256, built.fileSHA256);
  assert.equal(built.installable, false);
  assert.equal(built.entries[0].definition.includes(`'${built.payloadSHA256}'`), true);
  assert.deepEqual(buildManifest(release), built);
  const reinput = {...release, entries: built.entries, facts: built.facts};
  assert.equal(buildManifest(reinput).payloadSHA256, built.payloadSHA256);
  assert.throws(() => buildManifest({...release, expectedFromTarget: true}));
  assert.throws(() => buildManifest({...release, purpose: 'release'}));
  assert.throws(() => buildManifest({...release, referenceFileSHA256: null}));
});

test('compiled pin, evaluator frame/body and copied entry identity are independently admitted', () => {
  const trusted = {identity: 'private.catalog(text)', owner: 'owner', acl: ['owner=X/owner'], language: 'plpgsql', security_definer: false,
    volatility: 'v', strict: false, parallel: 'u', config: ['search_path=pg_catalog'], definition: 'BEGIN RETURN false; END'};
  const pinnedEntry={...entry,definition:entry.definition.replace(zero,'a'.repeat(64))};
  const valid = {expectedManifest: 'a'.repeat(64), compiledManifest: 'a'.repeat(64), expectedEvaluator: trusted, liveEvaluator: structuredClone(trusted), expectedEntry: pinnedEntry, liveEntry: structuredClone(pinnedEntry)};
  assert.equal(manifest.admitOrderedCurrent?.(valid), true);
  for (const alter of [x => { x.expectedManifest = 'b'.repeat(64); }, x => { x.liveEvaluator.owner = 'executor'; }, x => { x.liveEvaluator.definition = 'BEGIN RETURN true; END'; }, x => { x.liveEntry.identity = 'release.copied(text)'; }, x => { x.liveEntry.definition += ' '; }]) {
    const live = structuredClone(valid); alter(live);
    assert.equal(manifest.admitOrderedCurrent?.(live), false);
  }
  const wrongLiteral=structuredClone(valid);wrongLiteral.expectedEntry=entry;wrongLiteral.liveEntry=structuredClone(entry);
  assert.equal(manifest.admitOrderedCurrent(wrongLiteral),false,'entry raw manifest literal must equal the compiled pin');
  assert.equal(manifest.admitOrderedCurrent({...valid,expectedEvaluator:{},liveEvaluator:{}}),false,'missing frame cannot self-approve');
});

test('code admission refuses historical evaluator edges, bare calls and external statements', () => {
  for (const body of ['SELECT zasp_temporal68.current_ready()', 'SELECT zasp_authorization80_worker.catalog_ready()', 'SELECT public.zasp_inventory_live_fingerprint()', "EXECUTE 'SELECT true'", 'SELECT unknown_check()']) {
    assert.throws(() => manifest.admitCollectorSource?.(body), body);
  }
  assert.equal(manifest.admitCollectorSource?.('SELECT jsonb_build_object(\'name\', n.nspname) FROM pg_catalog.pg_namespace n'), true);
});

test('reserved provenance is exactly one closed typed row and participates in payload identity', () => {
  const built = buildManifest(release);
  const provenance = built.facts.filter(r => r.kind === 'build');
  assert.equal(provenance.length, 1);
  assert.equal(provenance[0].identity, 'provenance');
  assert.equal(manifest.validateOrderedManifestFacts?.(built.facts), true);
  const missing = built.facts.filter(r => r.kind !== 'build');
  assert.equal(manifest.validateOrderedManifestFacts?.(missing), false);
  const extra = structuredClone(built.facts); extra.push({...provenance[0], identity: 'other'});
  assert.equal(manifest.validateOrderedManifestFacts?.(extra), false);
  const malformed = structuredClone(built.facts); malformed.find(r => r.kind === 'build').fact.unreviewed_exclusion = 'routine';
  assert.equal(manifest.validateOrderedManifestFacts?.(malformed), false);
  const changedPin = buildManifest({...release, referenceFileSHA256: '1'.repeat(64)});
  assert.notEqual(changedPin.payloadSHA256, built.payloadSHA256);
});

test('one selected namespace yields exact keyed projections with absence and addition visible', () => {
  const rules = [{id: 'worker-functions', kind: 'routine', namespaces: ['release'], identities: [], fields: ['owner', 'definition', 'acl']}];
  const input = [{kind: 'routine', identity: 'release.f()', namespace: 'release', fact: {owner: 'owner', definition: 'SELECT 1', acl: null, cost: 100}},
    {kind: 'routine', identity: 'other.f()', namespace: 'other', fact: {owner: 'other', definition: 'SELECT 2', acl: null, cost: 100}}];
  const wanted = [{kind: 'routine', identity: '["worker-functions","release.f()"]', fact: {owner: 'owner', definition: 'SELECT 1', acl: null}}];
  assert.deepEqual(manifest.projectOrderedFacts?.(rules,input), wanted);
  const extra = [...input, {kind: 'routine', identity: 'release.g()', namespace: 'release', fact: {owner: 'owner', definition: 'SELECT 1', acl: null, cost: 100}}];
  assert.equal(compareFacts(wanted, manifest.projectOrderedFacts?.(rules,extra)), false);
  assert.equal(compareFacts(wanted, manifest.projectOrderedFacts?.(rules,[])), false);
  const unrelated = structuredClone(input); unrelated[0].fact.cost = 101;
  assert.deepEqual(manifest.projectOrderedFacts?.(rules,unrelated), wanted, 'unselected exported cost is not added hardening');
  for (const bad of [[{...rules[0], sql: 'SELECT true'}], [{...rules[0], fields: ['captured_ready']}], [{...rules[0], namespaces: []}], [...rules,rules[0]]]) {
    assert.throws(() => manifest.compileOrderedCollector?.(bad));
  }
  const compiled = manifest.compileOrderedCollector?.(rules);
  assert.equal(typeof compiled?.sql, 'string');
  assert.equal(manifest.admitCollectorSource(compiled.sql), true);
  assert.deepEqual(manifest.compileOrderedCollector(rules), compiled);
});

test('eight exact auth80 primitive comparisons retain source frames and refuse changed, missing or extra sites', () => {
  const raw=fs.readFileSync(new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/ordered-current-effective-contract3.json',import.meta.url));
  assert.equal(crypto.createHash('sha256').update(raw).digest('hex'),'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6');
  const contract=JSON.parse(raw);
  const got=manifest.classifyOrderedAuth80Live?.(contract);
  assert.equal(got?.sites.length,8);
  assert.equal(got.sites.filter(s=>s.identity==='zasp_temporal77.base67_fingerprint()')[0].security_definer,false);
  for(const site of got.sites) {
    const node=contract.nodes.find(n=>n.identity===site.identity);
    assert.equal(node.source.slice(site.start,site.end),site.text);
    assert.equal(site.owner,node.owner);
    assert.deepEqual(site.config,node.config);
  }
  for(const alter of [s=>s.replace("checksum='d7fb", "checksum='ffff"),s=>s.replace('fingerprint=zasp_authorization80.fingerprint()', 'fingerprint IS NOT NULL'),s=>s+'\n'+got.sites[0].text]) {
    const changed=structuredClone(contract);
    const node=changed.nodes.find(n=>n.identity==='zasp_authorization80_temporal.catalog_ready()');node.source=alter(node.source);
    assert.throws(()=>manifest.classifyOrderedAuth80Live(changed));
  }
  const forged=structuredClone(contract);forged.nodes.find(n=>n.identity==='zasp_authorization80.fingerprint()').source='SELECT NULL';
  assert.throws(()=>manifest.classifyOrderedAuth80Live(forged));
});

test('fixed native membership selector detects off-fixture incoming grants and ignores unrelated memberships', () => {
  const rules=[{id:'native-memberships',kind:'membership',namespaces:[],identities:[],fields:['admin','grantor'],predicate:'fixed-native-negative-universe'}];
  const input=[{kind:'membership',identity:'["customer","zasp_temporal_executor","owner"]',namespace:'customer',member:'zasp_temporal_executor',fact:{admin:false,grantor:'owner'}},
    {kind:'membership',identity:'["zasp_temporal_accounting","new_login","owner"]',namespace:'zasp_temporal_accounting',member:'new_login',fact:{admin:false,grantor:'owner'}},
    {kind:'membership',identity:'["customer","other_login","owner"]',namespace:'customer',member:'other_login',fact:{admin:false,grantor:'owner'}}];
  assert.equal(manifest.projectOrderedFacts(rules,[]).length,0);
  assert.equal(manifest.projectOrderedFacts(rules,input).length,2);
  assert.equal(compareFacts([],manifest.projectOrderedFacts(rules,input)),false);
  assert.equal(manifest.admitCollectorSource(manifest.compileOrderedCollector(rules).sql),true);
});

test('saved definitions preserve each original raw ACL form without JSON or role-name rewriting', () => {
  const rules=[{id:'saved',kind:'saved_function',namespaces:['zasp_authorization80_worker'],identities:[],fields:['definition','owner','acl']}];
  const raw='[{"grantee": "installer", "grantable": false}]';
  const inputs=[{kind:'saved_function',identity:'["zasp_authorization80_worker","prior(text)"]',namespace:'zasp_authorization80_worker',fact:{definition:'SELECT $1',owner:'installer',acl:raw}}];
  const projected=manifest.projectOrderedFacts(rules,inputs);
  assert.equal(projected[0].fact.acl,raw);
  const changed=structuredClone(inputs);changed[0].fact.acl='[{"grantee":"installer","grantable":false}]';
  assert.equal(compareFacts(projected,manifest.projectOrderedFacts(rules,changed)),false,'raw source bytes were not canonicalized');
  assert.equal(manifest.admitCollectorSource(manifest.compileOrderedCollector(rules).sql),true);
});

test('projected fact keys join entry spans and exclude only the fixed private registration self field', () => {
  const rules=[{id:'current-entries',kind:'routine',namespaces:['release'],identities:[],fields:['definition','owner','acl']}];
  const projected=manifest.projectOrderedFacts(rules,[{kind:'routine',identity:'release.entry(text)',namespace:'release',fact:{definition:entryBody,owner:'owner',acl:null}}]);
  assert.equal(projected[0].identity,'["current-entries","release.entry(text)"]');
  const selfIdentity='["private-registration","zasp_authorization80_ordered_current.registration"]';
  const facts=[...projected,{kind:'registration',identity:selfIdentity,fact:{singleton:true,format_version:1,profile_checksum:'a'.repeat(64),manifest_sha256:zero}}];
  const declared={...entry,identity:projected[0].identity};
  const input={...release,facts,entries:[declared]};
  const built=buildManifest(input);
  assert.equal(built.facts.find(r=>r.identity===selfIdentity).fact.manifest_sha256,built.payloadSHA256);
  assert.equal(built.entries[0].definition.includes(built.payloadSHA256),true);
  assert.equal(buildManifest({...input,facts:built.facts,entries:built.entries}).payloadSHA256,built.payloadSHA256);
  const unrelated=[...facts,{kind:'registration',identity:'other.registration',fact:{manifest_sha256:zero}}];
  const altered=structuredClone(unrelated);altered.find(r=>r.identity==='other.registration').fact.manifest_sha256='1'.repeat(64);
  assert.notEqual(buildManifest({...input,facts:unrelated}).payloadSHA256,buildManifest({...input,facts:altered}).payloadSHA256);
});

test('source-selected relation/name and public-prefix universes keep additions visible without broadening scope', () => {
  const rules=[{id:'capture',kind:'trigger',namespaces:[],identities:[],fields:['definition','enabled'],predicate:'user-triggers',selector:{all:[{field:'relation',equals:'public.runs'},{any:[{field:'name',equals:'capture'},{field:'name',equals:'no_truncate'}]}]}},
    {id:'source-functions',kind:'routine',namespaces:[],identities:[],fields:['definition'],selector:{all:[{field:'namespace',equals:'public'},{field:'name',startsWith:'zasp_export_'}]}}];
  const input=[{kind:'trigger',identity:'["public.runs","capture"]',namespace:'public',relation:'public.runs',name:'capture',fact:{definition:'CREATE TRIGGER capture',enabled:'O',internal:false}},
    {kind:'trigger',identity:'["public.other","capture"]',namespace:'public',relation:'public.other',name:'capture',fact:{definition:'CREATE TRIGGER capture',enabled:'O',internal:false}},
    {kind:'routine',identity:'public.zasp_export_read()',namespace:'public',name:'zasp_export_read',fact:{definition:'SELECT 1'}},
    {kind:'routine',identity:'customer.zasp_export_read()',namespace:'customer',name:'zasp_export_read',fact:{definition:'SELECT 2'}}];
  const projected=manifest.projectOrderedFacts(rules,input);
  assert.equal(projected.length,2);
  const extra=[...input,{kind:'routine',identity:'public.zasp_export_extra()',namespace:'public',name:'zasp_export_extra',fact:{definition:'SELECT 1'}}];
  assert.equal(compareFacts(projected,manifest.projectOrderedFacts(rules,extra)),false);
  assert.equal(manifest.admitCollectorSource(manifest.compileOrderedCollector(rules).sql),true);
  assert.throws(()=>manifest.compileOrderedCollector([{...rules[1],selector:{field:'sql',equals:'SELECT true'}}]));
  assert.throws(()=>manifest.compileOrderedCollector([{...rules[1],selector:{all:[]}}]));
});
