import test from 'node:test';
import assert from 'node:assert/strict';
import {parseCatalog,compareCatalogs} from './paired-catalog.mjs';
test('duplicate decoded JSON key refuses rather than keeping last value',()=>{
  assert.throws(()=>parseCatalog(Buffer.from('{"format":"first","for\\u006dat":"second"}')),/duplicate-key/);
});

const SPEC={"functions": "identity definition owner acl language volatility security_definer strict parallel config arguments result leakproof cost rows", "schemas": "name owner acl", "relations": "identity kind owner acl row_security forced_row_security options partition_bound view", "columns": "relation position name type not_null acl default identity generated collation", "constraints": "relation name definition validated deferrable deferred", "indexes": "relation identity definition valid ready live", "triggers": "relation name function enabled internal definition", "policies": "relation name permissive command roles using check", "roles": "name superuser inherit create_role create_db login replication bypass_rls connection_limit valid_until", "memberships": "role member grantor admin inherit set", "saved_functions": "schema signature definition owner acl", "saved_views": "schema signature definition", "registrations": "schema checksum fingerprint singleton predecessor outbox_predecessor profile_name", "saved_constraints": "schema signature definition", "saved_triggers": "schema relation name definition enabled", "static_sources": "identity category present rows", "types": "identity owner acl kind category relation element array base not_null default collation input output receive send analyze subscript length by_value alignment storage delimiter preferred defined type_modifier dimensions", "enum_values": "type label order", "domain_constraints": "type name definition validated deferrable deferred", "ranges": "type subtype collation opclass canonical subdiff multirange", "default_acls": "owner schema kind acl", "rewrite_rules": "relation name enabled instead event definition", "dependencies": "object referenced kind", "shared_dependencies": "object referenced kind", "extensions": "name schema owner version relocatable", "role_settings": "role database settings_sha256"};
const IDENTITIES={"functions": "identity", "schemas": "name", "relations": "identity", "columns": "relation position", "constraints": "relation name", "indexes": "identity", "triggers": "relation name", "policies": "relation name", "roles": "name", "memberships": "role member grantor", "saved_functions": "schema signature", "saved_views": "schema signature", "registrations": "schema", "saved_constraints": "schema signature", "saved_triggers": "schema relation name", "static_sources": "identity category", "types": "identity", "enum_values": "type label", "domain_constraints": "type name", "ranges": "type", "default_acls": "owner schema kind", "rewrite_rules": "relation name", "dependencies": "object referenced kind", "shared_dependencies": "object referenced kind", "extensions": "name", "role_settings": "role database"};
const FROM='ff7b2990b6bb507d3fe60780ef54306e35e02fa1789c089eb414087bb254668c';
const TO='e12fb150ebaf718d39883a8e6e3b63caac90fb05409895e0fc832e717ab46960';
function fixture(checksum=FROM){
 const d={format:'zasp-worker-effective-catalog-v2',compiled_checksum:checksum};
 for(const [category,fields] of Object.entries(SPEC)){
  const row=Object.fromEntries(fields.split(' ').map(k=>[k,null]));
  for(const k of IDENTITIES[category].split(' '))row[k]=k==='position'?1:'synthetic-'+k;
  d[category]=[row];
 }
 Object.assign(d.registrations[0],{schema:'zasp_authorization80_worker',checksum,fingerprint:'a'.repeat(64),singleton:true});
 d.functions[0].definition='SYNTHETIC-NOT-INSTALLED';return d;
}
const bytes=d=>Buffer.from(JSON.stringify(d));
function pair(a=fixture(),b=fixture()){return compareCatalogs(bytes(a),bytes(b));}
test('equal observations report every category and no authority',()=>{
 const r=pair();assert.equal(r.differences.length,0);assert.deepEqual(Object.keys(r.categories).sort(),Object.keys(SPEC).sort());
 for(const k of ['acceptance','production','native','upgradeInstalled','deployed','ledgerPromoted'])assert.equal(r[k],false);
});
for(const category of Object.keys(SPEC))test('full difference retained for '+category,()=>{
 const a=fixture(),b=fixture();const field=SPEC[category].split(' ').find(x=>!IDENTITIES[category].split(' ').includes(x))??SPEC[category].split(' ')[0];
 b[category][0][field]=field==='checksum'?'b'.repeat(64):'CHANGED-SYNTHETIC';
 if(category==='registrations'){b.registrations[0].fingerprint='b'.repeat(64);b.registrations[0].checksum=FROM;}
 const r=pair(a,b);assert.equal(r.differences.length,1);assert.equal(r.differences[0].category,category);assert.ok(r.differences[0].before.length+r.differences[0].after.length>0);
});
for(const [category,field] of [['functions','acl'],['functions','definition'],['saved_functions','definition'],['registrations','fingerprint'],['dependencies','referenced'],['default_acls','acl'],['roles','bypass_rls'],['role_settings','settings_sha256']])test('causal mutation '+category+'.'+field,()=>{
 const a=fixture(),b=fixture();b[category][0][field]='CHANGED-SYNTHETIC';if(field==='fingerprint')b[category][0][field]='b'.repeat(64);
 assert.equal(pair(a,b).differences.some(x=>x.category===category),true);
});
test('NULL differs from empty array and literal string null',()=>{
 for(const changed of [[], 'null']){const a=fixture(),b=fixture();b.functions[0].acl=changed;assert.equal(pair(a,b).differences.length,1);}
});
test('bag multiplicity is retained even for identical dependency records',()=>{
 const a=fixture(),b=fixture();b.dependencies.push({...b.dependencies[0]});const r=pair(a,b);assert.equal(r.differences.length,1);assert.equal(r.differences[0].before.length,1);assert.equal(r.differences[0].after.length,2);
});
test('category row ordering is immaterial but array-valued fields remain ordered',()=>{
 const a=fixture(),b=fixture();a.dependencies.push({...a.dependencies[0],referenced:'other'});b.dependencies=[...a.dependencies].reverse();assert.equal(pair(a,b).differences.length,0);
 a.functions[0].config=['a','b'];b.functions[0].config=['b','a'];assert.equal(pair(a,b).differences.length,1);
});
for(const category of Object.keys(SPEC))test('missing category refuses '+category,()=>{const d=fixture();delete d[category];assert.throws(()=>parseCatalog(bytes(d)),/document-shape/);});
test('duplicate unique object identity refuses',()=>{const d=fixture();d.functions.push({...d.functions[0]});assert.throws(()=>parseCatalog(bytes(d)),/duplicate-identity/);});
test('unknown field refuses',()=>{const d=fixture();d.functions[0].callerAuthority=true;assert.throws(()=>parseCatalog(bytes(d)),/record-shape/);});
test('missing identity refuses',()=>{const d=fixture();d.functions[0].identity=null;assert.throws(()=>parseCatalog(bytes(d)),/identity/);});
test('registration binding refuses',()=>{const d=fixture();d.registrations[0].checksum='b'.repeat(64);assert.throws(()=>parseCatalog(bytes(d)),/registration-binding/);});
test('numeric precision is not silently collapsed',()=>{
 const a=bytes(fixture()).toString().replace('"cost":null','"cost":9007199254740992');const b=a.replace('9007199254740992','9007199254740993');assert.equal(compareCatalogs(Buffer.from(a),Buffer.from(b)).differences.length,1);
});
test('malformed/trailing/deep JSON refuses with bounded diagnostic',()=>{
 for(const raw of ['{} trailing','[', '['.repeat(70)+']'.repeat(70)])assert.throws(()=>parseCatalog(Buffer.from(raw)),/paired catalog refused/);
});
test('historical checksum change is explicit, never normalized out',()=>{
 const r=pair(fixture(FROM),fixture(TO));assert.equal(r.compiledChecksumChanged,true);assert.equal(r.differences.some(x=>x.category==='registrations'),true);
});

test('full dependency bound preserves every record and identifies one changed edge',()=>{
 const a=fixture(),b=fixture();a.dependencies=Array.from({length:32768},(_,i)=>({object:'synthetic-'+i,referenced:'fixed',kind:'n'}));b.dependencies=a.dependencies.map(x=>({...x}));b.dependencies[123].referenced='changed';
 const r=pair(a,b);assert.equal(r.differences.length,1);assert.equal(r.differences[0].before.length,32768);assert.equal(r.differences[0].after.length,32768);assert.equal(r.differences[0].changedIdentities.length,2);
});

test('nested duplicate record field refuses',()=>{
 const raw=bytes(fixture()).toString().replace('"definition":"SYNTHETIC-NOT-INSTALLED"','"definition":"first","defin\\u0069tion":"second"');assert.throws(()=>parseCatalog(Buffer.from(raw)),/duplicate-key/);
});
test('nonfinite numeric token refuses',()=>{
 const raw=bytes(fixture()).toString().replace('"cost":null','"cost":1e999');assert.throws(()=>parseCatalog(Buffer.from(raw)),/number-range/);
});
