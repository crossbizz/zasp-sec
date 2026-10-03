// PRIVATE supplied-catalog consistency only. No installer, caller authority or publication.
import {createHash} from 'node:crypto';
const digest=raw=>createHash('sha256').update(raw).digest('hex');
const refuse=code=>{throw new Error('paired catalog refused: '+code);};
const MAX_BYTES=64*1024*1024, MAX_DEPTH=64, MAX_NODES=2000000;
class NumericToken {constructor(token){this.token=token;Object.freeze(this);}}
export const FIELDS=Object.freeze({"functions": "identity definition owner acl language volatility security_definer strict parallel config arguments result leakproof cost rows", "schemas": "name owner acl", "relations": "identity kind owner acl row_security forced_row_security options partition_bound view", "columns": "relation position name type not_null acl default identity generated collation", "constraints": "relation name definition validated deferrable deferred", "indexes": "relation identity definition valid ready live", "triggers": "relation name function enabled internal definition", "policies": "relation name permissive command roles using check", "roles": "name superuser inherit create_role create_db login replication bypass_rls connection_limit valid_until", "memberships": "role member grantor admin inherit set", "saved_functions": "schema signature definition owner acl", "saved_views": "schema signature definition", "registrations": "schema checksum fingerprint singleton predecessor outbox_predecessor profile_name", "saved_constraints": "schema signature definition", "saved_triggers": "schema relation name definition enabled", "static_sources": "identity category present rows", "types": "identity owner acl kind category relation element array base not_null default collation input output receive send analyze subscript length by_value alignment storage delimiter preferred defined type_modifier dimensions", "enum_values": "type label order", "domain_constraints": "type name definition validated deferrable deferred", "ranges": "type subtype collation opclass canonical subdiff multirange", "default_acls": "owner schema kind acl", "rewrite_rules": "relation name enabled instead event definition", "dependencies": "object referenced kind", "shared_dependencies": "object referenced kind", "extensions": "name schema owner version relocatable", "role_settings": "role database settings_sha256"});
const IDS=Object.freeze({"functions": "identity", "schemas": "name", "relations": "identity", "columns": "relation position", "constraints": "relation name", "indexes": "identity", "triggers": "relation name", "policies": "relation name", "roles": "name", "memberships": "role member grantor", "saved_functions": "schema signature", "saved_views": "schema signature", "registrations": "schema", "saved_constraints": "schema signature", "saved_triggers": "schema relation name", "static_sources": "identity category", "types": "identity", "enum_values": "type label", "domain_constraints": "type name", "ranges": "type", "default_acls": "owner schema kind", "rewrite_rules": "relation name", "dependencies": "object referenced kind", "shared_dependencies": "object referenced kind", "extensions": "name", "role_settings": "role database"});
const BAGS=new Set(['dependencies','shared_dependencies']);
const hash=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const exact=(x,keys)=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&!(x instanceof NumericToken)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
function strictJSON(raw){
 if(!Buffer.isBuffer(raw)||!raw.length||raw.length>MAX_BYTES)refuse('byte-cap');
 let text;try{text=new TextDecoder('utf-8',{fatal:true}).decode(raw);}catch{refuse('utf8');}
 let pos=0,nodes=0;
 function ws(){while(/[ \t\r\n]/.test(text[pos]??'!'))pos++;}
 function str(){const start=pos++;while(pos<text.length){const ch=text[pos++];if(ch==='"'){try{return JSON.parse(text.slice(start,pos));}catch{refuse('string');}}if(ch==='\\'){if(pos>=text.length)refuse('string');pos++;}else if(ch.charCodeAt(0)<32)refuse('string');}refuse('string');}
 function value(depth){
  if(depth>MAX_DEPTH||++nodes>MAX_NODES)refuse('depth-node-cap');ws();const ch=text[pos];
  if(ch==='"')return str();
  if(ch==='{'){
   pos++;ws();const obj=Object.create(null),seen=new Set();if(text[pos]==='}'){pos++;return obj;}
   while(true){ws();if(text[pos]!=='"')refuse('object');const key=str();if(seen.has(key))refuse('duplicate-key');seen.add(key);ws();if(text[pos++]!==':')refuse('object');obj[key]=value(depth+1);ws();const sep=text[pos++];if(sep==='}')return obj;if(sep!==',')refuse('object');}
  }
  if(ch==='['){pos++;ws();const list=[];if(text[pos]===']'){pos++;return list;}while(true){list.push(value(depth+1));ws();const sep=text[pos++];if(sep===']')return list;if(sep!==',')refuse('array');}}
  for(const [token,v]of [['true',true],['false',false],['null',null]])if(text.startsWith(token,pos)){pos+=token.length;return v;}
  const m=/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(text.slice(pos));if(!m)refuse('json-token');if(!Number.isFinite(Number(m[0])))refuse('number-range');pos+=m[0].length;return new NumericToken(m[0]);
 }
 const result=value(0);ws();if(pos!==text.length)refuse('trailing');return result;
}
function encode(x){
 if(x instanceof NumericToken)return x.token;
 if(Array.isArray(x))return '['+x.map(encode).join(',')+']';
 if(x!==null&&typeof x==='object')return '{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+encode(x[k])).join(',')+'}';
 return JSON.stringify(x);
}
const atom=x=>x===null||typeof x==='string'||typeof x==='boolean'||x instanceof NumericToken||Array.isArray(x)&&x.every(v=>typeof v==='string');
function identity(category,row){
 const fields=IDS[category].split(' '),parts=[];
 for(const field of fields){const v=row[field];if(field==='position'){if(!(v instanceof NumericToken)||!/^[1-9]\d*$/.test(v.token))refuse('identity');}
  else if(!(category==='default_acls'&&field==='schema'&&v===null)&&!(typeof v==='string'&&v.length>0))refuse('identity');parts.push(v);}
 return encode(parts);
}
export function parseCatalog(raw){
 const doc=strictJSON(raw);if(!exact(doc,['format','compiled_checksum',...Object.keys(FIELDS)]))refuse('document-shape');
 if(doc.format!=='zasp-worker-effective-catalog-v2'||!hash(doc.compiled_checksum))refuse('document-binding');
 let workers=0;
 for(const [category,spec]of Object.entries(FIELDS)){
  const rows=doc[category];if(!Array.isArray(rows)||rows.length>(category==='dependencies'?32768:20000)||category==='functions'&&!rows.length)refuse('category-shape-cap');
  const seen=new Set();for(const row of rows){if(!exact(row,spec.split(' '))||!Object.values(row).every(atom))refuse('record-shape');
   const id=identity(category,row);if(seen.has(id)&&!BAGS.has(category))refuse('duplicate-identity');seen.add(id);
   if(category==='registrations'){
    if(!hash(row.checksum)||!hash(row.fingerprint))refuse('registration-binding');
    if(row.schema==='zasp_authorization80_worker'){workers++;if(row.checksum!==doc.compiled_checksum||row.singleton!==true)refuse('registration-binding');}
   }
  }
 }
 if(workers!==1)refuse('registration-binding');return doc;
}
export function compareCatalogs(beforeBytes,afterBytes){
 const before=parseCatalog(beforeBytes),after=parseCatalog(afterBytes),categories=Object.create(null),differences=[];
 for(const category of Object.keys(FIELDS)){
  const a=before[category].map(encode).sort(),b=after[category].map(encode).sort();
  categories[category]={beforeCount:a.length,afterCount:b.length,beforeSHA256:digest(Buffer.from('['+a.join(',')+']')),afterSHA256:digest(Buffer.from('['+b.join(',')+']'))};
  if(a.length!==b.length||a.some((v,i)=>v!==b[i])){
   const group=rows=>{const map=new Map();for(const row of rows){const id=identity(category,row);if(!map.has(id))map.set(id,[]);map.get(id).push(encode(row));}for(const bag of map.values())bag.sort();return map;};
   const leftGroups=group(before[category]),rightGroups=group(after[category]);
   const ids=new Set([...leftGroups.keys(),...rightGroups.keys()]);
   const changedIdentities=[...ids].sort().filter(id=>{
    const left=leftGroups.get(id)??[],right=rightGroups.get(id)??[];return left.length!==right.length||left.some((v,i)=>v!==right[i]);
   });
   differences.push({category,changedIdentities,before:a,after:b});
  }
 }
 return {format:'private-paired-catalog-difference-v1',beforeSHA256:digest(beforeBytes),afterSHA256:digest(afterBytes),beforeCompiledChecksum:before.compiled_checksum,afterCompiledChecksum:after.compiled_checksum,compiledChecksumChanged:before.compiled_checksum!==after.compiled_checksum,categories,differences,acceptance:false,production:false,native:false,upgradeInstalled:false,deployed:false,ledgerPromoted:false};
}
