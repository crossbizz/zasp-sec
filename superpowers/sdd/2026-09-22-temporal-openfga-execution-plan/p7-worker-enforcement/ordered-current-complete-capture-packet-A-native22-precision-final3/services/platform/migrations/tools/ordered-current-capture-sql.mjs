// This compiler formats source-owned descriptors. It is not an authority API:
// packet emission separately rederives and closes the pinned source ledger.
import {orderedFactTypes} from './build-ordered-current-integrity.mjs';
const literal=s=>"'"+s.replaceAll("'","''")+"'";
const classes={
 pg_proc:['pg_proc c','c.oid::regprocedure::text'],
 pg_class:['pg_class c','c.oid::regclass::text'],
 pg_type:['pg_type c','c.oid::regtype::text'],
 pg_namespace:['pg_namespace c','c.nspname::text'],
 pg_authid:['pg_roles c','c.rolname::text'],
 pg_database:['pg_database c','c.datname::text'],
 pg_attribute:['pg_attribute c',"jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text",'c.attrelid','c.attnum'],
 pg_constraint:['pg_constraint c',"jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text"],
 pg_policy:['pg_policy c',"jsonb_build_array(c.polrelid::regclass::text,c.polname)::text"],
 pg_trigger:['pg_trigger c',"jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text"],
 pg_default_acl:['pg_default_acl c',"jsonb_build_array(c.defaclrole::regrole::text,CASE WHEN c.defaclnamespace=0 THEN NULL ELSE c.defaclnamespace::regnamespace::text END,c.defaclobjtype)::text"]
};
function executableSQL(sql){
 let out='';for(let i=0;i<sql.length;){const c=sql[i];
  if(c==='"'){let identifier='',ended=false;i++;while(i<sql.length){if(sql[i]==='"'){if(sql[i+1]==='"'){identifier+='"';i+=2;continue;}i++;ended=true;break;}identifier+=sql[i++];}if(!ended||!/^[a-z_][a-z_0-9]*$/i.test(identifier))throw Error('capture SQL unsupported quoted identifier');out+=identifier;continue;}
  if(c==="'"){const escapeString=/[eE]/.test(sql[i-1]??'')&&!/[a-z_0-9$]/i.test(sql[i-2]??'');let ended=false;i++;while(i<sql.length){if(sql[i]==="'"){if(sql[i+1]==="'"){i+=2;continue;}i++;ended=true;break;}if(sql[i]==='\\'&&escapeString&&sql[i+1]!==undefined){i+=2;continue;}i++;}if(!ended)throw Error('capture SQL unterminated quote');out+=' ';continue;}
  if(sql.slice(i,i+2)==='--'){const end=sql.indexOf('\n',i+2);i=end<0?sql.length:end;out+=' ';continue;}
  if(sql.slice(i,i+2)==='/*'){let level=1;i+=2;while(i<sql.length&&level){if(sql.slice(i,i+2)==='/*'){level++;i+=2;}else if(sql.slice(i,i+2)==='*/'){level--;i+=2;}else i++;}if(level)throw Error('capture SQL unterminated comment');out+=' ';continue;}
  if(c==='$'){const tag=sql.slice(i).match(/^\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$/)?.[0];if(tag){const end=sql.indexOf(tag,i+tag.length);if(end<0)throw Error('capture SQL unterminated dollar string');i=end+tag.length;out+=' ';continue;}}
  out+=c;i++;
 }return out;
}
export function assertCaptureSelectSQL(sql){
 if(typeof sql!=='string')throw Error('capture SQL text required');const code=executableSQL(sql).trim().replace(/;\s*$/,'').replace(/\s*\.\s*/g,'.');
 if(!/^(?:SELECT|WITH)\b/i.test(code)||/;|\b(?:INSERT|UPDATE|DELETE|MERGE|CREATE|ALTER|DROP|TRUNCATE|COPY|CALL|DO|GRANT|REVOKE|LIMIT|OFFSET|SET|RESET|INTO|LOCK|VACUUM|ANALYZE)\b/i.test(code)||/\b(?:public\.)?zasp_[a-z0-9_.]+\s*\(/i.test(code)||/\b(?:pg_sleep|pg_read_file|pg_read_binary_file|pg_write_file|dblink|lo_import|lo_export|set_config|nextval|setval)\s*\(/i.test(code))throw Error('capture SQL must be read-only SELECT without application calls or prefix limits');
}
const row=(id,identity,handle,multiplicity,fact)=>`jsonb_build_object('ruleId',${literal(id)},'identity',${identity},'handle',${handle},'multiplicity',${multiplicity},'fact',${fact})`;
function contractRule(rule,phase,section,fields,bag,rosterRuleId=null,demandRuleId=null){return {kind:rule.kind,section,phase,fields,fieldTypes:Object.fromEntries(fields.map(f=>[f,rule.fieldTypes[f]])),sourceMaxRows:rule.sourceMaxRows,refusalMaxRows:rule.refusalMaxRows,bag,rosterRuleId,demandRuleId};}
export function compileOrderedCaptureRule(rule){
 if(!rule||!Array.isArray(rule.fields)||!Array.isArray(rule.projections)||rule.fields.length!==rule.projections.length||new Set(rule.fields).size!==rule.fields.length||rule.fields.some(f=>!Object.hasOwn(rule.fieldTypes??{},f)))throw Error('capture field shape');
 const prefix=rule.sqlPrefix?rule.sqlPrefix.trim()+' ':'';
 const fact='jsonb_build_object('+rule.fields.flatMap((f,i)=>[literal(f),`(${rule.projections[i]})`]).join(',')+')';
 const phase=rule.sqlPhase??'original',section=rule.section??'rawInputs';
 const rules={};let demand=null,keys=null,original;
 if(rule.bag){
  original=`${prefix}SELECT ${row(rule.id,'fact::text','NULL','count(*)','fact')} FROM (SELECT ${fact} AS fact ${rule.from}) captured GROUP BY fact`;
  rules[rule.id]=contractRule(rule,phase,section,rule.fields,true);
 }else{
  const key=classes[rule.canonicalClass];if(!key)throw Error('capture canonical class '+rule.canonicalClass);
  if(phase!=='original'||typeof rule.handleExpression!=='string')throw Error('capture handle linkage required');
  const demandID=rule.id+':demand',keysID=rule.id+':keys';
  demand=`${prefix}SELECT ${row(demandID,'NULL',rule.handleExpression,'1',"'{}'::jsonb")} ${rule.from}`;
  keys=`SELECT ${row(keysID,key[1],'d.handle','1',"'{}'::jsonb")} FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN ${key[0]} ON ${key[2]??'c.oid'}=split_part(d.handle,':',2)::oid${key[3]?` AND ${key[3]}=split_part(d.handle,':',3)::integer`:''} WHERE d."ruleId"=${literal(demandID)} AND split_part(d.handle,':',1)=${literal(rule.canonicalClass)}`;
  original=`${prefix}SELECT ${row(rule.id,'NULL',rule.handleExpression,'1',fact)} ${rule.from}`;
  rules[demandID]=contractRule(rule,'demand','demand',[],false);
  rules[keysID]=contractRule(rule,'keys','roster',[],false,null,demandID);
  rules[rule.id]=contractRule(rule,phase,section,rule.fields,false,keysID);
 }
 for(const sql of [demand,keys,original].filter(Boolean))assertCaptureSelectSQL(sql);
 return {demand,keys,original,rules};
}

// Finite adapters for the catalog kinds emitted by the pinned lowerers. Alias
// recognition only binds a known catalog table; unknown FROM shapes refuse.
export function prepareOrderedCaptureRule(input){
 const r=structuredClone(input);
 if(!r.fieldTypes)r.fieldTypes=Object.fromEntries(r.fields.map((f,i)=>{
  if(r.additionalFieldTypes?.[f])return [f,r.additionalFieldTypes[f]];
  const t=orderedFactTypes[r.kind]?.[f];
  if(!t&&f!=='projected_identity')throw Error('capture field type mapping '+r.id+'.'+f);
  const type=t==='boolean'?'boolean':t==='integer'?'integer':t==='number'?'number':'text';
  if(type==='text')r.projections[i]=`(${r.projections[i]})::text`;
  return [f,type+'?'];
 }));
 if(r.bag||r.canonicalClass)return r;
 if(['saved_function','saved_view','saved_constraint','saved_trigger','export_saved'].includes(r.kind)){r.bag=true;return r;}
 if(['policy_view','index_view','information_column'].includes(r.kind)){
  if(r.kind==='policy_view'){r.canonicalClass='pg_policy';r.handleExpression="(SELECT 'pg_policy:'||capture_policy.oid::text||':0' FROM pg_policy capture_policy JOIN pg_class capture_class ON capture_class.oid=capture_policy.polrelid JOIN pg_namespace capture_ns ON capture_ns.oid=capture_class.relnamespace WHERE capture_policy.polname=policyname AND capture_class.relname=tablename AND capture_ns.nspname=schemaname)";}
  if(r.kind==='index_view'){r.canonicalClass='pg_class';r.handleExpression="(SELECT 'pg_class:'||capture_class.oid::text||':0' FROM pg_class capture_class JOIN pg_namespace capture_ns ON capture_ns.oid=capture_class.relnamespace WHERE capture_class.relname=indexname AND capture_ns.nspname=schemaname)";}
  if(r.kind==='information_column'){r.canonicalClass='pg_attribute';r.handleExpression="(SELECT 'pg_attribute:'||capture_attribute.attrelid::text||':'||capture_attribute.attnum::text FROM pg_attribute capture_attribute JOIN pg_class capture_class ON capture_class.oid=capture_attribute.attrelid JOIN pg_namespace capture_ns ON capture_ns.oid=capture_class.relnamespace WHERE capture_attribute.attname=column_name AND capture_class.relname=table_name AND capture_ns.nspname=table_schema)";}
  return r;
 }
 const tableFor={routine:'pg_proc',relation:'pg_class',view:'pg_class',class_index:'pg_class',type:'pg_type',namespace:'pg_namespace',role:'pg_roles',column:'pg_attribute',column_name:'pg_attribute',column_all:'pg_attribute',constraint:'pg_constraint',global_constraint:'pg_constraint',index:'pg_index',policy:'pg_policy',trigger:'pg_trigger',foreign_key_trigger:'pg_trigger',trigger_routine:'pg_trigger'};
 const table=tableFor[r.kind];if(!table)throw Error('capture key mapping '+r.kind);
 const match=r.from.match(new RegExp('\\b(?:FROM|JOIN)\\s+'+table+'(?:\\s+([a-z_][a-z_0-9]*))?','i'));
 let alias=match?.[1];if(alias&&/^(WHERE|JOIN|LEFT|RIGHT|FULL|INNER|CROSS|ON|ORDER|GROUP)$/i.test(alias))alias=null;
 if(!match&&table==='pg_class'&&/^FROM selected c\b/.test(r.from))alias='c';
 else if(!match)throw Error('capture catalog alias mapping '+r.id);
 const q=alias?alias+'.':'';r.canonicalClass=table==='pg_roles'?'pg_authid':table==='pg_index'?'pg_class':table;
 const oid=table==='pg_attribute'?q+'attrelid':table==='pg_index'?q+'indexrelid':q+'oid';
 r.handleExpression=literal(r.canonicalClass+':')+'||'+oid+"::text||':'||"+(table==='pg_attribute'?q+'attnum::text':"'0'");
 return r;
}
