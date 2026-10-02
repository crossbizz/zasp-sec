import fs from 'node:fs';
import crypto from 'node:crypto';
import {higherReadinessRegions} from './worker-readiness-regions.mjs';

// Reproducible migration-source builder; see worker-readiness-graph.md here.

const [input, output, manifestOutput, mode] = process.argv.slice(2);
if(mode && mode!=='--check' && mode!=='--update')throw Error('unknown generation mode');
if (!input || !output || !manifestOutput) throw Error('explicit capture/output/manifest required');
const raw = fs.readFileSync(input), capture = JSON.parse(raw);
const hash = x => crypto.createHash('sha256').update(x).digest('hex');
const root = 'zasp_temporal77.base67_fingerprint()';
const leaf = 'zasp_authorization80_worker.catalog_ready()';
const bySignature = new Map(capture.functions.map(f => [f.signature,f]));
const byName = new Map();
for(const f of capture.functions){const name=`${f.schema}.${f.name}`;if(!byName.has(name))byName.set(name,[]);byName.get(name).push(f);}
const workerChecksum = capture.registrations.worker[0].checksum;
const catalogDigest = hash(bySignature.get(leaf).source);
const quote = x => "'"+x.replaceAll("'","''")+"'";
const normal = x => x.replaceAll(workerChecksum,'<worker-checksum>').replaceAll(catalogDigest,'<worker-catalog>');

// Mask lexical literals/comments without moving character offsets. The
// resulting edits are captured fixed positions, never regex replacements of
// quoted regprocedure identities. Non-ASCII sources fail closed below.
function masked(source) {
  const out = [...source]; let i = 0;
  const hide = end => { while(i<end) out[i++]=' '; };
  while(i<source.length) {
    if(source.startsWith('--',i)){const end=source.indexOf('\n',i);hide(end<0?source.length:end);continue;}
    if(source.startsWith('/*',i)){let j=i+2,d=1;while(j<source.length&&d){if(source.startsWith('/*',j)){d++;j+=2;}else if(source.startsWith('*/',j)){d--;j+=2;}else j++;}if(d)throw Error('comment');hide(j);continue;}
    if(source[i]==="'"||source[i]==='"'){const q=source[i];const escape=q==="'"&&/[eE]/.test(source[i-1]??'')&&!/[a-z0-9_]/i.test(source[i-2]??'');let j=i+1;while(j<source.length){if(escape&&source[j]==='\\'){j+=2;continue;}if(source[j]===q){if(source[j+1]===q){j+=2;continue;}j++;break;}j++;}hide(j);continue;}
    const dollar=source.slice(i).match(/^\$(?:[a-z_][a-z0-9_]*)?\$/i);if(dollar){const j=source.indexOf(dollar[0],i+dollar[0].length);if(j<0)throw Error('dollar');hide(j+dollar[0].length);continue;}
    i++;
  }
  return out.join('');
}
function calls(fn) {
  const code=masked(fn.source), result=[];
  const re=/(?<![a-z0-9_.])((?:(?:public|zasp_[a-z0-9_]+)\s*\.\s*)?[a-z_][a-z0-9_]*)\s*\(/gi;
  for(const m of code.matchAll(re)) {
    let name=m[1].replace(/\s/g,'').toLowerCase();if(!name.includes('.'))name='public.'+name;
    if(name==='public.zasp_production_security_agent_existing_tests_global_fingerprint')name=name.slice(0,-1);
    const targets=byName.get(name);if(!targets)continue;
    let end=m.index+m[0].length,depth=1;const startArgs=end;
    while(end<code.length&&depth){if(code[end]==='(')depth++;else if(code[end]===')')depth--;end++;}
    if(depth)throw Error('unbalanced call');
    result.push({target:targets[0].signature,targets:targets.map(f=>f.signature),start:m.index,end,args:fn.source.slice(startArgs,end-1),text:fn.source.slice(m.index,end)});
  }
  return result;
}
const graph=new Map(capture.functions.map(f=>[f.signature,calls(f)]));
const depends=new Set([leaf]);
for(let i=0;i<capture.functions.length;i++)for(const [sig,edges] of graph)if(edges.some(e=>e.targets.some(t=>depends.has(t))))depends.add(sig);
const selected=new Set();
function select(sig){if(selected.has(sig)||!depends.has(sig))return;selected.add(sig);for(const e of graph.get(sig)){if(e.targets.length!==1)throw Error('ambiguous selected function call '+e.text);select(e.target);}}
select(root);
const parameters=new Map([
 ['zasp_authorization79.ready(text)',{name:'c',type:'text'}],
 ['zasp_security_agent_budgets_function_identity(oid)',{name:'function_value',type:'oid'}],
 ['zasp_discovery_schedule_replay_function_identity(oid)',{name:'value',type:'oid'}],
]);
const order=[],active=new Set(),done=new Set();
function visit(sig){if(done.has(sig))return;if(active.has(sig))throw Error('readiness cycle');active.add(sig);for(const e of graph.get(sig))if(selected.has(e.target))visit(e.target);active.delete(sig);done.add(sig);order.push(sig);}
visit(root);
const names=new Map(order.filter(sig=>!parameters.has(sig)&&sig!==root).map((sig,i)=>[sig,'readiness_'+i]));
const records=[];
for(const sig of order) {
  const fn=bySignature.get(sig);
  if(fn.owner!=='zasp_discovery_authority'||fn.language!=='sql'||fn.volatility!=='s'||fn.strict||fn.parallel!=='u'||JSON.stringify(fn.config)!==JSON.stringify(['search_path=pg_catalog, public'])||/[^\x00-\x7f]/.test(fn.source))throw Error('ineligible frame '+sig);
  if(fn.arguments&&!parameters.has(sig))throw Error('unapproved parameters '+sig);
  const source=fn.source;
  if(parameters.has(sig)) {
    const code=masked(source);let depth=0;
    for(const m of code.matchAll(/\(|\)|\bFROM\b/gi)){if(m[0]==='(')depth++;else if(m[0]===')')depth--;else if(depth===0)throw Error('parameter body outer FROM '+sig);}
    if(!/^\s*SELECT\b/i.test(code))throw Error('parameter body not scalar SELECT');
  }
  const edits=graph.get(sig).filter(e=>selected.has(e.target)).sort((a,b)=>b.start-a.start);
  for(const e of edits)if(edits.some(x=>x!==e&&x.start<e.start&&x.end>e.end))throw Error('nested selected calls require explicit review');
  records.push({signature:sig,sourceHash:hash(normal(source)),definitionHash:hash(normal(fn.definition)),sourceLength:source.length,securityDefiner:fn.security_definer,acl:fn.acl,parameter:parameters.get(sig)??null,cte:names.get(sig)??null,edits});
}
const data=JSON.stringify(records);
if(data.includes('$readiness_records$'))throw Error('delimiter');
let sql=`-- Generated by the bounded readiness graph builder from an independently\n-- captured installed catalog. Only base67's computation changes; fingerprint\n-- bytes, direct gates and differing security frames remain unchanged.\nDO $readiness_graph$\nDECLARE records jsonb:=$readiness_records$${data}$readiness_records$::jsonb;\n p jsonb;e jsonb;f record;source_value text;original_value text;replacement text;computed jsonb:='{}';ctes text:='';query_value text;definition_value text;start_value integer;end_value integer;\nBEGIN\n FOR p IN SELECT value FROM jsonb_array_elements(records) LOOP\n  SELECT x.prosrc,x.proowner::regrole::text owner_name,x.proacl::text acl,l.lanname,x.provolatile,x.proisstrict,x.proparallel,x.prosecdef,x.proconfig INTO STRICT f FROM pg_proc x JOIN pg_language l ON l.oid=x.prolang WHERE x.oid=(p->>'signature')::regprocedure;\n  IF f.owner_name<>'zasp_discovery_authority' OR f.acl IS DISTINCT FROM p->>'acl' OR f.lanname<>'sql' OR f.provolatile<>'s' OR f.proisstrict OR f.proparallel<>'u' OR f.prosecdef IS DISTINCT FROM(p->>'securityDefiner')::boolean OR f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, public']\n   OR length(f.prosrc)<>(p->>'sourceLength')::integer OR encode(digest(convert_to(replace(replace(f.prosrc,'-- worker profile checksum','<worker-checksum>'),'-- worker catalog body digest','<worker-catalog>'),'UTF8'),'sha256'),'hex')<>p->>'sourceHash'\n  THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='readiness graph exact source or frame changed';END IF;\n  IF p->>'signature'<>${quote(leaf)} AND split_part(p->>'signature','.',1)<>'zasp_authorization80_worker' THEN\n   INSERT INTO zasp_authorization80_worker.predecessor_functions SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc WHERE oid=(p->>'signature')::regprocedure ON CONFLICT(signature) DO NOTHING;\n  END IF;\n  source_value:=f.prosrc;\n  IF p->>'signature'=${quote(root)} THEN original_value:=source_value;END IF;\n  FOR e IN SELECT value FROM jsonb_array_elements(p->'edits') LOOP\n   start_value:=(e->>'start')::integer;end_value:=(e->>'end')::integer;\n   IF substring(source_value FROM start_value+1 FOR end_value-start_value) IS DISTINCT FROM e->>'text' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='readiness graph call anchor changed';END IF;\n   SELECT value INTO STRICT query_value FROM jsonb_each_text(computed) WHERE key=e->>'target';\n   replacement:=replace(query_value,'<readiness-argument>',e->>'args');\n   source_value:=substring(source_value FROM 1 FOR start_value)||replacement||substring(source_value FROM end_value+1);\n  END LOOP;\n  source_value:=regexp_replace(btrim(source_value),';[[:space:]]*$','');\n  IF p->'parameter'<>'null'::jsonb THEN\n   computed:=computed||jsonb_build_object(p->>'signature','('||source_value||' FROM (SELECT (<readiness-argument>)::'||(p#>>'{parameter,type}')||' AS '||quote_ident(p#>>'{parameter,name}')||') AS readiness_argument)');\n  ELSIF p->>'signature'<>${quote(root)} THEN\n   IF ctes<>'' THEN ctes:=ctes||',';END IF;\n   ctes:=ctes||quote_ident(p->>'cte')||'(value) AS MATERIALIZED ('||CASE WHEN p->>'signature'=${quote(leaf)} THEN 'SELECT zasp_authorization80_worker.catalog_ready()' ELSE source_value END||')';\n   computed:=computed||jsonb_build_object(p->>'signature','(SELECT value FROM '||quote_ident(p->>'cte')||')');\n  ELSE\n   query_value:='SELECT CASE WHEN current_user=''zasp_discovery_authority'' THEN (WITH '||ctes||' '||source_value||') ELSE ('||regexp_replace(btrim(original_value),';[[:space:]]*$','')||') END';\n  END IF;\n END LOOP;\n definition_value:=pg_get_functiondef(${quote(root)}::regprocedure);\n IF (length(definition_value)-length(replace(definition_value,original_value,'')))/length(original_value)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='readiness graph root body anchor changed';END IF;\n EXECUTE replace(definition_value,original_value,E'\\n'||query_value||E'\\n');\nEND $readiness_graph$;\n`;
// On any live catalog drift, execute the original recipe, not a stale copied
// leaf. Both role and catalog CASE branches contain their own subqueries so
// no materialized fused expression is demanded by either fallback branch.
const declaration='query_value text;definition_value text;start_value integer;end_value integer;';
sql=sql.replace(declaration,declaration+'catalog_cte text;');
// Full definition pin also binds return/set semantics, argument names/modes,
// defaults and function attributes that are not represented by prosrc alone.
sql=sql.replace('SELECT x.prosrc,x.proowner', 'SELECT pg_get_functiondef(x.oid) definition,x.prosrc,x.proowner');
const shapeGate="  THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='readiness graph exact source or frame changed';END IF;";
if(sql.split(shapeGate).length!==2)throw Error('definition shape gate anchor');
sql=sql.replace(shapeGate,"   OR encode(digest(convert_to(replace(replace(f.definition,'-- worker profile checksum','<worker-checksum>'),'-- worker catalog body digest','<worker-catalog>'),'UTF8'),'sha256'),'hex')<>p->>'definitionHash'\n"+shapeGate);
const rootQuery="query_value:='SELECT CASE WHEN current_user=''zasp_discovery_authority'' THEN (WITH '||ctes||' '||source_value||') ELSE ('||regexp_replace(btrim(original_value),';[[:space:]]*$','')||') END';";
if(sql.split(rootQuery).length!==2)throw Error('root query generation anchor');
const catalogName=names.get(leaf);
if(order[0]!==leaf||catalogName!=='readiness_0')throw Error('catalog must be first materialized node');
sql=sql.replace(rootQuery,()=>"catalog_cte:='readiness_0(value) AS MATERIALIZED (SELECT zasp_authorization80_worker.catalog_ready())';\n   IF left(ctes,length(catalog_cte)+1)<>catalog_cte||',' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='readiness graph materialized gate changed';END IF;\n   query_value:='SELECT CASE WHEN current_user=''zasp_discovery_authority'' THEN (WITH '||catalog_cte||' SELECT CASE WHEN (SELECT value FROM readiness_0) THEN (WITH '||substring(ctes FROM length(catalog_cte)+2)||' SELECT ('||source_value||')) ELSE ('||regexp_replace(btrim(original_value),';[[:space:]]*$','')||') END) ELSE ('||regexp_replace(btrim(original_value),';[[:space:]]*$','')||') END';");
const higher=higherReadinessRegions({bySignature,calls,masked,depends,hash,normal,quote,workerChecksum,catalogDigest});
// The new regions consume verified pre-base67 originals. Install them first;
// the existing base67 expansion does not call any of these three roots.
sql=higher.sql+sql;
const manifest=JSON.stringify({captureSHA256:hash(raw),root,leaf,expanded:records.map(({edits,...r})=>({...r,edits:edits.map(e=>({target:e.target,text:e.text,start:e.start,end:e.end}))})),regions:higher.regions,sqlSHA256:hash(sql)},null,2)+'\n';
if(mode==='--check') {
  if(fs.readFileSync(output,'utf8')!==sql||fs.readFileSync(manifestOutput,'utf8')!==manifest)throw Error('generated readiness artifact differs');
} else if(mode==='--update') {
  const prior=JSON.parse(fs.readFileSync(manifestOutput));
  if(hash(fs.readFileSync(output))!==prior.sqlSHA256)throw Error('generated output changed outside builder');
  fs.writeFileSync(output,sql);fs.writeFileSync(manifestOutput,manifest);
} else {
  fs.writeFileSync(output,sql,{flag:'wx'});
  fs.writeFileSync(manifestOutput,manifest,{flag:'wx'});
}
console.log(JSON.stringify({expanded:records.length,materialized:names.size,sqlBytes:sql.length,sqlSHA256:hash(sql)}));
