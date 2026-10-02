import crypto from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {higherReadinessRegions} from './worker-readiness-regions.mjs';

// Pure opt-in successor. No file, process, CLI, generator or installed-row I/O.
// The bounded compiler body below is a source-faithful in-memory adaptation of
// the pinned build-worker-readiness-graph.mjs lines 11-104, without its writer.
export function compileWorkerHigherGraph({functions,workerChecksum}) {
const capture={functions};
const hash = x => crypto.createHash('sha256').update(x).digest('hex');
const root = 'zasp_temporal77.base67_fingerprint()';
const leaf = 'zasp_authorization80_worker.catalog_ready()';
const bySignature = new Map(capture.functions.map(f => [f.signature,f]));
const byName = new Map();
for(const f of capture.functions){const name=`${f.schema}.${f.name}`;if(!byName.has(name))byName.set(name,[]);byName.get(name).push(f);}
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
    const targets=byName.get(name);if(!targets){if(fn.originalAdmitted&&(name.startsWith('zasp_')||name.startsWith('public.zasp_')))throw Error('missing admitted application callable '+name);continue;}
    let end=m.index+m[0].length,depth=1;const startArgs=end;
    while(end<code.length&&depth){if(code[end]==='(')depth++;else if(code[end]===')')depth--;end++;}
    if(depth)throw Error('unbalanced call');
    result.push({target:targets[0].signature,targets:targets.map(f=>f.signature),start:m.index,end,args:fn.source.slice(startArgs,end-1),text:fn.source.slice(m.index,end)});
  }
  return result;
}
for(const f of capture.functions)if(bySignature.get(f.signature)!==f)throw Error('duplicate callable signature');
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
  if(!fn.originalAdmitted)throw Error('unadmitted selected original '+sig);
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
// Call resolution still sees the entire admitted application universe. A
// selected higher node may supply bytes only from the verified originals.
const originalsBySignature={get(signature){const fn=bySignature.get(signature);if(!fn?.originalAdmitted)throw Error('unadmitted higher original '+signature);return fn;}};
const higher=higherReadinessRegions({bySignature:originalsBySignature,calls,masked,depends,hash,normal,quote,workerChecksum,catalogDigest});
// The new regions consume verified pre-base67 originals. Install them first;
// the existing base67 expansion does not call any of these three roots.
sql=higher.sql+sql;
const baseReplay=replayWorkerBaseRecords(records,bySignature);
return {sql,higher,records,baseReplay,catalogDigest};
}

const sha = x => crypto.createHash('sha256').update(x).digest('hex');
const fail = message => { throw Error('worker higher '+message); };
const pins = Object.freeze({
 contractRaw:'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6',
 catalogRaw:'b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077',
 releaseRaw:'4ad7d7218fff014766d92d8af7522ed5bb382b95e5fa1e12d9be70a407543425',
 graphRaw:'530acbf49171985068c55928cb4f0a89b1c383ab223effd533af9450375b5ef6',
 compilerRaw:'fb66f8649b5fea1cf54dbaa7776665b5375fd64bb6808c2b7c75036812a56da7',
 regionsRaw:'d72a3e431dd7fd2abfd15612a03a7d0d8c2b6dca1b064f37536d4151d4f83309',
 captureSourceRaw:'60be84a43d564c9c7da3999a22155a7734a1163f258d58206f8bcfabbabc43f6',
});
const workerChecksum='5b129ed0592dde0af626a47bb656a572e009c1cefa182293429a454727af7bf9';
const catalogDigest='28bc26660db8eae036fd2f36bc215fcf2e27c1aba6d2c7c42d5d6a58e73c5016';
const normalize = value => value.replaceAll(workerChecksum,'<worker-checksum>').replaceAll(catalogDigest,'<worker-catalog>');
const fields=['owner','acl','language','volatility','strict','parallel','security_definer','config','arguments','result','cost','rows','leakproof'];
const roots=['zasp_temporal68.predecessor_ready(text,text)','zasp_temporal68.ready(text,text)','zasp_temporal77.base67_fingerprint()','zasp_temporal78.ready(text,text)'];
const targets=[
 [119914,'c6eed3d3fd1aad9eb53690e2a1e364dc576e1910224af2fec91813189c944bb6'],
 [7871,'f9557bcb94debad45801d1715181e4592c47be92fa79005b3c811b6281757f83'],
 [117393,'ae6456305a2ffc9aa054dd32e085fd7595859714c1cdf56946c8d837c082e907'],
 [25122,'a6a988fd4b42b6c63dc66b34a2de51476a0bfe9452ef4536b061206d120999ac'],
];
const frame = row => Object.fromEntries(fields.map(key=>[key,row[key]]));
function bodyOf(definition,required=true) {
 const pieces=definition.split('$function$');
 if(pieces.length!==3){if(required)fail('definition body delimiter');return '';}
 return pieces[1];
}
function identityOf(identity) {
 const match=/^([a-z_][a-z0-9_]*)\.([a-z_][a-z0-9_]*|"[a-z_][a-z0-9_]*")\((.*)\)$/.exec(identity??'');
 if(!match)fail('validated qualified identity required');
 return {schema:match[1],name:match[2].replaceAll('"',''),identityArguments:match[3]};
}
function checkHeader(row,definition=row.definition) {
 const identity=identityOf(row.identity),header=definition.split('$function$')[0];
 const match=/^CREATE OR REPLACE FUNCTION ([a-z_][a-z0-9_]*)\.([a-z_][a-z0-9_]*)\(([^\n]*)\)\n/.exec(header);
 if(!match||match[1]!==identity.schema||match[2]!==identity.name||match[3]!==row.arguments)fail('identity header or definition header '+row.identity);
 const canonical=row.arguments?row.arguments.split(',').map(arg=>arg.trim().replace(/^[a-z_][a-z0-9_]*\s+/, '')).join(','):'';
 if(canonical!==identity.identityArguments)fail('definition header identity arguments '+row.identity);
 const result=header.match(/\n RETURNS ([^\n]+)\n/)?.[1],language=header.match(/\n LANGUAGE ([a-z]+)\n/)?.[1];
 const volatility=/\bIMMUTABLE\b/.test(header)?'i':/\bSTABLE\b/.test(header)?'s':'v';
 const parallel=/\bPARALLEL SAFE\b/.test(header)?'s':/\bPARALLEL RESTRICTED\b/.test(header)?'r':'u';
 const strict=/\bSTRICT\b|\bRETURNS NULL ON NULL INPUT\b/.test(header),security_definer=/\bSECURITY DEFINER\b/.test(header),leakproof=/\bLEAKPROOF\b/.test(header);
 const cost=Number(header.match(/\bCOST ([0-9.]+)/)?.[1]??(language==='c'||language==='internal'?1:100));
 const rows=Number(header.match(/\bROWS ([0-9.]+)/)?.[1]??(result?.startsWith('SETOF ')?1000:0));
 const config=header.includes(" SET search_path TO 'pg_catalog', 'public'\n")?['search_path=pg_catalog, public']:null;
 for(const [key,value] of Object.entries({result,language,volatility,parallel,strict,security_definer,leakproof,cost,rows,config}))if(!isDeepStrictEqual(row[key],value))fail('definition header typed frame '+row.identity+' '+key);
 return identity;
}
const one=(rows,predicate,label)=>{const values=rows.filter(predicate);if(values.length!==1)fail('unique '+label);return values[0];};

// Source-authorized text recipe, not final base67 bytes. This exact SQL span
// is selected inside the pinned assembled release; no additional SQL input.
const base67Recipe=` -- Native77 already moved the effective67 recipe into this private function.
 -- Keep its deployment_compile exception and both public67 wrappers intact.
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_temporal77.base67_fingerprint()';
 needle:='pg_get_functiondef(p.oid)';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered67 direct identity anchors changed';END IF;
 d:=replace(d,needle,'zasp_authorization80_worker.ordered_writer_definition(p.oid)');
 d:=zasp_authorization80_worker.ordered62_replace(d,'ELSE public.zasp_sa_multistep_function_identity(p.oid) END','ELSE zasp_authorization80_worker.ordered_writer_normalized_identity(p.oid) END');
 EXECUTE d;
END $ordered_writer_catalog$;`;
export function deriveWorkerBase67Original(definition,source) {
 const start=source.indexOf(base67Recipe);
 if(start<0||source.indexOf(base67Recipe,start+1)>=0)fail('base67 recipe span');
 if(sha(definition)!=='04b617fc84998753930d0f8947456fe8c989c556e5815c37bfa2e3c4f60524a8')fail('base67 saved original');
 const from=['pg_get_functiondef(p.oid)','ELSE public.zasp_sa_multistep_function_identity(p.oid) END'];
 const to=['zasp_authorization80_worker.ordered_writer_definition(p.oid)','ELSE zasp_authorization80_worker.ordered_writer_normalized_identity(p.oid) END'];
 const anchorCounts=from.map(x=>definition.split(x).length-1);
 if(!isDeepStrictEqual(anchorCounts,[2,1]))fail('base67 2+1 anchor cardinality');
 for(let i=0;i<2;i++)definition=definition.split(from[i]).join(to[i]);
 const sourceBody=bodyOf(definition),definitionSHA256=sha(definition),sourceSHA256=sha(sourceBody);
 if(definitionSHA256!=='1c00ffffdf90307f3b99bc9eae0645df72442cebc58f34df6a873536cf1a6e92'||sourceSHA256!=='604cb02288a00024e6816728fdf954988a2224cd1a7e31fc601294fb2503acd8')fail('base67 intermediate source authority');
 return {definition,source:sourceBody,definitionSHA256,sourceSHA256,anchorCounts,recipeSpan:[start,start+base67Recipe.length],recipeSHA256:sha(base67Recipe)};
}

// Untrusted preparation/helper results are not closure evidence. Only the
// raw-byte pinned opt-in entrypoint below can return sourceClosed.
export function prepareWorkerHigherUniverse({contract,catalog,release,graph}) {
 if(graph.records.length!==82||new Set(graph.records.map(x=>x.signature)).size!==82)fail('unique 82-node roster');
 const callable=new Map(),identities=new Set();
 for(const row of catalog.functions){
  const identity=identityOf(row.identity);
  if(identities.has(row.identity))fail('duplicate callable '+row.identity);identities.add(row.identity);
  // Exact original capture boundary, not an 82-node map: functions from any
  // zasp_ schema, or public functions whose own names begin zasp_. C extension
  // rows are not captured application callables and stay opaque SQL bytes.
  if(!(identity.schema.startsWith('zasp_')||identity.schema==='public'&&identity.name.startsWith('zasp_')))continue;
  const header=/^CREATE OR REPLACE FUNCTION ([a-z_][a-z0-9_]*)\.([a-z_][a-z0-9_]*|"[a-z_][a-z0-9_]*")\(/.exec(row.definition);
  if(!header||header[1]!==identity.schema||header[2].replaceAll('"','')!==identity.name)fail('callable kind/identity header '+row.identity);
  // Whole catalog name/signature universe, including unselected callables.
  // Only graph originals below carry originalAdmitted; other bodies are used
  // to discover dependencies, never to supply copied expected expressions.
  callable.set(row.identity,{...row,...identity,signature:identity.schema==='public'?row.identity.slice(7):row.identity,source:bodyOf(row.definition,false),originalAdmitted:false});
 }
 const dependencyProvenance=prepareDependencyOrigins(callable,catalog,release,new Set(graph.records.map(x=>x.signature)));
 const originals=[],frameCounts={sqlInvoker:0,sqlDefiner:0,plpgsqlDefiner:0};let base67;
 for(const pin of graph.records){
  const qualified=pin.signature.includes('.')?pin.signature:'public.'+pin.signature;
  const current=one(catalog.functions,x=>x.identity===qualified,'catalog '+qualified),node=one(contract.nodes,x=>x.identity===qualified,'contract '+qualified);
  const ownIdentity=checkHeader(current);checkHeader(node);
  for(const key of fields)if(!isDeepStrictEqual(node[key],current[key]))fail('typed frame '+qualified+' '+key);
  if(node.definition!==current.definition||node.source!==bodyOf(node.definition)||sha(node.definition)!==node.definitionSHA256||sha(node.source)!==node.sourceSHA256)fail('source authority contract/catalog '+qualified);
  let definition=current.definition,source=node.source,origin='contract-and-catalog-original';
  if(roots.includes(pin.signature)){
   const saved=one(catalog.saved_functions,x=>x.schema==='zasp_authorization80_worker'&&x.signature===pin.signature,'saved '+pin.signature);
   if(saved.owner!==node.owner||saved.acl!==node.acl)fail('typed frame saved owner/ACL '+qualified);
   checkHeader(current,saved.definition);definition=saved.definition;source=bodyOf(definition);origin='worker-saved-original';
   if(pin.signature===roots[2]){base67=deriveWorkerBase67Original(definition,release.source);definition=base67.definition;source=base67.source;checkHeader(current,definition);origin='worker-saved-original-plus-source-recipe';}
  }
  if(sha(normalize(definition))!==pin.definitionHash||sha(normalize(source))!==pin.sourceHash||node.owner!==pin.owner||node.acl!==pin.acl)fail('source authority graph original '+qualified);
  if(node.language==='sql')frameCounts[node.security_definer?'sqlDefiner':'sqlInvoker']++;else if(node.language==='plpgsql'&&node.security_definer)frameCounts.plpgsqlDefiner++;else fail('typed frame language '+qualified);
  const original={...frame(node),...ownIdentity,identity:qualified,signature:pin.signature,definition,source,origin,originalAdmitted:true};
  originals.push(original);callable.set(qualified,original);
 }
 if(!isDeepStrictEqual(frameCounts,{sqlInvoker:58,sqlDefiner:13,plpgsqlDefiner:11}))fail('typed frame counts');
 return {functions:[...callable.values()],originals,frameCounts,base67,dependencyProvenance,callableUniverse:{catalogRows:catalog.functions.length,applicationFunctions:callable.size,excludedExtensionRows:catalog.functions.length-callable.size}};
}

function prepareDependencyOrigins(callable,catalog,release,graphSignatures) {
 // This proves only the source-authorized retirement69 save/wrapper recipe.
 // It does not assert that the entire dependency universe was one snapshot.
 const recipeStart=447349,recipeEnd=451824,recipeSHA256='a3370f7136ec5a45c7202d9003ac04735675e3f41318cba896894879a675e639';
 const recipe=release.source.slice(recipeStart,recipeEnd);
 const wrapperStart=release.source.indexOf('CREATE OR REPLACE FUNCTION zasp_temporal69.fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $retirement69_gate$');
 if(sha(recipe)!==recipeSHA256||wrapperStart!==452532||recipeEnd>=wrapperStart||!recipe.includes("FROM pg_proc WHERE oid='zasp_temporal69.fingerprint()'::regprocedure;"))fail('dependency provenance recipe source span');
 const records=[],excluded=[],savedRows=catalog.saved_functions.filter(x=>x.schema==='zasp_authorization80_worker'&&!graphSignatures.has(x.signature));
 if(savedRows.length!==92)fail('dependency provenance unique 92-row roster');
 for(const [signature,savedDefinitionSHA256,savedSourceSHA256,currentDefinitionSHA256,headerSHA256] of dependencyOriginPins){
  if(graphSignatures.has(signature))fail('dependency provenance cannot override admitted original');
  const matches=savedRows.filter(x=>x.signature===signature);if(matches.length!==1)fail('dependency provenance unique saved '+signature);
  const saved=matches[0],qualified=signature.includes('.')?signature:'public.'+signature,current=callable.get(qualified);
  if(!current||current.signature!==signature)fail('dependency provenance unique callable '+signature);
  const savedHeader=saved.definition.split('$function$')[0],currentHeader=current.definition.split('$function$')[0],source=bodyOf(saved.definition);
  if(sha(saved.definition)!==savedDefinitionSHA256||sha(source)!==savedSourceSHA256||sha(current.definition)!==currentDefinitionSHA256||sha(savedHeader)!==headerSHA256||savedHeader!==currentHeader||saved.owner!==current.owner||saved.acl!==current.acl)fail('dependency provenance source/header/owner/ACL drift '+signature);
  records.push({signature,savedDefinitionSHA256,savedSourceSHA256,currentDefinitionSHA256,headerSHA256,owner:current.owner,acl:current.acl,provenance:'unique-pinned-worker-saved-definition-v1',savingProfile:saved.schema,catalogSHA256:pins.catalogRaw,releaseSHA256:pins.releaseRaw,originalAdmitted:false});
  callable.set(qualified,{...current,definition:saved.definition,source,origin:'dependency-provenance-only-worker-saved',originalAdmitted:false});
 }
 for(const [signature,reason] of dependencyExcludedPins){
  const matches=savedRows.filter(x=>x.signature===signature);if(matches.length!==1)fail('dependency provenance unique excluded '+signature);
  const saved=matches[0],current=callable.get(signature.includes('.')?signature:'public.'+signature);
  if(!current||saved.owner!==current.owner)fail('dependency provenance excluded owner drift '+signature);
  const headerEqual=saved.definition.split('$function$')[0]===current.definition.split('$function$')[0],aclEqual=saved.acl===current.acl;
  if(reason==='header'?(headerEqual||!aclEqual):(!headerEqual||aclEqual))fail('dependency provenance exact exclusion reason '+signature);
  excluded.push({signature,reason,ownerEqual:true,headerEqual,aclEqual,originalAdmitted:false});
 }
 return {scope:'dependency-discovery-only-not-a-whole-historical-snapshot',records,excluded,retirement69Recipe:{span:[recipeStart,recipeEnd],sha256:recipeSHA256,wrapperStart,savedBeforeWrapper:true,assembledSourceSHA256:release.source_sha256}};
}

export function replaceWorkerBodyLiteral(definition,source,replacement) {
 if(!source||definition.split(source).length!==2)fail('definition body must have one occurrence');
 return definition.replace(source,()=> '\n'+replacement+'\n');
}
function replayWorkerBaseRecords(records,bySignature) {
 const root=roots[2],leaf='zasp_authorization80_worker.catalog_ready()',computed=new Map(),ctes=[];let query;
 // SQL installer btrim(text) strips ordinary spaces only; retaining source
 // newlines here is part of full-definition equality, unlike region strip().
 const strip=s=>s.replace(/^ +| +$/g,'').replace(/;\s*$/,'');
 for(const record of records){
  const fn=bySignature.get(record.signature);let source=fn.source;
  if(sha(normalize(source))!==record.sourceHash||source.length!==record.sourceLength)fail('base source authority');
  for(const edit of record.edits){
   if(source.slice(edit.start,edit.end)!==edit.text||!computed.has(edit.target))fail('base edit span/text/order');
   const replacement=computed.get(edit.target).split('<readiness-argument>').join(edit.args);
   source=source.slice(0,edit.start)+replacement+source.slice(edit.end);
  }
  source=strip(source);
  if(record.parameter){computed.set(record.signature,'('+source+' FROM (SELECT (<readiness-argument>)::'+record.parameter.type+' AS '+record.parameter.name+') AS readiness_argument)');}
  else if(record.signature!==root){ctes.push(record.cte+'(value) AS MATERIALIZED ('+(record.signature===leaf?'SELECT zasp_authorization80_worker.catalog_ready()':source)+')');computed.set(record.signature,'(SELECT value FROM '+record.cte+')');}
  else {
   const catalogCTE='readiness_0(value) AS MATERIALIZED (SELECT zasp_authorization80_worker.catalog_ready())';
   if(ctes[0]!==catalogCTE)fail('base catalog materialized gate');
   const original=strip(fn.source);
   query="SELECT CASE WHEN current_user='zasp_discovery_authority' THEN (WITH "+catalogCTE+' SELECT CASE WHEN (SELECT value FROM readiness_0) THEN (WITH '+ctes.slice(1).join(',')+' SELECT ('+source+')) ELSE ('+original+') END) ELSE ('+original+') END';
  }
 }
 if(!query)fail('base root missing');
 return {query,materialized:ctes.length,edits:records.reduce((n,r)=>n+r.edits.length,0)};
}

function graphBlock(raw,tag){const parts=Buffer.from(raw).toString('utf8').split(tag);if(parts.length!==3)fail('graph equivalence block delimiter');return JSON.parse(parts[1]);}
export function proveWorkerHigherGraph(compiled,graphRaw) {
 const higher=graphBlock(graphRaw,'$higher_records$'),base=graphBlock(graphRaw,'$readiness_records$');
 if(!isDeepStrictEqual(compiled.higher.records,higher.records)||!isDeepStrictEqual(compiled.higher.regions,higher.regions)||!isDeepStrictEqual(compiled.records,base)||compiled.sql!==Buffer.from(graphRaw).toString('utf8')||sha(compiled.sql)!==pins.graphRaw)fail('graph equivalence full records/regions/edits/joined SQL');
 if(compiled.records.length!==52||compiled.baseReplay.materialized!==48||compiled.baseReplay.edits!==61||!isDeepStrictEqual(compiled.higher.regions.map(x=>x.signature),[roots[0],roots[1],roots[3]])||!isDeepStrictEqual(compiled.higher.regions.map(x=>x.expanded.length),[67,7,30])||!isDeepStrictEqual(compiled.higher.regions.map(x=>x.materialized.length),[47,4,16]))fail('graph equivalence roster/order/counts');
 return true;
}

export function workerHigherSourceReplay(options={}) {
 const flags={sourceClosed:false,native:false,installable:false,executable:false};
 if(options.optIn!==true)return {version:'worker-higher-source-replay-v1',status:'refused',reason:'explicit source-only opt-in required',...flags};
 for(const [key,pin] of Object.entries(pins))if(!(typeof options[key]==='string'||Buffer.isBuffer(options[key]))||sha(options[key])!==pin)fail('input authority '+key);
 const captureSelector="p.prokind='f' AND(left(n.nspname,5)='zasp_' OR n.nspname='public' AND left(p.proname,5)='zasp_')";
 if(Buffer.from(options.captureSourceRaw).toString('utf8').split(captureSelector).length!==2)fail('input authority exact capture selector');
 const contract=JSON.parse(options.contractRaw),catalog=JSON.parse(options.catalogRaw),release=JSON.parse(options.releaseRaw);
 if(release.checksum!==workerChecksum||release.profile!=='canonical61-temporal78-authorization79-80-worker-v1'||release.format!=='zasp-worker-compiled-release-v1'||release.source_sha256!=='233c2caf66299ad50ee1a573c116746c905a885612a72980b6ce41c916a68850'||sha(release.source)!==release.source_sha256||release.source.length!==829825)fail('input authority assembled release');
 const graph=graphBlock(options.graphRaw,'$higher_records$'),prepared=prepareWorkerHigherUniverse({contract,catalog,release,graph});
 const compiled=compileWorkerHigherGraph({...prepared,workerChecksum});
 proveWorkerHigherGraph(compiled,options.graphRaw);
 if(compiled.catalogDigest!==catalogDigest)fail('source authority catalog digest');
 const accepted=[];
 for(let i=0;i<roots.length;i++){
  const identity=roots[i],original=prepared.originals.find(x=>x.signature===identity),current=one(catalog.functions,x=>x.identity===identity,'catalog final '+identity);
  const region=compiled.higher.regions.find(x=>x.signature===identity);let replacement;
  if(region){if(original.source!==region.prefix+region.originalExpression+region.suffix)fail('higher original region anchor');replacement=region.prefix?region.prefix+'('+region.query+')'+region.suffix:region.query;}
  else replacement=compiled.baseReplay.query;
  // Profile binds catalog digest first, checksum second, after insertion.
  const definition=replaceWorkerBodyLiteral(original.definition,original.source,replacement).replaceAll('-- worker catalog body digest',catalogDigest).replaceAll('-- worker profile checksum',workerChecksum);
  const body=bodyOf(definition);checkHeader(current,definition);
  for(const key of fields)if(!isDeepStrictEqual(original[key],current[key]))fail('typed frame changed during text-only replay '+key);
  if(definition!==current.definition||body!==bodyOf(current.definition)||Buffer.byteLength(definition)!==targets[i][0]||sha(definition)!==targets[i][1])fail('complete final definition source authority '+identity);
  accepted.push({ruleId:'worker-line-5',kind:'routine',identity,status:'sourceClosed',sourceClosed:true,native:false,installable:false,executable:false,replacementDefinition:definition,replacementFactSHA256:sha(JSON.stringify({acl:current.acl,definition,owner:current.owner})),definitionSHA256:sha(definition),sourceSHA256:sha(body),body,frame:frame(current),originalDefinitionSHA256:sha(original.definition),originalSourceSHA256:sha(original.source),origin:original.origin});
 }
 return {
  version:'worker-higher-source-replay-v1',status:'sourceClosed',...flags,sourceClosed:true,accepted,
  inputLedger:{
   contractSHA256:pins.contractRaw,catalogSHA256:pins.catalogRaw,releaseSHA256:pins.releaseRaw,
   graphSHA256:pins.graphRaw,compilerSHA256:pins.compilerRaw,regionsSHA256:pins.regionsRaw,
   captureSourceSHA256:pins.captureSourceRaw,captureSelector,callableUniverse:prepared.callableUniverse,
   dependencyProvenance:prepared.dependencyProvenance,
   assembledSourceSHA256:release.source_sha256,profileChecksum:workerChecksum,catalogDigest,
   base67:prepared.base67,higherRecords:compiled.higher.records,
   originalFrames:prepared.originals.map(x=>({signature:x.signature,...frame(x)})),frameCounts:prepared.frameCounts,
  },
  baseReplay:compiled.baseReplay,
  registration:{ruleId:'worker-line-2',kind:'worker_registration',status:'refused',sourceClosed:false,reason:'complete 34-site registration aggregate has not been source replayed'},
 };
}

// Independently reviewed source provenance pins from admitted saved/current
// catalog bytes, not generated graph records or installed target observations.
// Tuple: signature, saved definition/body, current definition, shared header.
const dependencyOriginPins = Object.freeze([
 ["zasp_discovery_create_gateway_device(text,text,text,text,text)","f02c10d2e57f03970b97ff8078bd18c77e251b47dd84d4a795683d0e04946e57","d1277822abbbccc570f266567fe9b9caca9341b9cc93976af932068f90af2082","fcce687b955e63fcfa1884c6d9d813454ecc9661bc31d53ef6ed6ca7bbba4498","993bdd56e9f71d825d6ddecd589c8c75c088b0f4e469466b76f6f4f7753663cf"],
 ["zasp_discovery_transition_gateway_device(text,text,text,text,bigint,text)","2fed193bbd1f214d723b26cf2e2525f51fd3977007b8853e9c4d521e3c2ad432","899817cc65ecdafff7e6d1f562de573b0602801ca5a673d202c89644868ab31c","823e637cf4ec3faccf4d37894a9f35355d559dd3c8b978b3a53499983f1a999f","728fbc97057e4b919c96cbc6056929dc3421dc2ba920d0eb28394de272e646d3"],
 ["zasp_execution_record_public_mutation(text,text,text,text,text,text,jsonb,jsonb,text,text,bigint,text,text,text)","565b052e418c623a7d231e88ee5606e86bd5f661e7e4dba7788bca8b41cf272e","2452c62a07efc5e3e57e5ccb3bd21929657bffd0218c5c894ab92850307ab729","565b052e418c623a7d231e88ee5606e86bd5f661e7e4dba7788bca8b41cf272e","f7d01f72afabee1f617b6511bf03a5b035a54c55daef25cefff8f7abc4550db8"],
 ["zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)","16241155ae5c203fca07c0d29460674d972a695244efa7322908612547d5f5ca","5ce07d3622129462f2d41f584f0a41c987b559a3b9430f7bb2f172bc5f9389d9","4a3a6a4acb9c260b4cdb889020bdee2212e84986657a627313303e76876897eb","ac9c27e6bae39dcd68e8ed1cba5f2a2e558f1cb139eb5929154cd4b401a15508"],
 ["zasp_production_runtime_sandbox_binding_live_fingerprint()","2c94159c4c058f53e186d7b69f19e49be0f2c8512360ec4cb31533dd345b8239","02225e624377df8b05d5bbf6c5c8e4490c726d5f582247bb1a7f5bf09fbd63b9","2c94159c4c058f53e186d7b69f19e49be0f2c8512360ec4cb31533dd345b8239","bc8bc2ac206305731edaca713155e7431f5a4c44a45d7c629c3eaa2cf391a89c"],
 ["zasp_production_runtime_sandbox_search_live_fingerprint()","6bf3fe41adc81f4d7383c9a49a22f0c8aae69f2cefe575dc2bd682bfcd69d532","b2a552726f8ecbc9ed8715850a635f8a9c908099bc1b3439fb66289d53b90fdf","6bf3fe41adc81f4d7383c9a49a22f0c8aae69f2cefe575dc2bd682bfcd69d532","27d92f35ae9d2f6ac9a9add9fd775d5a1d7995ede390ca1531e6dfe917872dd2"],
 ["zasp_runtime_authenticate_gateway_enrollment(bytea,bytea,text)","989888233035789f675c700b9499b5748598de4e42245d81033e5236d0ad88ce","3f371a883198a72bc14d181f28a6be78d7f8530e322f3a8036586e8b57455a85","f4a9ccafe624889102ac52f3a3365a9aad0bbf75bb22e120a59b69b6c7500b51","75a3d28ffe78f4378085eda6c3954782516f6230720c0a4a47baf5d820ebc252"],
 ["zasp_runtime_data_plane_live_fingerprint()","141e17d4073082143d17909a2a2268b3f2101e8b216d8d8b6e3c3b03b94b9bba","53dfa23ba3cc8a7b7ae20f5fa370b6fdc2432f223e38dfd6cc5158d5ff177832","4b99a00150b76abbaa0f8fc9ef9202d68289598fe7c9590b42636a40a1ff5905","96ae8f8373a3116be46c6507541b9ca42188f57c7ef8e6eacedd7634fbdd95c5"],
 ["zasp_runtime_gateway_advance_replay(text,bigint,bigint,bytea)","12dd0327a7f1ccb0af90aa5295a4fc94e5d12b6bcdf4dc535422d8be7b1c3dde","00e934bddaf45e489bbfdad50cd74d6cfdef95313abc4b63a32085b3c2c1c8a9","ef9d7fc08a68552959c34fe2c667bb6687e387a26f4c505132042a227b8f98e2","6f4696002c5b63b9a5dc237e58ba32e70974cce53ff002bde7a8439299908d2d"],
 ["zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamp with time zone)","ef05b1f5e92c84b0f131a6df523f38713fa6e4da0f688fcf68a94696c2299e9e","9f294f7a545dd347dedd783d317e9f66e60883f5d09bdf352dedb60b5651feed","0e009deec6d0d7556625e6919c7bccfd416334d36f47e3ee4baa945413793953","2ce2dfae04b5b047027082b753e37c4d435d4980e50a49dd5387ed65bf86351a"],
 ["zasp_runtime_gateway_record_event_v27(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,jsonb,timestamp with time zone)","9e05950a1e38f00b95eb420d57c0c97bb85461dac8696fab61b43569d2d8a0cf","e1cd1a4bfae38dc71b59c8ec6d1260ce8cf8989536321c876abaac7445f27827","46915cad9f47fceb797a6d6e05a46ec12a5bae44e2035960e4f8c7282d2229dd","2e6ceea24e57dbbe067cefb7bba82187b88e26d325115c955621c8fe015dbe3b"],
 ["zasp_runtime_issue_gateway_enrollment(text,text,text,text,text,bigint,bigint,bytea,bytea,bytea,timestamp with time zone)","d9fc13da257612324f5a7af443a6ab6fc3e4053e8c24cb783debe119dc919975","d158b079ade8de4caa69aafd98c25b6e39cd1908824034c482ab6de06767add9","332be2be2cd1ecb4b931a20e90795f7d82d89463d890f40b990e46285e2d4e76","753d88594e5e5b31812e16515160d10bb55a639aae47fa970538ecd78c7274d0"],
 ["zasp_runtime_revoke_gateway_enrollment(text,text,text,text,text)","b243889076dd69fb41812db531d837c18ea2d451a3c7f379c670cff13db06d4c","a6b367018d775536146504ea93e97fec62a9b6f17d92ff7d8f45ca62b0eb4536","bed5c8d58228117430aea86ffb0cbe3d278b27ec89266e1225bc3a1ee027d5a1","845bccb1c9c2e9e5ac6361653dec012700363e4c575ebce05c250ab73442bd05"],
 ["zasp_security_agent_claim_session_policy_effects(text,text,integer,integer)","4a2f6573b6fe331283eabe8178d3ff0f4dce0435338ef744ae154e73312acf93","448491199ee5a187a85cdd591cf9110b2b4d719aa4c3752c93018a66870c6b80","763c74a1da94da0dac8be2547b8ebcbcc57ddd969e74fd05d5b8115845b7b9de","a0ce7d965c8acb67a8e8111249f586d96b0785d4eca816e5fd1884ce3456eb67"],
 ["zasp_security_agent_claim_temporary_policy_effects(text,text,integer,integer)","b4efe2386c2d3957b147bb115e8735c32ea25519c264eb8fa437289ecc5779b8","e5854b72d1a5b3db5757b917e9adb0401de717668f18f24fc8a445fd7c78e98d","5afc4429f99d3d13265bd39fe2e90b2eea0bf4a8c537556b11d0b1b08579c014","3724e29a439a49db072afa6b0fe4406e8e788961c927f63b439c09a8edec4b74"],
 ["zasp_security_agent_finish_session_policy_effect(text,text,text,text,text,text,text,text,bytea,text,text)","36c8e60e53106f9c6616e8e742d9df0e6e2a6dc1d708e23f49240665fb17f906","b14703cad88a57da63164e15f077ac5789c426215f61c322d869989f22db3068","a6e5f3af27af52899462d47ec44318fc203c1b656018bd8907640625cdba5263","df0f4e0e5c899f16e4d06277debe52c4e3bcd69a62571333eb9b105b7eb6389c"],
 ["zasp_security_agent_finish_temporary_policy_effect(text,text,text,text,text,text,text,text,bytea,text,text)","88df19d79a8617d45465eee1b465c50689f68b50b9aae37391b617a8ca8b0e04","d23a2f954b0eb3e4ef8a742f6d5e1b26c73f82c3e124c67eaff13b9ea1028b17","287720b27f9cdea9a7d9af4f992d0696ad29b4c7b58aa80a4055c4dcbdeecbff","52d86e55eaab3b7a02f03b84003ff1461c63f5e22bc131c7588934023b9b3ae0"],
 ["zasp_security_agent_live_fingerprint()","4afcee0f4c7d281a0df8c356bbe49bbe83add596abff4c56ae800bd53857eff8","e238fa83428b193a83dffd30764802cb3f8541502a8db657f0d7b23addbee4e4","c4c10a7d9baa047f126f1a2156eb1fd775d8a4b66aabb5335d450c67979816d7","089bbb647f7cc8a8dca59989638eb619c61565f2a6a97d103de54072e8e36a9c"],
 ["zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)","b3eab388aebcf4edb05a94392e04cefb2e056d5a8f6ae0537cf37b9798812357","a26ab6656650b11a9eefe8fe0a63ac6432ec2f353a85bc5f24648b04d72caae5","3b11d898c81dccb91307e53eb0b3263386be7ab5213c02b8d87e58458be593c5","0c4cb50a0cac04009172742ad7d382b43632fca10dd3bd5e604250295d612876"],
 ["zasp_security_agent_store_session_policy_target_v27(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)","9faa12a1296152841a2685db939b2f329c0cb970e9b5d41a2c95fe1e57d74c9a","f1d4c7df213eeb97c0cf5be414fd850754270dbe95e3f27277d326b0154a7157","e02c17d18db10c4aa63a9b524802c098648f3c33e22f45b95a3a614403bedb8c","54f3100689194b7f7d768eeb15af5b13f8424413710bb78f6b11b3b999e98a77"],
 ["zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)","11e01bbe7ad1cac1a321f045f97af4a52b387fcf3262f231d125854d05aa0e38","36aec22d10645a60b9ca8896df623130cf0a78552d4bfa50be77f71ad8546f49","aea3277458b428cedc6b77f7300701026567f38c4ea11cec4c41506676abacc4","6f68fc2c5236faf555f6c396fcf03cc1cc6cb15c63541445eec742705cc08526"],
 ["zasp_security_agent_store_temporary_policy_target_v27(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)","2543bc69f642ddbae68d276ab61b45dbb5fc9ae32c946d131727687f1e9ccc03","864b3dcb62a35d323bb5e5462d049e2241dd88781a6e6498196478c5b7a32b79","540186136a34b3e7c9eb79557b3ae414eebfd15f1fb922c9e1cfd71454737fd5","11b89c2b9be036190f182a0c0de753fa120f8423b0add438b5a9b98bb98aa10c"],
 ["zasp_security_agent_temporary_policy_live_fingerprint()","e1b8801b1748c7a22645163f554aa47a8987a4f837e220abe5029ab6353ba029","a8b949d3a36e8da737e15c78efa15c0c05bd3c412a982c3deed7aef9a0754e65","99f0a4b6f2b7b8714ec232683acf8a2a6a48cc97474c0cc23af9ab5f9c204c82","bf49a641bb6804bcae499916e82474080034d01b3fe739304713d5257054eeb9"],
 ["zasp_authorization79.capture()","c03d791c6095a691abb5c250c19a4784b05e57aa287b72b3aa830b295e6a4116","8b6e8484d0f24629275945c4ab221dacc1e6456af750abb919426bd2d943acb5","dedb4431a5e49612675dc9e964ee40111c6076ba761e3897697f06962faa2b04","fb8e0b23246a7d92dc444bf29f9fa379facdbfbda6482c4471b667442294da4b"],
 ["zasp_authorization79.pending(integer)","c7e6ef3559fd784a61beb5586c1b93111cfd43c6f97908c20e58c9b44215a979","09999f50623606d2ab069351f34030f156e4bb927600138a6812441d752ed3aa","aeed087066a4355f1c2b9e434dc7a237ff451846b6828abdace8e6bd050514d1","42b698757fd301d6b41aba61d060e17b4f58002ee98d69d7250ca3916857610c"],
 ["zasp_authorization79.snapshot(text)","d3b4bbd943f7118bf28008348fd81408bde0929fc62c505b386b8db891c08d51","3aa748d5193a2b555e6972f3151c44fc1dcf73c669711f6acdd56bb35c648199","ca8cb8ac90f403045c4042c3a381ab6da067ef96c8fa3d4f190182faf1db5047","91b9238a1a6b17c11c3e6deb68c9c510dfbade8c1ede70524e20c6dd8f0b4edf"],
 ["zasp_ordered_public62.api(text,text,jsonb)","443d50a27ae56a5cd58aee1d8aade4638df2ed2b817099283c82754ee88561a6","b5c65ed6babe9cf3d70f1728c2bd2efffc6fa19d58e658571bed819f605e5e37","87611725c9fe5424e8b0e2cce13cedb719ac74eff5cf9a7a1b0503add4ba7369","be20eece72c711006c1b44142f2885d45959a76c2db197bbd04657bb491e3d19"],
 ["zasp_ordered_public62.mutate(text,text,jsonb)","79dc837d15b1eac2ea184afce2fa96f2a7159d0747b1fed2aa162118baef501d","fbddca80bf47f304fd3bd45c1eef9b46cffe6696872692fb8afae00709fa4906","8c8ce4ad99d9f1dc039f246179083a96ed1f2dfffacdaead849478c8f568a651","13ec26bbca2c1cbed405abee06a28d84a0ea2535ceb580c30da3cbe9267f1baf"],
 ["zasp_sa_multistep_prior.application(text,text,jsonb)","f9b7e0558b0b7f231eae380deb1fa041af29b671357fb19251341177551cca26","702e6db063498e2c3fe325fefe38d565a2bec4295b2000de70b4f23a6e03f2fc","4ba471de460c2054542d49f204942e36cd28003c946502ca00b2e1385bb9dc95","e5bf543b7070c7bcb5a1b4245cc9fa978016f4c3c045f038195047a3992a599b"],
 ["zasp_sa_multistep_prior.application_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)","e404cc03464ef4a0c58d134393f82d55e3e6617a025d7b2de9d44cd26cfba56c","19158cbbc8ce8d894f59982595d8a174bc7d39e4a5cf5485c1b920ab07c84d99","1f1b4047a67ffe469d0aba7cf67b0a1b1335e59e6153f8412d894dcc27ba458a","1c6602eb431e320811c33329714b51457b580352702ca45d81d0c6a542d3b883"],
 ["zasp_sa_multistep_prior.cleanup(text,text,jsonb)","2d35a718e728ec53620fe87442e11575044ffb8f619ff5f94f9e7cda4a15fc65","1d9c0f6a59932c1ff4f1c27d55be4ef9d9e349704fbd12d2085279fc88e2f673","1acb12f19eb84376f7a8df758a1ce8d6b3012ff6931a84c86c30419a003f8337","0fb7235f23f847812b3fd7bd58772e961b8ce772266f25cb16491e589eb7cab6"],
 ["zasp_temporal68.application(jsonb)","0ec3aeb0a20d15e2c3018db6b7377b0ed5038a8fc8698c626d6bfede57a6bb47","0b7f5149724e8b555c1db8b5044de5c0ca91d41c03c0dafe0c096bedf2868857","51f52f4dd50614d12867ca11bedc5b7a42aff039adcc2e6f8ca0524a75bf7ac0","d83554b06f31942e40280bc3854472b1f8aa15c8d49f648114050cc814cc4609"],
 ["zasp_temporal68.cleanup(jsonb)","f7c57637f6d27b79bd0f5bb78f7f7d397e98f50e9b1e77ee1b2ae949b2008637","2e7c5f133e4fcfa423495af1836e9334f63e34eaafded530e351b39141026c88","79c47df61e6935fc62f42050cb76db3084f1446fea11cc1f0fb563593f26d9dd","14a4df8e5d4f13b94ef0bb1f0741f124b7d207a6c8ebee9ad20d447b591c7fc5"],
 ["zasp_temporal68.delivery(jsonb)","6bb4cfbe1425947439bd96d9665662e31cf0485928173da904f3049539b28af0","c72ea430759658aa53da4957066c1a1bf15ab70b6099bbff1ceaa7d61ee8fde1","2dfc8e7b2474e0062b34b6ef027876083db3cd4978e1fe3df3174e9100023df3","d1c6e848bfb0f7398a3e50475b8ff398ce8c92ecc4dfa21c74731948283295cf"],
 ["zasp_temporal68.effect(jsonb)","affd74185ebf0ca1f9d2528af5bf4484b43f5a22c6f017f62f3b478fe27d3003","a46431b2444bf0d867a6dd4b1151566430f9c88896dfb96c0be2a1534559ca32","7db9c4352c009be8a8b68d45754cd535625ea39b5d5d075c4bf68c96f904eff5","58fc35788a12af74c8bd27fa01469819fd4580b279a7480a361a7cf8e5c2d031"],
 ["zasp_temporal68.invocation(jsonb)","8d9d8747760107f099fdf8a78a2748d1cca9b6f32653a6ed8570f4279fd2b389","982b9d3c36fac9bc976ce3c253d0b084f3da66d8817ca23fc38bdc13b30b61f4","99b5da5f817939f9f68c866385ad027242a403bda4bc622dac9b9bfb02aa489b","6288a21f78f5ff61a603090f9c05a301be3504d47e8309175f0736f0db5c2295"],
 ["zasp_temporal68.late_usage_valid(text,text,text,text)","4af1beac221fd700c2b967314d11da1a0be48e0a5fbdfbe113f59b19f5613821","f6c825bee950b59e1eaae7a7c1df1d715e8d0102ca02408899ff3fabcdcc8cdf","99770b02d3918306843dd2a2aa5e9841117b756a3c4f911bf63df3236684045a","8b3a1ab692e9e389bd3547ac04b8017513fc13233747c6853fce75ea0fc60ab9"],
 ["zasp_temporal68.linked(jsonb)","eb7e28b6c56133f68dfc09575748c757328e7c0ce90e6f4600fcb3582f024866","93e9db92f4d7eaba65a71d591543e33223482a94d7c901e2285005c0bcecd7eb","57656ceb993c18b2c12a080320278e7061dffcff6fd39bb4df1a5b2f488c4560","8103a24e77168e3ae60069c47e4ca8836569f4feeada210725285211dc79187d"],
 ["zasp_temporal68.plan(jsonb)","b61456e87488c18df1a6941ae0ad9c6dc36b72321a36d02b079281c508a83b0f","ddfd24b1919e7573a70129de90a08a5c1dfe018e0ad130f9eff194c9fab4e4d5","9600b42c646ef055e80f6992345792bacd384c4b6014165b804c431327e9f6a0","db704ee788b9e854eab690265fe14d2ecdfe436c5a06b429cea87a4759a9ead9"],
 ["zasp_temporal68.planning_terminal_valid(text,text,text,text)","bfcb83359414e68f4a5970bd2a0370c5d2c36d297ed41b1fc640e78e51ce07d2","b54e881cfc064e5dafd145a5437cebba5622b4dc88859dc0f94366e84ee02a32","4bb92a511206f84ba08ce4ad175b9e9cbc3173674bc4ee79e424ceb72dfd48c7","7fb09fe2456f8837cf7d9dd8b3b8339bb53f1471d07427f046b09f933e38cc17"],
 ["zasp_temporal68.status(jsonb)","f1ec8f349d0b709893e603cd7bc9db92c57d34137f0af7404cdf2a1f3bf56418","0efc96710f88f1fcdf503e4ceb80f248a895b835964d82d7574b3d0e893718eb","1ad27b0d918b7fb32dcafeb8806caac87e8215e2f7effd66c3aae5349ca14a89","23e0438506f50fa72203b0378127d6c1f8015cd2b84efa114eb996bc23572e9a"],
 ["zasp_temporal68.test_settle(jsonb)","06091c5aee2ea0a58309ebc68a291e8ec4264cc417aa3b28c36d3e88f65fb16a","91405ecf899ea092e26b0dc2b9b94f47c078e9cef1589061c498dfaba6b287d0","0bfebbdc8f139b8f30bf882dabd39842605c6dd71fe18bbffa89e51e5c62b09d","b0b8e79104784d6cebcd2c2d45d7794bb75a085b183bffcabb739dae28636fb8"],
 ["zasp_temporal68.test_stop(jsonb)","e8f17d76346a18d92a0782f7a7be3a254ffbc4860b174a5c84f9422c724484cb","c8112e0ec36be9fe83dba4f0e22c4ac3e7b94792c8f28af01cc10e8499438d09","bfe22a648c43b7de74a72d897f877d2a7ac841d5b3dd1015eb50d63ebab8063b","1217fef134348ca11077b01c59862033e7ead4ab9467819258192b19460ac597"],
 ["zasp_temporal69.fingerprint()","1d91724a967194f8d876e640dd75c7bda451377e40c3143bff4934bd215dfd3c","57137e840e362f0c1ce2b25a2be2032d0655bba7e834a6b7175382b663569167","a05b5c3a51f4f31fb0127ccd7275e54e411f710e56d76088eee6c53ddb372b18","ed0a4a51bcb57f1f4f262b39b91bafbb4e6f5d4bfd80cd796cd3aabcfc6c3ce9"],
 ["zasp_temporal69.stop_test(jsonb)","02f7423960bf35228028bed6eee56d6c8a4eab97ac87b9b0add627d18fcf9072","d5932899cc3f51315bd92a2890dcd80c1fc26b69528d46b3a12587cfffa1e7b5","02f7423960bf35228028bed6eee56d6c8a4eab97ac87b9b0add627d18fcf9072","6ddb1dc5250b90a6a1628ec0c5eea5ec219c5af9bc93ff52095034ced00c676a"],
 ["zasp_temporal72.commit_apply(text,text,text,text,text,timestamp with time zone)","b2f880114180383ef560753b763cc25042b758a36b6373d6e543ba9e20f7f784","83e5b9aa55be0783e7b541f690fc90cb82e4312e5edbf01c71d959cbde11e504","fa494eac5ff249fb957ba3d25115a98cf7329bd06e8e6f2ebc7d33b52c9df49a","6ed06c1cffab7e1703fb02e0913b7a30e9e20734f1dc2d97c3c53058ad92c1a2"],
 ["zasp_temporal72.finish(text,text,text,text,text,text,text,text)","2637e72ff8861d02f083d8ead28d7aa1bd48dda9307f84400c549f8404545f95","3f62d75acc6b6ab8ed238bd2736ff657da21d73e57506e7445bed6a7094e6109","db0912675c4144f479a546b324450d37996d67b7205b4a90806ee2b7ba5f1c51","cc3f340b1a99d14e6f625665567230c3f35a0444fedb7388e1a29f3fa70013b8"],
 ["zasp_temporal72.guard_page_effect(text,text,text,text,text,timestamp with time zone)","308c6359967775b81394cab6c0f9bbfeb120e125de9d462ce1480b9444b10aee","04a0dc6123a211f79c3c87ffe0ee85c90ec1f592420c227ab674fd9c1887fc1e","ca22d6a5131f6e560e6f8a3b5301c67c88a0f2d7b9afd0e39998f03e0e23b804","af2711f6f34972bbacbfee5c3dbb97b87cd12390c4cb0b8ca6302609fdb8ebdd"],
 ["zasp_temporal72.prepare_apply(text,text,text,text,text,text,timestamp with time zone,text)","9e162feec5b070a3dbe908e6d8f871df64f0d95d409e52961944765cbf6175e9","82e86e7c1561976ae463fc991efc2afe53d8be14b99d9244a039b8da4afc2ab7","860e8e00865d2b25ef42e7d74da42302e95105070640e75edbbb7644a87dc1db","82bda1bd2fc20c02d627f4422d91baacfdb0cb60a9d176072a9e22b4dc97eb12"],
 ["zasp_temporal72.prepare_page(text,text,text,text,text,text,timestamp with time zone,bigint,text)","f6cccae9c6013ff61bc59af4c4a6505b6c8a638a0a31dcac7943fb6a84b29071","087be92179a455fd6feedcb856c6178e1e1ed428d52bdc220713d8a93310a6e4","57ea93d7a3c2a207170d50c63108ce08b3639c169e5ec4973d98d486eb645e9b","3b02e723e8bf2a3865050e1db18214abd2ae63a86cfc2fa224eacb4c5219e610"],
 ["zasp_temporal72.public_delete_schedule(text,text,text,text,text,text,bigint,text,text,text)","23fecd8c7777b82329aee646dfed803c05921cb9cc831ec41e4af1e6a61661db","7f746c06c841f11618565be0a686f490266d9c28f6ab4b468f8b61d0e26c1a16","97416733b6d8c7614c280680eedfee55d8155722db6fb91a2a984094e7170c30","0f3a9763943513abcf229123ec31caa4dc57e3e3384c9c5012e22eac579adc87"],
 ["zasp_temporal72.public_put_schedule(text,text,text,text,text,text,bigint,integer,text,text,text,text)","7f5f768c6d5d17986933ad5f96f9023406bfc377a4d066ba339f106e5bb63fa9","96753fee2c908e29c122f9341ea7ebe21d2fe2a48aed2a9ef65eeb6e62cd9691","c0b5dd74ec62591d4ed25f35534ed9a2d083242b1c0d370a5c11b4b4205ddb5a","3d9e7f2188f489708e6e772299a337f642ef2a98d9b6fdfe600b5101afde5ee1"],
 ["zasp_temporal72.public_request_sync(text,text,text,text,text,text,bigint,text,text,text,bytea,text,text,text,text,text)","8afe792caae8703c5548f3cef8b22ae4c5d3e96128f06f5b8e41d1566f76c5fe","a94e3aa2d89f04e9c149a39115324b7df06358f7cc217a00dcbe5174c7576449","7b13145d39a9807f1fc1a9d1e2304a44ed2db811883a1e5ba20f4d51b8053d74","719887d508ac909bbf7af6a9a48c1959b135549f6a4eeae96a2a48f9d8882e8a"],
 ["zasp_temporal72.record_page(text,text,text,text,text,jsonb)","392bb78ac4f7b5fe6891b497b389fddb96afc26306a7c8066f41fcfcf94dcf85","29394b7b3aa405e849fc10632bde08b18faf6cc3150512f07b9987cc7e2aa295","e64433012b2fd44786786c2ee9bc39b5131d933b96a84bf5b3af114187029f04","8add522d2bfd2cc444296f118fb558f7ccfcd86f75a314dd63b254149ae178b4"],
 ["zasp_temporal72.scheduled_admit(text,text,text,text,text,bigint,timestamp with time zone)","194f9368038ef8d3c2f32cb2de5f8cca93f7d3fb7ac9b1adc2b3767a5c6332b6","bc7a2e31aa006f69d9271c2ec2075db381ae83251c3427fcde987e01836efb4f","1b9be4ea06b7f7a37983f626940170e3b8a08ab4e2160b1de6c92509269a175f","c0b93cab49d7d756846e09a8e6dc063b69273cc43385627bf59885671789c1c5"],
 ["zasp_temporal72.settle(text,text,text,text,text,text,timestamp with time zone,text,text)","6a031c506881b50c632d921aab6f0890e14fe60b0b839bc37c0558842c620ebb","4749400c5654ae2a285a61390b9507e2d1940b03d98d564faffe81384def4187","2d6d902ba955e516f1f2985056d8780e31b8f83901c327a56df7269bcc99ed62","a76ad405e99b2903b30af4347565427c5e17eb46446cbd62139bf6052d44994f"],
 ["zasp_temporal74.cleanup(jsonb)","0a858b3de242cd449ffb412f0398c60956aa14d97838f357fb839611382662e9","d0d80c37f56782b461f5f31f323f24049eb7c33a049aa3926efcab7c29f27df9","284b6641606e8d7dcf902bef1479246cfca997109d5b8fc57d20aa1c7d472a3d","6bcab8d37d3ec19f0fd2b221508b8c78e589f0010335f01a5c16d087414f8622"],
 ["zasp_temporal74.context(text,text,text,text)","5c5b46902fe1900113fe27dcfcee7d7ea17901fa0a33066ca2f4b2288d464438","9571d8c1167d32c8cc183b098ff6fc23d3b61fe4a2995e541915c38d8189cf9d","7f7ccb2d14735069c8fd992c8f9baf2d984157ea363bcc4f74bbde20de4dca77","63320fd10c5a59267f966608f4b8368ecee98d31110c90655159237c039324d8"],
 ["zasp_temporal74.context_parent(text,text,text,text,jsonb)","7e64330909c7da48d06251e2640b3f28780048b6c97217e7da0d507c03b16888","798a12172514a7298028172e4fccfa7cdb58ec594264fa01bd95141553edbd06","f41517670515c38cba42ed10d3478bf5e1d355c077b8286c2efb94fc1cf57053","013944025f380e4e33539e84694b382683f34e0f2d9a7ff991da3abdc66e89c0"],
 ["zasp_temporal74.effect(jsonb)","6ec964d0e0efeb707d5af7cba9a042a458e4875357f21997b95c73ac477538f0","0ae311cba9cbf9167153fc2d7e6503f732a695e4e9c4da9d8d854e082cf97158","199cdc010d2609546f516ba9df7fa5945d517a4769be6bc97d25d07f232ca037","8ffa70e0fadff12ba0191f9837f7f8a6beee238d3a8d888fdd319ce92eb5bff0"],
 ["zasp_temporal74.inspect(jsonb)","8321f1d4bb689fca40498fef7c27a9a378f225c12434fe404356547b65870763","1acddf439dacb45331eac1973a6ef62a660abcc61cfacb50ea8f42a32dd81a1d","e3bb4833fabeaa831034528b3b0fcf348cecd24719de63bca79f787fc535cff4","80f995ed19be23a44fddadf9fd590ff2e32c1a634c70ca9afa2eb85f1d78616d"],
 ["zasp_temporal74.invocation(jsonb)","daeffb053d1bd80179fb97a8793b8c8eec87c50213e8fb66549feaf44f3aa9c6","c651f90dc91038cd1adb86e4dc312a90a5ef30fd52ed4fee70eb7fa118fdcd3c","979af9296c125e0211c32461fa1a056bd4672037a9ae909807a3e00a34aac81f","993dea0501a7196399033845ef48ad7619361b6355c991126df8ab6120b19d81"],
 ["zasp_temporal74.late_usage_valid(text,text,text,text)","b008ba6a5b6302b8abd8ecefe3e4669e13b45f1b2ed3523e9aca8ad7f89e242e","f7ccc567f809ad6db4d67904904fcd9cd9557bff69a2837648b6c27e44c33cd8","7ec81ed1c3436772d732b9f8a40f9d1c74d5c64cbeff5a82ab5b91383a003a5b","012320132db9ff62acd88ff93379e9a23fa4da8419571592b0e44554722ab8f6"],
 ["zasp_temporal74.linked(jsonb)","49669a8315f3a112f209ec840c253a97d6eb7b1aa7e1c3ee54fd09d6cf328408","4c6f77eb2f307b857f15479a762fd3a789e5140ca4809e9b699f639054348f9c","53bc8c8b5f463ac709b95bb6c6c6af5f2b4dcd06c326adf6a4d7df7fff26def7","850b19887ba2081ccd8b55a1a421ee2417022eb6994c900dfd4ec3e1c60b5e3f"],
 ["zasp_temporal74.load_plan(jsonb)","be6416d7df192717451b8493ea31cc095dca20a82d92e77a6a8a68a4aa235922","6f794a57e5dd106fcfc09cb57066141448f6f50b65fb1a8c758708328e77b3ec","d6b150e2ec6da33e897d236660254fe479bfea4cd4c2b6cd65a097c320c826b7","81bb2386916f8c526ea56b2b7eb229d8197927293cfe836d9163c7f2e5ba681c"],
 ["zasp_temporal74.plan(jsonb)","23fa89713db4b798e94566948693db4b554f889dc721d92f92b70ac2eb53ac60","fc1dee465ab5c2cd654f27ebd4c324fd36d36e53aaa1daf564a07b92c861d026","d42ef4862ba8858e6e3f295fe949c67d2c4c2ccc7e54ee8a83cc68001f80295c","8cc474f7b5a9cb70c7e0732c3464706ce1dbec2304f2399a252c262e158317c9"],
 ["zasp_temporal74.planning_state(jsonb)","47581fadfadbbf62138e0a7577b97152cfc44ca0836c2a0f279ce55890719fcd","3d0ef5ce1e49321044003932b776b3700e60a2bbc5cdeba80f6738197bf1a2e0","faf824111f39a57dd2d1d48afa1c0eb05e33ddbe08021e1988aff861245e3818","58a709455180528564ad4a869444fa689ad3ae6e2c7b6665c7edad8f60779692"],
 ["zasp_temporal74.planning_terminal_valid(text,text,text,text)","dd196c61f0041e311af83bf588c87ed24ae16abf87b0f38e18a122837db4320f","55ef89c3304d88f39c5c8918b2518ac04d6069087a8e5b89eec8158927c37c45","f80b48cccb83ac40a4a6d01a0cb9d567a63600b42d855c3ee3f544633bb971ed","392f38f53dbf6132d8e3f524ed5cddda5152c3385e40994d15fffe037ce12b65"],
 ["zasp_temporal74.serialize_revocation()","b7cd7ac0c629d8c757f15bb967da1de40dd23d851d4b2f9c3da38fc2a080bf43","01a641bf81783e536a9066c27342c3f1e9ba692fb001bc400e1a5ea98aa6da87","20cea5f8885d2bc3621de3b5592cb5e2f8ad47152f9caa9d42951ba1f1141f0a","05263380e3470653a9d1baaa33a4fb61e896f7ba81d05f3b7a0c9a6be7ef69b7"],
 ["zasp_temporal74.takeover(text,text,text,text)","01534a76ab6d9c62993a0f03da4b38dc517a7572c9c3a318d4b1acfc8c49e640","32f77cf2bece602163fd14ff451212631f50b90d9a2d8729a2d42349fd9f1c1e","8cc3eb14d15bd22db319eec1a1cefe4243ae2dbafaa3655198642f616ad56d67","4b38013579d0dd3ebebb745bf9677b21d4281e260492e6bd9dbd962681227811"],
 ["zasp_temporal74.test_settle(jsonb)","a6dd4c7806531ecfc88a971f5e2e4b6bb6c7c52d8f4be0ac11b7892d654ceda6","29502a4986b12309a441ad755c89aa90b764bdc3c04c9434b8f46bf20ba96c2e","a6dd4c7806531ecfc88a971f5e2e4b6bb6c7c52d8f4be0ac11b7892d654ceda6","8f30a15b07e525cb2f7852f4409f39d60802b27fee5e42b67b29df18a88dad71"],
 ["zasp_temporal74.test_state(jsonb)","cf5e6255bf1cbf692683b8e8f22f306518cda7c91d88bd15973709eea0b92b44","33fa37e90d4396bcb759fb4658928a3cdeba52e84adedaa3539873395a37b07c","7d8f7073cc90c0f3dae0d0bdf6a613a3aad593724db04e8c0e7cad0cdaf0ef1d","6f81d64b8b8b81a97d996fe091993cdf70831be03d199becb13dfccbf039563b"],
 ["zasp_temporal74.test_validate_output(text,text,text,text,text,jsonb,bytea,jsonb,bytea)","0dae68986983bc12abd4cbf715de700e528c314d2125a7640bfbe336c09e9a80","3ec6a7505bec4d0e485d1b08f28ce27c656964232c3e16ef9a4dd26ee4372087","4e31e59c4e364143e4272307b1237ed2e216c1c83a833c99f41bd6f87eba7e7c","ef838770bea4546f0ccb47f83bca6dfff9cdb3acf2c2f8de148b2fada48e6d77"],
 ["zasp_temporal75.admit_body(text,text,text,text,bigint,text,text,bigint,text,text,text,text,boolean)","e6d9fa37b77b9966cf1354a2386e1ce074983c0df08e3a2a166a5286516c689b","538ab3e39d529e428313aed56b67cf2ee166a3113276a34ed4107e831226cafb","e6d9fa37b77b9966cf1354a2386e1ce074983c0df08e3a2a166a5286516c689b","968dc69dbced52ba3d900a59ba5be4ba7510dfe65084dd81fab04d92ff1375d0"],
 ["zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)","1b179e9ba0e2579ab33f22edcd80f90202c4e49e0b55c636390308bcadd488f1","17212a678f51d2dde7192c148892966e23503c554faad98a5b4b8b8311d139e3","02b37c42775a6dc83b9b2ec31017adeb3250994ae3b1c37598be1fcdbd712033","8fc84c47b8770b2a06a9bd17f0d497179842315469850f1260bfe86623fb61e3"],
 ["zasp_temporal77.rules_capable(jsonb)","9a21d2cce1981a3a7c7013de167cf8c0969c7349671088cb40c0c2b6543edc0c","8eb5c78649f69b33e0e656b576b103e9707651d24b9273fffc831a2f0abf8c5d","e62231368a206c1eaa61f540b82a7a2d659a1408b55721a5858d3d75c526a181","b82ad9786df545fd31e0fc07882f72181e54c28693c605edc7d1ee583e3b5f15"],
 ["zasp_temporal78.admit_body(text,text,text,text,bigint,text,text,bigint,text,text,text,text,boolean)","9b0abbb6cdf84c6bbd05867443212b37a4fc3bf59195fe0e1903699a377418d4","4af2c17c6223c4aa2435a34ceceeeed6b8bf75ac749fe0654434ef6fe5387313","3fd59b6513d723cb393f121c9f8b5db097c6d8833ed66ca2efbd5986e84abf97","01ec662496e92799c61c541944a1d439701e5a81901fecd41bd3c162843cb532"],
 ["zasp_temporal78.admit_occurrence(jsonb)","dd03782e9946073e20b81c8909e9b8bf9b92526b3aeacb2a3cc63c86f957847d","485141b5a26c959de3def31a0a9b39231837a180fd9577223e82e242eca98a14","7695ae2afc99dbe3fdf8c2f63283560e22ec1ef9ecd0feccd471bc63e9fe08c2","bc495df338aaa156b3331d14760ec6c23ec41f244ad1a9db062292e6b8432994"],
 ["zasp_temporal78.apply(jsonb)","56b4094f5693dc525c320a4f340203e9fec26ca7812b4f7d6f414a3e05decf48","d67a1446d9a0d22d08cf2129e64cdfdfa92c18d5302779e70ba289f54e0506fe","8d1c90f3f797b4e1ecda48140fb6ea60ef5d5dc850a99afa2d29588835361a53","85eec25b165fe2e50181b9b53d0da3010bc0245e35e854e3801ec5a3ec085bbe"],
 ["zasp_temporal78.cleanup(jsonb)","272c1490304f57e393814a4ccab7a174bfaf9e9b6b0606d68555a6e9454ce9db","b0af62f4abf101fab23bdab1d467eb695aaf91d52b234707ff6468fd3e76a50d","04fe56819d4028bc80c3e679c582edfcfc0eeead56a63696f5529e0e8a928976","f698373f553c130442a6f155062c3360f4dc7364455eda0ee4a6d52e479b40c7"],
 ["zasp_temporal78.late_usage_valid(text,text,text,text)","5e1176a1db33dd38d0f9b880d22d08ef8f881be5943a75d465df37df423cf276","1d8eb24b062f4065e9170ee11ba89e55260e7c45ac32e562de194c55ee970f2a","517216c0ee16156f01956a8e2a15ccbf7d32e0ae6e57bd0239831d67c8ec34c8","84076e23ec8d240a519d698c66b24bf73625432eee49c4d674ce2d15a26351b2"],
 ["zasp_temporal78.plan(jsonb)","8b819b46dfa6fcaeeba990759cc0985490c8128fc20748682e86bd8c06659018","2394b6ba91016686ea28420894acee33b64869ea0979636788efa4eeb74531f8","4f02d8eba52e8d46c68def4cc6b9d0e33a14a02762c0ce32fa5cc3d01d694a12","d2e7dd557acc9d2774036c232fc59ebf451d9fbe40872fcbd9d28a4e47117d2c"],
 ["zasp_temporal78.planning_state(jsonb)","8bd907cbaa3e42672be03b5997a09bd0f307dc817ba68f7f00906bd1bf571737","e15b292ee30874e9a822ebf1510cc5f87547233653b7986ee66b82cc14bb0f26","b253ea84722254122d262704d1d14a3a983b3206964a286061151ba513aaa97a","e8fb3bb0f67e9037ec91daa3714e6ae93ed1755c1cbba8b68f05a06d7f618d4f"],
 ["zasp_temporal78.planning_terminal_valid(text,text,text,text)","71dfbfc24a14f3fe0e5c38c1bcf9a31f48905da6f78d6dc15f7fd0fe0f7bde5a","ebd8007745998afee6309728cf60aca2e86fd572d9bcc6a09a1ec0b7e17627af","8c30f8db8c1d7093f87c062298aeed1dd5b4441754768deb2837edc2653c352f","b2bfe2c0b2b697a66521275b5bd125dd9996bf1616ee720a3bf19417900395c8"],
 ["zasp_temporal78.predecessor76_fingerprint()","b48638963e0fce9857aebfeb0c3bb5120bc7fa904aa9b2fe77046b6e7cca197a","90d3b0e8c029972858947533720684217b37b51ddffafe863c99bd0c6e9d62e1","923e6d0331ce700b03ed574482bedd881a49e10b2734b039842be5058c73af34","8849af209319472a96468c328a29dbab4dad84c68e8b01a54a1ef055462addbe"],
 ["zasp_temporal78.predecessor77_fingerprint()","a2d3385034c09f4c88f56905c726c4db6717d516164722586c9b841a49f9f825","a0caf9f83a9f3fcb37f2a02d8b50c602f9a965eb38ac231c30964b94e2c12ace","6381357469c4fde1b2bcb423f249623380912168ac4a12d31273bbd94c74c9b8","6f633ff367ccac7b113f89a590a491d22c3dc9212252f37682331713ee4a8c5f"],
 ["zasp_temporal78.serialize_revocation()","146f1fed25638ce9caaf2dae4f02732b60556676ae6fd6d82aa4341f57b3ce14","c9f34fce917e1b326abea42f52711a6bca90e36136a61b29421c5b224c240576","7528e0927eb9a631e7d22cf5d1898c519aec9190956845ef55fa73d7afeee56e","05fcd50f6f82c477b2d8e60267e0e3e1391f8c4dfff24e9c2d1467b493b5f869"],
]);
const dependencyExcludedPins = Object.freeze([
 ['zasp_temporal68.progress(jsonb)','header'],
 ['zasp_temporal69.inspect(jsonb)','acl'],
 ['zasp_temporal69.inspect_message(jsonb)','acl'],
 ['zasp_temporal69.stop(jsonb)','acl'],
 ['zasp_temporal74.activate(text,text,text,text,text,text,bigint,text,timestamp with time zone,text,text,text)','header'],
]);
