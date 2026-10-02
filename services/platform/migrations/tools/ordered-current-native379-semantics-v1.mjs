// Fixed original-source expression programs for the owned native fixture.
// This module emits SQL; it never connects to PostgreSQL or accepts observations.
import crypto from 'node:crypto';
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const canonical=x=>JSON.stringify(x,(_,v)=>v&&typeof v==='object'&&!Array.isArray(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])):v);
const quote=x=>"'"+x.replaceAll("'","''")+"'";
const fail=x=>{throw Error('ordered-current native379 semantic '+x);};
const authority='zasp_discovery_authority',owner='zasp_test';
const dimensions=['role','search_path','timezone','read_only','transaction','advisory_locks','schema_locks','catalog'];
const frameSQL="SELECT jsonb_build_object('role',current_user,'session_user',session_user,'search_path',current_setting('search_path'),'timezone',current_setting('TimeZone'),'read_only',current_setting('transaction_read_only'),'isolation',current_setting('transaction_isolation')) AS state";
const stage=(id,role,sql,expected)=>({id,role,sql,sqlSHA256:sha(sql),expected});
const command={outcome:'command-success'};
const value=x=>({outcome:'rows',rows:[{value:x}],sqlState:null});
function sourceNode(contract,identity){const n=contract.nodes.find(n=>n.identity===identity);if(!n||sha(n.source)!==n.sourceSHA256)fail('source '+identity);return n;}
function span(contract,identity,text,from=0){
 const n=sourceNode(contract,identity),start=n.source.indexOf(text,from);if(start<0||n.source.indexOf(text,start+1)>=0&&from===0)fail('ambiguous source span '+identity+' '+text.slice(0,40));
 return {sourceIdentity:identity,sourceSHA256:n.sourceSHA256,definitionSHA256:n.definitionSHA256,start,end:start+Buffer.byteLength(text),siteSHA256:sha(text),source:text,frame:{owner:n.owner,acl:n.acl,config:n.config,language:n.language,securityDefiner:n.security_definer}};
}
function sourceExpression(contract,identity,startText,endText){const n=sourceNode(contract,identity),start=n.source.indexOf(startText),end=n.source.indexOf(endText,start)+endText.length;if(start<0||end<start)fail('expression span');return span(contract,identity,n.source.slice(start,end),start);}
function routineSQL(identity,result,{error=null,args=''}={}){
 const name=identity.slice(0,identity.indexOf('('));
 const body=error?`BEGIN RAISE EXCEPTION USING ERRCODE=${quote(error)},MESSAGE='native379-selected-poison'; END`:`BEGIN RETURN ${result===null?'NULL':quote(result)}; END`;
 return `CREATE OR REPLACE FUNCTION ${name}(${args}) RETURNS text LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,public AS $native379$${body}$native379$`;
}
function snapshotSQL({relations=[],routines=[],schemas=[]}){
 const names=[...new Set([...schemas,...relations.map(x=>x.split('.')[0]),...routines.map(x=>x.split('.')[0])])];
 const values=names.map(quote).join(',')||"''";
 // Exact scoped catalog state, source text, grants, configuration and row bags.
 const pieces=[`'frame',(${frameSQL.replace(' AS state','').replace('SELECT ','')})`,
  `'schemas',(SELECT coalesce(jsonb_agg(to_jsonb(n) ORDER BY n.nspname),'[]'::jsonb) FROM pg_namespace n WHERE n.nspname IN(${values}))`,
  `'routines',(SELECT coalesce(jsonb_agg(jsonb_build_object('row',to_jsonb(p),'definition',pg_get_functiondef(p.oid)) ORDER BY p.oid),'[]'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname IN(${values}) AND p.prokind='f')`,
  `'relations',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY c.oid),'[]'::jsonb) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN(${values}))`,
  `'constraints',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY c.oid),'[]'::jsonb) FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname IN(${values}))`,
  `'triggers',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.oid),'[]'::jsonb) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN(${values}))`,
  `'roles',(SELECT jsonb_agg(to_jsonb(r) ORDER BY r.rolname) FROM pg_roles r WHERE rolname LIKE 'zasp_%')`,
  `'memberships',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY m.oid),'[]'::jsonb) FROM pg_auth_members m)`];
 for(const [catalog,key]of [['pg_attribute','attrelid'],['pg_attrdef','adrelid'],['pg_policy','polrelid'],['pg_rewrite','ev_class'],['pg_index','indrelid']])pieces.push(`${quote(catalog)},(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY to_jsonb(a)::text COLLATE "C"),'[]'::jsonb) FROM ${catalog} a JOIN pg_class c ON c.oid=a.${key} JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN(${values}))`);
 pieces.push(`'types',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.oid),'[]'::jsonb) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname IN(${values}))`);
 for(const relation of [...new Set(relations)])pieces.push(`${quote(relation)},(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text COLLATE "C"),'[]'::jsonb) FROM ${relation} r)`);
 return `SELECT encode(sha256(convert_to(jsonb_build_object(${pieces.join(',')})::text,'UTF8')),'hex') AS snapshot`;
}
export function native379SQLProgram(control,{setup,probe,expected,objects,preconditions=[],searchPath='pg_catalog,public'}){
 const snapshot=snapshotSQL(objects),steps=[stage('setup-session',owner,"RESET ROLE; SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL READ COMMITTED, READ WRITE; SET SESSION search_path TO pg_catalog,public; SET SESSION TimeZone TO 'UTC'",command),stage('snapshot-before',owner,snapshot,{outcome:'capture',key:'before'}),stage('begin',owner,'BEGIN',command)];
 for(const [i,sql]of preconditions.entries())steps.push(stage('precondition-'+i,owner,sql,value(true)));
 steps.push(stage('mutate',owner,setup,command),stage('source-frame',owner,`SET LOCAL ROLE ${authority}; SET LOCAL search_path=${searchPath}; SET LOCAL TimeZone='UTC'`,command),stage('probe-savepoint',authority,'SAVEPOINT native379_probe',command),stage('probe',authority,probe,expected),stage('recover-probe',authority,'ROLLBACK TO SAVEPOINT native379_probe',command),stage('restore',authority,'ROLLBACK',command),stage('snapshot-after',owner,snapshot,{outcome:'equal-captured',key:'before'}));
 control.program={format:'native379-sql-program-v1',transaction:'owned-read-write-rollback',connection:'same-owned-session',steps};
 control.restoration={operation:'rollback-and-compare-exact-pre-state',dimensions,beforeNextProbe:true,timeoutIsDenial:false,snapshotSQL:snapshot,restoreSQL:'ROLLBACK',assertionSQL:snapshot,assertion:'exact-json-row-equality-to-snapshot-before',protocolTransactionStatusAfter:'I'};
 return control;
}
function obligation(id,category,sourceRuleId,sourceSite,mutation,expected,execution){
 if(!Object.keys(mutation.operands??{}).length)fail('missing exact operands');
 return native379SQLProgram({id,controlClass:'source-obligation',sourceRuleId,phase:'null-error-lazy-demand',category,ruleIds:[],facts:[],sourceSite,mutation,mutationSHA256:sha(canonical(mutation)),expected:{...expected,firstError:expected.firstError??null}},execution);
}
function scalarSavedSetup(relation,key,definition,{duplicate=false,remove=false,nullable=false}={}){
 let sql=`ALTER TABLE ${relation} DISABLE TRIGGER USER; `;
 if(duplicate)sql+=`ALTER TABLE ${relation} DROP CONSTRAINT predecessor_functions_pkey; `;
 if(nullable)sql+=`ALTER TABLE ${relation} ALTER COLUMN definition DROP NOT NULL; `;
 sql+=`DELETE FROM ${relation} WHERE signature=${quote(key)}; `;
 if(!remove){const row=`(${quote(key)},${definition===null?'NULL':quote(definition)},'zasp_discovery_authority','{}')`;sql+=`INSERT INTO ${relation}(signature,definition,owner_name,acl) VALUES ${row}${duplicate?','+row:''};`;}
 return sql;
}
function first(site,stageName,sqlState,extra={}){return {...site,stage:stageName,sqlState,...extra};}

export function buildNative379SemanticControls({contract,checkpoint}){
 const controls=[],closed=checkpoint.sourceCoverage.currentSourceClosure.packet;
 const temporalIdentity='zasp_temporal78.predecessor77_fingerprint()',helper='zasp_authorization80_worker.ordered_writer_definition(oid)',selected='zasp_temporal77.base67_fingerprint()',put='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)';
 const expression=sourceExpression(contract,temporalIdentity,'CASE WHEN p.oid IN(SELECT signature::regprocedure','END END END');
 const member=span(contract,temporalIdentity,"SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%'",expression.start);
 const helperCall=span(contract,temporalIdentity,'zasp_authorization80_worker.ordered_writer_definition(p.oid)',expression.start);
 const saved=span(contract,sourceNode(contract,helper).identity,'SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=value::regprocedure::text');
 const relation='zasp_authorization80_worker.predecessor_functions',outer='zasp_temporal78.predecessor_functions';
 const outerClear=`ALTER TABLE ${outer} DISABLE TRIGGER USER; DELETE FROM ${outer} WHERE signature IN(${quote(selected)},${quote(put)}); `;
 const query=identity=>`SELECT (${expression.source}) AS value FROM pg_proc p WHERE p.oid=${quote(identity)}::regprocedure`;
 const objects={relations:[relation,outer],routines:[helper]};
 const selectedPredicate=`p.oid=${quote(selected)}::regprocedure`;
 for(const [category,definition,mode,expected]of [
  ['explicit-null',null,{nullable:true},value(null)],['empty','',{},value('')],['scalar-zero',null,{remove:true},value(null)],['scalar-many','native379-selected',{duplicate:true},{outcome:'error',sqlState:'21000'}],
 ]){
  const mutation={operation:'execute-fixed-sql',operands:{relation,key:{signature:selected},column:'definition',value:definition,mode,selectedIdentity:selected,predicate:selectedPredicate,branch:'outer-membership-false-put-false-base-true',helperIdentity:helper,callOrder:[helper]},sql:outerClear+scalarSavedSetup(relation,selected,definition,mode)};mutation.sqlSHA256=sha(mutation.sql);
  controls.push(obligation('semantics:temporal77:'+category,category,'temporal:78.predecessor77_fingerprint:function',expression,mutation,{...expected,firstError:category==='scalar-many'?first(saved,'selected-saved-scalar','21000'):null},{setup:mutation.sql,probe:query(selected),expected,objects}));
 }
 // Poison only a helper-local regprocedure binding. The original helper body is
 // unchanged; the put-source branch must not demand that helper-local binding.
 const missing=closed.temporal77.helper.bindings[0];
 const missingSite=span(contract,helper,quote(missing)+'::regprocedure');
 for(const selectedBranch of [false,true]){
  const identity=selectedBranch?selected:put,category=selectedBranch?'lazy-selected':'lazy-unselected',expected=selectedBranch?{outcome:'error',sqlState:'42883'}:value('native379-put');
  const setup=outerClear+scalarSavedSetup(relation,put,'native379-put')+`ALTER FUNCTION ${missing} RENAME TO native379_missing_helper_binding`;
  const mutation={operation:'execute-fixed-sql',operands:{relation,key:{signature:put},value:'native379-put',selectedIdentity:identity,helperIdentity:helper,missingBinding:missing,branch:selectedBranch?'base-true':'put-true',predicate:`p.oid=${quote(identity)}::regprocedure`,callOrder:selectedBranch?[helper]:[],forbiddenCalls:selectedBranch?[]:[helper]},sql:setup,sqlSHA256:sha(setup)};
  controls.push(obligation('semantics:temporal77:'+category,category,'temporal:78.predecessor77_fingerprint:function',expression,mutation,{...expected,firstError:selectedBranch?first(missingSite,'helper-local-regprocedure-binding','42883'):null},{setup,probe:query(identity),expected,objects:{...objects,routines:[helper,missing]}}));
 }
 const putScalar=span(contract,temporalIdentity,'SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p.oid::regprocedure::text',expression.start);
 const firstSetup=outerClear+scalarSavedSetup(relation,put,'native379-put',{duplicate:true})+' '+routineSQL(helper,null,{error:'ZX002',args:'value oid'});
 controls.push(obligation('semantics:temporal77:first-error','first-error','temporal:78.predecessor77_fingerprint:function',expression,{operation:'execute-fixed-sql',operands:{relation,key:{signature:put},rowCount:2,value:'native379-put',predicate:`p.oid=${quote(put)}::regprocedure`,selectedIdentity:put,helperIdentity:helper,branch:'put-true',callOrder:[],forbiddenCalls:[helper],laterSQLState:'ZX002'},sql:firstSetup,sqlSHA256:sha(firstSetup)},{outcome:'error',sqlState:'21000',firstError:first(putScalar,'put-source-scalar-before-helper','21000',{later:helperCall,laterSQLState:'ZX002'})},{setup:firstSetup,probe:query(put),expected:{outcome:'error',sqlState:'21000'},objects}));
 // Membership is an IN bag, not a join. Duplicate signatures cannot multiply
 // the outer row. NULL signatures fail LIKE and contribute no member.
 for(const [category,signatures,expectedRows]of [['duplicate-bag',[selected,selected],[selected,selected]],['membership-null',[null],[]],['invalid-cast',['zasp_temporal77.native379_invalid_cast()'],null],['reg-object',['zasp_temporal77.native379_missing()'],null],['like-underscore',['zaspXtemporal77.native379()'],['zaspxtemporal77.native379()']]]){
  let setup=`ALTER TABLE ${outer} DISABLE TRIGGER USER; ALTER TABLE ${outer} DROP CONSTRAINT predecessor_functions_pkey; ALTER TABLE ${outer} ALTER COLUMN signature DROP NOT NULL; DELETE FROM ${outer} WHERE signature LIKE 'zasp_temporal77.%'; `;
  if(category==='like-underscore')setup+="CREATE SCHEMA zaspXtemporal77; CREATE FUNCTION zaspXtemporal77.native379() RETURNS text LANGUAGE sql AS 'SELECT NULL::text'; ";
  setup+=`INSERT INTO ${outer}(signature,definition,owner_name,acl) VALUES ${signatures.map(s=>`(${s===null?'NULL':quote(s)},'native379-member','zasp_discovery_authority','{}')`).join(',')}`;
  const directCast='signature::regprocedure',caseSite=category==='invalid-cast'?span(contract,temporalIdentity,directCast,expression.start):member;
  const probe=category==='invalid-cast'?`SELECT signature::regprocedure::text AS value FROM (VALUES(${quote(signatures[0])})) AS invalid_cast(signature)`:`SELECT coalesce(jsonb_agg(member::regprocedure::text ORDER BY member::regprocedure::text),'[]'::jsonb) AS value FROM (${member.source}) AS members(member)`;
  const expected=expectedRows===null?{outcome:'error',sqlState:'42883'}:value(expectedRows);
  const mutation={operation:'execute-fixed-sql',operands:{relation:outer,keys:signatures,column:'signature',values:signatures,likePattern:'zasp_temporal77.%',predicate:member.source,branch:'membership',helperIdentity:null,callOrder:[]},sql:setup,sqlSHA256:sha(setup)};
  const c=obligation('semantics:temporal77:'+category,category,'temporal:78.predecessor77_fingerprint:function',member,mutation,{...expected,firstError:expectedRows===null?first(member,'membership-regprocedure-cast','42883'):null},{setup,probe,expected,objects:{...objects,schemas:category==='like-underscore'?['zaspxtemporal77']:[]}});
  if(category==='invalid-cast'){
   c.sourceSite=caseSite;c.mutation.operands={...c.mutation.operands,predicate:directCast,branch:'direct-regprocedure-cast'};c.mutationSHA256=sha(canonical(c.mutation));
   const step=c.program.steps.find(s=>s.id==='probe');step.sql=probe;step.sqlSHA256=sha(probe);c.expected.firstError=first(caseSite,'direct-regprocedure-cast','42883');
  }else if(category==='reg-object'){c.mutation.operands={...c.mutation.operands,branch:'membership-regobject-resolution'};c.mutationSHA256=sha(canonical(c.mutation));}
  if(category==='duplicate-bag')c.program.steps.splice(c.program.steps.findIndex(s=>s.id==='recover-probe'),0,stage('membership-does-not-multiply',authority,`SELECT count(*) AS value FROM pg_proc p WHERE p.oid=${quote(selected)}::regprocedure AND p.oid IN(${member.source})`,value(1)));
  controls.push(c);
 }
 const aggregate=span(contract,temporalIdentity,"string_agg(value,E'\\n' ORDER BY value)");
 for(const order of [['b',null,'a','a'],['a','b','a',null]]){
  const setup='CREATE TEMP TABLE native379_bag(ordinal integer,value text); INSERT INTO native379_bag VALUES '+order.map((v,i)=>`(${i},${v===null?'NULL':quote(v)})`).join(',')+'; GRANT SELECT ON native379_bag TO zasp_discovery_authority';
  controls.push(obligation('semantics:temporal77:aggregate-order:'+controls.length,'aggregate-order','temporal:78.predecessor77_fingerprint:aggregate',aggregate,{operation:'execute-fixed-sql',operands:{relation:'pg_temp.native379_bag',columns:['ordinal','value'],rows:order.map((v,i)=>[i,v]),predicate:'all-four-rows',branch:'aggregate',helperIdentity:null,callOrder:[]},sql:setup,sqlSHA256:sha(setup)},value('a\na\nb'),{setup,probe:`SELECT ${aggregate.source} AS value FROM pg_temp.native379_bag`,expected:value('a\na\nb'),objects:{relations:[],routines:[]}}));
 }
 controls.push(...mixedControls(contract),...exportControls(contract,closed),...wrapperControls(contract,closed),...retirementControls(contract,closed.retirement));
 for(const [group,identity]of [['temporal77',helper],['mixed','public.zasp_discovery_schedule_replay_function_identity(oid)']]){
  const n=sourceNode(contract,identity),site=span(contract,identity,n.source),sql='SET LOCAL search_path=pg_catalog,public';
  controls.push(obligation('semantics:'+group+':original-frame-deparse','source-frame',group==='temporal77'?'temporal:78.predecessor77_fingerprint:function':'public:discovery_schedule_replay:function',site,{operation:'execute-fixed-sql',operands:{identity,searchPath:'pg_catalog, public',definitionSHA256:n.definitionSHA256,branch:'original-frame-deparse',callOrder:['pg_catalog.pg_get_functiondef(oid)']},sql,sqlSHA256:sha(sql)},value(n.definition),{setup:sql,probe:`SELECT pg_get_functiondef(${quote(identity)}::regprocedure) AS value`,expected:value(n.definition),objects:{routines:[identity]}}));
 }
 const aggregateIdentity='public.zasp_discovery_schedule_replay_live_fingerprint()',scheduleAggregate=span(contract,aggregateIdentity,"string_agg(value,E'\\n' ORDER BY value)"),aggregateSQL="CREATE TEMP TABLE native379_schedule_bag(value text); INSERT INTO pg_temp.native379_schedule_bag VALUES('b'),(NULL),('a'),('a'); GRANT SELECT ON pg_temp.native379_schedule_bag TO zasp_discovery_authority";
 controls.push(obligation('semantics:mixed:aggregate-null-bag','aggregate-order','public:discovery_schedule_replay:function',scheduleAggregate,{operation:'execute-fixed-sql',operands:{relation:'pg_temp.native379_schedule_bag',column:'value',rows:['b',null,'a','a'],branch:'aggregate',callOrder:['pg_catalog.string_agg(text,text)']},sql:aggregateSQL,sqlSHA256:sha(aggregateSQL)},value('a\na\nb'),{setup:aggregateSQL,probe:`SELECT ${scheduleAggregate.source} AS value FROM pg_temp.native379_schedule_bag`,expected:value('a\na\nb'),objects:{}}));
 const temporalMap={'like-underscore':'like-underscore','membership-null':'membership-null','membership-duplicates':'duplicate-bag','membership-cast-error':'invalid-cast','saved-zero-null':'scalar-zero','saved-multiple-error':'scalar-many','helper-unselected-no-demand':'lazy-unselected','helper-selected-binding-error':'lazy-selected','put-source-before-helper':'first-error','native-first-error':'first-error','original-frame-deparse':'original-frame-deparse','aggregate-null-bag':'aggregate-order-0'};
 const scheduleMap={'outer-cast-error':'outer-cast-error','unselected-helper-binding':'unselected-helper-binding','selected-helper-binding':'selected-helper-binding','guard-false-null':'guard-false','guard-null-null':'guard-null','saved-zero-null':'scalar-zero','saved-multiple-error':'scalar-many','native-first-error':'first-error','original-frame-deparse':'original-frame-deparse','aggregate-null-bag':'aggregate-null-bag'};
 temporalMap['aggregate-null-bag']=controls.find(c=>c.id.startsWith('semantics:temporal77:')&&c.category==='aggregate-order').id.slice('semantics:temporal77:'.length);
 for(const [family,nativeCases,prefix,mapping]of [['temporal77',closed.temporal77.nativeCases,'semantics:temporal77:',temporalMap],['schedule',closed.mixed.schedule.nativeCases,'semantics:mixed:',scheduleMap],['export',closed.mixed.export.nativeCases,'semantics:export:',{}],['wrapper',closed.wrappers[0].nativeCases,'semantics:wrapper:',{}]])for(const name of nativeCases){const id=prefix+(mapping[name]??name),control=controls.find(c=>c.id===id);if(!control)fail('unlowered native case '+family+':'+name);(control.sourceCaseIds??=[]).push({family,id:name});}
 return controls;
}

function mixedControls(contract){
 const controls=[],identity='public.zasp_discovery_schedule_replay_function_identity(oid)',node=sourceNode(contract,identity),site=span(contract,identity,node.source,0);
 const target='public.zasp_execution_live_fingerprint()',key='zasp_execution_live_fingerprint()',relation='zasp_temporal72.predecessor_functions',fingerprint='zasp_temporal72.fingerprint()',fp='b5d7f17f5350c89b337c6c875975402ab67b10ffc6facc2ea34c042342e9f07e',checksum='e51eecf1201f930449ea508838e94dd5344262f92a4d23768999d93697f2c940';
 const guardSetup=`ALTER TABLE zasp_temporal72.registration DISABLE TRIGGER USER; UPDATE zasp_temporal72.registration SET checksum=${quote(checksum)},fingerprint=${quote(fp)}; `+routineSQL(fingerprint,fp)+'; ';
 const probe=arg=>`SELECT public.zasp_discovery_schedule_replay_function_identity(${quote(arg)}::regprocedure) AS value`;
 const scalar=span(contract,identity,'SELECT definition FROM zasp_temporal72.predecessor_functions WHERE to_regprocedure(signature)=value');
 const guardCall=span(contract,identity,'zasp_temporal72.fingerprint()');
 const objects={relations:[relation,'zasp_temporal72.registration'],routines:[fingerprint,identity]};
 const outerIdentity='public.zasp_discovery_schedule_replay_live_fingerprint()',outerRelation='zasp_schedule_replay_prior.functions';
 const outerCast=span(contract,outerIdentity,'SELECT signature::regprocedure FROM zasp_schedule_replay_prior.functions');
 const outerSetup=`ALTER TABLE ${outerRelation} DISABLE TRIGGER USER; UPDATE ${outerRelation} SET signature='public.native379_missing()' WHERE signature='public.zasp_execution_live_fingerprint()'`;
 controls.push(obligation('semantics:mixed:outer-cast-error','invalid-cast','public:discovery_schedule_replay:function',outerCast,{operation:'execute-fixed-sql',operands:{relation:outerRelation,key:{signature:'public.zasp_execution_live_fingerprint()'},column:'signature',value:'public.native379_missing()',branch:'outer-selector',callOrder:[]},sql:outerSetup,sqlSHA256:sha(outerSetup)},{outcome:'error',sqlState:'42883',firstError:first(outerCast,'outer-selector-regprocedure-before-helper','42883')},{setup:outerSetup,probe:`SELECT count(*) AS value FROM (${outerCast.source}) AS selected(value) WHERE value IS NOT NULL`,expected:{outcome:'error',sqlState:'42883'},objects:{relations:[outerRelation]}}));
 const binding=span(contract,identity,"'public.zasp_execution_live_fingerprint()'::regprocedure");
 for(const demanded of [false,true]){
  const setup='ALTER FUNCTION public.zasp_execution_live_fingerprint() RENAME TO native379_missing_binding',expected=demanded?{outcome:'error',sqlState:'42883'}:value('undemanded');
  const query=demanded?probe('public.zasp_attack_lab_execution_live_fingerprint()'):"SELECT CASE WHEN false THEN public.zasp_discovery_schedule_replay_function_identity('public.zasp_attack_lab_execution_live_fingerprint()'::regprocedure) ELSE 'undemanded' END AS value";
  controls.push(obligation('semantics:mixed:'+(demanded?'selected-helper-binding':'unselected-helper-binding'),demanded?'lazy-selected':'lazy-unselected','public:discovery_schedule_replay:function',binding,{operation:'execute-fixed-sql',operands:{function:'public.zasp_execution_live_fingerprint()',rename:'native379_missing_binding',helperIdentity:identity,branch:demanded?'demand-helper':'case-false',callOrder:demanded?[identity]:[],forbiddenCalls:demanded?[]:[identity]},sql:setup,sqlSHA256:sha(setup)},{...expected,firstError:demanded?first(binding,'helper-in-binding','42883'):null},{setup,probe:query,expected,objects:{routines:['public.zasp_execution_live_fingerprint()',identity]}}));
 }
 for(const [category,definition,mode,expected]of [['explicit-null',null,{nullable:true},value(null)],['empty','',{},value('')],['scalar-zero',null,{remove:true},value(null)],['scalar-many','native379-mixed',{duplicate:true},{outcome:'error',sqlState:'21000'}]]){
  const setup=guardSetup+scalarSavedSetup(relation,key,definition,mode);
  controls.push(obligation('semantics:mixed:'+category,category,'public:discovery_schedule_replay:function',site,{operation:'execute-fixed-sql',operands:{relation,key:{signature:key},column:'definition',value:definition,mode,selectedIdentity:target,predicate:'value IN(public.zasp_execution_live_fingerprint(),self) AND original72-guard-true',helperIdentity:identity,branch:'outer-true-inner-true',callOrder:[fingerprint]},sql:setup,sqlSHA256:sha(setup)},{...expected,firstError:category==='scalar-many'?first(scalar,'guard-true-saved-scalar','21000'):null},{setup,probe:probe(target),expected,objects}));
 }
 for(const [category,result]of [['guard-false','native379-wrong'],['guard-null',null]]){
  const setup=guardSetup+routineSQL(fingerprint,result);
  controls.push(obligation('semantics:mixed:'+category,'explicit-null','public:discovery_schedule_replay:function',site,{operation:'execute-fixed-sql',operands:{relation:'zasp_temporal72.registration',key:{singleton:true},fingerprintResult:result,helperIdentity:fingerprint,selectedIdentity:target,predicate:'outer-true-inner-'+(result===null?'null':'false'),branch:'inner-fallback-null',callOrder:[fingerprint]},sql:setup,sqlSHA256:sha(setup)},value(null),{setup,probe:probe(target),expected:value(null),objects}));
 }
 for(const selectedBranch of [false,true]){
  const arg=selectedBranch?target:'public.zasp_attack_lab_execution_live_fingerprint()',category=selectedBranch?'lazy-selected':'lazy-unselected';
  const setup=guardSetup+routineSQL(fingerprint,null,{error:'ZX001'}),definition=sourceNode(contract,arg).definition.replaceAll('37956023196757f30a7ecb415e9d7d7e6f76cfa32a3ffa2d45445c172f6313ab','<compiled-checksum>').replaceAll('1ed52fb5f9a83384e1d3fecbc3bc116d3981a36479e9b3b1f6ec04b5cd4f3b36','<compiled-fingerprint>');
  const expected=selectedBranch?{outcome:'error',sqlState:'ZX001'}:value(definition);
  controls.push(obligation('semantics:mixed:'+category,category,'public:discovery_schedule_replay:function',site,{operation:'execute-fixed-sql',operands:{relation:'zasp_temporal72.registration',key:{singleton:true},selectedIdentity:arg,helperIdentity:fingerprint,branch:selectedBranch?'outer-true':'outer-false-raw-definition',predicate:`value=${quote(arg)}::regprocedure`,callOrder:selectedBranch?[fingerprint]:[],forbiddenCalls:selectedBranch?[]:[fingerprint],poisonSQLState:'ZX001'},sql:setup,sqlSHA256:sha(setup)},{...expected,firstError:selectedBranch?first(guardCall,'selected-guard-call','ZX001'):null},{setup,probe:probe(arg),expected,objects}));
 }
 const firstSetup=guardSetup+scalarSavedSetup(relation,key,'native379-mixed',{duplicate:true})+' '+routineSQL(fingerprint,null,{error:'ZX001'});
 controls.push(obligation('semantics:mixed:first-error','first-error','public:discovery_schedule_replay:function',site,{operation:'execute-fixed-sql',operands:{relation,key:{signature:key},rowCount:2,selectedIdentity:target,branch:'outer-true',helperIdentity:fingerprint,callOrder:[fingerprint],firstSQLState:'ZX001',laterSQLState:'21000'},sql:firstSetup,sqlSHA256:sha(firstSetup)},{outcome:'error',sqlState:'ZX001',firstError:first(guardCall,'guard-before-saved-scalar','ZX001',{later:scalar,laterSQLState:'21000'})},{setup:firstSetup,probe:probe(target),expected:{outcome:'error',sqlState:'ZX001'},objects}));
 return controls;
}

function exportControls(contract,closed){
 const controls=[],identity='public.zasp_sa_export_live_fingerprint()',recipe=closed.mixed.export.recipe;
 sourceNode(contract,identity);
 const predicate=recipe.bindings.migration_owned.source,condition=span(contract,identity,predicate);
 const ownerExpression="CASE WHEN migration_owned THEN '<registered-migration-principal>' ELSE 'owner:'||owner_name END";
 const aclExpression="CASE WHEN migration_owned THEN (SELECT jsonb_agg(CASE WHEN a->>'grantee'=owner_name THEN jsonb_build_array('registered-migration-principal',a-'grantee') ELSE jsonb_build_array('literal',a) END ORDER BY n)::text FROM jsonb_array_elements(acl) WITH ORDINALITY x(a,n)) ELSE acl::text END";
 const aclSite=span(contract,identity,aclExpression),roleCall=span(contract,identity,"pg_has_role(r.oid,'zasp_discovery_authority','MEMBER')"),role='zasp_native379_export_owner',signature=recipe.bindings.migration_owned.signatures[0];
 const baseACL=[{grantee:role,grantor:'native379-grantor',privilege:'EXECUTE'},{grantee:'registered-migration-principal',privilege:'EXECUTE'}];
 for(const nativeCase of closed.mixed.export.nativeCases){
  let acl=baseACL,registered=true,bindings=1,member=true,loweredPredicate=predicate.replace('public.zasp_discovery_principal_bindings','pg_temp.native379_export_bindings'),expectedError=null;
  if(nativeCase==='owner-not-registered'){bindings=0;registered=false;}
  if(nativeCase==='member-false'){member=false;registered=false;}
  if(nativeCase==='member-null'){registered=false;loweredPredicate=loweredPredicate.replace(roleCall.source,'NULL::boolean');}
  if(nativeCase==='duplicate-bindings-exists')bindings=2;
  if(nativeCase==='acl-ordinality')acl=[...baseACL].reverse();
  // Same privilege/grantor payload, but literal role names imitate both source
  // tags. Only the real owner's top-level grantee gets the registered tag.
  if(nativeCase==='acl-tags-cannot-collide')acl=[
   {grantee:role,grantor:'native379-grantor',privilege:'EXECUTE',grantable:false},
   {grantee:'registered-migration-principal',grantor:'native379-grantor',privilege:'EXECUTE',grantable:false},
   {grantee:'<registered-migration-principal>',grantor:'native379-grantor',privilege:'EXECUTE',grantable:false},
  ];
  // Owner text deliberately appears outside top-level grantee. The source
  // jsonb subtraction must preserve grantor, grant options and nested keys.
  if(nativeCase==='acl-remove-grantee-only')acl=[
   {grantee:role,grantor:role,privilege:'EXECUTE',grantable:true,note:role,metadata:{grantee:role,grantor:role,tag:'registered-migration-principal'}},
   {grantee:'native379-literal',grantor:role,privilege:'EXECUTE',grantable:false,metadata:{grantee:role}},
  ];
  if(nativeCase==='acl-empty-null')acl=[];
  if(nativeCase==='acl-scalar-error'||nativeCase==='native-first-error'){acl='native379-scalar';expectedError=nativeCase==='native-first-error'?'ZX001':'22023';}
  if(nativeCase==='raw-else-text'){acl={a:1,zz:2};bindings=0;registered=false;}
  if(nativeCase==='native-first-error')loweredPredicate=loweredPredicate.replace(roleCall.source,'pg_temp.native379_export_poison()');
  const sql=`CREATE ROLE ${role}; ${member?`GRANT zasp_discovery_authority TO ${role};`:''} CREATE TEMP TABLE native379_export_saved(signature text,definition text,owner_name text,acl jsonb); CREATE TEMP TABLE native379_export_bindings(principal_name text,authority_role text); INSERT INTO pg_temp.native379_export_saved VALUES(${quote(signature)},'native379-definition',${quote(role)},${quote(JSON.stringify(acl))}::jsonb); ${bindings?`INSERT INTO pg_temp.native379_export_bindings VALUES ${Array.from({length:bindings},()=>`(${quote(role)},'zasp_discovery_authority')`).join(',')};`:''} GRANT SELECT ON pg_temp.native379_export_saved,pg_temp.native379_export_bindings TO zasp_discovery_authority; ${nativeCase==='native-first-error'?"CREATE FUNCTION pg_temp.native379_export_poison() RETURNS boolean LANGUAGE plpgsql VOLATILE AS $native379$ BEGIN RAISE EXCEPTION USING ERRCODE='ZX001'; END $native379$; GRANT EXECUTE ON FUNCTION pg_temp.native379_export_poison() TO zasp_discovery_authority;":''}`;
  const cte=`WITH saved AS (SELECT s.*,${loweredPredicate} AS migration_owned FROM pg_temp.native379_export_saved s)`;
  let expectedACL=registered?Array.isArray(acl)&&acl.length?acl.map(a=>a.grantee===role?['registered-migration-principal',Object.fromEntries(Object.entries(a).filter(([k])=>k!=='grantee'))]:['literal',a]):null:acl;
  let expected=expectedError?{outcome:'error',sqlState:expectedError}:value([registered?'<registered-migration-principal>':'owner:'+role,expectedACL]);
  let probe=`${cte} SELECT jsonb_build_array(${ownerExpression},(${aclExpression})::jsonb) AS value FROM saved`;
  if(nativeCase==='raw-else-text'){probe=`${cte} SELECT ${aclExpression} AS value FROM saved`;expected=value('{"a": 1, "zz": 2}');}
  if(nativeCase==='aggregate-null-bag'){const agg=span(contract,identity,"string_agg(value,E'\\n' ORDER BY value)");probe=`SELECT ${agg.source} AS value FROM (VALUES('b'::text),(NULL::text),('a'::text),('a'::text)) AS identities(value)`;expected=value('a\na\nb');}
  const mutation={operation:'execute-fixed-sql',operands:{sourceRelation:'zasp_sa_export_prior.functions',relation:'pg_temp.native379_export_saved',key:{signature},row:{signature,definition:'native379-definition',owner_name:role,acl},sourceBindingRelation:'public.zasp_discovery_principal_bindings',bindingRelation:'pg_temp.native379_export_bindings',bindingRows:Array.from({length:bindings},()=>({principal_name:role,authority_role:'zasp_discovery_authority'})),member,branch:registered?'registered':'raw-else',predicate,executedPredicate:loweredPredicate,helperIdentity:'pg_catalog.pg_has_role(oid,name,text)',callOrder:nativeCase==='native-first-error'?['pg_temp.native379_export_poison()']:['pg_catalog.pg_has_role(oid,name,text)'],nativeCase,scope:'original-source-expression-with-explicit-input-relation-substitution',primitiveSubstitution:nativeCase==='member-null'?{source:roleCall.source,replacement:'NULL::boolean',reason:'valid joined pg_roles.oid and valid authority role cannot yield NULL; isolate original EXISTS NULL filtering'}:nativeCase==='native-first-error'?{source:roleCall.source,replacement:'pg_temp.native379_export_poison()',sqlState:'ZX001'}:null},sql,sqlSHA256:sha(sql)};
  const firstError=expectedError?first(nativeCase==='native-first-error'?roleCall:aclSite,nativeCase==='native-first-error'?'membership-before-acl-array':'jsonb-array-elements',expectedError,{laterSQLState:nativeCase==='native-first-error'?'22023':null}):null;
  const control=obligation('semantics:export:'+nativeCase,nativeCase==='native-first-error'?'first-error':'export-acl',recipe.ruleId,aclSite,mutation,{...expected,firstError},{setup:sql,probe,expected,objects:{schemas:['zasp_sa_export_prior']}});control.sourcePredicate=condition;controls.push(control);
 }
 return controls;
}

function wrapperControls(contract,closed){
 const controls=[],w=closed.wrappers.find(w=>w.sourceIdentity==='zasp_temporal65.fingerprint()');if(!w)fail('wrapper source');
 const site={sourceIdentity:w.sourceIdentity,sourceSHA256:w.sourceSHA256,definitionSHA256:w.definitionSHA256,start:w.start,end:w.end,siteSHA256:w.siteSHA256,source:w.source,frame:w.frame};
 const guard='zasp_temporal74.fingerprint()',outgoing='zasp_temporal74.outbox65_fingerprint()',relation='zasp_temporal74.registration',fingerprint='0be1a2bfe93c30928eb03eae744993df6ec6c4db692b909aed9b7c486de6aca5';
 const setupBase=`ALTER TABLE ${relation} DISABLE TRIGGER USER; UPDATE ${relation} SET checksum='6ecde7cb0053af3378f47aef84ecbe99ca31d9cdced9fbe6d0dc64ee7e01b39e',fingerprint=${quote(fingerprint)}; `+routineSQL(guard,fingerprint)+'; '+routineSQL(outgoing,'native379-wrapper')+'; ';
 const objects={relations:[relation],routines:[w.sourceIdentity,guard,outgoing]},probe='SELECT zasp_temporal65.fingerprint() AS value';
 for(const operation of w.nativeCases){
  let setup=setupBase,expected=value(null),branch='condition-false',firstError=null,callOrder=[guard],query=probe;
  if(operation==='condition-false-fallback')setup+=`DELETE FROM ${relation}`;
  else if(operation==='condition-null-fallback'){setup+=routineSQL(guard,null);branch='condition-null';}
  else if(operation==='selected-call-error'){setup+=routineSQL(outgoing,null,{error:'ZX001'});expected={outcome:'error',sqlState:'ZX001'};branch='condition-true';callOrder=[guard,outgoing];firstError=first(span(contract,w.sourceIdentity,'zasp_temporal74.outbox65_fingerprint()'),'selected-outgoing-call','ZX001');}
  else if(operation==='unselected-call-no-demand'){setup+=`DELETE FROM ${relation}; `+routineSQL(outgoing,null,{error:'ZX001'});branch='condition-false-outgoing-undemanded';}
  else if(operation==='registration-cardinality')setup+=`ALTER TABLE ${relation} DROP CONSTRAINT registration_pkey; INSERT INTO ${relation} SELECT * FROM ${relation}`;
  else if(operation==='owner-acl-frame-drift'){setup+=`ALTER FUNCTION ${w.sourceIdentity} OWNER TO zasp_security_agent_worker`;query=`SELECT p.proowner='zasp_discovery_authority'::regrole AND p.proacl::text=${quote(w.frame.acl)} AND p.proconfig=${quote('{"search_path=pg_catalog, public"}')}::text[] AS value FROM pg_proc p WHERE p.oid=${quote(w.sourceIdentity)}::regprocedure`;expected=value(false);branch='source-frame-admission';callOrder=[];}
  else if(operation==='native-first-error'){setup+=routineSQL(guard,null,{error:'ZX001'})+'; '+routineSQL(outgoing,null,{error:'ZX002'});expected={outcome:'error',sqlState:'ZX001'};branch='guard-errors-before-then';callOrder=[guard];firstError=first(span(contract,w.sourceIdentity,'zasp_temporal74.fingerprint()'),'condition-call-before-then','ZX001',{later:span(contract,w.sourceIdentity,'zasp_temporal74.outbox65_fingerprint()'),laterSQLState:'ZX002'});}
  else fail('unknown wrapper case '+operation);
  const category=operation==='native-first-error'?'first-error':operation==='selected-call-error'?'lazy-selected':operation==='unselected-call-no-demand'?'lazy-unselected':'wrapper';
  controls.push(obligation('semantics:wrapper:'+operation,category,w.ruleId,site,{operation:'execute-fixed-sql',operands:{relation,key:{singleton:true},checksum:'6ecde7cb0053af3378f47aef84ecbe99ca31d9cdced9fbe6d0dc64ee7e01b39e',fingerprint,guardIdentity:guard,helperIdentity:outgoing,branch,predicate:w.source,callOrder},sql:setup,sqlSHA256:sha(setup)},{...expected,firstError},{setup,probe:query,expected,objects}));
 }
 return controls;
}

function retirementControls(contract,retired){
 const controls=[],relation='zasp_temporal66.retired_authorities',node=sourceNode(contract,retired.sourceIdentity);
 const sourceSteps=retired.steps.map(step=>{const start=node.source.indexOf(step.source,retired.start);if(start<retired.start||start+step.source.length>retired.end)fail('retirement step span');return {...step,start,end:start+step.source.length,siteSHA256:sha(step.source)};});
 const site={sourceIdentity:retired.sourceIdentity,sourceSHA256:retired.sourceSHA256,definitionSHA256:retired.definitionSHA256,start:retired.start,end:retired.end,siteSHA256:retired.siteSHA256,source:retired.source,frame:retired.frame};
 const harness=`CREATE FUNCTION pg_temp.native379_retirement() RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $native379$ DECLARE n text; retired ${relation}%ROWTYPE; actual text; BEGIN ${retired.source}\n END LOOP; RETURN true; END $native379$; GRANT EXECUTE ON FUNCTION pg_temp.native379_retirement() TO zasp_discovery_authority; `;
 for(const [index,schema]of retired.schemas.entries())for(const operation of retired.nativeCases){
  let setup=`ALTER TABLE ${relation} DISABLE TRIGGER USER; DELETE FROM ${relation} WHERE schema_name IN('zasp_ordered_worker63','zasp_ordered_scheduler64'); `;
  const original=retired.originalFingerprints[index],fingerprint='native379-retired';
  let createSchema=true,insertRow=true,actual=fingerprint,saved=fingerprint,originalValue=original,expected=value(true),firstError=null,companion=null;
  if(operation==='schema-absent-row-absent-continue'){createSchema=false;insertRow=false;companion=retired.schemas[1-index];}
  else if(operation==='schema-present-row-absent-false'){insertRow=false;expected=value(false);}
  else if(operation==='schema-absent-row-present-false'){createSchema=false;expected=value(false);}
  else if(operation==='original-fingerprint-null-or-drift'){originalValue='native379-wrong-original';expected=value(false);}
  else if(operation==='retired-fingerprint-null-or-drift'){saved='native379-wrong-retired';expected=value(false);}
  else if(operation==='dynamic-fingerprint-error'){expected={outcome:'error',sqlState:'ZX001'};firstError=first({...site,...sourceSteps[4]},'dynamic-fingerprint','ZX001');}
  else if(operation==='native-first-error'){originalValue='native379-wrong-original';expected=value(false);firstError=first({...site,...sourceSteps[3]},'fixed-original-fingerprint',null,{later:{...site,...sourceSteps[4]},laterSQLState:'ZX002'});}
  else if(operation==='worker-execute-true')expected=value(false);
  else if(!['duplicate-select-into-not-scalar-error','worker-execute-null'].includes(operation))fail('retirement operation');
  if(companion){const companionOriginal=retired.originalFingerprints[1-index];setup+=`CREATE SCHEMA ${companion}; `+routineSQL(companion+'.fingerprint()',fingerprint)+`; REVOKE ALL ON FUNCTION ${companion}.fingerprint() FROM PUBLIC; GRANT USAGE ON SCHEMA ${companion} TO zasp_discovery_authority; GRANT EXECUTE ON FUNCTION ${companion}.fingerprint() TO zasp_discovery_authority; INSERT INTO ${relation}(schema_name,original_fingerprint,retired_fingerprint) VALUES (${quote(companion)},${quote(companionOriginal)},${quote(fingerprint)}); `;}
  if(createSchema){setup+=`CREATE SCHEMA ${schema}; `+routineSQL(schema+'.fingerprint()',actual,{error:operation==='dynamic-fingerprint-error'?'ZX001':operation==='native-first-error'?'ZX002':null})+`; REVOKE ALL ON FUNCTION ${schema}.fingerprint() FROM PUBLIC; GRANT USAGE ON SCHEMA ${schema} TO zasp_discovery_authority; GRANT EXECUTE ON FUNCTION ${schema}.fingerprint() TO zasp_discovery_authority; `;}
  const row=`(${quote(schema)},${quote(originalValue)},${quote(saved)})`;
  if(operation==='duplicate-select-into-not-scalar-error')setup+=`ALTER TABLE ${relation} DROP CONSTRAINT retired_authorities_pkey; `;
  if(insertRow)setup+=`INSERT INTO ${relation}(schema_name,original_fingerprint,retired_fingerprint) VALUES ${row}${operation==='duplicate-select-into-not-scalar-error'?','+row:''}; `;
  if(operation==='worker-execute-true')setup+=`GRANT USAGE ON SCHEMA ${schema} TO zasp_security_agent_worker; GRANT EXECUTE ON FUNCTION ${schema}.fingerprint() TO zasp_security_agent_worker; `;
  setup+=harness;
  let probe='SELECT pg_temp.native379_retirement() AS value';
  // has_function_privilege on a live oid and valid role is not nullable. This
  // typed SQL operator control injects NULL only at the predicate boundary; it
  // does not claim a real catalog row can have a NULL oid/privilege result.
  if(operation==='worker-execute-null')probe='SELECT NOT EXISTS(SELECT 1 FROM (VALUES(NULL::boolean)) AS privilege_probe(allowed) WHERE allowed) AS value';
  const mutation={operation,operands:{relation,schema,key:{schema_name:schema},originalFingerprint:original,insertedOriginalFingerprint:originalValue,retiredFingerprint:saved,actualFingerprint:actual,workerRole:'zasp_security_agent_worker',fingerprintFunction:schema+'.fingerprint()',companionSchema:companion,branchIdentity:companion?`target-${schema}-absent-companion-${companion}-verified`:'target-'+schema,rowCount:insertRow?operation==='duplicate-select-into-not-scalar-error'?2:1:0,duplicateRows:'identical-values',privilegeInput:operation==='worker-execute-null'?null:operation==='worker-execute-true',scope:operation==='worker-execute-null'?'isolated-original-EXISTS-null-operator':'original-retirement-source-block',callOrder:createSchema?[schema+'.fingerprint()']:companion?[companion+'.fingerprint()']:[]},sql:setup,sqlSHA256:sha(setup)};
  const c=obligation('retirement:'+schema+':'+operation,operation==='native-first-error'?'first-error':'retirement',retired.ruleId,site,mutation,{...expected,firstError},{setup,probe,expected,objects:{relations:[relation],schemas:retired.schemas},preconditions:[`SELECT to_regnamespace('zasp_ordered_worker63') IS NULL AND to_regnamespace('zasp_ordered_scheduler64') IS NULL AS value`]});
  c.sourceSteps=sourceSteps;controls.push(c);
 }
 return controls;
}
