// Exactly three reviewed expression regions. All runtime values remain local
// to one SQL evaluation; this generator does not install a cache or helper API.
export function higherReadinessRegions({bySignature,calls,masked,depends,hash,normal,quote,workerChecksum,catalogDigest}) {
  const leaf='zasp_authorization80_worker.catalog_ready()';
  const predecessor='zasp_temporal68.predecessor_ready(text,text)';
  const roots=[predecessor,'zasp_temporal68.ready(text,text)','zasp_temporal78.ready(text,text)'];
  const pure=new Set([
    ...Array.from({length:7},(_,i)=>`zasp_temporal${69+i}.ready(text,text)`),
    ...[76,77,78].map(n=>`zasp_temporal${n}.catalog_ready()`),
  ]);
  const opaque=new Set([predecessor,'zasp_authorization80.runtime_audit_ready()']);
  const bindings=new Map([
    ['zasp_authorization79.ready(text)',[['c','text']]],
    ['zasp_security_agent_budgets_function_identity(oid)',[['function_value','oid']]],
    ['zasp_discovery_schedule_replay_function_identity(oid)',[['value','oid']]],
    ...Array.from({length:11},(_,i)=>[`zasp_temporal${68+i}.ready(text,text)`,[['c','text'],['f','text']]]),
  ]);
  const fail=message=>{throw Error('higher readiness '+message);};
  const normalizeRuntime=s=>s.replaceAll(workerChecksum,'-- worker profile checksum').replaceAll(catalogDigest,'-- worker catalog body digest');
  const strip=s=>s.trim().replace(/;\s*$/,'');
  const pins=new Map();
  function pin(fn){
    pins.set(fn.signature,{signature:fn.signature,definitionHash:hash(normal(fn.definition)),sourceHash:hash(normal(fn.source)),owner:fn.owner,acl:fn.acl});
  }
  function frame(fn){
    if(fn.owner!=='zasp_discovery_authority'||fn.volatility!=='s'||fn.strict||fn.parallel!=='u'||JSON.stringify(fn.config)!==JSON.stringify(['search_path=pg_catalog, public'])||/[^\x00-\x7f]/.test(fn.source))fail('ineligible frame '+fn.signature);
  }
  function expression(fn){
    frame(fn);pin(fn);
    if(fn.language==='sql')return strip(fn.source);
    if(!pure.has(fn.signature))fail('unapproved procedural expression '+fn.signature);
    // Mask first: semicolons/control words inside literals do not become
    // procedural syntax. No declaration, exception, extra statement or END.
    const code=masked(fn.source),match=/^\s*BEGIN\s+RETURN\s+([\s\S]*);\s*END\s*;?\s*$/i.exec(code);
    if(!match||/[;]|\b(?:BEGIN|RETURN|EXCEPTION|PERFORM|DECLARE)\b/i.test(match[1]))fail('non-scalar wrapper '+fn.signature);
    const start=code.search(/\bRETURN\s+/i)+code.match(/\bRETURN\s+/i)[0].length;
    const end=code.lastIndexOf(';',code.toUpperCase().lastIndexOf('END'));
    return 'SELECT '+fn.source.slice(start,end);
  }
  function args(text){
    const code=masked(text);let depth=0,last=0;const result=[];
    for(let i=0;i<code.length;i++){if(code[i]==='(')depth++;else if(code[i]===')')depth--;else if(code[i]===','&&depth===0){result.push(text.slice(last,i));last=i+1;}}
    result.push(text.slice(last));return result;
  }
  function scalarParams(sig,query){
    const params=bindings.get(sig),fn=bySignature.get(sig);
    if(!fn.arguments)return null;
    if(!params||fn.arguments!==params.map(([n,t])=>`${n} ${t}`).join(', '))fail('unapproved parameters '+sig);
    let depth=0;const code=masked(query);
    for(const m of code.matchAll(/\(|\)|\bFROM\b/gi)){if(m[0]==='(')depth++;else if(m[0]===')')depth--;else if(depth===0)fail('parameter outer FROM '+sig);}
    if(!/^SELECT\s/i.test(query))fail('parameter non-scalar query '+sig);
    return params;
  }
  function qualify(query,params,alias){
    const code=masked(query),names=new Set(params.map(([name])=>name));
    for(const name of names){
      // This is a closed captured-scalar transform, not a SQL scope parser.
      // New local declarations/aliases require review, never silent rebinding.
      if(new RegExp(`\\bAS\\s+${name}\\b|\\b(?:FROM|JOIN)\\s+[a-z0-9_.]+\\s+(?:AS\\s+)?${name}\\b|\\)\\s+(?:AS\\s+)?${name}\\b|\\bWITH\\s+${name}\\b`,'i').test(code)||new RegExp(`\\bAS\\s+"${name}"`,'i').test(query))fail('unapproved parameter shadow');
    }
    const edits=[];
    for(const token of code.matchAll(/[a-z_][a-z0-9_$]*/gi)){
      if(!names.has(token[0].toLowerCase()))continue;
      const before=code.slice(0,token.index).trimEnd(),after=code.slice(token.index+token[0].length).trimStart();
      if(before.endsWith('.')||after.startsWith('.'))continue;
      edits.push({start:token.index,end:token.index+token[0].length,text:alias+'.'+token[0]});
    }
    for(const e of edits.reverse())query=query.slice(0,e.start)+e.text+query.slice(e.end);
    return query;
  }
  function copiedExpression(signature,query){
    const copyEdits=[];
    if(signature==='zasp_sa_export_live_fingerprint()'){
      const from='ORDER BY n)::text FROM jsonb_array_elements(acl) WITH ORDINALITY x(a,n)';
      const to='ORDER BY x.n)::text FROM jsonb_array_elements(acl) WITH ORDINALITY x(a,n)';
      if(query.split(from).length!==2)fail('ordinality anchor changed');
      query=query.replace(from,()=>to);copyEdits.push({from,to});
    }
    return {query,copyEdits};
  }
  function ambientInventory(query){
    // These are ALL parameters/locals in the captured enclosing PL frame.
    // Inspect copied nodes only: the root's original c/f predicates and its
    // dynamic tail remain untouched. This is a closed declaration inventory,
    // not inference that an arbitrary bare name belongs to an SQL scope.
    const code=masked(query),names=new Set(['c','f','n','retired','actual']);
    for(const token of code.matchAll(/[a-z_][a-z0-9_$]*/gi)){
      if(!names.has(token[0].toLowerCase()))continue;
      const before=code.slice(0,token.index).trimEnd(),after=code.slice(token.index+token[0].length).trimStart();
      if(before.endsWith('.')||after.startsWith('.'))continue;
      if(/\bAS$/i.test(before)||/\b(?:FROM|JOIN)\s+[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)?$/i.test(before))continue;
      if(token[0]==='n'&&/\bWITH ORDINALITY x\(a,$/.test(before)&&after.startsWith(')'))continue;
      fail('unbound ambient '+token[0]);
    }
  }
  const regions=[];
  for(const signature of roots){
    const fn=bySignature.get(signature);frame(fn);pin(fn);
    let prefix='',suffix='',originalExpression=fn.source;
    if(signature===predecessor){
      // Preserve both cheap rejection guards BEFORE demanding the catalog.
      const match=/^(\s*DECLARE[\s\S]*?BEGIN\s+IF c IS DISTINCT FROM '[0-9a-f]{64}' OR f IS DISTINCT FROM '[0-9a-f]{64}'\s+OR )([\s\S]*?)( THEN RETURN false;END IF;[\s\S]*)$/.exec(fn.source);
      if(!match)fail('static IF anchor changed');
      [prefix,originalExpression,suffix]=match.slice(1);
      if(!suffix.includes("FOREACH n IN ARRAY ARRAY['zasp_ordered_worker63','zasp_ordered_scheduler64'] LOOP"))fail('dynamic tail anchor changed');
    }else if(signature==='zasp_temporal78.ready(text,text)'){
      const match=/^(\s*SELECT c='[0-9a-f]{64}' AND f='[0-9a-f]{64}' AND )([\s\S]*)$/.exec(fn.source);
      if(!match)fail('nullable root guards changed');
      [prefix,originalExpression]=match.slice(1);
    }
    const rootQuery=prefix?'SELECT ('+strip(originalExpression)+')':strip(originalExpression);
    const nodes=new Map(),visiting=new Set();let bindingSequence=0;
    function visit(sig){
      if(nodes.has(sig))return;
      if(visiting.has(sig))fail('cycle '+sig);
      visiting.add(sig);
      const target=bySignature.get(sig);let query=expression(target);
      if(/higher_argument_/i.test(query))fail('reserved binding identifier');
      const params=scalarParams(sig,query),alias=params?'higher_argument_'+bindingSequence++:null;
      if(params)query=qualify(query,params,alias);
      const copied=copiedExpression(sig,query);query=copied.query;
      ambientInventory(query);
      const edges=calls({...target,source:query});
      for(const edge of edges){
        if(edge.targets.length!==1)fail('ambiguous call '+edge.text);
        if(depends.has(edge.target)&&!opaque.has(edge.target))visit(edge.target);
      }
      visiting.delete(sig);nodes.set(sig,{signature:sig,query,params,alias,edges,copyEdits:copied.copyEdits});
    }
    const rootEdges=calls({...fn,source:rootQuery});
    for(const edge of rootEdges){
      if(edge.targets.length!==1)fail('ambiguous root call '+edge.text);
      if(depends.has(edge.target)&&!opaque.has(edge.target))visit(edge.target);
    }
    if(!nodes.has(leaf))fail('missing shared catalog');
    const computed=new Map(),ctes=[],materialized=[],expanded=[];
    // Do not hoist a dynamic/opaque descendant indirectly through a wrapper.
    const unsafe=new Set(opaque);
    for(const node of nodes.values())if(node.edges.some(e=>unsafe.has(e.target)))unsafe.add(node.signature);
    const catalogName='higher_catalog';
    computed.set(leaf,`(SELECT value FROM ${catalogName})`);
    function rewrite(query,edges){
      const selected=edges.filter(e=>computed.has(e.target)).sort((a,b)=>b.start-a.start);
      for(const e of selected){
        if(selected.some(x=>x!==e&&x.start<e.start&&x.end>e.end))fail('nested selected calls');
        let replacement=computed.get(e.target),params=nodes.get(e.target)?.params;
        if(params){
          const actual=args(e.args);if(actual.length!==params.length)fail('argument arity');
          // A template may contain nested scalar bindings. Give every copy
          // fresh lexical aliases BEFORE inserting its caller's arguments.
          const aliases=new Map(),edits=[];
          for(const token of masked(replacement).matchAll(/\bhigher_argument_\d+\b/g)){
            if(!aliases.has(token[0]))aliases.set(token[0],'higher_argument_'+bindingSequence++);
            edits.push({start:token.index,end:token.index+token[0].length,text:aliases.get(token[0])});
          }
          for(const edit of edits.reverse())replacement=replacement.slice(0,edit.start)+edit.text+replacement.slice(edit.end);
          // Substitution callback keeps $ tokens in SQL literals literal.
          replacement=replacement.replace(/<higher-argument-(\d+)>/g,(_,n)=>actual[Number(n)]);
        }
        query=query.slice(0,e.start)+replacement+query.slice(e.end);
      }
      return query;
    }
    for(const node of nodes.values()){
      expanded.push({signature:node.signature,parameter:node.params,copyEdits:node.copyEdits});
      if(node.signature===leaf)continue;
      let query=rewrite(node.query,node.edges);
      if(node.params){
        const values=node.params.map(([name,type],i)=>`(<higher-argument-${i}>)::${type} AS ${name}`).join(',');
        computed.set(node.signature,`(${query} FROM (SELECT ${values}) AS ${node.alias})`);
      }else if(unsafe.has(node.signature))computed.set(node.signature,`(${query})`);
      else{
        const name='higher_'+ctes.length;
        ctes.push(`${name}(value) AS MATERIALIZED (${query})`);materialized.push(node.signature);
        computed.set(node.signature,`(SELECT value FROM ${name})`);
      }
    }
    // A changed leaf must take the original recipe without executing its new
    // body. Full pg_get_functiondef pins return/args and all frame attributes.
    const catalog=bySignature.get(leaf);
    const liveDefinition="replace(replace(pg_get_functiondef(p.oid),'-- worker profile checksum','<worker-checksum>'),'-- worker catalog body digest','<worker-catalog>')";
    const gate=`EXISTS(SELECT 1 FROM pg_proc p WHERE p.oid='${leaf}'::regprocedure AND p.proowner='zasp_discovery_authority'::regrole AND p.proacl::text=${quote(catalog.acl)} AND encode(digest(convert_to(${liveDefinition},'UTF8'),'sha256'),'hex')=${quote(hash(normal(catalog.definition)))}) AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE checksum='-- worker profile checksum')`;
    const catalogCTE=`${catalogName}(value) AS MATERIALIZED (SELECT CASE WHEN ${gate} THEN zasp_authorization80_worker.catalog_ready() ELSE NULL END)`;
    const fused=rewrite(rootQuery,rootEdges);
    const inside=ctes.length?`WITH ${ctes.join(',')} SELECT (${fused})`:fused;
    const query=`SELECT CASE WHEN current_user='zasp_discovery_authority' THEN (WITH ${catalogCTE} SELECT CASE WHEN (SELECT value FROM ${catalogName}) THEN (${inside}) ELSE (${rootQuery}) END) ELSE (${rootQuery}) END`;
    regions.push({signature,prefix,originalExpression,suffix,query:normalizeRuntime(query),expanded,materialized});
  }
  // Verify ALL precursor bodies before mutating any root. Original recipes in
  // subsequent regions cannot accidentally pick up an already-fused sibling.
  const records=[...pins.values()];
  const payload=JSON.stringify({records,regions});
  if(payload.includes('$higher_records$'))fail('delimiter');
  const sql=`\n-- Three fixed higher expressions; separate readiness invocations never share values.\nDO $higher_readiness$\nDECLARE data jsonb:=$higher_records$${payload}$higher_records$::jsonb; p jsonb;r jsonb;d text;s text;v text;saved record;\nBEGIN\n FOR p IN SELECT value FROM jsonb_array_elements(data->'records') LOOP\n  SELECT pg_get_functiondef(oid),prosrc INTO STRICT d,s FROM pg_proc WHERE oid=(p->>'signature')::regprocedure;\n  IF encode(digest(convert_to(replace(replace(d,'-- worker profile checksum','<worker-checksum>'),'-- worker catalog body digest','<worker-catalog>'),'UTF8'),'sha256'),'hex')<>p->>'definitionHash' OR encode(digest(convert_to(replace(replace(s,'-- worker profile checksum','<worker-checksum>'),'-- worker catalog body digest','<worker-catalog>'),'UTF8'),'sha256'),'hex')<>p->>'sourceHash'\n   OR NOT EXISTS(SELECT 1 FROM pg_proc WHERE oid=(p->>'signature')::regprocedure AND proowner::regrole::text=p->>'owner' AND proacl::text IS NOT DISTINCT FROM p->>'acl')\n  THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='higher readiness exact predecessor changed';END IF;\n END LOOP;\n FOR r IN SELECT value FROM jsonb_array_elements(data->'regions') LOOP\n  SELECT * INTO saved FROM zasp_authorization80_worker.predecessor_functions WHERE signature=r->>'signature';\n  IF FOUND AND (saved.definition IS DISTINCT FROM pg_get_functiondef((r->>'signature')::regprocedure) OR saved.owner_name IS DISTINCT FROM 'zasp_discovery_authority' OR saved.acl IS DISTINCT FROM (SELECT COALESCE(proacl::text,'') FROM pg_proc WHERE oid=(r->>'signature')::regprocedure)) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='higher readiness saved root changed';END IF;\n END LOOP;\n FOR p IN SELECT value FROM jsonb_array_elements(data->'records') LOOP\n  IF p->>'signature'<>'${leaf}' AND split_part(p->>'signature','.',1)<>'zasp_authorization80_worker' THEN\n   INSERT INTO zasp_authorization80_worker.predecessor_functions SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc WHERE oid=(p->>'signature')::regprocedure ON CONFLICT(signature) DO NOTHING;\n  END IF;\n END LOOP;\n FOR r IN SELECT value FROM jsonb_array_elements(data->'regions') LOOP\n  SELECT pg_get_functiondef(oid),prosrc INTO STRICT d,s FROM pg_proc WHERE oid=(r->>'signature')::regprocedure;\n  IF s IS DISTINCT FROM (r->>'prefix')||(r->>'originalExpression')||(r->>'suffix') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='higher readiness region anchor changed';END IF;\n  v:=CASE WHEN r->>'prefix'='' THEN r->>'query' ELSE (r->>'prefix')||'('||(r->>'query')||')'||(r->>'suffix') END;\n  IF (length(d)-length(replace(d,s,'')))/length(s)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='higher readiness definition anchor changed';END IF;\n  EXECUTE replace(d,s,E'\\n'||v||E'\\n');\n END LOOP;\nEND $higher_readiness$;\n`;
  return {sql,regions,records};
}
