// Source-contract tooling only. Not embedded by any migration or runtime.
// Lexical obligations are evidence for a reviewed fixed-source partition, not
// a claim to parse arbitrary SQL, resolve overloads, or approve a live catalog.
import crypto from 'node:crypto';
import {orderedSavedFunctionTables} from './ordered-current-catalog.mjs';
import {staticRelations} from './ordered-current-static-catalog.mjs';
export {compileOrderedCollector,projectOrderedFacts,validateOrderedSelectors} from './ordered-current-catalog.mjs';
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
export function reconcileOrderedEffective(catalog, compiledSource, roots) {
  if (!Array.isArray(roots) || !roots.length || new Set(roots).size !== roots.length) throw Error('invalid fixed roots');
  const identities = new Map(), names = new Map();
  for (const f of catalog.functions) {
    if (identities.has(f.identity)) throw Error('duplicate effective identity');
    identities.set(f.identity, f);
    const name = f.identity.slice(0, f.identity.indexOf('('));
    if (!names.has(name)) names.set(name, []);
    names.get(name).push(f);
  }
  const body = f => {
    if (!['sql', 'plpgsql'].includes(f.language)) return null;
    const parts = f.definition.split('$function$');
    if (parts.length !== 3 || !parts[0].endsWith('AS ')) throw Error('unsupported effective body');
    return parts[1];
  };
  const unique = name => {
    const matches = names.get(name) ?? [];
    if (!matches.length) throw Error('unresolved callable: ' + name);
    if (matches.length !== 1) throw Error('ambiguous callable: ' + name);
    return matches[0];
  };
  for (const root of roots) if (!identities.has(root)) throw Error('missing fixed root: ' + root);
  const input = inspectOrderedCompiled(compiledSource);
  const declarations = input.declarations.map(d => {
    const effective = unique(d.name), source = body(effective), effectiveBodySHA256 = sha(source);
    return {identity: effective.identity, start: d.start, end: d.end,
      compiledBodySHA256: d.bodySHA256, effectiveBodySHA256,
      status: d.bodySHA256 === effectiveBodySHA256 ? 'body-exact' : 'effective-body-differs'};
  });
  const transforms = input.transforms.map(t => ({start: t.start, end: t.end, tag: t.tag,
    bodySHA256: t.bodySHA256, disposition: 'retained-install-provenance', source: t.source}));
  const pending = [...roots], nodes = new Map(), edges = [];
  const relations = new Set(catalog.relations.map(r => r.identity));
  while (pending.length) {
    const identity = pending.shift();
    if (nodes.has(identity)) continue;
    const f = identities.get(identity), source = body(f);
    const inventory = source === null ? {calls: [], relations: [], dynamic: [], universe: []} : inspectOrderedSource(source);
    nodes.set(identity, {...f, definitionSHA256: sha(f.definition), source, sourceSHA256: source === null ? null : sha(source), inventory});
    const code = source === null ? '' : mask(source);
    for (const call of inventory.calls) {
      // The fixed captured spelling exceeds PostgreSQL's identifier limit.
      // Do not apply a generic truncation fallback to unknown application names.
      const name = call.name === 'public.zasp_production_security_agent_existing_tests_global_fingerprint'
        ? 'public.zasp_production_security_agent_existing_tests_global_fingerprin' : call.name;
      if (/\bINSERT\s+INTO\s*$/i.test(code.slice(0, call.start))) {
        if (!relations.has(name)) throw Error('unresolved insert target: ' + name);
        edges.push({from: identity, to: name, kind: 'insert-target', site: call.id});
        continue;
      }
      const target = unique(name);
      edges.push({from: identity, to: target.identity, kind: 'call', site: call.id});
      pending.push(target.identity);
    }
  }
  return {declarations, transforms, nodes: [...nodes.values()].sort((a,b) => a.identity.localeCompare(b.identity, 'en')),
    edges: edges.sort((a,b) => (a.from+'\0'+a.site).localeCompare(b.from+'\0'+b.site, 'en'))};
}

export function partitionOrderedBody(source, callSites) {
  if (!Array.isArray(callSites) || new Set(callSites).size !== callSites.length) throw Error('duplicate or invalid call sites');
  const inventory = new Map(inspectOrderedSource(source).calls.map(call => [call.id, call]));
  const selected = callSites.map(id => {
    if (!inventory.has(id)) throw Error('unknown call site');
    return inventory.get(id);
  }).sort((a, b) => a.start - b.start);
  const result = [];
  let offset = 0;
  const append = (start, end, disposition, extra = {}) => {
    if (end === start) return;
    const text = source.slice(start, end);
    result.push({start, end, text, sha256: sha(text), disposition, ...extra});
  };
  for (const call of selected) {
    if (call.start < offset) throw Error('overlapping call sites');
    append(offset, call.start, 'retain-original');
    append(call.start, call.end, 'replace-structural-edge', {site: call.id, callee: call.name});
    offset = call.end;
  }
  append(offset, source.length, 'retain-original');
  return result;
}

// Supplemental pinned-source audit. Tokens include SQL syntax/type/alias forms;
// callers must classify every token, not mistake this for a SQL call parser.
export function inspectOrderedCallTokens(source) {
  const code = mask(source);
  return [...code.matchAll(/(?<![a-z0-9_.$])([a-z_][a-z0-9_]*(?:\s*\.\s*[a-z_][a-z0-9_]*)?)\s*\(/gi)]
    .map(m => ({name: m[1].replace(/\s/g, '').toLowerCase(), start: m.index, text: source.slice(m.index, m.index + m[0].length)}));
}

export function inspectOrderedInlineLive(source) {
  // Two reviewed expressions copied into the fixed higher/base materialized
  // recipes. Preserve their enclosing CASE/boolean expression, not just the
  // table token or EXISTS result. No expression is evaluated by this tool.
  const recipes = [
    {kind: 'metadata-owner-normalization',
      marker: "CASE WHEN key IN('production_discovery_execution_prior_owner','red_team_execution_prior_permissions_owner')",
      text: "CASE WHEN key IN('production_discovery_execution_prior_owner','red_team_execution_prior_permissions_owner') AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings b JOIN pg_roles r ON r.rolname=b.principal_name WHERE b.principal_name=value AND b.authority_role='zasp_discovery_authority' AND r.rolcanlogin) THEN 'registered-migration-owner' ELSE value END",
      correlatedInputs: ['key', 'value']},
    {kind: 'saved-export-migration-owner',
      marker: "s.signature IN('public.zasp_workflow_mutate_v3(",
      text: "s.signature IN('public.zasp_workflow_mutate_v3(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text)','public.zasp_workflow_replay(text,text,text,text,text,text,jsonb)')\n AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings b JOIN pg_roles r ON r.rolname=b.principal_name WHERE b.principal_name=s.owner_name AND b.authority_role='zasp_discovery_authority' AND pg_has_role(r.oid,'zasp_discovery_authority','MEMBER'))",
      correlatedInputs: ['s.signature', 's.owner_name']}
  ];
  const spans = [];
  for (const recipe of recipes) {
    let from = 0;
    for (;;) {
      const start = source.indexOf(recipe.marker, from);
      if (start < 0) break;
      const end = start + recipe.text.length;
      if (source.slice(start, end) !== recipe.text) throw Error('inline live clause changed: ' + recipe.kind);
      spans.push({kind: recipe.kind, start, end, text: recipe.text,
        sha256: sha(recipe.text), disposition: 'retain-live-inline-expression',
        correlatedInputs: recipe.correlatedInputs,
        liveRelations: ['public.zasp_discovery_principal_bindings', 'pg_roles'],
        obligation: 'Evaluate the original correlated expression in its original owner/configuration and SQL scope at each fresh boundary; never replace with a captured result or fixture principal.'});
      from = end;
    }
  }
  return spans.sort((a, b) => a.start - b.start);
}
export function inspectOrderedCompiled(source) {
  const code=mask(source),declarations=[],transforms=[];
  const body=(start,offset,kind)=>{
    const head=source.slice(offset).match(kind==='function'?/^[\s\S]*?\bAS\s+(\$(?:[a-z_][a-z0-9_]*)?\$)/i:/^\s*(\$(?:[a-z_][a-z0-9_]*)?\$)/i);
    if(!head||head[0].length>4096)throw Error('unsupported compiled '+kind+' body');
    const begin=offset+head[0].length,end=source.indexOf(head[1],begin);
    if(end<0)throw Error('unterminated compiled body');
    return {start,end:end+head[1].length,tag:head[1],source:source.slice(begin,end),text:source.slice(start,end+head[1].length)};
  };
  for(const m of code.matchAll(/\bCREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+((?:public|zasp_[a-z0-9_]+)\.[a-z_][a-z0-9_]*)\s*\(/gi)) {
    const value=body(m.index,m.index+m[0].length,'function');
    declarations.push({...value,name:m[1],bodySHA256:sha(value.source),inventory:inspectOrderedSource(value.source)});
  }
  for(const m of code.matchAll(/^DO\b/gim)) {
    const value=body(m.index,m.index+m[0].length,'do');
    transforms.push({...value,bodySHA256:sha(value.source),inventory:inspectOrderedSource(value.source)});
  }
  return {declarations,transforms};
}

function mask(source) {
  if (typeof source !== 'string' || /[^\x00-\x7f]/.test(source)) throw Error('unsupported source encoding');
  const out = [...source];
  let i = 0;
  const hide = end => { while(i < end) { if(out[i] !== '\n') out[i] = ' '; i++; } };
  while(i < source.length) {
    if(source.startsWith('--',i)) { const end=source.indexOf('\n',i); hide(end<0?source.length:end); continue; }
    if(source.startsWith('/*',i)) {
      let j=i+2, depth=1;
      while(j<source.length && depth) { if(source.startsWith('/*',j)){depth++;j+=2;}else if(source.startsWith('*/',j)){depth--;j+=2;}else j++; }
      if(depth) throw Error('unterminated comment'); hide(j); continue;
    }
    if(source[i]==="'" || source[i]==='"') {
      const quote=source[i], escape=quote==="'" && /[eE]/.test(source[i-1]??'') && !/[a-z0-9_]/i.test(source[i-2]??'');
      let j=i+1, closed=false;
      while(j<source.length) { if(escape && source[j]==='\\'){j+=2;continue;} if(source[j]===quote){if(source[j+1]===quote){j+=2;continue;}j++;closed=true;break;}j++; }
      if(!closed) throw Error('unterminated quote'); hide(j); continue;
    }
    const dollar=source.slice(i).match(/^\$(?:[a-z_][a-z0-9_]*)?\$/i);
    if(dollar){const end=source.indexOf(dollar[0],i+dollar[0].length);if(end<0)throw Error('unterminated dollar quote');hide(end+dollar[0].length);continue;}
    i++;
  }
  return out.join('');
}

export function inspectOrderedSource(source) {
  const code=mask(source), result={calls:[],relations:[],dynamic:[],universe:[]};
  const add=(kind,start,end,extra={})=>{const text=source.slice(start,end);result[kind].push({id:sha(kind+'\0'+start+'\0'+text),start,end,text,...extra});};
  for(const m of code.matchAll(/(?<![a-z0-9_.])((?:(?:public|zasp_[a-z0-9_]+)\s*\.\s*)?zasp_[a-z0-9_]+|(?:public|zasp_[a-z0-9_]+)\s*\.\s*[a-z_][a-z0-9_]*)\s*\(/gi)) {
    let end=m.index+m[0].length, depth=1;
    while(end<code.length && depth){if(code[end]==='(')depth++;else if(code[end]===')')depth--;end++;}
    if(depth) throw Error('unterminated application call');
    let name=m[1].replace(/\s/g,'').toLowerCase();if(!name.includes('.'))name='public.'+name;
    add('calls',m.index,end,{name});
  }
  for(const m of code.matchAll(/\b(?:FROM|JOIN|UPDATE|INTO)\s+((?:public|pg_catalog|zasp_[a-z0-9_]+)\s*\.\s*[a-z_][a-z0-9_]*|(?:pg_[a-z0-9_]+|zasp_[a-z0-9_]+))\b/gi)) {
    const start=m.index+m[0].indexOf(m[1]);add('relations',start,start+m[1].length,{name:m[1].replace(/\s/g,'').toLowerCase()});
  }
  for(const m of code.matchAll(/\b(?:EXECUTE|FOREACH)\b/gi)) add('dynamic',m.index,m.index+m[0].length,{keyword:m[0].toUpperCase()});
  const spans=new Set();
  for(const m of code.matchAll(/\b(?:pronamespace|relnamespace|typnamespace|nspname|nspacl|nspowner)\b/gi)) {
    const start=source.lastIndexOf('\n',m.index)+1, next=source.indexOf('\n',m.index),end=next<0?source.length:next;
    if(!spans.has(start)){spans.add(start);add('universe',start,end,{expression:source.slice(start,end)});}
  }
  return result;
}

export function verifyOrderedPartition(inventory, rows) {
  const expected=new Set(Object.values(inventory).flat().map(x=>x.id));
  if(!Array.isArray(rows) || rows.length!==expected.size) return false;
  const seen=new Set();
  for(const row of rows) {
    if(!expected.has(row.id)||seen.has(row.id)||!['retain-live','structural-required','historical-representation','dynamic-reviewed'].includes(row.disposition))return false;
    seen.add(row.id);
  }
  return seen.size===expected.size;
}

// Typed representation for direct-integrity development. A selected field is a
// requirement only when its original source-site selector requires it. These
// admissible field names are not an instruction to compare every exported field.
const stringFields = words => Object.fromEntries(words.split(' ').map(k => [k, 'string']));
const booleanFields = words => Object.fromEntries(words.split(' ').map(k => [k, 'boolean']));
const arrayFields = words => Object.fromEntries(words.split(' ').map(k => [k, k === 'acl' ? 'acl' : 'array']));
const provenanceTypes = {format_version: 'integer', purpose: 'string', profile_checksum: 'string', compiled_source_sha256: 'string', contract_sha256: 'string', reference_file_sha256: 'string', generator_sha256: 'string', postgres: 'string', pgcrypto: 'string', module_sha256: 'array', entry_spans: 'array'};
const sourceColumnTypes={...stringFields('namespace_name type_identity default_pretty_text_or_empty relation relation_name name type default collation identity generated storage compression default_text_or_empty acl_text_or_empty'),...booleanFields('not_null dropped'),...arrayFields('acl dependencies'),position:'integer',normalized_position:'integer',type_modifier:'integer'};
export const orderedFactTypes = Object.freeze({
  build: provenanceTypes,
  namespace: {...stringFields('name acl_text_or_empty owner'), ...arrayFields('acl')},
  routine: {...stringFields('identity inventory_owner inventory_acl_text inventory_body execution_acl_text execution_config_text execution_body precision_definition namespace_name source sql_body kind argument_defaults variadic_type result_type name identity_arguments config_text_or_empty acl_text_or_empty owner language definition result arguments volatility parallel binary support'), ...booleanFields('security_definer strict leakproof returns_set'), ...arrayFields('acl config input_types all_types argument_modes argument_names transforms'), cost: 'number', rows: 'number',default_count:'integer'},
  relation: {...stringFields('execution_acl_text namespace_name name acl_text_or_empty options_text_or_empty kind owner persistence replica_identity tablespace access_method partition_bound'), ...booleanFields('row_security forced_row_security'), ...arrayFields('acl options parents')},
  column: sourceColumnTypes,
  column_name: sourceColumnTypes,
  column_all: sourceColumnTypes,
  global_constraint:{...stringFields('relation_name name relation definition definition_pretty constraint_type'),...booleanFields('validated deferrable deferred no_inherit')},
  policy_view:stringFields('namespace_name name relation_name table_name roles roles_text command using check permissive'),
  index_view:stringFields('name table_name definition'),
  information_column:stringFields('name table_name relation_name data_type is_nullable default_text_or_empty'),
  constraint: {...stringFields('relation_name name relation definition_pretty definition constraint_type referenced_relation match update_action delete_action backing_index'), ...booleanFields('validated deferrable deferred inherited no_inherit'), ...arrayFields('columns referenced_columns')},
  index: {...stringFields('owner definition_pretty relation_name name definition predicate expressions'), ...booleanFields('valid ready live unique primary exclusion'), ...arrayFields('keys')},
  class_index:stringFields('name definition'),
  policy: {...stringFields('execution_roles_text namespace_name relation relation_name name roles_csv_public_sorted roles_named_array_text using_text_or_empty check_text_or_empty command using check'), ...booleanFields('permissive'), ...arrayFields('dependencies'), roles:'acl'},
  foreign_key_trigger:{...stringFields('relation name referenced_relation trigger_relation constraint_relation function enabled arguments columns_text when_text_or_empty'),...booleanFields('deferrable deferred'),event_bits:'integer',argument_count:'integer'},
  trigger: {...stringFields('execution_definition namespace_name relation_name function_name function_identity_arguments relation name definition_pretty enabled definition function function_definition function_owner arguments when referenced_relation old_table new_table'), function_acl:'acl', ...booleanFields('internal deferrable deferred'), event_bits: 'integer'},
  view: {...stringFields('definition owner'), ...arrayFields('acl options')},
  rewrite: {...stringFields('event enabled definition qualification action'), ...booleanFields('instead'), ...arrayFields('dependencies')},
  type: {...stringFields('category relation element array alignment storage delimiter kind owner base default collation subtype input output receive send analyze subscript'), ...booleanFields('not_null by_value preferred defined'), ...arrayFields('acl labels attributes constraints'),length:'integer',type_modifier:'integer',dimensions:'integer'},
  operator: stringFields('procedure left_type right_type result_type commutator negator'),
  collation: {...stringFields('provider locale version'), ...booleanFields('deterministic')},
  default_acl: arrayFields('acl'),
  role: {...stringFields('name'),...booleanFields('inventory_v1_managed_here execution_v1_managed_here login inherit superuser create_db create_role replication bypass_rls')},
  membership: {...booleanFields('admin inherit set'), ...stringFields('grantor')},
  role_setting: arrayFields('config'),
  saved_function: {...stringFields('signature definition owner'), ...arrayFields('acl')},
  saved_view: stringFields('definition'),
  saved_constraint: stringFields('signature definition'),
  saved_trigger: stringFields('definition enabled name'),
  registration: {...stringFields('checksum fingerprint predecessor profile_name outbox_predecessor profile_checksum manifest_sha256'), ...booleanFields('singleton'), format_version: 'integer'},
  profile_registration: {...stringFields('checksum profile_name'), ...booleanFields('singleton')},
  runtime_registration: {...stringFields('checksum fingerprint'), ...booleanFields('singleton')},
  worker_registration: stringFields('fingerprint'),
  fixed_runtime_profile: {...stringFields('name'),...booleanFields('singleton')},
  dependency: stringFields('object referenced dependency_kind'),
  shared_dependency: stringFields('object referenced dependency_kind'),
  extension: {...stringFields('schema version owner'), ...booleanFields('relocatable')}
});
const byteOrder = (a, b) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
const hexSHA = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const plainObject = value => value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype;
// JSON strings carry their own lengths/escaping. Sorting uses UTF-8 bytes,
// independent of the host's locale. Array order is always significant.
export function canonicalOrderedJSON(value) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') {
    if (value.includes('\0') || /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) throw Error('unsupported PostgreSQL text');
    return JSON.stringify(value);
  }
  if (typeof value === 'number' && Number.isFinite(value) && !Object.is(value, -0)) {
    const encoded=JSON.stringify(value);
    if(/[eE]/.test(encoded)||Math.abs(value)>Number.MAX_SAFE_INTEGER)throw Error('unsupported canonical numeric range');
    return encoded;
  }
  if (Array.isArray(value)) return '[' + value.map(canonicalOrderedJSON).join(',') + ']';
  if (plainObject(value)) return '{' + Object.keys(value).sort(byteOrder).map(k => canonicalOrderedJSON(k) + ':' + canonicalOrderedJSON(value[k])).join(',') + '}';
  throw Error('unsupported JSON value');
}
export function normalizeOrderedFacts(rows) {
  if (!Array.isArray(rows)) throw Error('facts must be rows');
  const keys = new Set();
  const result = rows.map(row => {
    if (!plainObject(row) || Object.keys(row).sort().join(',') !== 'fact,identity,kind' || !Object.hasOwn(orderedFactTypes, row.kind) || typeof row.identity !== 'string' || !row.identity || !plainObject(row.fact) || !Object.keys(row.fact).length) throw Error('malformed fact row');
    const key = canonicalOrderedJSON([row.kind, row.identity]);
    if (keys.has(key)) throw Error('duplicate fact key');
    keys.add(key);
    for (const [field, value] of Object.entries(row.fact)) {
      const type = orderedFactTypes[row.kind][field];
      if (!Object.hasOwn(orderedFactTypes[row.kind],field)) throw Error('undeclared fact field: ' + row.kind + '.' + field);
      if (value === null) continue;
      const valid = type === 'acl' ? typeof value === 'string' || Array.isArray(value) && value.every(v => typeof v === 'string') : type === 'array' ? Array.isArray(value) && value.every(v => typeof v === 'string') : type === 'integer' ? Number.isSafeInteger(value) : typeof value === type;
      if (!valid) throw Error('invalid fact type: ' + row.kind + '.' + field);
    }
    return JSON.parse(canonicalOrderedJSON(row));
  });
  return result.sort((a,b) => byteOrder(a.kind,b.kind) || byteOrder(a.identity,b.identity));
}
export function compareFacts(expected, live) {
  try { return canonicalOrderedJSON(normalizeOrderedFacts(expected)) === canonicalOrderedJSON(normalizeOrderedFacts(live)); }
  catch { return false; }
}

const manifestCall = 'zasp_authorization80_ordered_current.require('; 
const selfToken = '@ordered-current-manifest@';
export function normalizeEntry(entry) {
  if (!plainObject(entry) || typeof entry.identity !== 'string' || !entry.identity || typeof entry.definition !== 'string' || /[^\x00-\x7f]/.test(entry.definition) || !plainObject(entry.manifestSpan)) throw Error('invalid compiler entry');
  const {start, end} = entry.manifestSpan, source = entry.definition;
  if (!Number.isSafeInteger(start) || end !== start + 64 || start < 1 || end >= source.length || source[start-1] !== "'" || source[end] !== "'" || !hexSHA(source.slice(start,end))) throw Error('manifest span is not one SHA literal');
  // This is deliberately the exact compiler spelling. A second site, comments,
  // alternative whitespace, casts or caller-supplied normalization all refuse.
  if (source.split(manifestCall).length !== 2 || source.slice(start-manifestCall.length-1,start) !== manifestCall+"'" || source.slice(end,end+2) !== "')") throw Error('manifest literal site changed');
  return {identity: entry.identity, definition: source.slice(0,start)+selfToken+source.slice(end), manifestLiteral: source.slice(start,end)};
}

const privateRegistration = '["private-registration","zasp_authorization80_ordered_current.registration"]';
export function validateOrderedManifestFacts(facts) {
  try {
    const rows = normalizeOrderedFacts(facts), reserved = rows.filter(r => r.kind === 'build');
    if (reserved.length !== 1 || reserved[0].identity !== 'provenance') return false;
    const p = reserved[0].fact;
    if (Object.keys(p).sort().join(',') !== Object.keys(provenanceTypes).sort().join(',') || Object.values(p).some(v => v === null) || p.format_version !== 1 || p.purpose !== 'development-only') return false;
    for (const field of ['profile_checksum','compiled_source_sha256','contract_sha256','reference_file_sha256','generator_sha256']) if (!hexSHA(p[field])) return false;
    if (!p.postgres || !p.pgcrypto || !p.module_sha256.length || p.module_sha256.some(v => !/^[^=\n]+=[a-f0-9]{64}$/.test(v))) return false;
    const identities = new Set();
    for (const encoded of p.entry_spans) {
      const span = JSON.parse(encoded);
      if (!plainObject(span) || Object.keys(span).sort().join(',') !== 'end,identity,start' || typeof span.identity !== 'string' || !span.identity || identities.has(span.identity) || !Number.isSafeInteger(span.start) || span.start < 1 || span.end !== span.start+64) return false;
      identities.add(span.identity);
    }
    return true;
  } catch { return false; }
}
function provenanceRow(release,entries) {
  return {kind:'build',identity:'provenance',fact:{format_version:1,purpose:release.purpose,profile_checksum:release.profileChecksum,
    compiled_source_sha256:release.compiledSourceSHA256,contract_sha256:release.contractSHA256,reference_file_sha256:release.referenceFileSHA256,
    generator_sha256:release.generatorSHA256,postgres:release.postgres,pgcrypto:release.pgcrypto,
    module_sha256:Object.entries(release.moduleSHA256).sort(([a],[b])=>byteOrder(a,b)).map(([name,pin])=>name+'='+pin),
    entry_spans:entries.map(e=>({identity:e.identity,...e.manifestSpan})).sort((a,b)=>byteOrder(a.identity,b.identity)).map(canonicalOrderedJSON)}};
}
function manifestPayload(release, facts, entries) {
  const normalized = normalizeOrderedFacts(facts);
  const names = new Set();
  for (const entry of entries) {
    if (names.has(entry.identity)) throw Error('duplicate compiler entry');
    names.add(entry.identity);
    const row = normalized.find(r => r.kind === 'routine' && r.identity === entry.identity);
    if (!row || row.fact.definition !== entry.definition) throw Error('compiler entry and expected definition differ');
    row.fact.definition = normalizeEntry(entry).definition;
  }
  for (const row of normalized) {
    if (row.kind === 'registration' && row.identity === privateRegistration) {
      if (!hexSHA(row.fact.manifest_sha256)) throw Error('invalid typed self-reference');
      // Only this typed field is omitted. Other registration bytes stay bound.
      delete row.fact.manifest_sha256;
    }
  }
  return normalized;
}
export function buildManifest(release) {
  if (!plainObject(release) || release.expectedFromTarget !== false) throw Error('target-derived expectations refused');
  // No release mode exists until independent fresh-build equivalence and the
  // complete original selector lowering have passed review and native checks.
  if (release.format !== 1 || release.purpose !== 'development-only') throw Error('release artifact not admitted');
  for (const field of ['profileChecksum','compiledSourceSHA256','contractSHA256','referenceFileSHA256','generatorSHA256']) if (!hexSHA(release[field])) throw Error('missing provenance: '+field);
  if (!plainObject(release.moduleSHA256) || !Object.keys(release.moduleSHA256).length || !Object.values(release.moduleSHA256).every(hexSHA) || typeof release.postgres !== 'string' || !release.postgres || typeof release.pgcrypto !== 'string' || !release.pgcrypto || !Array.isArray(release.entries)) throw Error('invalid build provenance');
  const facts = normalizeOrderedFacts(release.facts), entries = structuredClone(release.entries);
  const buildRow = provenanceRow(release,entries), existingBuild = facts.filter(r=>r.kind==='build');
  if (existingBuild.length) {
    if (existingBuild.length!==1 || canonicalOrderedJSON(existingBuild[0])!==canonicalOrderedJSON(buildRow)) throw Error('reserved provenance differs');
  } else facts.push(buildRow);
  if (!validateOrderedManifestFacts(facts)) throw Error('invalid reserved provenance');
  const payload = canonicalOrderedJSON(manifestPayload(release,facts,entries));
  const payloadSHA256 = sha(payload);
  for (const entry of entries) {
    const {start,end} = entry.manifestSpan;
    entry.definition = entry.definition.slice(0,start)+payloadSHA256+entry.definition.slice(end);
    facts.find(r => r.kind === 'routine' && r.identity === entry.identity).fact.definition = entry.definition;
  }
  for (const row of facts) if (row.kind === 'registration' && row.identity === privateRegistration) row.fact.manifest_sha256 = payloadSHA256;
  const second = canonicalOrderedJSON(manifestPayload(release,facts,entries));
  if (second !== payload) throw Error('manifest normalization did not reach fixed point');
  const artifact = {format: 1, installable: false, payloadSHA256, payload: JSON.parse(payload), entries, facts};
  const file = canonicalOrderedJSON(artifact)+'\n';
  return {...artifact,file,fileSHA256:sha(file)};
}

// Development model of the independent caller boundary. SQL and typed Go
// callers must compare their own pins before invoking catalog; this helper is
// not evidence of native SQL or product routing behavior.
export function admitOrderedCurrent(value) {
  try {
    const expected=value.expectedEvaluator;
    if(!plainObject(expected)||Object.keys(expected).sort().join(',')!=='acl,config,definition,identity,language,owner,parallel,security_definer,strict,volatility')return false;
    for(const field of ['identity','owner','language','parallel','volatility','definition'])if(typeof expected[field]!=='string'||!expected[field])return false;
    if(typeof expected.security_definer!=='boolean'||typeof expected.strict!=='boolean'||expected.config!==null&&(!Array.isArray(expected.config)||expected.config.some(x=>typeof x!=='string'))||expected.acl!==null&&typeof expected.acl!=='string'&&(!Array.isArray(expected.acl)||expected.acl.some(x=>typeof x!=='string')))return false;
    return hexSHA(value.compiledManifest) && value.expectedManifest === value.compiledManifest &&
      normalizeEntry(value.liveEntry).manifestLiteral === value.compiledManifest &&
      canonicalOrderedJSON(value.expectedEvaluator) === canonicalOrderedJSON(value.liveEvaluator) &&
      canonicalOrderedJSON(value.expectedEntry) === canonicalOrderedJSON(value.liveEntry);
  } catch { return false; }
}

export function admitCollectorSource(source) {
  const code = mask(source);
  if (/"[^"]+"\s*(?:\.\s*"[^"]+"\s*)?\(/.test(source)) throw Error('quoted collector call refused');
  if (/\b(?:execute|call|insert|update|delete|merge|create|alter|drop|grant|revoke|set|copy)\b/i.test(code)) throw Error('non-read-only collector statement');
  const allowed = new Set('jsonb_build_object jsonb_build_array jsonb_agg jsonb_array_elements jsonb_each jsonb_object_keys to_json to_jsonb count bool_and coalesce nullif array_agg string_agg unnest format_type pg_get_functiondef pg_get_function_identity_arguments pg_get_function_result pg_get_function_arguments pg_get_expr pg_get_constraintdef pg_get_indexdef pg_get_triggerdef pg_get_viewdef pg_get_ruledef aclexplode acldefault encode digest convert_to substring length octet_length starts_with regexp_replace btrim split_part chr shobj_description format current_database to_regprocedure replace'.split(' '));
  const syntax = new Set('and any array as by exists from in lateral not on or select values where filter over materialized then else'.split(' '));
  for (const token of inspectOrderedCallTokens(source)) {
    // This fixed column-alias declaration is not a callable edge. Do not admit
    // an args(...) call elsewhere, or a caller-selected alias column list.
    if(token.name==='args'&&code.slice(0,token.start).endsWith('pg_catalog.unnest(p.proargtypes) WITH ORDINALITY AS ')&&code.slice(token.start).startsWith('args(unnest, ordinality) ORDER BY args.ordinality)'))continue;
    const name = token.name.replace(/^pg_catalog\./,'');
    if (!allowed.has(name) && !syntax.has(name)) throw Error('unadmitted collector edge: '+token.name);
  }
  for (const relation of inspectOrderedSource(source).relations) if (!relation.name.startsWith('pg_catalog.pg_')&&!['information_schema.columns','pg_catalog.unnest','pg_catalog.aclexplode','zasp_authorization80.runtime_profile'].includes(relation.name)&&!orderedSavedFunctionTables.includes(relation.name)&&!staticRelations.includes(relation.name)) throw Error('unadmitted collector relation: '+relation.name);
  return true;
}

export function classifyOrderedAuth80Live(contract) {
  const primitiveIdentity='zasp_authorization80.fingerprint()';
  const primitive=contract.nodes.find(n=>n.identity===primitiveIdentity);
  if(!primitive || sha(primitive.source)!=='7dc72d5920409b1d7e82e81d4e4876c7f955e6506ef62199b4b0a5468687add8' || sha(primitive.definition)!=='43666a5377f268edd06cdb1e226e16d8f4897364ef79b96b78fc6d3240778edd' || primitive.owner!=='zasp_discovery_authority' || primitive.security_definer!==false || primitive.acl!=='{zasp_discovery_authority=X/zasp_discovery_authority}' || canonicalOrderedJSON(primitive.config)!=='["search_path=pg_catalog, public"]' || inspectOrderedSource(primitive.source).calls.length) throw Error('auth80 primitive body/frame changed');
  const expression="EXISTS(SELECT 1 FROM zasp_authorization80.registration WHERE checksum='d7fbda32a2b3b9ea0ffbd4f7c7a7967a9d4fba2f6573f49e8386e9586a18a1fd' AND fingerprint=zasp_authorization80.fingerprint())";
  const counts=new Map([['zasp_authorization80_temporal.catalog_ready()',1],['zasp_temporal68.predecessor_ready(text,text)',3],['zasp_temporal68.ready(text,text)',1],['zasp_temporal77.base67_fingerprint()',1],['zasp_temporal78.ready(text,text)',2]]);
  const sites=[];
  for(const n of contract.nodes) {
    const calls=inspectOrderedSource(n.source||'').calls.filter(c=>c.name==='zasp_authorization80.fingerprint');
    if(calls.length!==(counts.get(n.identity)||0))throw Error('auth80 primitive consumer count changed');
    const spans=[...(n.source||'').matchAll(new RegExp(expression.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'),'g'))];
    if(spans.length!==calls.length)throw Error('auth80 whole comparison changed');
    for(const match of spans)sites.push({identity:n.identity,start:match.index,end:match.index+expression.length,text:expression,sha256:sha(expression),
      owner:n.owner,acl:n.acl,config:n.config,security_definer:n.security_definer,
      disposition:'retain-exact-fresh-auth80-primitive-comparison-outside-direct-collector'});
  }
  if(sites.length!==8)throw Error('auth80 original comparison missing');
  return {primitive:{identity:primitiveIdentity,sourceSHA256:sha(primitive.source),definitionSHA256:sha(primitive.definition),owner:primitive.owner,acl:primitive.acl,config:primitive.config,security_definer:primitive.security_definer},sites,
    obligation:'Execute each complete original EXISTS comparison freshly in its original frame and position. Preserve surrounding registration cardinality and NULL semantics. Independently bind primitive body/frame. Do not compare its raw registration fingerprint or login-dependent policy/trigger facts to fixture constants.',
    scope:'This only partitions the auth80 primitive branches; it is not proof that every other selected owner/ACL/registration fact is portable.'};
}
