-- Dormant direct-integrity module template. Not part of composed80 assembly.
-- Installation is refused by the development artifact loader. Expected rows
-- must be embedded build literals; never populate them from the target catalog.
CREATE SCHEMA zasp_authorization80_ordered_current AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_authorization80_ordered_current FROM PUBLIC;

CREATE TABLE zasp_authorization80_ordered_current.registration(
 singleton boolean PRIMARY KEY CHECK(singleton),
 format_version integer NOT NULL CHECK(format_version=1),
 profile_checksum text NOT NULL CHECK(profile_checksum ~ '^[a-f0-9]{64}$'),
 manifest_sha256 text NOT NULL CHECK(manifest_sha256 ~ '^[a-f0-9]{64}$')
);
CREATE TABLE zasp_authorization80_ordered_current.expected(
 kind text NOT NULL,
 identity text NOT NULL,
 fact jsonb NOT NULL CHECK(jsonb_typeof(fact)='object'),
 PRIMARY KEY(kind,identity)
);
ALTER TABLE zasp_authorization80_ordered_current.registration OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_authorization80_ordered_current.expected OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_authorization80_ordered_current.registration ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_authorization80_ordered_current.expected ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON ALL TABLES IN SCHEMA zasp_authorization80_ordered_current FROM PUBLIC;

CREATE FUNCTION zasp_authorization80_ordered_current.canonical(value jsonb) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT SECURITY INVOKER SET search_path=pg_catalog AS $canonical$
DECLARE result text;
BEGIN
 CASE jsonb_typeof(value)
 WHEN 'object' THEN
  SELECT '{'||COALESCE(string_agg(to_jsonb(e.key)::text||':'||zasp_authorization80_ordered_current.canonical(e.value),',' ORDER BY e.key COLLATE "C"),'')||'}'
  INTO result FROM jsonb_each(value) e;
 WHEN 'array' THEN
  SELECT '['||COALESCE(string_agg(zasp_authorization80_ordered_current.canonical(e.value),',' ORDER BY e.ordinality),'')||']'
  INTO result FROM jsonb_array_elements(value) WITH ORDINALITY e;
 WHEN 'number' THEN result:=trim_scale((value#>>'{}')::numeric)::text;
 ELSE result:=value::text;
 END CASE;
 RETURN result;
END
$canonical$;

CREATE FUNCTION zasp_authorization80_ordered_current.normalize_rows(rows jsonb, expected_manifest text) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE STRICT SECURITY INVOKER SET search_path=pg_catalog AS $normalize$
DECLARE provenance jsonb; span jsonb;
 result jsonb; body text; start_at integer; end_at integer;
 call_prefix constant text:='zasp_authorization80_ordered_current.require(';
BEGIN
 IF jsonb_typeof(rows)<>'array' OR expected_manifest !~ '^[a-f0-9]{64}$' THEN RETURN NULL; END IF;
 IF (SELECT count(*) FROM jsonb_array_elements(rows) r WHERE r->>'kind'='build')<>1 THEN RETURN NULL; END IF;
 SELECT r->'fact' INTO provenance FROM jsonb_array_elements(rows) r WHERE r->>'kind'='build' AND r->>'identity'='provenance';
 IF provenance IS NULL OR (SELECT array_agg(key ORDER BY key COLLATE "C") FROM jsonb_object_keys(provenance) key)
  IS DISTINCT FROM ARRAY['compiled_source_sha256','contract_sha256','entry_spans','format_version','generator_sha256','module_sha256','pgcrypto','postgres','profile_checksum','purpose','reference_file_sha256']::text[]
  OR provenance->>'format_version'<>'1' OR provenance->>'purpose'<>'development-only'
  OR jsonb_typeof(provenance->'entry_spans')<>'array' OR jsonb_typeof(provenance->'module_sha256')<>'array'
  OR jsonb_array_length(provenance->'module_sha256')=0 THEN RETURN NULL; END IF;
 IF EXISTS(SELECT 1 FROM jsonb_each(provenance) p WHERE p.value='null'::jsonb)
  OR EXISTS(SELECT 1 FROM unnest(ARRAY['compiled_source_sha256','contract_sha256','generator_sha256','profile_checksum','reference_file_sha256']) k WHERE provenance->>k !~ '^[a-f0-9]{64}$') THEN RETURN NULL; END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(rows) r GROUP BY r->>'kind',r->>'identity' HAVING count(*)<>1) THEN RETURN NULL; END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(rows) r WHERE jsonb_typeof(r)<>'object'
  OR (SELECT array_agg(key ORDER BY key COLLATE "C") FROM jsonb_object_keys(r) key) IS DISTINCT FROM ARRAY['fact','identity','kind']::text[]
  OR jsonb_typeof(r->'fact') IS DISTINCT FROM 'object' OR jsonb_typeof(r->'identity') IS DISTINCT FROM 'string' OR jsonb_typeof(r->'kind') IS DISTINCT FROM 'string') THEN RETURN NULL; END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(rows) r WHERE r->>'kind'='registration' AND r->>'identity'='["private-registration","zasp_authorization80_ordered_current.registration"]'
  AND r->'fact'->>'manifest_sha256' IS DISTINCT FROM expected_manifest) THEN RETURN NULL; END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements_text(provenance->'entry_spans') e GROUP BY (e::jsonb)->>'identity' HAVING count(*)<>1) THEN RETURN NULL; END IF;
 -- Only the finite entry-span list needs procedural validation. Ordinary fact
 -- rows are transformed together below, without recopying a growing JSON array.
 FOR span IN SELECT e::jsonb FROM jsonb_array_elements_text(provenance->'entry_spans') e LOOP
    SELECT r->'fact'->>'definition' INTO body FROM jsonb_array_elements(rows) r WHERE r->>'kind'='routine' AND r->>'identity'=span->>'identity';
    start_at:=(span->>'start')::integer; end_at:=(span->>'end')::integer;
    IF body IS NULL OR octet_length(body)<>length(body) OR start_at<1 OR end_at<>start_at+64
     OR substring(body FROM start_at+1 FOR 64) IS DISTINCT FROM expected_manifest
     OR substring(body FROM start_at-length(call_prefix) FOR length(call_prefix)+1) IS DISTINCT FROM call_prefix||''''
     OR substring(body FROM end_at+1 FOR 2) IS DISTINCT FROM ''')'
     OR length(body)-length(replace(body,call_prefix,''))<>length(call_prefix) THEN RETURN NULL; END IF;
 END LOOP;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('kind',r->>'kind','identity',r->>'identity','fact',
  CASE WHEN r->>'kind'='registration' AND r->>'identity'='["private-registration","zasp_authorization80_ordered_current.registration"]' THEN (r->'fact')-'manifest_sha256'
   WHEN s.value IS NOT NULL THEN jsonb_set(r->'fact','{definition}',to_jsonb(substring(r->'fact'->>'definition' FROM 1 FOR (s.value->>'start')::integer)||'@ordered-current-manifest@'||substring(r->'fact'->>'definition' FROM (s.value->>'end')::integer+1)))
   ELSE r->'fact' END) ORDER BY r->>'kind' COLLATE "C",r->>'identity' COLLATE "C"),'[]'::jsonb)
 INTO result FROM jsonb_array_elements(rows) r LEFT JOIN LATERAL
  (SELECT e::jsonb AS value FROM jsonb_array_elements_text(provenance->'entry_spans') e WHERE r->>'kind'='routine' AND (e::jsonb)->>'identity'=r->>'identity') s ON true;
 RETURN result;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN NULL;
END
$normalize$;

CREATE FUNCTION zasp_authorization80_ordered_current.catalog(expected_manifest text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $catalog$
DECLARE expected_rows jsonb; normalized jsonb; live_rows jsonb; provenance jsonb;
BEGIN
 IF current_user<>'zasp_discovery_authority' OR expected_manifest IS NULL OR expected_manifest !~ '^[a-f0-9]{64}$' THEN RETURN false; END IF;
 IF (SELECT count(*) FROM zasp_authorization80_ordered_current.registration)<>1 THEN RETURN false; END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_ordered_current.registration WHERE singleton AND format_version=1 AND manifest_sha256=expected_manifest) THEN RETURN false; END IF;
 SELECT jsonb_agg(jsonb_build_object('kind',kind,'identity',identity,'fact',fact) ORDER BY kind COLLATE "C",identity COLLATE "C")
 INTO expected_rows FROM zasp_authorization80_ordered_current.expected;
 normalized:=zasp_authorization80_ordered_current.normalize_rows(expected_rows,expected_manifest);
 IF normalized IS NULL OR encode(pg_catalog.sha256(convert_to(zasp_authorization80_ordered_current.canonical(normalized),'UTF8')),'hex') IS DISTINCT FROM expected_manifest THEN RETURN false; END IF;
 SELECT fact INTO provenance FROM zasp_authorization80_ordered_current.expected WHERE kind='build' AND identity='provenance';
 IF provenance->>'postgres' IS DISTINCT FROM pg_catalog.version() THEN RETURN false; END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_ordered_current.registration WHERE profile_checksum=provenance->>'profile_checksum') THEN RETURN false; END IF;
 -- A partial development manifest cannot admit an evaluator without its own
 -- immutable private closure. Complete reference emission must supply these.
 IF EXISTS(SELECT 1 FROM unnest(ARRAY[
  'zasp_authorization80_ordered_current.canonical(jsonb)',
  'zasp_authorization80_ordered_current.normalize_rows(jsonb,text)',
  'zasp_authorization80_ordered_current.catalog(text)',
  'zasp_authorization80_ordered_current.require(text)']) signature
  WHERE NOT EXISTS(SELECT 1 FROM zasp_authorization80_ordered_current.expected WHERE kind='routine' AND identity='["private-routines",'||to_json(signature)::text||']' AND fact ?& ARRAY['source','binary','sql_body','kind','owner','acl','language','security_definer','volatility','strict','parallel','leakproof','config','returns_set','cost','rows','input_types','all_types','argument_names','argument_modes','argument_defaults','default_count','variadic_type','result_type','support','transforms'])) THEN RETURN false; END IF;
 WITH live AS MATERIALIZED (
  -- ordered-current:direct-collector-begin
  SELECT NULL::text AS kind,NULL::text AS identity,NULL::jsonb AS fact WHERE false
  -- ordered-current:direct-collector-end
 ) SELECT COALESCE(jsonb_agg(jsonb_build_object('kind',kind,'identity',identity,'fact',fact) ORDER BY kind COLLATE "C",identity COLLATE "C"),'[]'::jsonb)
 INTO live_rows FROM live;
 -- Exactly the validated reserved key joins live facts for normalization.
 live_rows:=live_rows||jsonb_build_array(jsonb_build_object('kind','build','identity','provenance','fact',provenance));
 live_rows:=zasp_authorization80_ordered_current.normalize_rows(live_rows,expected_manifest);
 RETURN live_rows IS NOT NULL AND live_rows=normalized;
END
$catalog$;

CREATE FUNCTION zasp_authorization80_ordered_current.require(expected_manifest text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $require$
BEGIN
 IF zasp_authorization80_ordered_current.catalog(expected_manifest) IS DISTINCT FROM true THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered current integrity refused';
 END IF;
END
$require$;

ALTER FUNCTION zasp_authorization80_ordered_current.canonical(jsonb) OWNER TO zasp_discovery_authority;
ALTER FUNCTION zasp_authorization80_ordered_current.normalize_rows(jsonb,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION zasp_authorization80_ordered_current.catalog(text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION zasp_authorization80_ordered_current.require(text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA zasp_authorization80_ordered_current FROM PUBLIC;
-- Default ACLs may have granted a non-PUBLIC role access at creation. Strip
-- those grants only from the just-created private objects; leave defaults and
-- every original schema untouched. Independent admission still verifies ACLs.
DO $private_acl$
DECLARE target record;
BEGIN
 FOR target IN
  SELECT DISTINCT objects.object_kind,objects.identity,grants.grantee::regrole::text AS grantee
  FROM (
   SELECT 'SCHEMA'::text AS object_kind,pg_catalog.quote_ident(n.nspname) AS identity,n.nspowner AS owner,n.nspacl AS acl
   FROM pg_catalog.pg_namespace n WHERE n.nspname='zasp_authorization80_ordered_current'
   UNION ALL
   SELECT 'TABLE',pg_catalog.format('%I.%I',n.nspname,c.relname),c.relowner,c.relacl
   FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='zasp_authorization80_ordered_current' AND c.relkind='r'
   UNION ALL
   SELECT 'FUNCTION',pg_catalog.format('%I.%I(%s)',n.nspname,p.proname,pg_catalog.pg_get_function_identity_arguments(p.oid)),p.proowner,p.proacl
   FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
   WHERE n.nspname='zasp_authorization80_ordered_current'
  ) objects CROSS JOIN LATERAL pg_catalog.aclexplode(objects.acl) grants
  WHERE grants.grantee<>0 AND grants.grantee<>owner
 LOOP
  EXECUTE pg_catalog.format('REVOKE ALL ON %s %s FROM %s',target.object_kind,target.identity,target.grantee);
 END LOOP;
END
$private_acl$;
-- ordered-current:embedded-expectations
