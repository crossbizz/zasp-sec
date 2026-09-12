DO $guard$
BEGIN
 IF NOT COALESCE(public.zasp_production_runtime_correlation_routing_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=49),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_correlation_routing_fingerprint')),false) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sandbox prerequisite rejected';
 END IF;
END
$guard$;

-- Null is historical evidence that wasn't retained, never observed absence.
-- Old observations and exact snapshot-v1 bytes are not rewritten or backfilled.
ALTER TABLE public.zasp_runtime_candidate_observations ADD COLUMN sandbox_id text
 CHECK(sandbox_id IS NULL OR (octet_length(sandbox_id) BETWEEN 1 AND 256
  AND sandbox_id=btrim(sandbox_id,U&'\0009\000A\000B\000C\000D\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000')
  AND sandbox_id !~ E'[\\r\\n]'));

-- PostgreSQL never reuses a dropped column's physical attribute number. Pin
-- the new column's live ordinal so a guarded rollback/reinstall has the same
-- semantic identity. Preserve physical ordinals for every predecessor column.
DO $ordinal$
DECLARE definition text;needle text:='a.attname,a.attnum,format_type';
BEGIN
 SELECT pg_get_functiondef('public.zasp_production_runtime_candidate_authority_live_fingerprint()'::regprocedure) INTO STRICT definition;
 IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sandbox ordinal predecessor rejected';END IF;
 EXECUTE replace(definition,needle,'a.attname,CASE WHEN a.attrelid=''public.zasp_runtime_candidate_observations''::regclass AND a.attname=''sandbox_id'' THEN (SELECT count(*) FROM pg_attribute live WHERE live.attrelid=a.attrelid AND live.attnum>0 AND live.attnum<=a.attnum AND NOT live.attisdropped) ELSE a.attnum END,format_type');
END
$ordinal$;

-- Old event rows remain unknown. The released v1 finisher's rowtype inserts
-- nulls in these fields; its exact replay comparison also checks the new fields.
ALTER TABLE public.zasp_runtime_session_events ADD COLUMN sandbox_id text,
 ADD COLUMN sandbox_source_sensor_id text,
 ADD CONSTRAINT zasp_runtime_session_sandbox_binding_check CHECK(
 (sandbox_id IS NULL AND sandbox_source_sensor_id IS NULL) OR
 (sandbox_id IS NOT NULL AND sandbox_source_sensor_id IS NOT NULL
  AND confidence IN('exact','strong') AND zasp_valid_product_id(sandbox_source_sensor_id)
  AND octet_length(sandbox_id) BETWEEN 1 AND 256
  AND sandbox_id=btrim(sandbox_id,U&'\0009\000A\000B\000C\000D\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000')
  AND sandbox_id !~ E'[\\r\\n]'));

DO $completion$
DECLARE definition text;needle text;replacement text;expected integer;
 readiness text:='IF NOT COALESCE(zasp_production_runtime_sandbox_binding_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=50),(SELECT value FROM zasp_schema_metadata WHERE key=''production_runtime_sandbox_binding_fingerprint'')),false) THEN RAISE EXCEPTION USING ERRCODE=''55000'',MESSAGE=''runtime sandbox authority unavailable'';END IF;';
 binding text:=$binding$
  IF (item ? 'sandbox_id')<>(item ? 'sandbox_source_sensor_id')
  OR item ? 'sandbox_id' AND (jsonb_typeof(item->'sandbox_id') IS DISTINCT FROM 'string' OR jsonb_typeof(item->'sandbox_source_sensor_id') IS DISTINCT FROM 'string')
  OR item->>'confidence'='exact' AND NOT (item ? 'sandbox_id')
  OR event_value.agent_id IS NOT NULL AND event_value.agent_id=event_value.session_id
  THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime session sandbox shape rejected';END IF;
  event_value.sandbox_id:=item->>'sandbox_id';event_value.sandbox_source_sensor_id:=item->>'sandbox_source_sensor_id';
 $binding$;
BEGIN
 SELECT pg_get_functiondef('public.zasp_runtime_finish_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)'::regprocedure) INTO STRICT definition;
 FOR needle,replacement,expected IN SELECT * FROM (VALUES
  ('FUNCTION public.zasp_runtime_finish_session_projection(', 'FUNCTION public.zasp_runtime_finish_sandbox_session_projection(', 1),
  ('BEGIN'||chr(10)||' IF num_nulls', 'BEGIN'||chr(10)||' '||readiness||chr(10)||' IF num_nulls', 1),
  ('implementation_value=''runtime-complete-v1''', 'implementation_value=''runtime-complete-v2''', 1),
  ('predecessor.state<>''succeeded''', 'predecessor.state<>''succeeded'' OR predecessor.implementation_version<>''runtime-projection-v2''', 1),
  ('IF NOT FOUND OR complete_row.predecessor_digest', 'IF NOT FOUND OR complete_row.implementation_version<>''runtime-complete-v2'' OR complete_row.predecessor_digest', 1),
  ('''runtime-projection-receipt-v1''', '''runtime-projection-receipt-v2''', 1),
  ('''runtime-projection-v1''', '''runtime-projection-v2''', 1),
  (' result_value:=zasp_runtime_finish_stage_v39(', ' '||readiness||chr(10)||' result_value:=zasp_runtime_finish_stage_v39(', 1),
  ('  IF event_value.event_id=ANY(ids)', binding||chr(10)||'  IF event_value.event_id=ANY(ids)', 1),
  (' RETURN result_value;', ' '||readiness||chr(10)||' RETURN result_value;', 1)
 ) AS changes(needle,replacement,expected) LOOP
  IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>expected THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sandbox completion predecessor rejected';END IF;
  definition:=replace(definition,needle,replacement);
 END LOOP;
 EXECUTE definition;
END
$completion$;
ALTER FUNCTION public.zasp_runtime_finish_sandbox_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_finish_sandbox_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_finish_sandbox_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea) TO zasp_runtime_coordinator;

-- New readers opt in without changing the released page/detail representation.
-- Keep the exact authorization, keyset pagination and evidence scoping from
-- those verified functions. Unknown/history bindings are omitted as a pair.
DO $reads$
DECLARE definition text; signature text; needle text; replacement text;
 readiness text:='IF NOT COALESCE(zasp_production_runtime_sandbox_binding_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=50),(SELECT value FROM zasp_schema_metadata WHERE key=''production_runtime_sandbox_binding_fingerprint'')),false) THEN RAISE EXCEPTION USING ERRCODE=''55000'',MESSAGE=''runtime sandbox authority unavailable'';END IF;';
BEGIN
 FOREACH signature IN ARRAY ARRAY['public.zasp_runtime_session_event_page(text,text,text,text,text,timestamptz,text,integer)','public.zasp_runtime_session_event_get(text,text,text,text,text,text)'] LOOP
  SELECT pg_get_functiondef(signature::regprocedure) INTO STRICT definition;
  FOR needle,replacement IN SELECT * FROM (VALUES
   ('FUNCTION public.zasp_runtime_session_event_', 'FUNCTION public.zasp_runtime_sandbox_session_event_'),
   (E'BEGIN\n', E'BEGIN\n '||readiness||E'\n'),
   ('''projected_at'',projected_at)', '''projected_at'',projected_at)||jsonb_strip_nulls(jsonb_build_object(''sandbox_id'',sandbox_id,''sandbox_source_sensor_id'',sandbox_source_sensor_id))')
  ) replacements(needle,replacement) LOOP
   IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sandbox read predecessor rejected';END IF;
   definition:=replace(definition,needle,replacement);
  END LOOP;
  EXECUTE definition;
 END LOOP;
END
$reads$;
ALTER FUNCTION public.zasp_runtime_sandbox_session_event_page(text,text,text,text,text,timestamptz,text,integer) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_sandbox_session_event_get(text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_sandbox_session_event_page(text,text,text,text,text,timestamptz,text,integer),public.zasp_runtime_sandbox_session_event_get(text,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_sandbox_session_event_page(text,text,text,text,text,timestamptz,text,integer),public.zasp_runtime_sandbox_session_event_get(text,text,text,text,text,text) TO zasp_discovery_api;

-- Derive a new closed function from the verified predecessor. Keep the released
-- function itself unchanged so old-v2 backlog still freezes snapshot-v1 bytes.
DO $freeze$
DECLARE definition text;needle text;replacement text;expected integer;
 readiness text:='IF NOT COALESCE(zasp_production_runtime_sandbox_binding_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=50),(SELECT value FROM zasp_schema_metadata WHERE key=''production_runtime_sandbox_binding_fingerprint'')),false) THEN RAISE EXCEPTION USING ERRCODE=''55000'',MESSAGE=''runtime sandbox authority unavailable'';END IF;';
BEGIN
 SELECT pg_get_functiondef('public.zasp_runtime_freeze_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea)'::regprocedure) INTO STRICT definition;
 FOR needle,replacement,expected IN SELECT * FROM (VALUES
  ('BEGIN'||chr(10)||' IF NOT COALESCE(zasp_runtime_principal_ready', 'BEGIN'||chr(10)||' '||readiness||chr(10)||' IF NOT COALESCE(zasp_runtime_principal_ready', 1),
  ('RETURN jsonb_build_object(''snapshot''', readiness||chr(10)||' RETURN jsonb_build_object(''snapshot''', 2),
  ('FUNCTION public.zasp_runtime_freeze_candidates(', 'FUNCTION public.zasp_runtime_freeze_sandbox_candidates(', 1),
  ('implementation_value=''runtime-correlation-v2''', 'implementation_value=''runtime-correlation-v3''', 1),
  ('pod_uid,container_id)', 'pod_uid,container_id,sandbox_id)', 1),
  ('event_value#>>''{observed_lineage,container_id}'');', 'event_value#>>''{observed_lineage,container_id}'',event_value#>>''{attributes,sandbox.id}'');', 1),
  ('''session_id'',session_id,''archive_digest''', '''session_id'',session_id,''sandbox_id'',sandbox_id,''archive_digest''', 1),
  ('''schema'',''runtime-candidate-snapshot-v1''', '''schema'',''runtime-candidate-snapshot-v2''', 1),
  ('IF FOUND THEN', 'IF FOUND THEN
  IF convert_from(prior.snapshot_body,''UTF8'')::jsonb->>''schema'' IS DISTINCT FROM ''runtime-candidate-snapshot-v2'' THEN RAISE EXCEPTION USING ERRCODE=''23505'',MESSAGE=''runtime sandbox replay version conflict'';END IF;', 1),
  ('IF domain_row.source_kind=''otlp'' AND domain_row.runtime_sensor_id IS NOT NULL AND event_value ? ''observed_lineage'' THEN', 'IF domain_row.source_kind=''otlp'' AND domain_row.runtime_sensor_id IS NOT NULL AND event_value ? ''observed_lineage'' THEN
   IF jsonb_typeof(event_value#>''{attributes,sandbox.id}'') IS DISTINCT FROM ''string'' OR COALESCE(octet_length(event_value#>>''{attributes,sandbox.id}''),0) NOT BETWEEN 1 AND 256 THEN RAISE EXCEPTION USING ERRCODE=''22023'',MESSAGE=''runtime sandbox identity rejected'';END IF;', 1)
 ) AS changes(needle,replacement,expected) LOOP
  IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>expected THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sandbox freeze predecessor rejected';
  END IF;
  definition:=replace(definition,needle,replacement);
 END LOOP;
 EXECUTE definition;
END
$freeze$;
ALTER FUNCTION public.zasp_runtime_freeze_sandbox_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_freeze_sandbox_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_freeze_sandbox_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea) TO zasp_runtime_correlation_worker;

-- Correlation selection remains v1 or v1/v2. The new helper keeps the same
-- stage lock, fairness and exhaustion
-- logic, but declares the v3 compatibility marker for its mutations.
DO $claims$
DECLARE definition text;needle text;replacement text;expected integer;
BEGIN
 SELECT pg_get_functiondef('public.zasp_runtime_claim_stage_compatible(text,text,integer,integer,boolean)'::regprocedure) INTO STRICT definition;
 FOR needle,replacement,expected IN SELECT * FROM (VALUES
  ('FUNCTION public.zasp_runtime_claim_stage_compatible(', 'FUNCTION public.zasp_runtime_claim_stage_sandbox_compatible(', 1),
  ('stage_row.implementation_version=''runtime-correlation-v2''', 'stage_row.implementation_version IN(''runtime-correlation-v2'',''runtime-correlation-v3'')', 2),
  ('CASE WHEN allow_v2 THEN ''runtime-correlation-v2''', 'CASE WHEN allow_v2 THEN ''runtime-correlation-v3''', 1)
 ) AS changes(needle,replacement,expected) LOOP
  IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>expected THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sandbox claim predecessor rejected';END IF;
  definition:=replace(definition,needle,replacement);
 END LOOP;
 definition:=replace(definition,'allow_v2','allow_v3');
 EXECUTE definition;
END
$claims$;
ALTER FUNCTION public.zasp_runtime_claim_stage_sandbox_compatible(text,text,integer,integer,boolean) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_claim_stage_sandbox_compatible(text,text,integer,integer,boolean) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.zasp_runtime_correlation_claim_version_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $guard$
BEGIN
 IF NEW.stage='correlate' AND NEW.implementation_version<>'runtime-correlation-v1'
 AND (NEW.attempt>OLD.attempt OR (NEW.state='failed' AND NEW.last_error_class='exhausted' AND (OLD.state IN('pending','retryable') OR OLD.state='leased' AND OLD.lease_expires_at<=transaction_timestamp())))
 AND NOT COALESCE((NEW.implementation_version='runtime-correlation-v2' AND current_setting('zasp.runtime_correlation_claim_version',true) IN('runtime-correlation-v2','runtime-correlation-v3') OR NEW.implementation_version='runtime-correlation-v3' AND current_setting('zasp.runtime_correlation_claim_version',true)='runtime-correlation-v3') AND zasp_runtime_stage_for_session()='correlate' AND zasp_runtime_principal_ready('zasp_runtime_correlation_worker'),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime correlation claim version rejected';END IF;
 RETURN NEW;
END
$guard$;

CREATE FUNCTION public.zasp_runtime_claim_correlation_v3(worker_value text,lease_token_value text,lease_seconds integer,claim_limit integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $claim$
BEGIN
 IF zasp_runtime_stage_for_session() IS DISTINCT FROM 'correlate' OR NOT COALESCE(zasp_runtime_principal_ready('zasp_runtime_correlation_worker'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime sandbox principal rejected';END IF;
 IF NOT COALESCE(zasp_production_runtime_sandbox_binding_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=50),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_sandbox_binding_fingerprint')),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sandbox authority unavailable';END IF;
 RETURN zasp_runtime_claim_stage_sandbox_compatible(worker_value,lease_token_value,lease_seconds,claim_limit,true);
END
$claim$;
ALTER FUNCTION public.zasp_runtime_claim_correlation_v3(text,text,integer,integer) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_claim_correlation_v3(text,text,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_claim_correlation_v3(text,text,integer,integer) TO zasp_runtime_correlation_worker;

-- Projection/completion workers declare their own reader capability. Preserve
-- the verified delivery, fairness and predecessor algorithm in both paths.
DO $session_claims$
DECLARE definition text;legacy text;needle text;replacement text;expected integer;
 readiness text:='IF NOT COALESCE(zasp_production_runtime_sandbox_binding_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=50),(SELECT value FROM zasp_schema_metadata WHERE key=''production_runtime_sandbox_binding_fingerprint'')),false) THEN RAISE EXCEPTION USING ERRCODE=''55000'',MESSAGE=''runtime sandbox authority unavailable'';END IF;';
BEGIN
 SELECT pg_get_functiondef('public.zasp_runtime_claim_stage_compatible(text,text,integer,integer,boolean)'::regprocedure) INTO STRICT definition;
 legacy:=definition;
 FOR needle,replacement,expected IN SELECT * FROM (VALUES
  ('FUNCTION public.zasp_runtime_claim_stage_compatible(', 'FUNCTION public.zasp_runtime_claim_session_stage_compatible(', 1),
  ('(stage_value<>''correlate'' OR stage_row.implementation_version=''runtime-correlation-v1'' OR allow_v2 AND stage_row.implementation_version=''runtime-correlation-v2'')', '(stage_value=''project'' AND (stage_row.implementation_version=''runtime-projection-v1'' OR allow_v2 AND stage_row.implementation_version=''runtime-projection-v2'') OR stage_value=''complete'' AND (stage_row.implementation_version=''runtime-complete-v1'' OR allow_v2 AND stage_row.implementation_version=''runtime-complete-v2''))', 2),
  ('(allow_v2 AND stage_value<>''correlate'')', '(stage_value NOT IN(''project'',''complete''))', 1),
  ('zasp.runtime_correlation_claim_version', 'zasp.runtime_session_claim_version', 3),
  ('CASE WHEN allow_v2 THEN ''runtime-correlation-v2'' ELSE ''runtime-correlation-v1'' END', 'CASE WHEN stage_value=''project'' THEN CASE WHEN allow_v2 THEN ''runtime-projection-v2'' ELSE ''runtime-projection-v1'' END ELSE CASE WHEN allow_v2 THEN ''runtime-complete-v2'' ELSE ''runtime-complete-v1'' END END', 1),
  (' WITH exhausted AS (', ' '||readiness||E'\n WITH exhausted AS (', 1),
  (' RETURN result_value;', ' '||readiness||E'\n RETURN result_value;', 1)
 ) changes(needle,replacement,expected) LOOP
  IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>expected THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime session claim predecessor rejected';END IF;
  definition:=replace(definition,needle,replacement);
 END LOOP;
 EXECUTE definition;
 -- The old helper still serves archive/index/correlation. Restrict both its
 -- exhaustion update and eligible selection for the two newly versioned stages.
 needle:='WHERE stage_row.stage=stage_value AND';
 IF (length(legacy)-length(replace(legacy,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime legacy session filter rejected';END IF;
 EXECUTE replace(legacy,needle,'WHERE stage_row.stage=stage_value AND (stage_value NOT IN(''project'',''complete'') OR stage_value=''project'' AND stage_row.implementation_version=''runtime-projection-v1'' OR stage_value=''complete'' AND stage_row.implementation_version=''runtime-complete-v1'') AND');
END
$session_claims$;
ALTER FUNCTION public.zasp_runtime_claim_session_stage_compatible(text,text,integer,integer,boolean) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_claim_session_stage_compatible(text,text,integer,integer,boolean) FROM PUBLIC;

-- Fence bodies already waiting at their advisory lock before CREATE OR REPLACE.
-- This is a compatibility marker, not a replacement for registered authority.
CREATE FUNCTION public.zasp_runtime_session_claim_version_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $guard$
BEGIN
 IF NEW.stage IN('project','complete') AND NEW.implementation_version IS DISTINCT FROM (CASE NEW.stage WHEN 'project' THEN 'runtime-projection-v1' ELSE 'runtime-complete-v1' END)
 AND (NEW.attempt>OLD.attempt OR (NEW.state='failed' AND NEW.last_error_class='exhausted' AND (OLD.state IN('pending','retryable') OR OLD.state='leased' AND OLD.lease_expires_at<=transaction_timestamp())))
 AND NOT COALESCE(NEW.implementation_version=CASE NEW.stage WHEN 'project' THEN 'runtime-projection-v2' ELSE 'runtime-complete-v2' END AND current_setting('zasp.runtime_session_claim_version',true)=NEW.implementation_version AND zasp_runtime_stage_for_session()=NEW.stage AND zasp_runtime_principal_ready(CASE NEW.stage WHEN 'project' THEN 'zasp_runtime_projection_worker' ELSE 'zasp_runtime_coordinator' END),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime session claim version rejected';END IF;
 RETURN NEW;
END
$guard$;
ALTER FUNCTION public.zasp_runtime_session_claim_version_guard() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_session_claim_version_guard() FROM PUBLIC;
CREATE TRIGGER zasp_runtime_session_claim_version BEFORE UPDATE ON public.zasp_runtime_stage_work FOR EACH ROW EXECUTE FUNCTION public.zasp_runtime_session_claim_version_guard();

CREATE FUNCTION public.zasp_runtime_claim_projection_v2(worker_value text,lease_token_value text,lease_seconds integer,claim_limit integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $claim$
BEGIN
 IF zasp_runtime_stage_for_session() IS DISTINCT FROM 'project' OR NOT COALESCE(zasp_runtime_principal_ready('zasp_runtime_projection_worker'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime sandbox principal rejected';END IF;
 IF NOT COALESCE(zasp_production_runtime_sandbox_binding_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=50),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_sandbox_binding_fingerprint')),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sandbox authority unavailable';END IF;
 RETURN zasp_runtime_claim_session_stage_compatible(worker_value,lease_token_value,lease_seconds,claim_limit,true);
END
$claim$;
CREATE FUNCTION public.zasp_runtime_claim_completion_v2(worker_value text,lease_token_value text,lease_seconds integer,claim_limit integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $claim$
BEGIN
 IF zasp_runtime_stage_for_session() IS DISTINCT FROM 'complete' OR NOT COALESCE(zasp_runtime_principal_ready('zasp_runtime_coordinator'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime sandbox principal rejected';END IF;
 IF NOT COALESCE(zasp_production_runtime_sandbox_binding_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=50),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_sandbox_binding_fingerprint')),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sandbox authority unavailable';END IF;
 RETURN zasp_runtime_claim_session_stage_compatible(worker_value,lease_token_value,lease_seconds,claim_limit,true);
END
$claim$;
ALTER FUNCTION public.zasp_runtime_claim_projection_v2(text,text,integer,integer) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_claim_completion_v2(text,text,integer,integer) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_claim_projection_v2(text,text,integer,integer),public.zasp_runtime_claim_completion_v2(text,text,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_claim_projection_v2(text,text,integer,integer) TO zasp_runtime_projection_worker;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_claim_completion_v2(text,text,integer,integer) TO zasp_runtime_coordinator;

DO $compatibility$
DECLARE definition text;prior text;function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 49','later_release."version" > 50'),'later."version">49','later."version">50'),'later."version" > 49','later."version" > 50');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sandbox compatibility rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;

-- Separate fixed-v2 progress. Canonical receipt authority, never v1 checkpoint state.
CREATE TABLE public.zasp_runtime_sandbox_search_outbox (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,batch_id text NOT NULL,batch_generation bigint NOT NULL,
 receipt_digest bytea NOT NULL CHECK(octet_length(receipt_digest)=32),
 receipt_reference text NOT NULL CHECK(length(receipt_reference) BETWEEN 1 AND 2048),
 receipt_version text NOT NULL CHECK(length(receipt_version) BETWEEN 1 AND 1024),
 document_ids text[] NOT NULL CHECK(cardinality(document_ids) BETWEEN 1 AND 1000),
 state text NOT NULL DEFAULT 'pending' CHECK(state IN('pending','leased','indexed','quarantined')),
 attempt integer NOT NULL DEFAULT 0 CHECK(attempt BETWEEN 0 AND 100),
 worker_id text,lease_digest bytea CHECK(lease_digest IS NULL OR octet_length(lease_digest)=32),lease_until timestamptz,
 next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),indexed_at timestamptz,
 PRIMARY KEY(organization_id,workspace_id,environment_id,batch_id,batch_generation),
 FOREIGN KEY(organization_id,workspace_id,environment_id,batch_id,batch_generation) REFERENCES public.zasp_runtime_session_projection_receipts(organization_id,workspace_id,environment_id,batch_id,batch_generation),
 CHECK((state IN('leased','indexed'))=(worker_id IS NOT NULL AND lease_digest IS NOT NULL)),
 CHECK((worker_id IS NULL)=(lease_digest IS NULL)),
 CHECK((state='leased')=(lease_until IS NOT NULL)),
 CHECK((state='indexed')=(indexed_at IS NOT NULL)),
 CHECK(isfinite(next_attempt_at) AND isfinite(created_at) AND (lease_until IS NULL OR isfinite(lease_until)) AND (indexed_at IS NULL OR isfinite(indexed_at)))
);
CREATE INDEX zasp_runtime_sandbox_search_due_idx ON public.zasp_runtime_sandbox_search_outbox(next_attempt_at,created_at) WHERE state IN('pending','leased');
ALTER TABLE public.zasp_runtime_sandbox_search_outbox OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_runtime_sandbox_search_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_sandbox_search_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY zasp_runtime_sandbox_search_outbox_authority ON public.zasp_runtime_sandbox_search_outbox TO zasp_discovery_authority USING(true) WITH CHECK(true);
REVOKE ALL ON public.zasp_runtime_sandbox_search_outbox FROM PUBLIC;

INSERT INTO public.zasp_runtime_sandbox_search_outbox(organization_id,workspace_id,environment_id,batch_id,batch_generation,receipt_digest,receipt_reference,receipt_version,document_ids)
 SELECT receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.batch_id,receipt.batch_generation,receipt.receipt_digest,project.result_reference,project.result_version_id,
 zasp_runtime_session_search_document_ids(receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.batch_id,receipt.batch_generation,receipt.event_ids)
 FROM public.zasp_runtime_session_projection_receipts receipt
 JOIN public.zasp_runtime_stage_work project USING(organization_id,workspace_id,environment_id,batch_id,batch_generation)
 JOIN public.zasp_runtime_stage_work complete USING(organization_id,workspace_id,environment_id,batch_id,batch_generation)
 WHERE project.stage='project' AND project.state='succeeded' AND project.result_digest=receipt.receipt_digest AND complete.stage='complete' AND complete.state='succeeded';
DO $backfill$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_runtime_session_projection_receipts receipt LEFT JOIN public.zasp_runtime_sandbox_search_outbox work USING(organization_id,workspace_id,environment_id,batch_id,batch_generation) WHERE work.batch_id IS NULL) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime session search backfill authority rejected';
 END IF;
END
$backfill$;

DO $sandbox_search_enqueue$
DECLARE definition text;
BEGIN
 SELECT pg_get_functiondef('public.zasp_runtime_session_search_enqueue()'::regprocedure) INTO STRICT definition;
 definition:=replace(replace(definition,'zasp_runtime_session_search_enqueue','zasp_runtime_sandbox_search_enqueue'),'zasp_runtime_session_search_outbox','zasp_runtime_sandbox_search_outbox');
 EXECUTE definition;
END
$sandbox_search_enqueue$;
ALTER FUNCTION public.zasp_runtime_sandbox_search_enqueue() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_sandbox_search_enqueue() FROM PUBLIC;
CREATE TRIGGER zasp_runtime_sandbox_search_enqueue AFTER INSERT ON public.zasp_runtime_session_projection_receipts FOR EACH ROW EXECUTE FUNCTION public.zasp_runtime_sandbox_search_enqueue();

-- Keep unsupported receipts out of the legacy target without rewriting its
-- checkpoints. Clone the unfiltered enqueue above before changing this entry.
DO $legacy_enqueue$
DECLARE definition text;needle text:='BEGIN'||chr(10);
BEGIN
 SELECT pg_get_functiondef('public.zasp_runtime_session_search_enqueue()'::regprocedure) INTO STRICT definition;
 IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='legacy search enqueue predecessor rejected';END IF;
 EXECUTE replace(definition,needle,needle||' IF EXISTS(SELECT 1 FROM zasp_runtime_stage_work project WHERE (project.organization_id,project.workspace_id,project.environment_id,project.batch_id,project.batch_generation)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.batch_id,NEW.batch_generation) AND project.stage=''project'' AND project.implementation_version IN(''runtime-projection-v2'',''runtime-projection-v3'')) THEN RETURN NEW;END IF;'||chr(10));
END
$legacy_enqueue$;

-- A cached predecessor enqueue must fail closed at the table boundary. Existing
-- v1 heartbeat/checkpoint updates do not pass this insert-only version fence.
CREATE FUNCTION public.zasp_runtime_legacy_search_insert_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $guard$
BEGIN
 IF NOT COALESCE(zasp_production_runtime_sandbox_binding_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=50),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_sandbox_binding_fingerprint')),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='legacy search routing unavailable';END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_runtime_stage_work project JOIN zasp_runtime_stage_work complete USING(organization_id,workspace_id,environment_id,batch_id,batch_generation)
 WHERE (project.organization_id,project.workspace_id,project.environment_id,project.batch_id,project.batch_generation)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.batch_id,NEW.batch_generation)
 AND project.stage='project' AND project.implementation_version='runtime-projection-v1' AND project.state='succeeded' AND project.result_digest=NEW.receipt_digest
 AND complete.stage='complete' AND complete.implementation_version='runtime-complete-v1' AND complete.state='succeeded') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='legacy search receipt version rejected';END IF;
 RETURN NEW;
END
$guard$;
ALTER FUNCTION public.zasp_runtime_legacy_search_insert_guard() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_legacy_search_insert_guard() FROM PUBLIC;
CREATE TRIGGER zasp_runtime_legacy_search_insert_guard BEFORE INSERT ON public.zasp_runtime_session_search_outbox FOR EACH ROW EXECUTE FUNCTION public.zasp_runtime_legacy_search_insert_guard();

-- Bounded, target-specific backlog scans and newest committed checkpoint.
CREATE INDEX zasp_runtime_sandbox_query_pending_idx ON public.zasp_runtime_sandbox_search_outbox(organization_id,workspace_id,environment_id,created_at) WHERE state IN('pending','leased');
CREATE INDEX zasp_runtime_sandbox_query_quarantine_idx ON public.zasp_runtime_sandbox_search_outbox(organization_id,workspace_id,environment_id,created_at) WHERE state='quarantined';
CREATE INDEX zasp_runtime_sandbox_query_indexed_idx ON public.zasp_runtime_sandbox_search_outbox(organization_id,workspace_id,environment_id,indexed_at DESC) WHERE state='indexed';

DO $sandbox_query$
DECLARE signature text;definition text;needle text:=E'BEGIN\n';
 readiness text:='IF NOT COALESCE(zasp_production_runtime_sandbox_binding_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=50),(SELECT value FROM zasp_schema_metadata WHERE key=''production_runtime_sandbox_binding_fingerprint'')),false) THEN RAISE EXCEPTION USING ERRCODE=''55000'',MESSAGE=''runtime sandbox search authority unavailable'';END IF;';
BEGIN
 FOREACH signature IN ARRAY ARRAY['public.zasp_runtime_session_query_status(text,text,text,text)','public.zasp_runtime_session_query_hydrate(text,text,text,text,text[])'] LOOP
  SELECT pg_get_functiondef(signature::regprocedure) INTO STRICT definition;
  IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sandbox query definition rejected';END IF;
  definition:=replace(replace(replace(definition,'zasp_runtime_session_query_status','zasp_runtime_sandbox_query_status'),'zasp_runtime_session_query_hydrate','zasp_runtime_sandbox_query_hydrate'),'zasp_runtime_session_search_outbox','zasp_runtime_sandbox_search_outbox');
  EXECUTE replace(definition,needle,needle||readiness||E'\n');
 END LOOP;
END
$sandbox_query$;
ALTER FUNCTION public.zasp_runtime_sandbox_query_status(text,text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_sandbox_query_hydrate(text,text,text,text,text[]) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_sandbox_query_status(text,text,text,text),public.zasp_runtime_sandbox_query_hydrate(text,text,text,text,text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_sandbox_query_status(text,text,text,text),public.zasp_runtime_sandbox_query_hydrate(text,text,text,text,text[]) TO zasp_discovery_api;

CREATE FUNCTION public.zasp_runtime_sandbox_search_worker_ready() RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $worker$
BEGIN
 RETURN COALESCE(zasp_runtime_principal_ready('zasp_runtime_index_worker') AND zasp_production_runtime_sandbox_binding_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=50),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_sandbox_binding_fingerprint')),false);
END
$worker$;

-- Claims take row locks without waiting and try the scope lock. Heartbeat and
-- finish take the scope lock before waiting on their one row. This avoids
-- holding a row while waiting behind recovery's scope lock.
CREATE FUNCTION public.zasp_runtime_sandbox_search_claim(worker_value text,token_value text,lease_seconds integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $claim$
DECLARE work zasp_runtime_sandbox_search_outbox%ROWTYPE;now_value timestamptz:=clock_timestamp();
BEGIN
 IF num_nulls(worker_value,token_value,lease_seconds)>0 OR worker_value !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' OR token_value !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$' OR lease_seconds NOT BETWEEN 5 AND 900
 OR NOT zasp_runtime_sandbox_search_worker_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime sandbox search worker rejected';END IF;
 FOR work IN SELECT * FROM zasp_runtime_sandbox_search_outbox q WHERE q.state IN('pending','leased') AND q.attempt>=100 AND (q.lease_until IS NULL OR q.lease_until<=now_value)
 AND EXISTS(SELECT 1 FROM zasp_runtime_stage_work project WHERE (project.organization_id,project.workspace_id,project.environment_id,project.batch_id,project.batch_generation)=(q.organization_id,q.workspace_id,q.environment_id,q.batch_id,q.batch_generation) AND project.stage='project' AND project.state='succeeded' AND project.implementation_version IN('runtime-projection-v1','runtime-projection-v2'))
 AND NOT EXISTS(SELECT 1 FROM zasp_recovery_holds h WHERE (h.organization_id,h.workspace_id,h.environment_id)=(q.organization_id,q.workspace_id,q.environment_id) AND h.state IN('requested','draining','held'))
 ORDER BY q.next_attempt_at,q.created_at,q.organization_id,q.workspace_id,q.environment_id,q.batch_id,q.batch_generation FOR UPDATE OF q SKIP LOCKED LIMIT 100 LOOP
  IF NOT pg_try_advisory_xact_lock(hashtextextended(concat_ws(chr(31),'zasp-recovery-hold',work.organization_id,work.workspace_id,work.environment_id),0)) THEN CONTINUE;END IF;
  IF NOT zasp_recovery_scope_mutable(work.organization_id,work.workspace_id,work.environment_id) THEN CONTINUE;END IF;
  IF NOT zasp_runtime_sandbox_search_worker_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sandbox search authority unavailable';END IF;
  UPDATE zasp_runtime_sandbox_search_outbox SET state='quarantined',worker_id=NULL,lease_digest=NULL,lease_until=NULL
  WHERE (organization_id,workspace_id,environment_id,batch_id,batch_generation)=(work.organization_id,work.workspace_id,work.environment_id,work.batch_id,work.batch_generation);
 END LOOP;
 FOR work IN SELECT * FROM zasp_runtime_sandbox_search_outbox q WHERE q.attempt<100 AND ((q.state='pending' AND q.next_attempt_at<=now_value) OR (q.state='leased' AND q.lease_until<=now_value))
 AND EXISTS(SELECT 1 FROM zasp_runtime_stage_work project WHERE (project.organization_id,project.workspace_id,project.environment_id,project.batch_id,project.batch_generation)=(q.organization_id,q.workspace_id,q.environment_id,q.batch_id,q.batch_generation) AND project.stage='project' AND project.state='succeeded' AND project.implementation_version IN('runtime-projection-v1','runtime-projection-v2'))
 AND NOT EXISTS(SELECT 1 FROM zasp_recovery_holds h WHERE (h.organization_id,h.workspace_id,h.environment_id)=(q.organization_id,q.workspace_id,q.environment_id) AND h.state IN('requested','draining','held'))
 ORDER BY q.next_attempt_at,q.created_at,q.organization_id,q.workspace_id,q.environment_id,q.batch_id,q.batch_generation FOR UPDATE OF q SKIP LOCKED LIMIT 100 LOOP
  IF NOT pg_try_advisory_xact_lock(hashtextextended(concat_ws(chr(31),'zasp-recovery-hold',work.organization_id,work.workspace_id,work.environment_id),0)) THEN CONTINUE;END IF;
  IF NOT zasp_recovery_scope_mutable(work.organization_id,work.workspace_id,work.environment_id) THEN CONTINUE;END IF;
  IF NOT zasp_runtime_sandbox_search_worker_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sandbox search authority unavailable';END IF;
  now_value:=clock_timestamp();
  UPDATE zasp_runtime_sandbox_search_outbox SET state='leased',attempt=attempt+1,worker_id=worker_value,lease_digest=digest(convert_to(token_value,'UTF8'),'sha256'),lease_until=now_value+make_interval(secs=>lease_seconds)
  WHERE (organization_id,workspace_id,environment_id,batch_id,batch_generation)=(work.organization_id,work.workspace_id,work.environment_id,work.batch_id,work.batch_generation) RETURNING * INTO work;
  IF NOT zasp_runtime_sandbox_search_worker_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sandbox search authority unavailable';END IF;
  RETURN jsonb_build_object('organization_id',work.organization_id,'workspace_id',work.workspace_id,'environment_id',work.environment_id,'batch_id',work.batch_id,'generation',work.batch_generation,'receipt_digest',encode(work.receipt_digest,'hex'),'receipt_reference',work.receipt_reference,'receipt_version',work.receipt_version,'document_ids',work.document_ids,'attempt',work.attempt,'lease_until',work.lease_until);
 END LOOP;
 IF NOT zasp_runtime_sandbox_search_worker_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sandbox search authority unavailable';END IF;
 RETURN NULL;
END
$claim$;

DO $sandbox_search_leases$
DECLARE signature text;definition text;needle text;
 readiness text:='IF NOT zasp_runtime_sandbox_search_worker_ready() THEN RAISE EXCEPTION USING ERRCODE=''55000'',MESSAGE=''runtime sandbox search authority unavailable'';END IF;';
 scope_guard text:='IF NOT zasp_recovery_scope_mutable(organization_value,workspace_value,environment_value) THEN RAISE EXCEPTION USING ERRCODE=''55000'',MESSAGE=''runtime sandbox search recovery hold active'';END IF;';
BEGIN
 FOREACH signature IN ARRAY ARRAY['public.zasp_runtime_session_search_heartbeat(text,text,text,text,bigint,text,text,integer,integer)','public.zasp_runtime_session_search_finish(text,text,text,text,bigint,text,text,integer,bytea,text,text[],integer)'] LOOP
  SELECT pg_get_functiondef(signature::regprocedure) INTO STRICT definition;
  definition:=replace(replace(replace(replace(definition,'zasp_runtime_session_search_heartbeat','zasp_runtime_sandbox_search_heartbeat'),'zasp_runtime_session_search_finish','zasp_runtime_sandbox_search_finish'),'zasp_runtime_session_search_worker_ready','zasp_runtime_sandbox_search_worker_ready'),'zasp_runtime_session_search_outbox','zasp_runtime_sandbox_search_outbox');
  needle:='SELECT * INTO work FROM';
  IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sandbox search lease definition rejected';END IF;
  definition:=replace(definition,needle,scope_guard||readiness||needle);
  needle:='now_value:=clock_timestamp();';
  IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sandbox search clock definition rejected';END IF;
  definition:=replace(definition,needle,needle||readiness);
  definition:=replace(definition,'RETURN jsonb_build_object',readiness||'RETURN jsonb_build_object');
  EXECUTE definition;
 END LOOP;
END
$sandbox_search_leases$;

CREATE FUNCTION public.zasp_runtime_sandbox_search_mutation_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $guard$
BEGIN
 IF NOT COALESCE(zasp_production_runtime_sandbox_binding_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=50),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_sandbox_binding_fingerprint')),false)
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sandbox search authority unavailable';END IF;
 IF TG_OP IN('UPDATE','DELETE') AND NOT zasp_recovery_scope_mutable(OLD.organization_id,OLD.workspace_id,OLD.environment_id) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sandbox search recovery hold active';END IF;
 IF TG_OP IN('INSERT','UPDATE') AND NOT zasp_recovery_scope_mutable(NEW.organization_id,NEW.workspace_id,NEW.environment_id) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sandbox search recovery hold active';END IF;
 IF NOT COALESCE(zasp_production_runtime_sandbox_binding_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=50),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_sandbox_binding_fingerprint')),false)
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sandbox search authority unavailable';END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
END
$guard$;
CREATE TRIGGER zasp_runtime_sandbox_search_recovery_guard BEFORE INSERT OR UPDATE OR DELETE ON public.zasp_runtime_sandbox_search_outbox FOR EACH ROW EXECUTE FUNCTION public.zasp_runtime_sandbox_search_mutation_guard();
DO $sandbox_search_owners$
DECLARE signature text;
BEGIN
 FOREACH signature IN ARRAY ARRAY['zasp_runtime_sandbox_search_worker_ready()','zasp_runtime_sandbox_search_mutation_guard()','zasp_runtime_sandbox_search_claim(text,text,integer)','zasp_runtime_sandbox_search_heartbeat(text,text,text,text,bigint,text,text,integer,integer)','zasp_runtime_sandbox_search_finish(text,text,text,text,bigint,text,text,integer,bytea,text,text[],integer)'] LOOP
  EXECUTE 'ALTER FUNCTION public.'||signature||' OWNER TO zasp_discovery_authority';
  EXECUTE 'REVOKE ALL ON FUNCTION public.'||signature||' FROM PUBLIC';
 END LOOP;
END
$sandbox_search_owners$;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_sandbox_search_claim(text,text,integer),public.zasp_runtime_sandbox_search_heartbeat(text,text,text,text,bigint,text,text,integer,integer),public.zasp_runtime_sandbox_search_finish(text,text,text,text,bigint,text,text,integer,bytea,text,text[],integer) TO zasp_runtime_index_worker;

CREATE FUNCTION public.zasp_production_runtime_sandbox_search_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT EXISTS(SELECT 1 FROM pg_class WHERE oid='public.zasp_runtime_sandbox_search_outbox'::regclass AND relrowsecurity AND relforcerowsecurity AND relowner=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority'))
 AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE((SELECT relacl FROM pg_class WHERE oid='public.zasp_runtime_sandbox_search_outbox'::regclass),acldefault('r',(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority')))) acl WHERE acl.grantee<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority'))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) acl WHERE a.attrelid='public.zasp_runtime_sandbox_search_outbox'::regclass AND acl.grantee<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority'))
 AND (SELECT count(*)=5 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname IN('zasp_runtime_sandbox_search_worker_ready','zasp_runtime_sandbox_search_mutation_guard','zasp_runtime_sandbox_search_claim','zasp_runtime_sandbox_search_heartbeat','zasp_runtime_sandbox_search_finish')
  AND p.proowner=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') AND p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog, public']
  AND p.provolatile=CASE WHEN p.proname='zasp_runtime_sandbox_search_worker_ready' THEN 's'::"char" ELSE 'v'::"char" END
  AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl WHERE acl.is_grantable OR acl.grantee<>p.proowner AND NOT(p.proname IN('zasp_runtime_sandbox_search_claim','zasp_runtime_sandbox_search_heartbeat','zasp_runtime_sandbox_search_finish') AND acl.grantee=(SELECT oid FROM pg_roles WHERE rolname='zasp_runtime_index_worker'))))
 AND has_function_privilege('zasp_runtime_index_worker','public.zasp_runtime_sandbox_search_claim(text,text,integer)','EXECUTE')
 AND has_function_privilege('zasp_runtime_index_worker','public.zasp_runtime_sandbox_search_heartbeat(text,text,text,text,bigint,text,text,integer,integer)','EXECUTE')
 AND has_function_privilege('zasp_runtime_index_worker','public.zasp_runtime_sandbox_search_finish(text,text,text,text,bigint,text,text,integer,bytea,text,text[],integer)','EXECUTE')
 AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.zasp_runtime_sandbox_search_outbox'::regclass AND tgname='zasp_runtime_sandbox_search_recovery_guard' AND tgenabled='O' AND tgfoid='public.zasp_runtime_sandbox_search_mutation_guard()'::regprocedure)
 AND (SELECT count(*)=2 FROM pg_proc p WHERE p.oid IN('public.zasp_runtime_sandbox_query_status(text,text,text,text)'::regprocedure,'public.zasp_runtime_sandbox_query_hydrate(text,text,text,text,text[])'::regprocedure)
  AND p.proowner=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') AND p.prosecdef AND p.provolatile='s' AND p.proconfig=ARRAY['search_path=pg_catalog, public']
  AND has_function_privilege('zasp_discovery_api',p.oid,'EXECUTE')
  AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl WHERE acl.is_grantable OR acl.grantee NOT IN(p.proowner,(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_api'))))
 AND (SELECT count(*)=2 FROM pg_proc p WHERE p.oid IN('public.zasp_runtime_sandbox_search_enqueue()'::regprocedure,'public.zasp_runtime_legacy_search_insert_guard()'::regprocedure) AND p.proowner=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') AND p.prosecdef AND p.provolatile='v' AND p.proconfig=ARRAY['search_path=pg_catalog, public'] AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl WHERE acl.is_grantable OR acl.grantee<>p.proowner))
 AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.zasp_runtime_session_search_outbox'::regclass AND tgname='zasp_runtime_legacy_search_insert_guard' AND tgenabled='O' AND tgfoid='public.zasp_runtime_legacy_search_insert_guard()'::regprocedure)
 AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.zasp_runtime_session_projection_receipts'::regclass AND tgname='zasp_runtime_sandbox_search_enqueue' AND tgenabled='O' AND tgfoid='public.zasp_runtime_sandbox_search_enqueue()'::regprocedure)
$security$;
ALTER FUNCTION public.zasp_production_runtime_sandbox_search_security_ready() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_runtime_sandbox_search_security_ready() FROM PUBLIC;

CREATE FUNCTION public.zasp_production_runtime_sandbox_search_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','function',p.proname,pg_get_function_identity_arguments(p.oid),r.rolname,p.prosecdef,COALESCE(p.proconfig::text,''),COALESCE(p.proacl::text,''),pg_get_functiondef(p.oid)) FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.oid IN('public.zasp_runtime_sandbox_search_enqueue()'::regprocedure,'public.zasp_runtime_legacy_search_insert_guard()'::regprocedure,'public.zasp_production_runtime_sandbox_search_security_ready()'::regprocedure,'public.zasp_production_runtime_sandbox_search_live_fingerprint()'::regprocedure)
 UNION ALL SELECT concat_ws('|','function',p.proname,pg_get_function_identity_arguments(p.oid),r.rolname,p.prosecdef,COALESCE(p.proconfig::text,''),COALESCE(p.proacl::text,''),pg_get_functiondef(p.oid)) FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.oid IN('public.zasp_runtime_sandbox_query_status(text,text,text,text)'::regprocedure,'public.zasp_runtime_sandbox_query_hydrate(text,text,text,text,text[])'::regprocedure)
 UNION ALL SELECT concat_ws('|','function',p.proname,pg_get_function_identity_arguments(p.oid),r.rolname,p.prosecdef,COALESCE(p.proconfig::text,''),COALESCE(p.proacl::text,''),pg_get_functiondef(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.proname IN('zasp_runtime_sandbox_search_worker_ready','zasp_runtime_sandbox_search_mutation_guard','zasp_runtime_sandbox_search_claim','zasp_runtime_sandbox_search_heartbeat','zasp_runtime_sandbox_search_finish')
 UNION ALL SELECT concat_ws('|','table',relname,relowner::regrole::text,relrowsecurity,relforcerowsecurity,COALESCE(relacl::text,'')) FROM pg_class WHERE oid='public.zasp_runtime_sandbox_search_outbox'::regclass
 UNION ALL SELECT concat_ws('|','constraint',conname,pg_get_constraintdef(oid),convalidated) FROM pg_constraint WHERE conrelid='public.zasp_runtime_sandbox_search_outbox'::regclass
 UNION ALL SELECT concat_ws('|','column',attname,format_type(atttypid,atttypmod),attnotnull,COALESCE(attacl::text,''),COALESCE(pg_get_expr(d.adbin,d.adrelid),'')) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.zasp_runtime_sandbox_search_outbox'::regclass AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','policy',policyname,roles::text,cmd,qual,with_check) FROM pg_policies WHERE schemaname='public' AND tablename='zasp_runtime_sandbox_search_outbox'
 UNION ALL SELECT concat_ws('|','index',indexname,indexdef) FROM pg_indexes WHERE schemaname='public' AND tablename='zasp_runtime_sandbox_search_outbox'
 UNION ALL SELECT concat_ws('|','trigger',tgrelid::regclass::text,tgname,tgenabled,pg_get_triggerdef(oid)) FROM pg_trigger WHERE tgrelid IN('public.zasp_runtime_session_projection_receipts'::regclass,'public.zasp_runtime_sandbox_search_outbox'::regclass,'public.zasp_runtime_session_search_outbox'::regclass) AND NOT tgisinternal
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
ALTER FUNCTION public.zasp_production_runtime_sandbox_search_live_fingerprint() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_runtime_sandbox_search_live_fingerprint() FROM PUBLIC;

CREATE FUNCTION public.zasp_production_runtime_sandbox_binding_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_production_runtime_correlation_routing_security_ready()
 AND zasp_production_runtime_sandbox_search_security_ready()
 AND has_function_privilege('zasp_runtime_projection_worker','public.zasp_production_runtime_sandbox_binding_readiness(text,text)','EXECUTE')
 AND (SELECT count(*) FROM pg_proc p WHERE p.oid IN('public.zasp_runtime_claim_stage_sandbox_compatible(text,text,integer,integer,boolean)'::regprocedure,'public.zasp_runtime_claim_correlation_v3(text,text,integer,integer)'::regprocedure,'public.zasp_runtime_freeze_sandbox_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea)'::regprocedure)
  AND p.proowner=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') AND p.prosecdef AND p.provolatile='v' AND p.proconfig=ARRAY['search_path=pg_catalog, public']
  AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl WHERE acl.is_grantable OR (acl.grantee<>p.proowner AND NOT (p.proname IN('zasp_runtime_claim_correlation_v3','zasp_runtime_freeze_sandbox_candidates') AND acl.grantee=(SELECT oid FROM pg_roles WHERE rolname='zasp_runtime_correlation_worker')))))=3
 AND has_function_privilege('zasp_runtime_correlation_worker','public.zasp_runtime_claim_correlation_v3(text,text,integer,integer)','EXECUTE')
 AND has_function_privilege('zasp_runtime_correlation_worker','public.zasp_runtime_freeze_sandbox_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea)','EXECUTE')
 AND EXISTS(SELECT 1 FROM pg_proc p WHERE p.oid='public.zasp_runtime_finish_sandbox_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)'::regprocedure
  AND p.proowner=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') AND p.prosecdef AND p.provolatile='v' AND p.proconfig=ARRAY['search_path=pg_catalog, public']
  AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl WHERE acl.is_grantable OR acl.grantee NOT IN(p.proowner,(SELECT oid FROM pg_roles WHERE rolname='zasp_runtime_coordinator'))))
 AND has_function_privilege('zasp_runtime_coordinator','public.zasp_runtime_finish_sandbox_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)','EXECUTE')
 AND (SELECT count(*)=2 FROM pg_proc p WHERE p.oid IN('public.zasp_runtime_sandbox_session_event_page(text,text,text,text,text,timestamptz,text,integer)'::regprocedure,'public.zasp_runtime_sandbox_session_event_get(text,text,text,text,text,text)'::regprocedure)
  AND p.proowner=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') AND p.prosecdef AND p.provolatile='s' AND p.proconfig=ARRAY['search_path=pg_catalog, public']
  AND has_function_privilege('zasp_discovery_api',p.oid,'EXECUTE')
  AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl WHERE acl.is_grantable OR acl.grantee NOT IN(p.proowner,(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_api'))))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) acl WHERE a.attrelid='public.zasp_runtime_session_events'::regclass AND acl.grantee<>(SELECT relowner FROM pg_class WHERE oid=a.attrelid))
 AND (SELECT count(*)=4 FROM pg_proc p WHERE p.oid IN('public.zasp_runtime_claim_session_stage_compatible(text,text,integer,integer,boolean)'::regprocedure,'public.zasp_runtime_session_claim_version_guard()'::regprocedure,'public.zasp_runtime_claim_projection_v2(text,text,integer,integer)'::regprocedure,'public.zasp_runtime_claim_completion_v2(text,text,integer,integer)'::regprocedure)
  AND p.proowner=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') AND p.prosecdef AND p.provolatile='v' AND p.proconfig=ARRAY['search_path=pg_catalog, public']
  AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl WHERE acl.is_grantable OR acl.grantee<>p.proowner AND NOT(p.proname='zasp_runtime_claim_projection_v2' AND acl.grantee=(SELECT oid FROM pg_roles WHERE rolname='zasp_runtime_projection_worker') OR p.proname='zasp_runtime_claim_completion_v2' AND acl.grantee=(SELECT oid FROM pg_roles WHERE rolname='zasp_runtime_coordinator'))))
 AND has_function_privilege('zasp_runtime_projection_worker','public.zasp_runtime_claim_projection_v2(text,text,integer,integer)','EXECUTE')
 AND has_function_privilege('zasp_runtime_coordinator','public.zasp_runtime_claim_completion_v2(text,text,integer,integer)','EXECUTE')
 AND EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid='public.zasp_runtime_stage_work'::regclass AND t.tgname='zasp_runtime_session_claim_version' AND t.tgfoid='public.zasp_runtime_session_claim_version_guard()'::regprocedure AND t.tgenabled='O' AND NOT t.tgisinternal)
$security$;
CREATE FUNCTION public.zasp_production_runtime_sandbox_binding_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','prior',zasp_production_runtime_correlation_routing_live_fingerprint())
 UNION ALL SELECT concat_ws('|','sandbox-search',zasp_production_runtime_sandbox_search_live_fingerprint())
 UNION ALL SELECT concat_ws('|','function',p.proname,pg_get_function_identity_arguments(p.oid),r.rolname,p.prosecdef,COALESCE(p.proconfig::text,''),COALESCE(p.proacl::text,''),pg_get_functiondef(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.proname IN('zasp_runtime_claim_session_stage_compatible','zasp_runtime_session_claim_version_guard','zasp_runtime_claim_projection_v2','zasp_runtime_claim_completion_v2')
 UNION ALL SELECT concat_ws('|','trigger',t.tgname,t.tgenabled,pg_get_triggerdef(t.oid,true)) FROM pg_trigger t WHERE t.tgrelid='public.zasp_runtime_stage_work'::regclass AND t.tgname='zasp_runtime_session_claim_version'
 UNION ALL SELECT concat_ws('|','function',p.proname,pg_get_function_identity_arguments(p.oid),r.rolname,p.prosecdef,COALESCE(p.proconfig::text,''),COALESCE(p.proacl::text,''),pg_get_functiondef(p.oid)) FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.oid='public.zasp_runtime_finish_sandbox_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)'::regprocedure
 UNION ALL SELECT concat_ws('|','session-column-acl',attname,COALESCE(attacl::text,'')) FROM pg_attribute WHERE attrelid='public.zasp_runtime_session_events'::regclass AND attnum>0 AND NOT attisdropped
 UNION ALL SELECT concat_ws('|','function',p.proname,pg_get_function_identity_arguments(p.oid),r.rolname,p.prosecdef,COALESCE(p.proconfig::text,''),COALESCE(p.proacl::text,''),pg_get_functiondef(p.oid)) FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.oid IN('public.zasp_runtime_sandbox_session_event_page(text,text,text,text,text,timestamptz,text,integer)'::regprocedure,'public.zasp_runtime_sandbox_session_event_get(text,text,text,text,text,text)'::regprocedure)
 UNION ALL SELECT concat_ws('|','function',p.proname,pg_get_function_identity_arguments(p.oid),r.rolname,p.prosecdef,COALESCE(p.proconfig::text,''),COALESCE(p.proacl::text,''),pg_get_functiondef(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.proname IN('zasp_runtime_claim_stage_sandbox_compatible','zasp_runtime_claim_correlation_v3','zasp_runtime_freeze_sandbox_candidates','zasp_production_runtime_sandbox_binding_security_ready','zasp_production_runtime_sandbox_binding_readiness','zasp_production_runtime_correlation_routing_readiness_v49','zasp_production_runtime_candidate_authority_live_fingerprint')
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
CREATE FUNCTION public.zasp_production_runtime_sandbox_binding_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT COALESCE(expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=50 AND name='production_runtime_sandbox_binding' AND checksum=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_runtime_sandbox_binding_checksum' AND value=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_runtime_sandbox_binding_fingerprint' AND value=expected_fingerprint) AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>50) AND zasp_production_runtime_sandbox_binding_security_ready() AND zasp_production_runtime_sandbox_binding_live_fingerprint()=expected_fingerprint,false)
$readiness$;
ALTER FUNCTION public.zasp_production_runtime_sandbox_binding_security_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_runtime_sandbox_binding_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_runtime_sandbox_binding_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_runtime_sandbox_binding_security_ready(),public.zasp_production_runtime_sandbox_binding_live_fingerprint(),public.zasp_production_runtime_sandbox_binding_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_runtime_sandbox_binding_readiness(text,text) TO zasp_runtime_ingest,zasp_runtime_correlation_worker,zasp_discovery_worker,zasp_runtime_index_worker,zasp_runtime_coordinator,zasp_discovery_api,zasp_runtime_projection_worker;

ALTER FUNCTION public.zasp_production_runtime_correlation_routing_readiness(text,text) RENAME TO zasp_production_runtime_correlation_routing_readiness_v49;
CREATE FUNCTION public.zasp_production_runtime_correlation_routing_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $compatibility$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=49 AND name='production_runtime_correlation_routing' AND checksum=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_runtime_correlation_routing_checksum' AND value=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_runtime_correlation_routing_fingerprint' AND value=expected_fingerprint) AND zasp_production_runtime_sandbox_binding_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=50),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_sandbox_binding_fingerprint'))
$compatibility$;
ALTER FUNCTION public.zasp_production_runtime_correlation_routing_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_runtime_correlation_routing_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_runtime_correlation_routing_readiness(text,text) TO zasp_runtime_ingest,zasp_runtime_correlation_worker,zasp_discovery_worker,zasp_runtime_index_worker,zasp_runtime_coordinator,zasp_discovery_api;
INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_runtime_sandbox_binding_fingerprint', 'a6f3e317cd99ef9890c7dff18487aa732b196349e133c687606e971c1456865d');
