DO $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>41)
 OR NOT public.zasp_production_runtime_session_reads_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=41),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_session_reads_fingerprint')) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime session search prerequisite rejected';
 END IF;
END
$guard$;
-- Receipt insertion and its outbox entry must share one commit. Hold this lock
-- before backfill and trigger installation so concurrent completions cannot fall
-- between them. The five original runtime stage contracts remain unchanged.
LOCK TABLE public.zasp_runtime_session_projection_receipts IN SHARE ROW EXCLUSIVE MODE;
CREATE TABLE public.zasp_runtime_session_search_outbox (
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
CREATE INDEX zasp_runtime_session_search_due_idx ON public.zasp_runtime_session_search_outbox(next_attempt_at,created_at) WHERE state IN('pending','leased');
ALTER TABLE public.zasp_runtime_session_search_outbox OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_runtime_session_search_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_session_search_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY zasp_runtime_session_search_outbox_authority ON public.zasp_runtime_session_search_outbox TO zasp_discovery_authority USING(true) WITH CHECK(true);
REVOKE ALL ON public.zasp_runtime_session_search_outbox FROM PUBLIC;

CREATE FUNCTION public.zasp_runtime_session_search_document_ids(organization_value text,workspace_value text,environment_value text,batch_value text,generation_value bigint,event_values text[]) RETURNS text[] LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $ids$
 SELECT array_agg(encode(digest(convert_to('zasp.runtime-session-search.occurrence.v1','UTF8')||decode('00','hex')||convert_to(organization_value,'UTF8')||decode('00','hex')||convert_to(workspace_value,'UTF8')||decode('00','hex')||convert_to(environment_value,'UTF8')||decode('00','hex')||convert_to(batch_value,'UTF8')||decode('00','hex')||convert_to(generation_value::text,'UTF8')||decode('00','hex')||convert_to(event_value,'UTF8'),'sha256'),'hex') ORDER BY position)
 FROM unnest(event_values) WITH ORDINALITY AS events(event_value,position)
$ids$;
ALTER FUNCTION public.zasp_runtime_session_search_document_ids(text,text,text,text,bigint,text[]) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_session_search_document_ids(text,text,text,text,bigint,text[]) FROM PUBLIC;

INSERT INTO public.zasp_runtime_session_search_outbox(organization_id,workspace_id,environment_id,batch_id,batch_generation,receipt_digest,receipt_reference,receipt_version,document_ids)
 SELECT receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.batch_id,receipt.batch_generation,receipt.receipt_digest,project.result_reference,project.result_version_id,
 zasp_runtime_session_search_document_ids(receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.batch_id,receipt.batch_generation,receipt.event_ids)
 FROM public.zasp_runtime_session_projection_receipts receipt
 JOIN public.zasp_runtime_stage_work project USING(organization_id,workspace_id,environment_id,batch_id,batch_generation)
 JOIN public.zasp_runtime_stage_work complete USING(organization_id,workspace_id,environment_id,batch_id,batch_generation)
 WHERE project.stage='project' AND project.state='succeeded' AND project.result_digest=receipt.receipt_digest AND complete.stage='complete' AND complete.state='succeeded';
DO $backfill$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_runtime_session_projection_receipts receipt LEFT JOIN public.zasp_runtime_session_search_outbox work USING(organization_id,workspace_id,environment_id,batch_id,batch_generation) WHERE work.batch_id IS NULL) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime session search backfill authority rejected';
 END IF;
END
$backfill$;
CREATE FUNCTION public.zasp_runtime_session_search_enqueue() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $enqueue$
BEGIN
 INSERT INTO zasp_runtime_session_search_outbox(organization_id,workspace_id,environment_id,batch_id,batch_generation,receipt_digest,receipt_reference,receipt_version,document_ids)
 SELECT NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.batch_id,NEW.batch_generation,NEW.receipt_digest,project.result_reference,project.result_version_id,
 zasp_runtime_session_search_document_ids(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.batch_id,NEW.batch_generation,NEW.event_ids)
 FROM zasp_runtime_stage_work project JOIN zasp_runtime_stage_work complete USING(organization_id,workspace_id,environment_id,batch_id,batch_generation)
 WHERE (project.organization_id,project.workspace_id,project.environment_id,project.batch_id,project.batch_generation)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.batch_id,NEW.batch_generation)
 AND project.stage='project' AND project.state='succeeded' AND project.result_digest=NEW.receipt_digest AND complete.stage='complete' AND complete.state='succeeded';
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime session search receipt authority rejected';END IF;
 RETURN NEW;
END
$enqueue$;
ALTER FUNCTION public.zasp_runtime_session_search_enqueue() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_session_search_enqueue() FROM PUBLIC;
CREATE TRIGGER zasp_runtime_session_search_enqueue AFTER INSERT ON public.zasp_runtime_session_projection_receipts FOR EACH ROW EXECUTE FUNCTION public.zasp_runtime_session_search_enqueue();

CREATE FUNCTION public.zasp_runtime_session_search_claim(worker_value text,token_value text,lease_seconds integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $claim$
DECLARE work zasp_runtime_session_search_outbox%ROWTYPE;now_value timestamptz:=clock_timestamp();
BEGIN
 IF num_nulls(worker_value,token_value,lease_seconds)>0 OR worker_value !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' OR token_value !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$' OR lease_seconds NOT BETWEEN 5 AND 900
 OR NOT zasp_runtime_session_search_worker_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime session search worker rejected';END IF;
 WITH exhausted AS (SELECT organization_id,workspace_id,environment_id,batch_id,batch_generation FROM zasp_runtime_session_search_outbox WHERE state IN('pending','leased') AND attempt>=100 AND (lease_until IS NULL OR lease_until<=now_value) FOR UPDATE SKIP LOCKED LIMIT 100)
 UPDATE zasp_runtime_session_search_outbox outbox_row SET state='quarantined',worker_id=NULL,lease_digest=NULL,lease_until=NULL FROM exhausted WHERE (outbox_row.organization_id,outbox_row.workspace_id,outbox_row.environment_id,outbox_row.batch_id,outbox_row.batch_generation)=(exhausted.organization_id,exhausted.workspace_id,exhausted.environment_id,exhausted.batch_id,exhausted.batch_generation);
 SELECT * INTO work FROM zasp_runtime_session_search_outbox WHERE attempt<100 AND ((state='pending' AND next_attempt_at<=now_value) OR (state='leased' AND lease_until<=now_value)) ORDER BY next_attempt_at,created_at,organization_id,workspace_id,environment_id,batch_id,batch_generation FOR UPDATE SKIP LOCKED LIMIT 1;
 IF NOT FOUND THEN RETURN NULL;END IF;
 now_value:=clock_timestamp();
 UPDATE zasp_runtime_session_search_outbox SET state='leased',attempt=attempt+1,worker_id=worker_value,lease_digest=digest(convert_to(token_value,'UTF8'),'sha256'),lease_until=now_value+make_interval(secs=>lease_seconds)
 WHERE (organization_id,workspace_id,environment_id,batch_id,batch_generation)=(work.organization_id,work.workspace_id,work.environment_id,work.batch_id,work.batch_generation) RETURNING * INTO work;
 RETURN jsonb_build_object('organization_id',work.organization_id,'workspace_id',work.workspace_id,'environment_id',work.environment_id,'batch_id',work.batch_id,'generation',work.batch_generation,'receipt_digest',encode(work.receipt_digest,'hex'),'receipt_reference',work.receipt_reference,'receipt_version',work.receipt_version,'document_ids',work.document_ids,'attempt',work.attempt,'lease_until',work.lease_until);
END
$claim$;
CREATE FUNCTION public.zasp_runtime_session_search_heartbeat(organization_value text,workspace_value text,environment_value text,batch_value text,generation_value bigint,worker_value text,token_value text,attempt_value integer,lease_seconds integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $heartbeat$
DECLARE work zasp_runtime_session_search_outbox%ROWTYPE;deadline timestamptz;now_value timestamptz;
BEGIN
 IF num_nulls(organization_value,workspace_value,environment_value,batch_value,generation_value,worker_value,token_value,attempt_value,lease_seconds)>0 OR lease_seconds NOT BETWEEN 5 AND 900 OR NOT zasp_runtime_session_search_worker_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime session search lease rejected';END IF;
 SELECT * INTO work FROM zasp_runtime_session_search_outbox WHERE (organization_id,workspace_id,environment_id,batch_id,batch_generation)=(organization_value,workspace_value,environment_value,batch_value,generation_value) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='runtime session search lease lost';END IF;
 now_value:=clock_timestamp();
 IF work.state<>'leased' OR work.lease_until<=now_value OR (work.worker_id,work.lease_digest,work.attempt) IS DISTINCT FROM (worker_value,digest(convert_to(token_value,'UTF8'),'sha256'),attempt_value) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='runtime session search lease lost';END IF;
 UPDATE zasp_runtime_session_search_outbox SET lease_until=now_value+make_interval(secs=>lease_seconds) WHERE (organization_id,workspace_id,environment_id,batch_id,batch_generation)=(organization_value,workspace_value,environment_value,batch_value,generation_value) RETURNING lease_until INTO deadline;
 RETURN jsonb_build_object('lease_until',deadline);
END
$heartbeat$;
CREATE FUNCTION public.zasp_runtime_session_search_finish(organization_value text,workspace_value text,environment_value text,batch_value text,generation_value bigint,worker_value text,token_value text,attempt_value integer,receipt_digest_value bytea,outcome_value text,document_values text[],retry_seconds integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $finish$
DECLARE work zasp_runtime_session_search_outbox%ROWTYPE;now_value timestamptz;
BEGIN
 IF num_nulls(organization_value,workspace_value,environment_value,batch_value,generation_value,worker_value,token_value,attempt_value,receipt_digest_value,outcome_value,document_values,retry_seconds)>0 OR outcome_value NOT IN('indexed','retryable','quarantined') OR octet_length(receipt_digest_value)<>32
 OR (outcome_value='retryable' AND retry_seconds NOT BETWEEN 1 AND 3600) OR (outcome_value<>'retryable' AND retry_seconds<>0)
 OR NOT zasp_runtime_session_search_worker_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime session search checkpoint rejected';END IF;
 SELECT * INTO work FROM zasp_runtime_session_search_outbox WHERE (organization_id,workspace_id,environment_id,batch_id,batch_generation)=(organization_value,workspace_value,environment_value,batch_value,generation_value) FOR UPDATE;
 now_value:=clock_timestamp();
 IF NOT FOUND OR (work.worker_id,work.lease_digest,work.attempt,work.receipt_digest) IS DISTINCT FROM (worker_value,digest(convert_to(token_value,'UTF8'),'sha256'),attempt_value,receipt_digest_value)
 OR (outcome_value='indexed' AND work.document_ids IS DISTINCT FROM document_values) OR (outcome_value<>'indexed' AND cardinality(document_values)<>0) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='runtime session search checkpoint binding rejected';END IF;
 IF work.state='indexed' AND outcome_value='indexed' THEN
  RETURN jsonb_build_object('state','indexed','batch_id',work.batch_id,'generation',work.batch_generation,'attempt',work.attempt,'receipt_digest',encode(work.receipt_digest,'hex'),'indexed_at',work.indexed_at);
 END IF;
 IF work.state<>'leased' OR work.lease_until<=now_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='runtime session search checkpoint lease lost';END IF;
 UPDATE zasp_runtime_session_search_outbox SET state=CASE WHEN outcome_value='retryable' THEN 'pending' ELSE outcome_value END,
 worker_id=CASE WHEN outcome_value='indexed' THEN worker_id ELSE NULL END,lease_digest=CASE WHEN outcome_value='indexed' THEN lease_digest ELSE NULL END,lease_until=NULL,
 indexed_at=CASE WHEN outcome_value='indexed' THEN now_value ELSE NULL END,next_attempt_at=now_value+make_interval(secs=>retry_seconds)
 WHERE (organization_id,workspace_id,environment_id,batch_id,batch_generation)=(organization_value,workspace_value,environment_value,batch_value,generation_value) RETURNING * INTO work;
 RETURN jsonb_build_object('state',work.state,'batch_id',work.batch_id,'generation',work.batch_generation,'attempt',work.attempt,'receipt_digest',encode(work.receipt_digest,'hex'),'indexed_at',work.indexed_at);
END
$finish$;

DO $owners$
DECLARE signature text;
BEGIN
 FOREACH signature IN ARRAY ARRAY['zasp_runtime_session_search_claim(text,text,integer)','zasp_runtime_session_search_heartbeat(text,text,text,text,bigint,text,text,integer,integer)','zasp_runtime_session_search_finish(text,text,text,text,bigint,text,text,integer,bytea,text,text[],integer)'] LOOP
  EXECUTE 'ALTER FUNCTION public.'||signature||' OWNER TO zasp_discovery_authority';
  EXECUTE 'REVOKE ALL ON FUNCTION public.'||signature||' FROM PUBLIC';
  EXECUTE 'GRANT EXECUTE ON FUNCTION public.'||signature||' TO zasp_runtime_index_worker';
 END LOOP;
END
$owners$;

DO $compatibility$
DECLARE definition text;prior text;function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 41','later_release."version" > 42'),'later."version">41','later."version">42'),'later."version" > 41','later."version" > 42');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime session search compatibility rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;

CREATE FUNCTION public.zasp_production_runtime_session_search_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_production_runtime_session_reads_security_ready()
 AND EXISTS(SELECT 1 FROM pg_class WHERE oid='public.zasp_runtime_session_search_outbox'::regclass AND relrowsecurity AND relforcerowsecurity AND relowner=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority'))
 AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE((SELECT relacl FROM pg_class WHERE oid='public.zasp_runtime_session_search_outbox'::regclass),acldefault('r',(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority')))) acl WHERE acl.grantee<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority'))
 AND NOT EXISTS(SELECT 1 FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' AND procedure.proname LIKE 'zasp_runtime_session_search_%'
 AND (procedure.proowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') OR NOT procedure.prosecdef OR NOT COALESCE(procedure.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public']
 OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(procedure.proacl,acldefault('f',procedure.proowner))) acl WHERE acl.privilege_type='EXECUTE' AND acl.grantee<>procedure.proowner AND NOT (acl.grantee=(SELECT oid FROM pg_roles WHERE rolname='zasp_runtime_index_worker') AND procedure.proname IN('zasp_runtime_session_search_claim','zasp_runtime_session_search_heartbeat','zasp_runtime_session_search_finish','zasp_runtime_session_search_worker_ready')))))
 AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.zasp_runtime_session_projection_receipts'::regclass AND tgname='zasp_runtime_session_search_enqueue' AND tgenabled='O' AND tgfoid='public.zasp_runtime_session_search_enqueue()'::regprocedure)
$security$;
CREATE FUNCTION public.zasp_production_runtime_session_search_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','prior',zasp_production_runtime_session_reads_live_fingerprint())
 UNION ALL SELECT concat_ws('|','function',procedure.proname,pg_get_function_identity_arguments(procedure.oid),owner.rolname,procedure.prosecdef,COALESCE(procedure.proconfig::text,''),COALESCE(procedure.proacl::text,''),pg_get_functiondef(procedure.oid)) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND (procedure.proname LIKE 'zasp_runtime_session_search_%' OR procedure.proname IN('zasp_production_runtime_session_search_readiness','zasp_production_runtime_session_search_security_ready'))
 UNION ALL SELECT concat_ws('|','table',relname,relowner::regrole::text,relrowsecurity,relforcerowsecurity,COALESCE(relacl::text,'')) FROM pg_class WHERE oid='public.zasp_runtime_session_search_outbox'::regclass
 UNION ALL SELECT concat_ws('|','constraint',conname,pg_get_constraintdef(oid),convalidated) FROM pg_constraint WHERE conrelid='public.zasp_runtime_session_search_outbox'::regclass
 UNION ALL SELECT concat_ws('|','column',attname,format_type(atttypid,atttypmod),attnotnull,COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),'')) FROM pg_attribute attribute_value LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute_value.attrelid AND default_value.adnum=attribute_value.attnum WHERE attribute_value.attrelid='public.zasp_runtime_session_search_outbox'::regclass AND attribute_value.attnum>0 AND NOT attribute_value.attisdropped
 UNION ALL SELECT concat_ws('|','policy',policyname,roles::text,cmd,qual,with_check) FROM pg_policies WHERE schemaname='public' AND tablename='zasp_runtime_session_search_outbox'
 UNION ALL SELECT concat_ws('|','index',indexname,indexdef) FROM pg_indexes WHERE schemaname='public' AND tablename='zasp_runtime_session_search_outbox'
 UNION ALL SELECT concat_ws('|','trigger',tgname,tgenabled,pg_get_triggerdef(oid)) FROM pg_trigger WHERE tgrelid='public.zasp_runtime_session_projection_receipts'::regclass AND NOT tgisinternal
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
CREATE FUNCTION public.zasp_production_runtime_session_search_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=42 AND name='production_runtime_session_search' AND checksum=expected_checksum) AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>42) AND zasp_production_runtime_session_search_security_ready() AND zasp_production_runtime_session_search_live_fingerprint()=expected_fingerprint
$readiness$;
ALTER FUNCTION public.zasp_production_runtime_session_search_security_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_runtime_session_search_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_runtime_session_search_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_runtime_session_search_security_ready(),public.zasp_production_runtime_session_search_live_fingerprint(),public.zasp_production_runtime_session_search_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_runtime_session_search_readiness(text,text) TO zasp_runtime_index_worker,zasp_runtime_coordinator,zasp_discovery_api;
CREATE FUNCTION public.zasp_runtime_session_search_worker_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $worker$
 SELECT COALESCE(zasp_runtime_principal_ready('zasp_runtime_index_worker') AND zasp_production_runtime_session_search_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=42),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_session_search_fingerprint')),false)
$worker$;
ALTER FUNCTION public.zasp_runtime_session_search_worker_ready() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_session_search_worker_ready() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_session_search_worker_ready() TO zasp_runtime_index_worker;
ALTER FUNCTION public.zasp_production_runtime_session_reads_readiness(text,text) RENAME TO zasp_production_runtime_session_reads_readiness_v41;
CREATE FUNCTION public.zasp_production_runtime_session_reads_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $compatibility$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=41 AND name='production_runtime_session_reads' AND checksum=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_runtime_session_reads_fingerprint' AND value=expected_fingerprint) AND zasp_production_runtime_session_search_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=42),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_session_search_fingerprint'))
$compatibility$;
ALTER FUNCTION public.zasp_production_runtime_session_reads_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_runtime_session_reads_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_runtime_session_reads_readiness(text,text) TO zasp_runtime_coordinator,zasp_discovery_api;
INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_runtime_session_search_fingerprint', '792b150a088a5ffd6459b171f29dc46474585437062104a552ac915390f2bc34');
