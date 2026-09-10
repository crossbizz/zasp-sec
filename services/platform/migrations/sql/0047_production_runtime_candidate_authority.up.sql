DO $guard$
BEGIN
 IF NOT public.zasp_production_reconciliation_lane_plan_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=46),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_reconciliation_lane_plan_fingerprint')) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime candidate prerequisite rejected';
 END IF;
END
$guard$;

CREATE TABLE public.zasp_runtime_candidate_observations (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,
 batch_id text NOT NULL,generation bigint NOT NULL CHECK(generation>0),event_ordinal integer NOT NULL CHECK(event_ordinal BETWEEN 1 AND 1000),
 source_sensor_id text NOT NULL,source_kind text NOT NULL DEFAULT 'otlp' CHECK(source_kind='otlp'),runtime_sensor_id text NOT NULL,
 archive_digest bytea NOT NULL CHECK(octet_length(archive_digest)=32),index_receipt_digest bytea NOT NULL CHECK(octet_length(index_receipt_digest)=32),
 agent_id text NOT NULL CHECK(zasp_valid_product_id(agent_id)),session_id text NOT NULL CHECK(zasp_valid_product_id(session_id)),
 observed_lineage jsonb NOT NULL CHECK(jsonb_typeof(observed_lineage)='object'),event_time timestamptz NOT NULL,
 cluster_uid text NOT NULL,node_uid text NOT NULL,boot_id text NOT NULL,pod_uid text NOT NULL,container_id text NOT NULL,
 admitted_at timestamptz NOT NULL DEFAULT clock_timestamp(),CHECK(agent_id<>session_id),
 PRIMARY KEY(organization_id,workspace_id,environment_id,batch_id,event_ordinal),
 FOREIGN KEY(organization_id,workspace_id,environment_id,batch_id,generation,source_sensor_id,source_kind) REFERENCES public.zasp_runtime_batch_authorities(organization_id,workspace_id,environment_id,batch_id,batch_generation,sensor_id,source_kind) ON DELETE RESTRICT,
 FOREIGN KEY(organization_id,workspace_id,environment_id,runtime_sensor_id) REFERENCES public.zasp_sensors(organization_id,workspace_id,environment_id,id) ON DELETE RESTRICT
);
CREATE INDEX zasp_runtime_candidate_lookup_v47 ON public.zasp_runtime_candidate_observations(organization_id,workspace_id,environment_id,runtime_sensor_id,cluster_uid,node_uid,boot_id,pod_uid,container_id,event_time,batch_id,event_ordinal);

CREATE TABLE public.zasp_runtime_candidate_snapshots (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,batch_id text NOT NULL,generation bigint NOT NULL CHECK(generation>0),
 source_sensor_id text NOT NULL,source_kind text NOT NULL CHECK(source_kind IN('tetragon','otlp')),runtime_sensor_id text,
 archive_digest bytea NOT NULL CHECK(octet_length(archive_digest)=32),index_receipt_digest bytea NOT NULL CHECK(octet_length(index_receipt_digest)=32),
 snapshot_body bytea NOT NULL CHECK(octet_length(snapshot_body) BETWEEN 1 AND 1048576),snapshot_digest bytea NOT NULL CHECK(octet_length(snapshot_digest)=32 AND snapshot_digest=digest(snapshot_body,'sha256')),
 frozen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,batch_id,generation),
 FOREIGN KEY(organization_id,workspace_id,environment_id,batch_id,generation,source_sensor_id,source_kind) REFERENCES public.zasp_runtime_batch_authorities(organization_id,workspace_id,environment_id,batch_id,batch_generation,sensor_id,source_kind) ON DELETE RESTRICT,
 FOREIGN KEY(organization_id,workspace_id,environment_id,runtime_sensor_id) REFERENCES public.zasp_sensors(organization_id,workspace_id,environment_id,id) ON DELETE RESTRICT
);
ALTER TABLE public.zasp_runtime_candidate_observations OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_runtime_candidate_snapshots OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_runtime_candidate_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_candidate_observations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_candidate_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_candidate_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY zasp_runtime_candidate_observations_authority ON public.zasp_runtime_candidate_observations TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE POLICY zasp_runtime_candidate_snapshots_authority ON public.zasp_runtime_candidate_snapshots TO zasp_discovery_authority USING(true) WITH CHECK(true);
REVOKE ALL ON public.zasp_runtime_candidate_observations,public.zasp_runtime_candidate_snapshots FROM PUBLIC;
CREATE TRIGGER zasp_runtime_candidate_observations_immutable BEFORE UPDATE OR DELETE ON public.zasp_runtime_candidate_observations FOR EACH ROW EXECUTE FUNCTION public.zasp_runtime_pairing_immutable();
CREATE TRIGGER zasp_runtime_candidate_snapshots_immutable BEFORE UPDATE OR DELETE ON public.zasp_runtime_candidate_snapshots FOR EACH ROW EXECUTE FUNCTION public.zasp_runtime_pairing_immutable();

-- The accepted archive checksum binds these fields to the already closed ingest
-- contract. The registered correlation worker also runs its strict decoder.
-- This helper rejects unsupported observation profiles instead of downgrading
-- them to unqualified identifiers. It does not attest a host.
CREATE FUNCTION public.zasp_runtime_candidate_lineage_valid(value jsonb,event_time_value timestamptz) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path TO pg_catalog, public AS $valid$
DECLARE identifier text;key_value text;start_value timestamptz;
BEGIN
 IF value IS NULL OR jsonb_typeof(value)<>'object' OR event_time_value IS NULL OR value->>'profile' IS DISTINCT FROM 'kubernetes-container-v1' OR octet_length(value::text)>1024 THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM jsonb_each(value) member WHERE member.key NOT IN('profile','cluster_uid','node_uid','boot_id','pod_uid','container_id','process_id','process_start_time','cgroup_id') OR jsonb_typeof(member.value)<>'string' OR member.value='""'::jsonb) THEN RETURN false;END IF;
 FOREACH key_value IN ARRAY ARRAY['cluster_uid','node_uid','boot_id','pod_uid'] LOOP
  identifier:=value->>key_value;
  IF NOT COALESCE(identifier ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND identifier<>'00000000-0000-0000-0000-000000000000',false) THEN RETURN false;END IF;
 END LOOP;
 IF NOT COALESCE(value->>'container_id' ~ '^(containerd|docker|cri-o)://[0-9a-f]{64}$' AND right(value->>'container_id',64)<>repeat('0',64),false) THEN RETURN false;END IF;
 IF (value ? 'process_id') IS DISTINCT FROM (value ? 'process_start_time') THEN RETURN false;END IF;
 IF value ? 'process_id' THEN
  IF value->>'process_id' !~ '^[1-9][0-9]{0,9}$' OR (value->>'process_id')::numeric>4294967295 THEN RETURN false;END IF;
  IF value->>'process_start_time' !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$' THEN RETURN false;END IF;
  start_value:=(value->>'process_start_time')::timestamptz;
  IF start_value<='1970-01-01T00:00:00Z'::timestamptz OR start_value>event_time_value THEN RETURN false;END IF;
 END IF;
 IF value ? 'cgroup_id' AND (value->>'cgroup_id' !~ '^[1-9][0-9]{0,19}$' OR (value->>'cgroup_id')::numeric>18446744073709551615) THEN RETURN false;END IF;
 RETURN true;
EXCEPTION WHEN invalid_datetime_format OR datetime_field_overflow OR invalid_text_representation OR numeric_value_out_of_range THEN RETURN false;
END
$valid$;
ALTER FUNCTION public.zasp_runtime_candidate_lineage_valid(jsonb,timestamptz) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_candidate_lineage_valid(jsonb,timestamptz) FROM PUBLIC;

-- Both replay and first admission call this AFTER their last blocking operation.
-- The outer transaction owns the correlate row; no additional row locks are
-- acquired here. Failure rolls back all observations and the snapshot insert.
CREATE FUNCTION public.zasp_runtime_candidate_execution_live(organization_value text,workspace_value text,environment_value text,batch_value text,generation_value bigint,worker_value text,lease_token_value text,attempt_value integer,implementation_value text,input_digest_value bytea,archive_digest_value bytea,receipt_digest_value bytea) RETURNS void LANGUAGE plpgsql SET search_path TO pg_catalog, public AS $live$
DECLARE now_value timestamptz:=clock_timestamp();
BEGIN
 IF NOT COALESCE(zasp_runtime_principal_ready('zasp_runtime_correlation_worker') AND zasp_runtime_stage_for_session()='correlate',false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime candidate principal rejected';END IF;
 IF NOT EXISTS(
  SELECT 1 FROM zasp_runtime_stage_work work
  JOIN zasp_runtime_batch_authorities batch ON (batch.organization_id,batch.workspace_id,batch.environment_id,batch.batch_id,batch.batch_generation)=(work.organization_id,work.workspace_id,work.environment_id,work.batch_id,work.batch_generation)
  JOIN zasp_runtime_stage_work predecessor ON (predecessor.organization_id,predecessor.workspace_id,predecessor.environment_id,predecessor.batch_id,predecessor.batch_generation,predecessor.stage,predecessor.state)=(work.organization_id,work.workspace_id,work.environment_id,work.batch_id,work.batch_generation,'index','succeeded')
  JOIN zasp_runtime_deliveries delivery ON (delivery.organization_id,delivery.workspace_id,delivery.environment_id,delivery.batch_id,delivery.batch_generation)=(work.organization_id,work.workspace_id,work.environment_id,work.batch_id,work.batch_generation)
  WHERE (work.organization_id,work.workspace_id,work.environment_id,work.batch_id,work.batch_generation,work.stage,work.state,work.lease_owner,work.lease_token,work.attempt,work.implementation_version,work.input_digest)=(organization_value,workspace_value,environment_value,batch_value,generation_value,'correlate','leased',worker_value,lease_token_value,attempt_value,implementation_value,input_digest_value)
   AND work.lease_expires_at>now_value AND batch.state='processing' AND batch.raw_artifact_checksum=archive_digest_value AND batch.content_digest=archive_digest_value
   AND work.predecessor_digest=predecessor.effect_digest AND predecessor.effect_digest=input_digest_value AND predecessor.input_digest=archive_digest_value AND predecessor.result_digest=receipt_digest_value
   AND delivery.disposition='held' AND delivery.lease_expires_at>now_value AND delivery.visibility_deadline>now_value
 ) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='runtime candidate execution authority expired';END IF;
END
$live$;
ALTER FUNCTION public.zasp_runtime_candidate_execution_live(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_candidate_execution_live(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea) FROM PUBLIC;

CREATE FUNCTION public.zasp_runtime_freeze_candidates(organization_value text,workspace_value text,environment_value text,batch_value text,generation_value bigint,worker_value text,lease_token_value text,attempt_value integer,implementation_value text,input_digest_value bytea,index_receipt_value bytea,archive_value bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $freeze$
DECLARE work_row zasp_runtime_stage_work%ROWTYPE;batch_row zasp_runtime_batch_authorities%ROWTYPE;domain_row zasp_runtime_batch_domains%ROWTYPE;index_row zasp_runtime_stage_work%ROWTYPE;prior zasp_runtime_candidate_snapshots%ROWTYPE;
 receipt jsonb;archive jsonb;event_value jsonb;ordinal_value bigint;archive_digest_value bytea;receipt_digest_value bytea;now_value timestamptz;candidate_values jsonb;body_value bytea;body_digest bytea;possible_count integer;
BEGIN
 IF NOT COALESCE(zasp_runtime_principal_ready('zasp_runtime_correlation_worker') AND zasp_runtime_stage_for_session()='correlate',false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime candidate principal rejected';END IF;
 IF NOT COALESCE(zasp_valid_product_id(organization_value) AND zasp_valid_product_id(workspace_value) AND zasp_valid_product_id(environment_value) AND zasp_valid_product_id(batch_value) AND generation_value>0 AND worker_value ~ '^[a-z][a-z0-9.-]{2,127}$' AND lease_token_value ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$' AND attempt_value BETWEEN 1 AND 100 AND implementation_value='runtime-correlation-v2' AND octet_length(input_digest_value)=32 AND octet_length(index_receipt_value) BETWEEN 1 AND 1048576 AND octet_length(archive_value) BETWEEN 1 AND 67108864,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime candidate input rejected';END IF;
 SELECT * INTO work_row FROM zasp_runtime_stage_work WHERE (organization_id,workspace_id,environment_id,batch_id,batch_generation,stage)=(organization_value,workspace_value,environment_value,batch_value,generation_value,'correlate') FOR UPDATE;
 now_value:=clock_timestamp();
 IF NOT FOUND OR work_row.state<>'leased' OR work_row.lease_owner IS DISTINCT FROM worker_value OR work_row.lease_token IS DISTINCT FROM lease_token_value OR work_row.attempt IS DISTINCT FROM attempt_value OR work_row.implementation_version IS DISTINCT FROM implementation_value OR work_row.input_digest IS DISTINCT FROM input_digest_value OR work_row.lease_expires_at<=now_value THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='runtime candidate lease missing';END IF;
 SELECT * INTO STRICT batch_row FROM zasp_runtime_batch_authorities WHERE (organization_id,workspace_id,environment_id,batch_id,batch_generation)=(organization_value,workspace_value,environment_value,batch_value,generation_value);
 SELECT * INTO STRICT domain_row FROM zasp_runtime_batch_domains WHERE (organization_id,workspace_id,environment_id,batch_id,generation,source_sensor_id,source_kind)=(organization_value,workspace_value,environment_value,batch_value,generation_value,batch_row.sensor_id,batch_row.source_kind);
 SELECT * INTO STRICT index_row FROM zasp_runtime_stage_work WHERE (organization_id,workspace_id,environment_id,batch_id,batch_generation,stage,state)=(organization_value,workspace_value,environment_value,batch_value,generation_value,'index','succeeded');
 archive_digest_value:=digest(archive_value,'sha256');receipt_digest_value:=digest(index_receipt_value,'sha256');
 IF batch_row.state<>'processing' OR batch_row.raw_artifact_checksum IS DISTINCT FROM archive_digest_value OR batch_row.content_digest IS DISTINCT FROM archive_digest_value OR batch_row.raw_artifact_size_bytes IS DISTINCT FROM octet_length(archive_value)::bigint OR index_row.result_digest IS DISTINCT FROM receipt_digest_value OR index_row.effect_digest IS DISTINCT FROM input_digest_value OR work_row.predecessor_digest IS DISTINCT FROM index_row.effect_digest OR index_row.input_digest IS DISTINCT FROM archive_digest_value OR index_row.predecessor_digest IS DISTINCT FROM archive_digest_value THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime candidate predecessor rejected';END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_runtime_stage_work WHERE (organization_id,workspace_id,environment_id,batch_id,batch_generation,stage,state,effect_digest,result_reference,result_version_id)=(organization_value,workspace_value,environment_value,batch_value,generation_value,'archive','succeeded',archive_digest_value,batch_row.raw_artifact_reference,batch_row.raw_artifact_version_id)) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime candidate archive predecessor rejected';END IF;
 receipt:=convert_from(index_receipt_value,'UTF8')::jsonb;archive:=convert_from(archive_value,'UTF8')::jsonb;
 IF NOT COALESCE(receipt->>'schema'='runtime-stage-receipt-v1' AND receipt->>'stage'='index' AND receipt->>'implementation_version'='runtime-index-v1' AND receipt->>'organization_id'=organization_value AND receipt->>'workspace_id'=workspace_value AND receipt->>'environment_id'=environment_value AND receipt->>'batch_id'=batch_value AND receipt->>'generation'=generation_value::text AND receipt->>'effect_digest'=encode(input_digest_value,'hex') AND receipt->>'archive_digest'=encode(archive_digest_value,'hex') AND receipt->>'archive_reference'=batch_row.raw_artifact_reference AND receipt->>'archive_version_id'=batch_row.raw_artifact_version_id AND receipt->>'input_digest'=encode(archive_digest_value,'hex') AND receipt->>'input_reference'=batch_row.raw_artifact_reference AND receipt->>'input_version_id'=batch_row.raw_artifact_version_id AND archive->>'source'=domain_row.source_kind AND jsonb_typeof(archive->'events')='array' AND jsonb_array_length(archive->'events')=batch_row.event_count,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime candidate archive binding rejected';END IF;
 SELECT * INTO prior FROM zasp_runtime_candidate_snapshots WHERE (organization_id,workspace_id,environment_id,batch_id,generation)=(organization_value,workspace_value,environment_value,batch_value,generation_value);
 IF FOUND THEN
  IF prior.archive_digest IS DISTINCT FROM archive_digest_value OR prior.index_receipt_digest IS DISTINCT FROM receipt_digest_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='runtime candidate replay conflict';END IF;
  PERFORM zasp_runtime_candidate_execution_live(organization_value,workspace_value,environment_value,batch_value,generation_value,worker_value,lease_token_value,attempt_value,implementation_value,input_digest_value,archive_digest_value,receipt_digest_value);
  RETURN jsonb_build_object('snapshot',encode(prior.snapshot_body,'hex'),'sha256',encode(prior.snapshot_digest,'hex'),'replayed',true);
 END IF;
 -- Only the two admission identities are locked. Existing candidate identities
 -- are sampled in the selection statement; a later revocation cannot rewrite
 -- an already frozen historical decision. Never lock another batch's stage.
 PERFORM id FROM zasp_sensors WHERE (organization_id,workspace_id,environment_id)=(organization_value,workspace_value,environment_value) AND id IN(domain_row.source_sensor_id,domain_row.runtime_sensor_id) ORDER BY id FOR SHARE;
 now_value:=clock_timestamp();
 IF work_row.lease_expires_at<=now_value OR NOT zasp_runtime_principal_ready('zasp_runtime_correlation_worker') OR NOT EXISTS(SELECT 1 FROM zasp_sensors WHERE (organization_id,workspace_id,environment_id,id,kind,state)=(organization_value,workspace_value,environment_value,domain_row.source_sensor_id,domain_row.source_kind,'active') AND revoked_at IS NULL) OR domain_row.runtime_sensor_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM zasp_sensors WHERE (organization_id,workspace_id,environment_id,id,kind,state)=(organization_value,workspace_value,environment_value,domain_row.runtime_sensor_id,'tetragon','active') AND revoked_at IS NULL) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime candidate enrollment rejected';END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_runtime_deliveries WHERE (organization_id,workspace_id,environment_id,batch_id,batch_generation,disposition)=(organization_value,workspace_value,environment_value,batch_value,generation_value,'held') AND lease_expires_at>now_value AND visibility_deadline>now_value) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='runtime candidate delivery missing';END IF;
 FOR event_value,ordinal_value IN SELECT value,ordinality FROM jsonb_array_elements(archive->'events') WITH ORDINALITY LOOP
  IF event_value ? 'observed_lineage' AND NOT zasp_runtime_candidate_lineage_valid(event_value->'observed_lineage',(event_value->>'event_time')::timestamptz) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime candidate lineage rejected';END IF;
  IF domain_row.source_kind='otlp' AND domain_row.runtime_sensor_id IS NOT NULL AND event_value ? 'observed_lineage' THEN
   INSERT INTO zasp_runtime_candidate_observations(organization_id,workspace_id,environment_id,batch_id,generation,event_ordinal,source_sensor_id,runtime_sensor_id,archive_digest,index_receipt_digest,agent_id,session_id,observed_lineage,event_time,cluster_uid,node_uid,boot_id,pod_uid,container_id)
   VALUES(organization_value,workspace_value,environment_value,batch_value,generation_value,ordinal_value,domain_row.source_sensor_id,domain_row.runtime_sensor_id,archive_digest_value,receipt_digest_value,event_value#>>'{attributes,agent.id}',event_value#>>'{attributes,session.id}',event_value->'observed_lineage',(event_value->>'event_time')::timestamptz,event_value#>>'{observed_lineage,cluster_uid}',event_value#>>'{observed_lineage,node_uid}',event_value#>>'{observed_lineage,boot_id}',event_value#>>'{observed_lineage,pod_uid}',event_value#>>'{observed_lineage,container_id}');
  END IF;
 END LOOP;
 -- Fixed five-minute event-time profile. At most 1,001 indexed observations
 -- per input event; an overflowing union fails closed rather than truncating.
 WITH targets AS MATERIALIZED (SELECT DISTINCT value->'observed_lineage' lineage,(value->>'event_time')::timestamptz event_time FROM jsonb_array_elements(archive->'events') WHERE value ? 'observed_lineage'),
 possible AS MATERIALIZED (
  SELECT selected.* FROM targets target CROSS JOIN LATERAL (
   SELECT observation.batch_id,observation.event_ordinal FROM zasp_runtime_candidate_observations observation
   WHERE (observation.organization_id,observation.workspace_id,observation.environment_id,observation.runtime_sensor_id,observation.cluster_uid,observation.node_uid,observation.boot_id,observation.pod_uid,observation.container_id)=(organization_value,workspace_value,environment_value,domain_row.runtime_sensor_id,target.lineage->>'cluster_uid',target.lineage->>'node_uid',target.lineage->>'boot_id',target.lineage->>'pod_uid',target.lineage->>'container_id')
    AND observation.event_time BETWEEN target.event_time-interval '5 minutes' AND target.event_time+interval '5 minutes'
   ORDER BY observation.event_time,observation.batch_id,observation.event_ordinal LIMIT 1001
  ) selected
 ), unique_rows AS MATERIALIZED (SELECT DISTINCT * FROM possible), selected AS (
  SELECT observation.* FROM unique_rows occurrence
  JOIN zasp_runtime_candidate_observations observation ON (observation.organization_id,observation.workspace_id,observation.environment_id,observation.batch_id,observation.event_ordinal)=(organization_value,workspace_value,environment_value,occurrence.batch_id,occurrence.event_ordinal)
  JOIN zasp_sensors source ON (source.organization_id,source.workspace_id,source.environment_id,source.id,source.kind,source.state)=(observation.organization_id,observation.workspace_id,observation.environment_id,observation.source_sensor_id,'otlp','active') AND source.revoked_at IS NULL
  JOIN zasp_runtime_batch_authorities origin ON (origin.organization_id,origin.workspace_id,origin.environment_id,origin.batch_id,origin.batch_generation)=(observation.organization_id,observation.workspace_id,observation.environment_id,observation.batch_id,observation.generation) AND origin.state IN('processing','succeeded')
  ORDER BY observation.batch_id,observation.event_ordinal LIMIT 1001
 ) SELECT COALESCE(jsonb_agg(jsonb_build_object('batch_id',batch_id,'generation',generation,'event_ordinal',event_ordinal,'source_sensor_id',source_sensor_id,'agent_id',agent_id,'session_id',session_id,'archive_digest',encode(archive_digest,'hex'),'index_receipt_digest',encode(index_receipt_digest,'hex'),'observed_lineage',observed_lineage,'event_time',to_char(event_time AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')) ORDER BY batch_id,event_ordinal),'[]'::jsonb),(SELECT count(*) FROM (SELECT 1 FROM unique_rows LIMIT 1001) bounded)
 INTO candidate_values,possible_count FROM selected;
 -- Detect overflow BEFORE authority filtering: revoked/failed rows must never
 -- occupy the internal bound and hide another viable identity beyond it.
 IF possible_count>1000 OR jsonb_array_length(candidate_values)>1000 THEN RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='runtime candidate snapshot overflow';END IF;
 body_value:=convert_to(jsonb_build_object('schema','runtime-candidate-snapshot-v1','organization_id',organization_value,'workspace_id',workspace_value,'environment_id',environment_value,'batch_id',batch_value,'generation',generation_value,'source_sensor_id',domain_row.source_sensor_id,'runtime_sensor_id',domain_row.runtime_sensor_id,'archive_digest',encode(archive_digest_value,'hex'),'index_receipt_digest',encode(receipt_digest_value,'hex'),'window_seconds',300,'candidates',candidate_values)::text,'UTF8');
 body_digest:=digest(body_value,'sha256');
 IF clock_timestamp()>=work_row.lease_expires_at THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='runtime candidate lease expired';END IF;
 INSERT INTO zasp_runtime_candidate_snapshots(organization_id,workspace_id,environment_id,batch_id,generation,source_sensor_id,source_kind,runtime_sensor_id,archive_digest,index_receipt_digest,snapshot_body,snapshot_digest)
 VALUES(organization_value,workspace_value,environment_value,batch_value,generation_value,domain_row.source_sensor_id,domain_row.source_kind,domain_row.runtime_sensor_id,archive_digest_value,receipt_digest_value,body_value,body_digest);
 PERFORM zasp_runtime_candidate_execution_live(organization_value,workspace_value,environment_value,batch_value,generation_value,worker_value,lease_token_value,attempt_value,implementation_value,input_digest_value,archive_digest_value,receipt_digest_value);
 RETURN jsonb_build_object('snapshot',encode(body_value,'hex'),'sha256',encode(body_digest,'hex'),'replayed',false);
END
$freeze$;
ALTER FUNCTION public.zasp_runtime_freeze_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_freeze_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_freeze_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea) TO zasp_runtime_correlation_worker;

DO $compatibility$
DECLARE definition text;prior text;function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 46','later_release."version" > 47'),'later."version">46','later."version">47'),'later."version" > 46','later."version" > 47');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime candidate compatibility rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;

CREATE FUNCTION public.zasp_production_runtime_candidate_authority_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_production_reconciliation_lane_plan_security_ready()
 AND (SELECT count(*)=2 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname IN('zasp_runtime_candidate_observations','zasp_runtime_candidate_snapshots') AND c.relkind='r' AND c.relowner=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') AND c.relrowsecurity AND c.relforcerowsecurity
  AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) acl WHERE acl.grantee<>c.relowner OR acl.is_grantable)
  AND NOT EXISTS(SELECT 1 FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) acl WHERE a.attrelid=c.oid AND acl.grantee<>c.relowner))
 AND (SELECT count(*)=2 FROM pg_policy WHERE polrelid IN('public.zasp_runtime_candidate_observations'::regclass,'public.zasp_runtime_candidate_snapshots'::regclass) AND polroles=ARRAY[(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority')] AND polcmd='*' AND polpermissive AND pg_get_expr(polqual,polrelid)='true' AND pg_get_expr(polwithcheck,polrelid)='true')
 AND (SELECT count(*)=2 FROM pg_policy WHERE polrelid IN('public.zasp_runtime_candidate_observations'::regclass,'public.zasp_runtime_candidate_snapshots'::regclass))
 AND (SELECT count(*)=2 FROM pg_trigger WHERE tgrelid IN('public.zasp_runtime_candidate_observations'::regclass,'public.zasp_runtime_candidate_snapshots'::regclass) AND tgname IN('zasp_runtime_candidate_observations_immutable','zasp_runtime_candidate_snapshots_immutable') AND tgfoid='public.zasp_runtime_pairing_immutable()'::regprocedure AND tgenabled='O' AND NOT tgisinternal)
 AND NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid IN('public.zasp_runtime_candidate_observations'::regclass,'public.zasp_runtime_candidate_snapshots'::regclass) AND NOT convalidated)
 AND EXISTS(SELECT 1 FROM pg_index WHERE indexrelid='public.zasp_runtime_candidate_lookup_v47'::regclass AND indisvalid AND indisready AND indislive)
 AND (SELECT count(*)=3 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname IN('zasp_runtime_candidate_lineage_valid','zasp_runtime_candidate_execution_live','zasp_runtime_freeze_candidates') AND p.proowner=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') AND p.prosecdef=(p.proname='zasp_runtime_freeze_candidates') AND p.proconfig=ARRAY['search_path=pg_catalog, public']
  AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl WHERE acl.is_grantable OR acl.grantee NOT IN(p.proowner,CASE WHEN p.proname='zasp_runtime_freeze_candidates' THEN (SELECT oid FROM pg_roles WHERE rolname='zasp_runtime_correlation_worker') ELSE p.proowner END)))
 AND has_function_privilege('zasp_runtime_correlation_worker','public.zasp_runtime_freeze_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea)','EXECUTE')
$security$;

CREATE FUNCTION public.zasp_production_runtime_candidate_authority_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','prior',zasp_production_reconciliation_lane_plan_live_fingerprint())
 UNION ALL SELECT concat_ws('|','function',p.proname,pg_get_function_identity_arguments(p.oid),r.rolname,p.prosecdef,COALESCE(p.proconfig::text,''),COALESCE(p.proacl::text,''),pg_get_functiondef(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.proname IN('zasp_runtime_candidate_lineage_valid','zasp_runtime_candidate_execution_live','zasp_runtime_freeze_candidates','zasp_production_runtime_candidate_authority_security_ready','zasp_production_runtime_candidate_authority_readiness','zasp_production_reconciliation_lane_plan_readiness_v46')
 UNION ALL SELECT concat_ws('|','table',c.relname,r.rolname,c.relkind,c.relrowsecurity,c.relforcerowsecurity,COALESCE(c.relacl::text,''),COALESCE(c.reloptions::text,'')) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND c.relname IN('zasp_runtime_candidate_observations','zasp_runtime_candidate_snapshots')
 UNION ALL SELECT concat_ws('|','column',a.attrelid::regclass::text,a.attname,a.attnum,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated,COALESCE(a.attacl::text,''),COALESCE(pg_get_expr(d.adbin,d.adrelid),'')) FROM pg_attribute a LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid IN('public.zasp_runtime_candidate_observations'::regclass,'public.zasp_runtime_candidate_snapshots'::regclass) AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',conrelid::regclass::text,conname,convalidated,pg_get_constraintdef(oid,true)) FROM pg_constraint WHERE conrelid IN('public.zasp_runtime_candidate_observations'::regclass,'public.zasp_runtime_candidate_snapshots'::regclass)
 UNION ALL SELECT concat_ws('|','index',indexrelid::regclass::text,indisvalid,indisready,indislive,pg_get_indexdef(indexrelid)) FROM pg_index WHERE indrelid IN('public.zasp_runtime_candidate_observations'::regclass,'public.zasp_runtime_candidate_snapshots'::regclass)
 UNION ALL SELECT concat_ws('|','policy',tablename,policyname,roles::text,permissive,cmd,qual,with_check) FROM pg_policies WHERE schemaname='public' AND tablename IN('zasp_runtime_candidate_observations','zasp_runtime_candidate_snapshots')
 UNION ALL SELECT concat_ws('|','trigger',tgrelid::regclass::text,tgname,tgenabled,pg_get_triggerdef(oid,true)) FROM pg_trigger WHERE tgrelid IN('public.zasp_runtime_candidate_observations'::regclass,'public.zasp_runtime_candidate_snapshots'::regclass) AND NOT tgisinternal
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
CREATE FUNCTION public.zasp_production_runtime_candidate_authority_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT COALESCE(expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=47 AND name='production_runtime_candidate_authority' AND checksum=expected_checksum) AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>47) AND zasp_production_runtime_candidate_authority_security_ready() AND zasp_production_runtime_candidate_authority_live_fingerprint()=expected_fingerprint,false)
$readiness$;
ALTER FUNCTION public.zasp_production_runtime_candidate_authority_security_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_runtime_candidate_authority_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_runtime_candidate_authority_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_runtime_candidate_authority_security_ready(),public.zasp_production_runtime_candidate_authority_live_fingerprint(),public.zasp_production_runtime_candidate_authority_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_runtime_candidate_authority_readiness(text,text) TO zasp_runtime_correlation_worker,zasp_discovery_worker,zasp_runtime_index_worker,zasp_runtime_coordinator,zasp_discovery_api;

ALTER FUNCTION public.zasp_production_reconciliation_lane_plan_readiness(text,text) RENAME TO zasp_production_reconciliation_lane_plan_readiness_v46;
CREATE FUNCTION public.zasp_production_reconciliation_lane_plan_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $compatibility$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=46 AND name='production_reconciliation_lane_plan' AND checksum=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_reconciliation_lane_plan_fingerprint' AND value=expected_fingerprint) AND zasp_production_runtime_candidate_authority_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=47),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_candidate_authority_fingerprint'))
$compatibility$;
ALTER FUNCTION public.zasp_production_reconciliation_lane_plan_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_reconciliation_lane_plan_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_reconciliation_lane_plan_readiness(text,text) TO zasp_discovery_worker,zasp_runtime_index_worker,zasp_runtime_coordinator,zasp_discovery_api;
INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_runtime_candidate_authority_fingerprint', '4217a4b8fcc9fc6b796012dbfcad58bb25ef0e773bc7f9f62347c1be818d7cc5');
