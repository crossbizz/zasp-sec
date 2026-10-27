-- Physical index cleanup is separate from logical expiry. Original immutable
-- pending intents remain evidence. Unknown or unavailable producer history
-- keeps an intent pending even after an observed empty provider index.
CREATE TABLE zasp_retention_v1.cleanup_scheduler(singleton boolean PRIMARY KEY CHECK(singleton),sequence bigint NOT NULL CHECK(sequence>=0));
INSERT INTO zasp_retention_v1.cleanup_scheduler VALUES(true,0);
CREATE TABLE zasp_retention_v1.cleanup_queue(organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,source_id text NOT NULL,kind text NOT NULL,last_served bigint NOT NULL DEFAULT 0,active_claim text,complete boolean NOT NULL DEFAULT false,last_outcome text NOT NULL DEFAULT 'pending',PRIMARY KEY(organization_id,workspace_id,environment_id,source_id,kind),FOREIGN KEY(organization_id,workspace_id,environment_id,source_id,kind) REFERENCES zasp_retention_v1.pending_cleanup);
CREATE TABLE zasp_retention_v1.cleanup_claims(claim_id text PRIMARY KEY CHECK(claim_id~'^[0-9a-f]{64}$'),organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,source_id text NOT NULL,source_digest text NOT NULL,kind text NOT NULL,cycle_key text NOT NULL,login_oid oid NOT NULL,worker_id text NOT NULL,token_digest text NOT NULL,lease_until timestamptz NOT NULL,claimed_at timestamptz NOT NULL DEFAULT clock_timestamp(),history_digest text NOT NULL CHECK(history_digest~'^[0-9a-f]{64}$'),history_max_completion_at timestamptz,FOREIGN KEY(organization_id,workspace_id,environment_id,source_id,kind) REFERENCES zasp_retention_v1.pending_cleanup);
CREATE TABLE zasp_retention_v1.cleanup_authorizations(id text PRIMARY KEY,claim_id text NOT NULL REFERENCES zasp_retention_v1.cleanup_claims,authorized_at timestamptz NOT NULL,history_digest text NOT NULL,history_max_completion_at timestamptz);
CREATE TABLE zasp_retention_v1.cleanup_observations(claim_id text PRIMARY KEY REFERENCES zasp_retention_v1.cleanup_claims,observation jsonb NOT NULL,drained boolean NOT NULL,complete boolean NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE FUNCTION zasp_retention_v1.require_maintenance() RETURNS void LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $maintenance$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR NOT(zasp_retention_v1.caller_ready('sweep','-- retention checksum') OR zasp_retention_v1.caller_ready('runtime-index','-- retention checksum')) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current retention maintenance authority required';END IF;
END $maintenance$;
CREATE FUNCTION zasp_retention_v1.writers_drained(o text,w text,e text) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $drain$
BEGIN
 -- A later successful attempt cannot attest an earlier unknown HTTP request.
 -- Every attempted original work item needs its own durable partition AND
 -- completion; lease expiry, retryable/failed states and missing history never
 -- infer quiescence. Pending attempt0 can only start through tombstone gates.
 IF EXISTS(SELECT 1 FROM zasp_retention_v1.index_admissions a WHERE(a.binding->>'organization_id',a.binding->>'workspace_id',a.binding->>'environment_id')=(o,w,e)
  AND EXISTS(SELECT 1 FROM jsonb_array_elements(a.items) item WHERE item->'visible'='true'::jsonb)
  AND NOT EXISTS(SELECT 1 FROM zasp_retention_v1.admission_settlements s WHERE s.admission_id=a.admission_id)) THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM public.zasp_runtime_stage_work work WHERE(work.organization_id,work.workspace_id,work.environment_id,work.stage)=(o,w,e,'index') AND(work.state IN('leased','unknown') OR EXISTS(SELECT 1 FROM generate_series(1,work.attempt) original_attempt WHERE NOT EXISTS(SELECT 1 FROM zasp_retention_v1.index_partitions p JOIN zasp_retention_v1.partition_completions c USING(partition_digest) WHERE(p.organization_id,p.workspace_id,p.environment_id,p.batch_id,p.generation,p.kind,p.attempt)=(o,w,e,work.batch_id,work.batch_generation,'raw-index',original_attempt))))) THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM public.zasp_runtime_session_search_outbox work WHERE(work.organization_id,work.workspace_id,work.environment_id)=(o,w,e) AND(work.state='leased' OR EXISTS(SELECT 1 FROM generate_series(1,work.attempt) original_attempt WHERE NOT EXISTS(SELECT 1 FROM zasp_retention_v1.index_partitions p JOIN zasp_retention_v1.partition_completions c USING(partition_digest) WHERE(p.organization_id,p.workspace_id,p.environment_id,p.batch_id,p.generation,p.kind,p.attempt)=(o,w,e,work.batch_id,work.batch_generation,'session-index-v1',original_attempt))))) THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM public.zasp_runtime_sandbox_search_outbox work WHERE(work.organization_id,work.workspace_id,work.environment_id)=(o,w,e) AND(work.state='leased' OR EXISTS(SELECT 1 FROM generate_series(1,work.attempt) original_attempt WHERE NOT EXISTS(SELECT 1 FROM zasp_retention_v1.index_partitions p JOIN zasp_retention_v1.partition_completions c USING(partition_digest) WHERE(p.organization_id,p.workspace_id,p.environment_id,p.batch_id,p.generation,p.kind,p.attempt)=(o,w,e,work.batch_id,work.batch_generation,'session-index-v2',original_attempt))))) THEN RETURN false;END IF;
 RETURN true;
END $drain$;
CREATE FUNCTION zasp_retention_v1.writer_history(o text,w text,e text) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public SET timezone='UTC' AS $history$
 WITH facts(v) AS(
 SELECT concat_ws('|','raw-work',(to_jsonb(work)-'lease_token')::text) FROM public.zasp_runtime_stage_work work WHERE(work.organization_id,work.workspace_id,work.environment_id,work.stage)=(o,w,e,'index')
 UNION ALL SELECT concat_ws('|','session-v1',to_jsonb(work)::text) FROM public.zasp_runtime_session_search_outbox work WHERE(work.organization_id,work.workspace_id,work.environment_id)=(o,w,e)
 UNION ALL SELECT concat_ws('|','session-v2',to_jsonb(work)::text) FROM public.zasp_runtime_sandbox_search_outbox work WHERE(work.organization_id,work.workspace_id,work.environment_id)=(o,w,e)
 UNION ALL SELECT concat_ws('|','admission',to_jsonb(a)::text) FROM zasp_retention_v1.index_admissions a WHERE(a.binding->>'organization_id',a.binding->>'workspace_id',a.binding->>'environment_id')=(o,w,e)
 UNION ALL SELECT concat_ws('|','admission-settlement',to_jsonb(s)::text) FROM zasp_retention_v1.admission_settlements s JOIN zasp_retention_v1.index_admissions a USING(admission_id) WHERE(a.binding->>'organization_id',a.binding->>'workspace_id',a.binding->>'environment_id')=(o,w,e)
 UNION ALL SELECT concat_ws('|','partition',to_jsonb(p)::text) FROM zasp_retention_v1.index_partitions p WHERE(p.organization_id,p.workspace_id,p.environment_id)=(o,w,e)
 UNION ALL SELECT concat_ws('|','partition-completion',to_jsonb(c)::text) FROM zasp_retention_v1.partition_completions c JOIN zasp_retention_v1.index_partitions p USING(partition_digest) WHERE(p.organization_id,p.workspace_id,p.environment_id)=(o,w,e)
 ) SELECT jsonb_build_object('history_digest',encode(digest(convert_to(coalesce(string_agg(v,E'\n' ORDER BY v),''),'UTF8'),'sha256'),'hex'),'max_completion_at',(SELECT max(c.recorded_at) FROM zasp_retention_v1.partition_completions c JOIN zasp_retention_v1.index_partitions p USING(partition_digest) WHERE(p.organization_id,p.workspace_id,p.environment_id)=(o,w,e))) FROM facts
$history$;
CREATE FUNCTION zasp_retention_v1.claim_matches(q jsonb,c zasp_retention_v1.cleanup_claims) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,public AS $claim_matches$
 SELECT coalesce((q->>'claim_id',q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'event_id',q->>'source_digest',q->>'kind',q->>'worker_id')=(c.claim_id,c.organization_id,c.workspace_id,c.environment_id,c.source_id,c.source_digest,c.kind,c.worker_id)
 AND q->>'lease_token'~'^[0-9a-f]{64}$' AND encode(digest(convert_to(q->>'lease_token','UTF8'),'sha256'),'hex')=c.token_digest AND q->>'lease_until'=to_char(c.lease_until AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),false)
$claim_matches$;
CREATE FUNCTION zasp_retention_v1.cleanup_claim(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET timezone='UTC' AS $claim$
DECLARE queue_value zasp_retention_v1.cleanup_queue;intent zasp_retention_v1.pending_cleanup;active zasp_retention_v1.cleanup_claims;sequence_value bigint;token_value text;claim_value text;deadline timestamptz;policy jsonb;history_value jsonb;BEGIN
 IF NOT zasp_retention_v1.caller_ready('runtime-index','-- retention checksum') OR current_setting('transaction_isolation')<>'read committed' OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['worker_id']) OR jsonb_typeof(q->'worker_id')<>'string' OR length(q->>'worker_id') NOT BETWEEN 1 AND 128 OR q->>'worker_id'<>btrim(q->>'worker_id') OR q->>'worker_id'~'[[:cntrl:]]' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention cleanup principal required';END IF;
 SELECT sequence INTO STRICT sequence_value FROM zasp_retention_v1.cleanup_scheduler WHERE singleton FOR UPDATE;
 SELECT queue.* INTO queue_value FROM zasp_retention_v1.cleanup_queue queue LEFT JOIN zasp_retention_v1.cleanup_claims c ON c.claim_id=queue.active_claim WHERE NOT queue.complete AND(c.claim_id IS NULL OR c.lease_until<=clock_timestamp() OR EXISTS(SELECT 1 FROM zasp_retention_v1.cleanup_observations observation WHERE observation.claim_id=c.claim_id)) ORDER BY queue.last_served,queue.organization_id,queue.workspace_id,queue.environment_id,queue.source_id,queue.kind LIMIT 1 FOR UPDATE OF queue;
 IF NOT FOUND THEN RETURN jsonb_build_object('found',false,'claim',NULL);END IF;
 IF sequence_value>=9223372036854775807 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='retention cleanup scheduler exhausted';END IF;
 UPDATE zasp_retention_v1.cleanup_scheduler SET sequence=sequence_value+1 WHERE singleton;
 UPDATE zasp_retention_v1.cleanup_queue SET last_served=sequence_value+1 WHERE(organization_id,workspace_id,environment_id,source_id,kind)=(queue_value.organization_id,queue_value.workspace_id,queue_value.environment_id,queue_value.source_id,queue_value.kind);
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-auth79/'||queue_value.organization_id,0));
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=queue_value.organization_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention cleanup organization unavailable';END IF;
 policy:=zasp_retention_v1.policy_lock(queue_value.organization_id,queue_value.workspace_id,queue_value.environment_id);
 IF NOT zasp_retention_v1.caller_ready('runtime-index','-- retention checksum') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention cleanup principal changed';END IF;
 IF policy IS NULL OR policy->>'deletion_enabled' IS DISTINCT FROM 'true' THEN
  UPDATE zasp_retention_v1.cleanup_queue SET last_outcome='policy_disabled' WHERE(organization_id,workspace_id,environment_id,source_id,kind)=(queue_value.organization_id,queue_value.workspace_id,queue_value.environment_id,queue_value.source_id,queue_value.kind);
  RETURN jsonb_build_object('found',false,'claim',NULL);
 END IF;
 SELECT * INTO STRICT intent FROM zasp_retention_v1.pending_cleanup WHERE(organization_id,workspace_id,environment_id,source_id,kind)=(queue_value.organization_id,queue_value.workspace_id,queue_value.environment_id,queue_value.source_id,queue_value.kind);
 IF NOT EXISTS(SELECT 1 FROM zasp_retention_v1.tombstones t WHERE(t.organization_id,t.workspace_id,t.environment_id,t.class,t.parent_id,t.source_id,t.source_digest)=(intent.organization_id,intent.workspace_id,intent.environment_id,'runtime_event','',intent.source_id,intent.source_digest)) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='retention cleanup intent changed';END IF;
 IF NOT zasp_retention_v1.writers_drained(intent.organization_id,intent.workspace_id,intent.environment_id) THEN
  UPDATE zasp_retention_v1.cleanup_queue SET last_outcome='writer_history_pending' WHERE(organization_id,workspace_id,environment_id,source_id,kind)=(intent.organization_id,intent.workspace_id,intent.environment_id,intent.source_id,intent.kind);
  RETURN jsonb_build_object('found',false,'claim',NULL);
 END IF;
 history_value:=zasp_retention_v1.writer_history(intent.organization_id,intent.workspace_id,intent.environment_id);
 IF NOT zasp_retention_v1.caller_ready('runtime-index','-- retention checksum') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='cleanup claim authority changed';END IF;
 token_value:=encode(gen_random_bytes(32),'hex');claim_value:=encode(gen_random_bytes(32),'hex');deadline:=clock_timestamp()+interval '30 seconds';
 INSERT INTO zasp_retention_v1.cleanup_claims VALUES(claim_value,intent.organization_id,intent.workspace_id,intent.environment_id,intent.source_id,intent.source_digest,intent.kind,intent.cycle_key,session_user::regrole,q->>'worker_id',encode(digest(convert_to(token_value,'UTF8'),'sha256'),'hex'),deadline,clock_timestamp(),history_value->>'history_digest',(history_value->>'max_completion_at')::timestamptz);
 UPDATE zasp_retention_v1.cleanup_queue SET active_claim=claim_value,last_outcome='claimed' WHERE(organization_id,workspace_id,environment_id,source_id,kind)=(intent.organization_id,intent.workspace_id,intent.environment_id,intent.source_id,intent.kind);
 RETURN jsonb_build_object('found',true,'claim',jsonb_build_object('claim_id',claim_value,'organization_id',intent.organization_id,'workspace_id',intent.workspace_id,'environment_id',intent.environment_id,'event_id',intent.source_id,'source_digest',intent.source_digest,'kind',intent.kind,'worker_id',q->>'worker_id','lease_token',token_value,'lease_until',to_char(deadline AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')));
END $claim$;
CREATE FUNCTION zasp_retention_v1.cleanup_authorize(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $authorize$
DECLARE c zasp_retention_v1.cleanup_claims;queue_value zasp_retention_v1.cleanup_queue;policy jsonb;history_value jsonb;BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR NOT zasp_retention_v1.caller_ready('runtime-index','-- retention checksum') OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['claim_id','organization_id','workspace_id','environment_id','event_id','source_digest','kind','worker_id','lease_token','lease_until']) OR EXISTS(SELECT 1 FROM jsonb_each(q) v WHERE jsonb_typeof(v.value)<>'string') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current cleanup claim required';END IF;
 PERFORM 1 FROM zasp_retention_v1.cleanup_scheduler WHERE singleton FOR UPDATE;
 SELECT * INTO c FROM zasp_retention_v1.cleanup_claims WHERE claim_id=q->>'claim_id';
 IF NOT FOUND OR c.login_oid<>session_user::regrole OR NOT zasp_retention_v1.claim_matches(q,c) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='cleanup claim binding rejected';END IF;
 SELECT * INTO STRICT queue_value FROM zasp_retention_v1.cleanup_queue WHERE(organization_id,workspace_id,environment_id,source_id,kind)=(c.organization_id,c.workspace_id,c.environment_id,c.source_id,c.kind) FOR UPDATE;
 IF queue_value.active_claim IS DISTINCT FROM c.claim_id OR queue_value.complete OR c.lease_until<=clock_timestamp() OR EXISTS(SELECT 1 FROM zasp_retention_v1.cleanup_observations WHERE claim_id=c.claim_id) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='cleanup claim no longer current';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-auth79/'||c.organization_id,0));
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=c.organization_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='cleanup organization unavailable';END IF;
 policy:=zasp_retention_v1.policy_lock(c.organization_id,c.workspace_id,c.environment_id);
 history_value:=zasp_retention_v1.writer_history(c.organization_id,c.workspace_id,c.environment_id);
 IF policy IS NULL OR policy->>'deletion_enabled' IS DISTINCT FROM 'true' OR NOT zasp_retention_v1.writers_drained(c.organization_id,c.workspace_id,c.environment_id) OR history_value->>'history_digest' IS DISTINCT FROM c.history_digest OR(history_value->>'max_completion_at')::timestamptz IS DISTINCT FROM c.history_max_completion_at THEN RETURN jsonb_build_object('authorized',false);END IF;
 IF NOT zasp_retention_v1.caller_ready('runtime-index','-- retention checksum') OR c.lease_until<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='cleanup forward authority expired';END IF;
 INSERT INTO zasp_retention_v1.cleanup_authorizations VALUES(encode(gen_random_bytes(32),'hex'),c.claim_id,clock_timestamp(),c.history_digest,c.history_max_completion_at);
 RETURN jsonb_build_object('authorized',true);
END $authorize$;
CREATE FUNCTION zasp_retention_v1.cleanup_settle(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $settle_cleanup$
DECLARE c zasp_retention_v1.cleanup_claims;queue_value zasp_retention_v1.cleanup_queue;observed jsonb;prior zasp_retention_v1.cleanup_observations;drained_value boolean;complete_value boolean;history_value jsonb;BEGIN
 -- Captured settlement is not a fresh forward grant. Exact captured loginOID,
 -- nonce, immutable intent and first outcome remain mandatory after revocation.
 IF NOT zasp_retention_v1.independent_seal('-- retention checksum') OR NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_authorization80_runtime.catalog_ready() OR current_setting('transaction_isolation')<>'read committed' OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['claim_id','organization_id','workspace_id','environment_id','event_id','source_digest','kind','worker_id','lease_token','lease_until','index_observed_empty','documents_checked','absent'])
 OR jsonb_typeof(q->'index_observed_empty') IS DISTINCT FROM 'boolean' OR jsonb_typeof(q->'documents_checked') IS DISTINCT FROM 'number' OR jsonb_typeof(q->'absent') IS DISTINCT FROM 'number' OR q->>'documents_checked'!~'^([0-9]|[1-5][0-9]|6[0-4])$' OR q->>'absent'!~'^([0-9]|[1-5][0-9]|6[0-4])$' OR(q->>'absent')::integer>(q->>'documents_checked')::integer OR(q->'index_observed_empty'='true'::jsonb AND(q->>'absent')::integer<>(q->>'documents_checked')::integer) OR EXISTS(SELECT 1 FROM jsonb_each(q-ARRAY['index_observed_empty','documents_checked','absent']) v WHERE jsonb_typeof(v.value)<>'string') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='cleanup captured observation rejected';END IF;
 PERFORM 1 FROM zasp_retention_v1.cleanup_scheduler WHERE singleton FOR UPDATE;
 SELECT * INTO c FROM zasp_retention_v1.cleanup_claims WHERE claim_id=q->>'claim_id';
 IF NOT FOUND OR c.login_oid<>session_user::regrole OR NOT zasp_retention_v1.claim_matches(q-ARRAY['index_observed_empty','documents_checked','absent'],c) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='cleanup captured binding rejected';END IF;
 observed:=jsonb_build_object('index_observed_empty',q->'index_observed_empty','documents_checked',q->'documents_checked','absent',q->'absent');
 SELECT * INTO prior FROM zasp_retention_v1.cleanup_observations WHERE claim_id=c.claim_id;
 IF FOUND THEN IF prior.observation IS DISTINCT FROM observed THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='cleanup observation replay changed';END IF;RETURN jsonb_build_object('recorded',true,'drained',prior.drained,'complete',prior.complete);END IF;
 SELECT * INTO STRICT queue_value FROM zasp_retention_v1.cleanup_queue WHERE(organization_id,workspace_id,environment_id,source_id,kind)=(c.organization_id,c.workspace_id,c.environment_id,c.source_id,c.kind) FOR UPDATE;
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-auth79/'||c.organization_id,0));
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=c.organization_id FOR UPDATE;
 history_value:=zasp_retention_v1.writer_history(c.organization_id,c.workspace_id,c.environment_id);
 drained_value:=FOUND AND zasp_retention_v1.writers_drained(c.organization_id,c.workspace_id,c.environment_id) AND history_value->>'history_digest'=c.history_digest AND(history_value->>'max_completion_at')::timestamptz IS NOT DISTINCT FROM c.history_max_completion_at;
 complete_value:=drained_value AND q->'index_observed_empty'='true'::jsonb AND queue_value.active_claim=c.claim_id AND NOT queue_value.complete AND EXISTS(SELECT 1 FROM zasp_retention_v1.cleanup_authorizations WHERE claim_id=c.claim_id AND history_digest=c.history_digest AND history_max_completion_at IS NOT DISTINCT FROM c.history_max_completion_at);
 INSERT INTO zasp_retention_v1.cleanup_observations VALUES(c.claim_id,observed,drained_value,complete_value,clock_timestamp());
 IF queue_value.active_claim=c.claim_id THEN UPDATE zasp_retention_v1.cleanup_queue SET complete=complete_value,last_outcome=CASE WHEN complete_value THEN 'observed_empty_drained' WHEN NOT drained_value THEN 'writer_history_pending' ELSE 'provider_pending' END WHERE(organization_id,workspace_id,environment_id,source_id,kind)=(c.organization_id,c.workspace_id,c.environment_id,c.source_id,c.kind);END IF;
 RETURN jsonb_build_object('recorded',true,'drained',drained_value,'complete',complete_value);
END $settle_cleanup$;
