-- Supplementary effect accounting never rewrites the original source receipt.
CREATE TABLE zasp_retention_v1.index_partitions(organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,batch_id text NOT NULL,generation bigint NOT NULL,kind text NOT NULL CHECK(kind IN('raw-index','session-index-v1','session-index-v2')),attempt integer NOT NULL,worker_id text NOT NULL,lease_token_digest text NOT NULL,partition_digest text NOT NULL UNIQUE,binding jsonb NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(organization_id,workspace_id,environment_id,batch_id,generation,kind,attempt));
CREATE TABLE zasp_retention_v1.partition_completions(partition_digest text PRIMARY KEY REFERENCES zasp_retention_v1.index_partitions(partition_digest),completion jsonb NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp());
-- Each actual producer authorization mints a distinct durable admission. A
-- concurrent execution sharing an original lease cannot settle another one's
-- still in-flight HTTP write by reusing a partition receipt.
CREATE TABLE zasp_retention_v1.index_admissions(admission_id text PRIMARY KEY CHECK(admission_id~'^[0-9a-f]{64}$'),login_oid oid NOT NULL,kind text NOT NULL CHECK(kind IN('raw-index','session-index-v1','session-index-v2')),binding jsonb NOT NULL,items jsonb NOT NULL,admitted_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE zasp_retention_v1.admission_settlements(admission_id text PRIMARY KEY REFERENCES zasp_retention_v1.index_admissions,partition_digest text NOT NULL REFERENCES zasp_retention_v1.index_partitions(partition_digest),recorded_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE FUNCTION zasp_retention_v1.record_admission(q jsonb,kind_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $admission$
DECLARE nonce_value text;result_value jsonb;binding_value jsonb;BEGIN
 result_value:=zasp_retention_v1.index_partition(q);
 nonce_value:=encode(gen_random_bytes(32),'hex');
 binding_value:=(q-ARRAY['lease_token','lease_expires_at','lease_until','admission_ids'])||jsonb_build_object('lease_token_digest',encode(digest(convert_to(q->>'lease_token','UTF8'),'sha256'),'hex'));
 INSERT INTO zasp_retention_v1.index_admissions VALUES(nonce_value,session_user::regrole,kind_value,binding_value,result_value->'items',clock_timestamp());
 RETURN result_value||jsonb_build_object('admission_id',nonce_value);
END $admission$;
CREATE FUNCTION zasp_retention_v1.record_partition(q jsonb,session_value boolean) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET timezone='UTC' AS $record_partition$
DECLARE lease_value jsonb;binding_value jsonb;kind_value text;ids text[];written text[];suppressed text[];events text[];expected_ids text[];result_value text;retained zasp_retention_v1.index_partitions;item text;BEGIN
 lease_value:=q-ARRAY['full_document_ids','written_document_ids','suppressed_document_ids','original_content_digest','provider_content_digest','admission_ids'];
 IF jsonb_typeof(q) IS DISTINCT FROM 'object' OR q->>'original_content_digest'!~'^[0-9a-f]{64}$' OR q->>'provider_content_digest'!~'^[0-9a-f]{64}$'
 OR jsonb_typeof(q->'original_content_digest') IS DISTINCT FROM 'string' OR jsonb_typeof(q->'provider_content_digest') IS DISTINCT FROM 'string'
 OR jsonb_typeof(q->'admission_ids') IS DISTINCT FROM 'array' OR jsonb_array_length(q->'admission_ids') NOT BETWEEN 1 AND 1000
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(q->'admission_ids') v WHERE jsonb_typeof(v)<>'string' OR v#>>'{}'!~'^[0-9a-f]{64}$')
 OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(q->'admission_ids') v GROUP BY v HAVING count(*)>1)
 OR jsonb_typeof(q->'full_document_ids') IS DISTINCT FROM 'array' OR jsonb_typeof(q->'written_document_ids') IS DISTINCT FROM 'array' OR jsonb_typeof(q->'suppressed_document_ids') IS DISTINCT FROM 'array'
 OR jsonb_array_length(q->'full_document_ids') NOT BETWEEN 1 AND 1000 OR jsonb_array_length(q->'written_document_ids')>1000 OR jsonb_array_length(q->'suppressed_document_ids')>1000
 OR EXISTS(SELECT 1 FROM jsonb_array_elements((q->'full_document_ids')||(q->'written_document_ids')||(q->'suppressed_document_ids')) v WHERE jsonb_typeof(v)<>'string') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='retention write partition rejected';END IF;
 IF session_value THEN PERFORM zasp_retention_v1.check_session_index_lease(lease_value);kind_value:=CASE q->>'index_family' WHEN 'session-v1' THEN 'session-index-v1' ELSE 'session-index-v2' END;
 ELSE PERFORM zasp_retention_v1.check_index_lease(lease_value);kind_value:='raw-index';END IF;
 SELECT array_agg(value ORDER BY ordinal) INTO ids FROM jsonb_array_elements_text(q->'full_document_ids') WITH ORDINALITY entry(value,ordinal);
 SELECT coalesce(array_agg(value ORDER BY ordinal),'{}') INTO written FROM jsonb_array_elements_text(q->'written_document_ids') WITH ORDINALITY entry(value,ordinal);
 SELECT coalesce(array_agg(value ORDER BY ordinal),'{}') INTO suppressed FROM jsonb_array_elements_text(q->'suppressed_document_ids') WITH ORDINALITY entry(value,ordinal);
 SELECT array_agg(value ORDER BY ordinal) INTO events FROM jsonb_array_elements_text(q->'event_ids') WITH ORDINALITY entry(value,ordinal);
 IF session_value THEN
  expected_ids:=public.zasp_runtime_session_search_document_ids(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'batch_id',(q->>'generation')::bigint,events);
  IF to_jsonb(ids) IS DISTINCT FROM q->'document_ids' THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='retention full session document binding changed';END IF;
 ELSE
  SELECT array_agg('evt_'||encode(digest(convert_to(q->>'organization_id','UTF8')||decode('00','hex')||convert_to(q->>'workspace_id','UTF8')||decode('00','hex')||convert_to(q->>'environment_id','UTF8')||decode('00','hex')||convert_to(q->>'batch_id','UTF8')||decode('00','hex')||convert_to(value,'UTF8')||decode('00','hex')||convert_to(q->>'input_digest','UTF8'),'sha256'),'hex') ORDER BY ordinal) INTO expected_ids FROM unnest(events) WITH ORDINALITY entry(value,ordinal);
 END IF;
 IF ids IS DISTINCT FROM expected_ids OR cardinality(written)+cardinality(suppressed)<>cardinality(ids)
 OR EXISTS(SELECT 1 FROM unnest(written||suppressed) v GROUP BY v HAVING count(*)<>1)
 OR EXISTS(SELECT 1 FROM unnest(written||suppressed) v WHERE NOT v=ANY(ids))
 OR written IS DISTINCT FROM ARRAY(SELECT value FROM unnest(ids) WITH ORDINALITY entry(value,ordinal) WHERE value=ANY(written) ORDER BY ordinal)
 OR suppressed IS DISTINCT FROM ARRAY(SELECT value FROM unnest(ids) WITH ORDINALITY entry(value,ordinal) WHERE value=ANY(suppressed) ORDER BY ordinal)
 OR EXISTS(SELECT 1 FROM unnest(ids,events) pair(doc,event_id) WHERE doc=ANY(suppressed) AND NOT EXISTS(SELECT 1 FROM zasp_retention_v1.tombstones t WHERE(t.organization_id,t.workspace_id,t.environment_id,t.class,t.parent_id,t.source_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id','runtime_event','',pair.event_id)))
 THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='retention write partition content changed';END IF;
 -- Keep only a token digest. Heartbeat extension must not alter an otherwise
 -- identical effect receipt; authoritative live deadlines were checked above.
 binding_value:=(q-ARRAY['lease_token','lease_expires_at','lease_until','admission_ids'])||jsonb_build_object('lease_token_digest',encode(digest(convert_to(q->>'lease_token','UTF8'),'sha256'),'hex'));

 -- Only this private execution's exact nonces may account for its effects.
 IF EXISTS(SELECT 1 FROM jsonb_array_elements_text(q->'admission_ids') wanted(id) LEFT JOIN zasp_retention_v1.index_admissions a ON a.admission_id=wanted.id WHERE a.admission_id IS NULL OR a.login_oid<>session_user::regrole OR a.kind<>kind_value
 OR(a.binding-'event_ids') IS DISTINCT FROM(binding_value-ARRAY['event_ids','full_document_ids','written_document_ids','suppressed_document_ids','original_content_digest','provider_content_digest'])
 OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(a.binding->'event_ids') v WHERE NOT v=ANY(events)))
 OR EXISTS(SELECT 1 FROM unnest(events) original_id WHERE NOT EXISTS(SELECT 1 FROM zasp_retention_v1.index_admissions a CROSS JOIN LATERAL jsonb_array_elements(a.items) admitted WHERE a.admission_id IN(SELECT value FROM jsonb_array_elements_text(q->'admission_ids')) AND admitted->>'event_id'=original_id))
 OR EXISTS(SELECT 1 FROM unnest(ids,events) pair(doc,event_id) WHERE doc=ANY(written) AND NOT EXISTS(SELECT 1 FROM zasp_retention_v1.index_admissions a CROSS JOIN LATERAL jsonb_array_elements(a.items) allowed WHERE a.admission_id IN(SELECT value FROM jsonb_array_elements_text(q->'admission_ids')) AND allowed->>'event_id'=pair.event_id AND allowed->'visible'='true'::jsonb))
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention private producer admission required';END IF;
 result_value:=encode(digest(convert_to(binding_value::text,'UTF8'),'sha256'),'hex');
 INSERT INTO zasp_retention_v1.index_partitions VALUES(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'batch_id',(q->>'generation')::bigint,kind_value,(q->>'attempt')::integer,q->>'worker_id',binding_value->>'lease_token_digest',result_value,binding_value,clock_timestamp()) ON CONFLICT DO NOTHING;
 SELECT * INTO STRICT retained FROM zasp_retention_v1.index_partitions WHERE(organization_id,workspace_id,environment_id,batch_id,generation,kind,attempt)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'batch_id',(q->>'generation')::bigint,kind_value,(q->>'attempt')::integer);
 IF retained.binding IS DISTINCT FROM binding_value OR retained.partition_digest IS DISTINCT FROM result_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='retention write partition replay conflict';END IF;
 INSERT INTO zasp_retention_v1.admission_settlements SELECT value,result_value,clock_timestamp() FROM jsonb_array_elements_text(q->'admission_ids') ON CONFLICT DO NOTHING;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements_text(q->'admission_ids') v WHERE NOT EXISTS(SELECT 1 FROM zasp_retention_v1.admission_settlements a WHERE a.admission_id=v.value AND a.partition_digest=result_value)) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='retention admission settlement changed';END IF;
 IF session_value THEN PERFORM zasp_retention_v1.check_session_index_lease(lease_value);ELSE PERFORM zasp_retention_v1.check_index_lease(lease_value);END IF;
 RETURN jsonb_build_object('partition_digest',result_value);
END $record_partition$;
CREATE FUNCTION zasp_retention_v1.record_index_partition(q jsonb) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $raw_partition$ SELECT zasp_retention_v1.record_partition(q,false) $raw_partition$;
CREATE FUNCTION zasp_retention_v1.record_session_index_partition(q jsonb) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $session_partition$ SELECT zasp_retention_v1.record_partition(q,true) $session_partition$;
CREATE FUNCTION zasp_retention_v1.current_finish_stage(organization_value text,workspace_value text,environment_value text,batch_value text,generation_value bigint,worker_value text,lease_token_value text,attempt_value integer,input_digest_value bytea,implementation_value text,outcome_value text,effect_digest_value bytea,result_reference_value text,result_version_value text,result_digest_value bytea,error_class_value text,retry_after_seconds integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $finish_raw$
DECLARE partition_value zasp_retention_v1.index_partitions;completion_value jsonb;result_value jsonb;BEGIN
 IF NOT zasp_retention_v1.caller_ready('runtime-index','-- retention checksum') OR public.zasp_runtime_stage_for_session() IS DISTINCT FROM 'index' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention index completion authority required';END IF;
 IF outcome_value='succeeded' THEN
  SELECT * INTO partition_value FROM zasp_retention_v1.index_partitions WHERE(organization_id,workspace_id,environment_id,batch_id,generation,kind,attempt)=(organization_value,workspace_value,environment_value,batch_value,generation_value,'raw-index',attempt_value) FOR SHARE;
  IF NOT FOUND OR(partition_value.worker_id,partition_value.lease_token_digest,partition_value.binding->>'input_digest',partition_value.binding->>'implementation_version',partition_value.binding->>'original_content_digest') IS DISTINCT FROM(worker_value,encode(digest(convert_to(lease_token_value,'UTF8'),'sha256'),'hex'),encode(input_digest_value,'hex'),implementation_value,encode(effect_digest_value,'hex')) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='confirmed retention partition required';END IF;
 END IF;
 result_value:=zasp_authorization80_runtime.runtime_finish_stage(organization_value,workspace_value,environment_value,batch_value,generation_value,worker_value,lease_token_value,attempt_value,input_digest_value,implementation_value,outcome_value,effect_digest_value,result_reference_value,result_version_value,result_digest_value,error_class_value,retry_after_seconds);
 IF outcome_value='succeeded' THEN
  completion_value:=jsonb_build_object('result_reference',result_reference_value,'result_version_id',result_version_value,'result_digest',encode(result_digest_value,'hex'),'native_result',result_value);
  INSERT INTO zasp_retention_v1.partition_completions VALUES(partition_value.partition_digest,completion_value,clock_timestamp()) ON CONFLICT DO NOTHING;
  IF NOT EXISTS(SELECT 1 FROM zasp_retention_v1.partition_completions WHERE partition_digest=partition_value.partition_digest AND completion=completion_value) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='retention completion replay conflict';END IF;
 END IF;
 IF NOT zasp_retention_v1.caller_ready('runtime-index','-- retention checksum') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention index completion authority changed';END IF;
 RETURN result_value;
END $finish_raw$;
CREATE FUNCTION zasp_retention_v1.finish_session_index(organization_value text,workspace_value text,environment_value text,batch_value text,generation_value bigint,worker_value text,token_value text,attempt_value integer,receipt_digest_value bytea,outcome_value text,document_values text[],retry_seconds integer,sandbox_value boolean) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $finish_session$
DECLARE partition_value zasp_retention_v1.index_partitions;result_value jsonb;kind_value text;BEGIN
 IF NOT zasp_retention_v1.caller_ready('runtime-index','-- retention checksum') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention session completion authority required';END IF;
 kind_value:=CASE sandbox_value WHEN true THEN 'session-index-v2' ELSE 'session-index-v1' END;
 IF outcome_value='indexed' THEN
  SELECT * INTO partition_value FROM zasp_retention_v1.index_partitions WHERE(organization_id,workspace_id,environment_id,batch_id,generation,kind,attempt)=(organization_value,workspace_value,environment_value,batch_value,generation_value,kind_value,attempt_value) FOR SHARE;
  IF NOT FOUND OR(partition_value.worker_id,partition_value.lease_token_digest,partition_value.binding->>'receipt_digest',partition_value.binding->'full_document_ids') IS DISTINCT FROM(worker_value,encode(digest(convert_to(token_value,'UTF8'),'sha256'),'hex'),encode(receipt_digest_value,'hex'),to_jsonb(document_values)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='confirmed retention session partition required';END IF;
 END IF;
 IF sandbox_value THEN result_value:=zasp_authorization80_runtime.runtime_sandbox_search_finish(organization_value,workspace_value,environment_value,batch_value,generation_value,worker_value,token_value,attempt_value,receipt_digest_value,outcome_value,document_values,retry_seconds);
 ELSE result_value:=public.zasp_runtime_session_search_finish(organization_value,workspace_value,environment_value,batch_value,generation_value,worker_value,token_value,attempt_value,receipt_digest_value,outcome_value,document_values,retry_seconds);END IF;
 IF outcome_value='indexed' THEN
  INSERT INTO zasp_retention_v1.partition_completions VALUES(partition_value.partition_digest,result_value,clock_timestamp()) ON CONFLICT DO NOTHING;
  IF NOT EXISTS(SELECT 1 FROM zasp_retention_v1.partition_completions WHERE partition_digest=partition_value.partition_digest AND completion=result_value) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='retention session completion replay conflict';END IF;
 END IF;
 IF NOT zasp_retention_v1.caller_ready('runtime-index','-- retention checksum') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention session completion authority changed';END IF;
 RETURN result_value;
END $finish_session$;
CREATE FUNCTION zasp_retention_v1.current_session_search_finish(organization_value text,workspace_value text,environment_value text,batch_value text,generation_value bigint,worker_value text,token_value text,attempt_value integer,receipt_digest_value bytea,outcome_value text,document_values text[],retry_seconds integer) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $finish_v1$ SELECT zasp_retention_v1.finish_session_index(organization_value,workspace_value,environment_value,batch_value,generation_value,worker_value,token_value,attempt_value,receipt_digest_value,outcome_value,document_values,retry_seconds,false) $finish_v1$;
CREATE FUNCTION zasp_retention_v1.current_sandbox_search_finish(organization_value text,workspace_value text,environment_value text,batch_value text,generation_value bigint,worker_value text,token_value text,attempt_value integer,receipt_digest_value bytea,outcome_value text,document_values text[],retry_seconds integer) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $finish_v2$ SELECT zasp_retention_v1.finish_session_index(organization_value,workspace_value,environment_value,batch_value,generation_value,worker_value,token_value,attempt_value,receipt_digest_value,outcome_value,document_values,retry_seconds,true) $finish_v2$;
