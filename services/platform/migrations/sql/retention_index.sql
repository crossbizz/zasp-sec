-- Private producer admission. Unlike human reads, raw indexing occurs before
-- canonical SQL projection. The application must authenticate the complete
-- original archive and IDs before this original full-lease retention partition.
CREATE FUNCTION zasp_retention_v1.index_partition(q jsonb) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $partition$
DECLARE result jsonb:='[]';id_value text;BEGIN
 IF q->>'class' IS DISTINCT FROM 'runtime_event' OR jsonb_typeof(q->'event_ids') IS DISTINCT FROM 'array' OR jsonb_array_length(q->'event_ids') NOT BETWEEN 1 AND 1000
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(q->'event_ids') v WHERE jsonb_typeof(v)<>'string' OR NOT public.zasp_valid_product_id(v#>>'{}'))
 OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(q->'event_ids') v GROUP BY v HAVING count(*)>1) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='retention index identities rejected';END IF;
 FOR id_value IN SELECT value FROM jsonb_array_elements_text(q->'event_ids') LOOP
  result:=result||jsonb_build_array(jsonb_build_object('event_id',id_value,'visible',NOT EXISTS(SELECT 1 FROM zasp_retention_v1.tombstones t WHERE(t.organization_id,t.workspace_id,t.environment_id,t.class,t.parent_id,t.source_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id','runtime_event','',id_value))));
 END LOOP;
 RETURN jsonb_build_object('items',result);
END $partition$;
CREATE FUNCTION zasp_retention_v1.check_index_lease(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET timezone='UTC' AS $index$
DECLARE work public.zasp_runtime_stage_work;predecessor public.zasp_runtime_stage_work;BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR NOT zasp_retention_v1.caller_ready('runtime-index','-- retention checksum')
 OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','class','event_ids','batch_id','generation','stage','attempt','implementation_version','predecessor_digest','input_digest','input_reference','input_version_id','lease_expires_at','worker_id','lease_token'])
 OR EXISTS(SELECT 1 FROM jsonb_each(q-ARRAY['event_ids','generation','attempt','predecessor_digest']) v WHERE jsonb_typeof(v.value)<>'string')
 OR jsonb_typeof(q->'generation') IS DISTINCT FROM 'number' OR jsonb_typeof(q->'attempt') IS DISTINCT FROM 'number'
 OR q->>'stage' IS DISTINCT FROM 'index' OR q->>'generation'!~'^[1-9][0-9]{0,17}$' OR q->>'attempt'!~'^([1-9]|[1-9][0-9]|100)$'
 OR q->>'input_digest'!~'^[0-9a-f]{64}$' OR jsonb_typeof(q->'predecessor_digest') NOT IN('string','null')
 OR length(q->>'worker_id') NOT BETWEEN 1 AND 128 OR length(q->>'lease_token') NOT BETWEEN 16 AND 128
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention original index lease required';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-auth79/'||(q->>'organization_id'),0));
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=q->>'organization_id' FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention index organization unavailable';END IF;
 SELECT * INTO work FROM public.zasp_runtime_stage_work WHERE(organization_id,workspace_id,environment_id,batch_id,batch_generation,stage)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'batch_id',(q->>'generation')::bigint,'index') FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention index source unavailable';END IF;
 SELECT * INTO predecessor FROM public.zasp_runtime_stage_work WHERE(organization_id,workspace_id,environment_id,batch_id,batch_generation,stage_order)=(work.organization_id,work.workspace_id,work.environment_id,work.batch_id,work.batch_generation,work.stage_order-1) FOR SHARE;
 IF NOT FOUND OR predecessor.state<>'succeeded' OR (predecessor.result_reference,predecessor.result_version_id) IS DISTINCT FROM(q->>'input_reference',q->>'input_version_id')
 OR work.state<>'leased' OR (work.lease_owner,work.lease_token,work.attempt,work.implementation_version,encode(work.input_digest,'hex'),encode(work.predecessor_digest,'hex')) IS DISTINCT FROM(q->>'worker_id',q->>'lease_token',(q->>'attempt')::integer,q->>'implementation_version',q->>'input_digest',q->>'predecessor_digest')
 OR work.predecessor_digest IS DISTINCT FROM predecessor.effect_digest OR work.input_digest IS DISTINCT FROM predecessor.effect_digest
 OR work.lease_expires_at<=clock_timestamp() OR (q->>'lease_expires_at')::timestamptz<=clock_timestamp() OR work.lease_expires_at<(q->>'lease_expires_at')::timestamptz
 OR NOT zasp_retention_v1.caller_ready('runtime-index','-- retention checksum') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention current index lease rejected';END IF;
 RETURN zasp_retention_v1.index_partition(q);
END $index$;
CREATE FUNCTION zasp_retention_v1.check_session_index_lease(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET timezone='UTC' AS $session_index$
DECLARE work record;receipt public.zasp_runtime_session_projection_receipts;ids text[];BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR NOT zasp_retention_v1.caller_ready('runtime-index','-- retention checksum')
 OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','class','event_ids','batch_id','generation','receipt_digest','receipt_reference','receipt_version','document_ids','attempt','lease_until','worker_id','lease_token','projection_implementation_version','index_family'])
 OR EXISTS(SELECT 1 FROM jsonb_each(q-ARRAY['event_ids','document_ids','generation','attempt']) v WHERE jsonb_typeof(v.value)<>'string')
 OR jsonb_typeof(q->'generation') IS DISTINCT FROM 'number' OR jsonb_typeof(q->'attempt') IS DISTINCT FROM 'number'
 OR q->>'index_family' NOT IN('session-v1','sandbox-v2') OR q->>'projection_implementation_version' NOT IN('runtime-projection-v1','runtime-projection-v2','runtime-projection-v3')
 OR q->>'generation'!~'^[1-9][0-9]{0,17}$' OR q->>'attempt'!~'^([1-9]|[1-9][0-9]|100)$' OR q->>'receipt_digest'!~'^[0-9a-f]{64}$'
 OR jsonb_typeof(q->'document_ids') IS DISTINCT FROM 'array' OR jsonb_array_length(q->'document_ids') NOT BETWEEN 1 AND 1000
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(q->'document_ids') v WHERE jsonb_typeof(v)<>'string' OR v#>>'{}'!~'^[0-9a-f]{64}$')
 OR length(q->>'worker_id') NOT BETWEEN 1 AND 128 OR length(q->>'lease_token') NOT BETWEEN 16 AND 128 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention original session index lease required';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-auth79/'||(q->>'organization_id'),0));
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=q->>'organization_id' FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention session index organization unavailable';END IF;
 IF q->>'index_family'='session-v1' THEN
  SELECT * INTO work FROM public.zasp_runtime_session_search_outbox WHERE(organization_id,workspace_id,environment_id,batch_id,batch_generation)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'batch_id',(q->>'generation')::bigint) FOR SHARE;
 ELSE
  SELECT * INTO work FROM public.zasp_runtime_sandbox_search_outbox WHERE(organization_id,workspace_id,environment_id,batch_id,batch_generation)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'batch_id',(q->>'generation')::bigint) FOR SHARE;
 END IF;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention session index source unavailable';END IF;
 SELECT * INTO receipt FROM public.zasp_runtime_session_projection_receipts WHERE(organization_id,workspace_id,environment_id,batch_id,batch_generation)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'batch_id',(q->>'generation')::bigint) FOR SHARE;
 SELECT array_agg(value ORDER BY ordinal) INTO ids FROM jsonb_array_elements_text(q->'document_ids') WITH ORDINALITY document(value,ordinal);
 IF receipt.batch_id IS NULL OR encode(receipt.receipt_digest,'hex') IS DISTINCT FROM q->>'receipt_digest'
 OR NOT EXISTS(SELECT 1 FROM public.zasp_runtime_stage_work project WHERE(project.organization_id,project.workspace_id,project.environment_id,project.batch_id,project.batch_generation,project.stage)=(receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.batch_id,receipt.batch_generation,'project') AND project.state='succeeded' AND project.implementation_version=q->>'projection_implementation_version' AND project.result_digest=receipt.receipt_digest AND(project.result_reference,project.result_version_id)=(work.receipt_reference,work.receipt_version))
 OR work.state<>'leased' OR(work.worker_id,encode(work.lease_digest,'hex'),work.attempt,encode(work.receipt_digest,'hex'),work.receipt_reference,work.receipt_version,work.document_ids) IS DISTINCT FROM(q->>'worker_id',encode(digest(convert_to(q->>'lease_token','UTF8'),'sha256'),'hex'),(q->>'attempt')::integer,q->>'receipt_digest',q->>'receipt_reference',q->>'receipt_version',ids)
 OR work.lease_until<=clock_timestamp() OR(q->>'lease_until')::timestamptz<=clock_timestamp() OR work.lease_until<(q->>'lease_until')::timestamptz
 OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(q->'event_ids') id WHERE NOT id=ANY(receipt.event_ids))
 OR NOT zasp_retention_v1.caller_ready('runtime-index','-- retention checksum') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention current session index lease rejected';END IF;
 RETURN zasp_retention_v1.index_partition(q);
END $session_index$;

CREATE FUNCTION zasp_retention_v1.index_visibility(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $raw_admit$
BEGIN
 PERFORM zasp_retention_v1.check_index_lease(q);
 RETURN zasp_retention_v1.record_admission(q,'raw-index');
END $raw_admit$;
CREATE FUNCTION zasp_retention_v1.session_index_visibility(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $session_admit$
BEGIN
 PERFORM zasp_retention_v1.check_session_index_lease(q);
 RETURN zasp_retention_v1.record_admission(q,CASE q->>'index_family' WHEN 'session-v1' THEN 'session-index-v1' ELSE 'session-index-v2' END);
END $session_admit$;
