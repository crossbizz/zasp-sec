-- The native owner supplies the canonical source and request digest. No body,
-- context or provider response is copied into metadata or the signed proof.
CREATE FUNCTION zasp_authorization80_worker.planning78_source(phase text,q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $planning_source$
DECLARE x zasp_temporal78.run_owners%ROWTYPE;j zasp_temporal78.planning_jobs%ROWTYPE;reference_value jsonb;f jsonb;compensation boolean:=phase IN('reconcile','late_usage','recovery');
BEGIN
 IF phase IS NULL OR phase NOT IN('state','load','prepare','start','result','settle','artifacts','admit','reconcile','late_usage','recovery') OR octet_length(q::text)>524288
 OR phase='state' AND NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','definition_version'])
 OR phase<>'state' AND(q->>'operation' IS DISTINCT FROM phase OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','definition_version','operation']||CASE WHEN phase IN('load','recovery') THEN ARRAY[]::text[] ELSE ARRAY['payload'] END)) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='worker planning request rejected';END IF;
 SELECT * INTO x FROM zasp_temporal78.run_owners WHERE(organization_id,workspace_id,environment_id,run_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id') AND to_jsonb(definition_version)=q->'definition_version';
 IF x.run_id IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker planning owner changed';END IF;
 reference_value:=jsonb_build_object('organization_id',x.organization_id,'workspace_id',x.workspace_id,'environment_id',x.environment_id,'run_id',x.run_id,'definition_version',x.definition_version,'input_digest',x.input_digest);
 IF compensation THEN reference_value:=reference_value||jsonb_build_object('reason','workflow_failed');END IF;
 f:=zasp_authorization80_worker.finding_source(CASE WHEN compensation THEN 'finding.cleanup' ELSE 'finding.planning' END,reference_value);
 SELECT * INTO j FROM zasp_temporal78.planning_jobs WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) FOR SHARE;
 IF compensation AND(j.run_id IS NULL OR j.state NOT IN('loaded','prepared','started','completed','settled','artifacts','needs_human')) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker captured planning unavailable';END IF;
 RETURN f||jsonb_build_object('planning_phase',phase,'request_digest',encode(digest(convert_to(q::text,'UTF8'),'sha256'),'hex'),'job_digest',zasp_authorization80_worker.planner_job_digest(to_jsonb(j)));
END $planning_source$;

CREATE FUNCTION zasp_authorization80_worker.require_planning78(phase text,q jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $planning_require$
DECLARE envelope json;body_bytes bytea;proof jsonb;source_value jsonb;k bytea;purpose_value text;now_ms bigint:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;revision_value zasp_authorization79.organizations%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='worker planning requires read committed';END IF;
 IF phase IS NULL OR phase NOT IN('state','load','prepare','start','result','settle','artifacts','admit','reconcile','late_usage','recovery') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker planning phase rejected';END IF;
 purpose_value:=CASE WHEN phase IN('reconcile','late_usage','recovery') THEN 'captured-compensation' ELSE 'worker-forward' END;
 IF NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal68.principal_ready(CASE purpose_value WHEN 'worker-forward' THEN 'zasp_temporal_executor' ELSE 'zasp_temporal_compensation' END) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker planning role rejected';END IF;
 envelope:=NULLIF(current_setting('zasp.worker_proof',true),'')::json;
 IF envelope IS NULL OR octet_length(envelope::text)>65536 OR json_typeof(envelope)<>'object' OR NOT zasp_authorization80.unique_json(envelope) OR(SELECT count(*) FROM json_each(envelope))<>3 OR EXISTS(SELECT 1 FROM json_each(envelope) WHERE key NOT IN('body','version','mac') OR json_typeof(value)<>'string') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker proof rejected';END IF;
 SELECT key INTO k FROM zasp_authorization80_worker.verifiers WHERE purpose=purpose_value AND version=envelope->>'version' FOR SHARE;
 body_bytes:=decode(envelope->>'body','base64');
 IF k IS NULL OR octet_length(body_bytes) NOT BETWEEN 1 AND 32768 OR envelope->>'mac' IS DISTINCT FROM encode(hmac(convert_to('zasp-authorization-'||purpose_value||'-v1','UTF8')||decode('00','hex')||body_bytes,k,'sha256'),'hex') OR NOT zasp_authorization80.unique_json(convert_from(body_bytes,'UTF8')::json) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker proof rejected';END IF;
 proof:=convert_from(body_bytes,'UTF8')::jsonb;
 IF NOT COALESCE(proof->>'purpose'=purpose_value AND proof->>'key_version'=envelope->>'version' AND proof->>'operation'='finding.planning.'||phase AND proof->'request'='null'::jsonb AND proof->>'session_user'=session_user AND(proof->>'issued_at')::bigint<=now_ms+5000 AND(proof->>'expires_at')::bigint>now_ms AND(proof->>'expires_at')::bigint-(proof->>'issued_at')::bigint BETWEEN 1 AND 60000,false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker planning proof binding rejected';END IF;
 SELECT * INTO revision_value FROM zasp_authorization79.organizations WHERE organization_id=q->>'organization_id' FOR UPDATE;
 IF revision_value.organization_id IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker captured organization missing';END IF;
 IF purpose_value='worker-forward' THEN
  IF revision_value.desired<>revision_value.applied OR proof->'revision' IS DISTINCT FROM jsonb_build_object('organization_id',revision_value.organization_id,'desired',revision_value.desired,'applied',revision_value.applied,'generation',revision_value.generation,'store_id',revision_value.store_id,'model_id',revision_value.model_id) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker authorization revision changed';END IF;
 END IF;
 source_value:=zasp_authorization80_worker.planning78_source(phase,q);
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF NOT COALESCE((proof->>'issued_at')::bigint<=now_ms+5000 AND(proof->>'expires_at')::bigint>now_ms AND(proof->>'expires_at')::bigint-(proof->>'issued_at')::bigint BETWEEN 1 AND 60000,false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker proof expired after source locks';END IF;
 IF proof->'facts' IS DISTINCT FROM source_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker planning source changed';END IF;
EXCEPTION WHEN data_exception THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker proof rejected';
END $planning_require$;

CREATE FUNCTION zasp_authorization80_worker.planning78_recovery_result(j jsonb) RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,public AS $recovery_result$
 SELECT jsonb_build_object('run_id',j->'run_id','state',j->'state','reservation_id',j->'reservation_id','request_digest',j->'request_digest','credential_digest',j#>'{lookup_request,credential_digest}','usage_known',j->'result_value'->'usage' IS NOT NULL AND j->'result_value'->'usage'<>'null'::jsonb,'has_response',j->'raw_result' IS NOT NULL AND j->'raw_result'<>'null'::jsonb)
$recovery_result$;

CREATE FUNCTION zasp_authorization80_worker.planning78_recovery(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $recovery$
DECLARE j zasp_temporal78.planning_jobs%ROWTYPE;BEGIN
 PERFORM zasp_authorization80_worker.require_planning78('recovery',q);
 SELECT * INTO STRICT j FROM zasp_temporal78.planning_jobs WHERE(organization_id,workspace_id,environment_id,run_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id');
 RETURN zasp_authorization80_worker.planning78_recovery_result(to_jsonb(j));
END $recovery$;
