-- Private preflight implementation. Callers own scope, source and safety locks;
-- neither a worker nor an API login receives direct EXECUTE on this core.
DO $preflight$
DECLARE d text;
BEGIN
 d:=pg_get_functiondef('public.zasp_attack_lab_preflight(text,text,text,text)'::regprocedure);
 d:=replace(d,'FUNCTION public.zasp_attack_lab_preflight(','FUNCTION public.zasp_sa_attack_lab_preflight_core(');
 d:=replace(d,'NOT zasp_security_agent_principal_ready(''zasp_security_agent_api'') OR ','');
 d:=replace(d,'transaction_timestamp()','clock_timestamp()');
 EXECUTE d;
END $preflight$;

-- Canonical lock order: organization admission, parent run/step/definition,
-- test definition, source run/attempt, environment, target, credential binding.
-- The exact-source path never resolves a newer run after operator approval.
CREATE FUNCTION public.zasp_sa_attack_lab_source(o text,w text,e text,test_value text,version_value bigint,exact_source text DEFAULT NULL)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $source$
DECLARE d public.zasp_red_team_definitions%ROWTYPE;r public.zasp_red_team_runs%ROWTYPE;a public.zasp_red_team_attempts%ROWTYPE;
 target_value jsonb;class_value text;binding_expires timestamptz;decision jsonb;
BEGIN
 SELECT * INTO d FROM public.zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version,enabled)=(o,w,e,test_value,version_value,true) FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='attack lab preflight unavailable';END IF;
 SELECT candidate.* INTO r FROM public.zasp_red_team_runs candidate
 JOIN public.zasp_red_team_attempts attempt ON (attempt.organization_id,attempt.workspace_id,attempt.environment_id,attempt.run_id,attempt.attempt)=(candidate.organization_id,candidate.workspace_id,candidate.environment_id,candidate.run_id,candidate.attempt)
 WHERE (candidate.organization_id,candidate.workspace_id,candidate.environment_id,candidate.definition_id,candidate.definition_version,candidate.state,candidate.verdict)=(o,w,e,test_value,version_value,'complete','fail')
 AND (exact_source IS NULL OR candidate.run_id=exact_source)
 AND candidate.completed_at<=clock_timestamp()
 AND attempt.verdict='fail' AND attempt.completed_at=candidate.completed_at AND attempt.input_digest=candidate.input_digest
 AND (attempt.evidence_key,attempt.evidence_version_id,attempt.evidence_checksum,attempt.evidence_size,attempt.evidence_reference)=(candidate.evidence_key,candidate.evidence_version_id,candidate.evidence_checksum,candidate.evidence_size,candidate.evidence_reference)
 AND octet_length(candidate.evidence_checksum)=32 AND candidate.evidence_checksum<>decode(repeat('00',32),'hex') AND candidate.evidence_size>0 AND candidate.evidence_version_id<>''
 ORDER BY candidate.completed_at DESC,candidate.run_id DESC LIMIT 1 FOR UPDATE OF candidate;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='attack lab preflight unavailable';END IF;
 SELECT * INTO a FROM public.zasp_red_team_attempts WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=(o,w,e,r.run_id,r.attempt) FOR SHARE;
 IF NOT FOUND OR a.verdict IS DISTINCT FROM 'fail' OR (a.completed_at,a.input_digest,a.evidence_key,a.evidence_version_id,a.evidence_checksum,a.evidence_size,a.evidence_reference) IS DISTINCT FROM (r.completed_at,r.input_digest,r.evidence_key,r.evidence_version_id,r.evidence_checksum,r.evidence_size,r.evidence_reference) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab source changed';END IF;
 class_value:=public.zasp_production_security_agent_run_context_lock_env(o,w,e);
 target_value:=public.zasp_production_security_agent_run_context_lock_target(o,w,e,d.target_id);
 SELECT valid_until INTO binding_expires FROM public.zasp_attack_lab_credential_bindings WHERE (organization_id,workspace_id,environment_id,target_id,credential_reference,state)=(o,w,e,d.target_id,target_value->'attributes'->'red_team'->>'credential_reference','active') AND credential_class=d.safety->>'credential_class' AND credential_class IN('test_write','read_only') FOR SHARE;
 IF NOT FOUND OR NOT COALESCE(class_value IN('development','test','staging') AND class_value=d.safety->>'environment' AND target_value->>'state'='active' AND (target_value->>'fresh_until')::timestamptz>clock_timestamp() AND binding_expires>clock_timestamp(),false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab safety unavailable';END IF;
 decision:=public.zasp_sa_attack_lab_preflight_core(o,w,e,r.run_id);
 IF (decision->>'decision_expires_at')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab safety expired';END IF;
 RETURN jsonb_build_object('source_run_id',r.run_id,'source_attempt',r.attempt,'definition_id',d.definition_id,'definition_version',d.version,'target_id',d.target_id,'target_kind',d.target_kind,
  'source_input_digest',encode(r.input_digest,'hex'),'source_completed_at',r.completed_at,
  'source_evidence',jsonb_build_object('key',r.evidence_key,'version',r.evidence_version_id,'sha256',encode(r.evidence_checksum,'hex'),'size',r.evidence_size,'reference',r.evidence_reference),
  'preflight',decision);
END $source$;

-- Extract, rather than impersonate, the registered API implementation. The API
-- entrypoints retain their signatures and ACLs; both callers share these cores.
DO $cores$
DECLARE name_value text;signature_value text;d text;anchor text;replacement text;
BEGIN
 FOREACH name_value IN ARRAY ARRAY['create_run','cancel_run'] LOOP
  signature_value:='zasp_attack_lab_'||name_value||CASE WHEN name_value='create_run' THEN '(text,text,text,text,text,text,text,bytea,text)' ELSE '(text,text,text,text,text,text,bigint,text)' END;
  PERFORM public.zasp_sa_attack_lab_save(signature_value);
  d:=pg_get_functiondef(('public.'||signature_value)::regprocedure);
  d:=replace(d,'FUNCTION public.zasp_attack_lab_'||name_value||'(','FUNCTION public.zasp_sa_attack_lab_'||name_value||'_core(');
  anchor:='NOT zasp_security_agent_principal_ready(''zasp_security_agent_api'') OR ';
  IF (length(d)-length(replace(d,anchor,'')))/length(anchor)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack lab core predecessor rejected';END IF;
  d:=replace(replace(d,anchor,''),'transaction_timestamp()','clock_timestamp()');
  IF name_value='create_run' THEN
   anchor:=' SELECT * INTO STRICT source_row FROM zasp_red_team_runs';
   replacement:=$check$ PERFORM public.zasp_sa_attack_lab_source(organization_value,workspace_value,environment_value,definition_id,definition_version,source_run_value) FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,source_run_value);
$check$;
   d:=replace(d,anchor,replacement||anchor);
   d:=replace(d,';RETURN result_value;',';'||replacement||'RETURN result_value;');
  END IF;
  EXECUTE d;
 END LOOP;
END $cores$;
CREATE OR REPLACE FUNCTION public.zasp_attack_lab_create_run(organization_value text,workspace_value text,environment_value text,actor_value text,idempotency_value text,run_value text,source_run_value text,decision_digest_value bytea,correlation_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $api$
BEGIN
 IF NOT public.zasp_security_agent_principal_ready('zasp_security_agent_api') OR NOT public.zasp_sa_attack_lab_guard() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='attack lab admission unavailable';END IF;
 RETURN public.zasp_sa_attack_lab_create_run_core(organization_value,workspace_value,environment_value,actor_value,idempotency_value,run_value,source_run_value,decision_digest_value,correlation_value);
END $api$;
CREATE OR REPLACE FUNCTION public.zasp_attack_lab_cancel_run(organization_value text,workspace_value text,environment_value text,actor_value text,idempotency_value text,run_value text,expected_version_value bigint,correlation_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $api$
BEGIN
 IF NOT public.zasp_security_agent_principal_ready('zasp_security_agent_api') OR NOT public.zasp_sa_attack_lab_guard() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='attack lab cancellation unavailable';END IF;
 RETURN public.zasp_sa_attack_lab_cancel_run_core(organization_value,workspace_value,environment_value,actor_value,idempotency_value,run_value,expected_version_value,correlation_value);
END $api$;
