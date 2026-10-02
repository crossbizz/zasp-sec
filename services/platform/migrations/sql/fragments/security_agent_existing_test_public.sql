-- Closed historical proof projection. No application role can read the link
-- table or these helpers; the existing API run-context wrapper is the boundary.
CREATE FUNCTION public.zasp_production_security_agent_existing_tests_public_artifact(value jsonb)
RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $artifact$
 SELECT jsonb_build_object('reference_digest',encode(digest(convert_to(value->>'reference','UTF8'),'sha256'),'hex'),
  'version_id',value->'version_id','sha256',value->'sha256','size_bytes',value->'size_bytes')
$artifact$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_public_artifact(jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_public_artifact(jsonb) FROM PUBLIC;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_public_attempt(value jsonb)
RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $attempt$
 SELECT CASE WHEN value IS NULL OR value='null'::jsonb THEN 'null'::jsonb ELSE jsonb_build_object(
  'run_id',value->'run_id','attempt',value->'attempt','input_digest',value->'input_digest',
  'input_artifact',public.zasp_production_security_agent_existing_tests_public_artifact(value->'input_artifact'),
  'output_artifact',public.zasp_production_security_agent_existing_tests_public_artifact(value->'output_artifact')) END
$attempt$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_public_attempt(jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_public_attempt(jsonb) FROM PUBLIC;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_public_step(o text,w text,e text,r text,step_value jsonb)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $step$
DECLARE link_row public.zasp_security_agent_test_links%ROWTYPE;effect_row public.zasp_security_agent_effects%ROWTYPE;
 input_value bytea;proof_value jsonb;receipt_value jsonb;snapshot_value jsonb;proof_bytes bytea;
 verification_value jsonb:='null'::jsonb;checks_value jsonb;
BEGIN
 SELECT * INTO link_row FROM public.zasp_security_agent_test_links
 WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,step_value->>'step_id');
 IF NOT FOUND THEN
  IF step_value->'effect'<>'null'::jsonb AND step_value->>'action' IN('run_test','rerun_test') THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test public proof unavailable';END IF;
  RETURN step_value;
 END IF;
 SELECT * INTO STRICT effect_row FROM public.zasp_security_agent_effects
 WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,link_row.step_id,link_row.action_key);
 SELECT input_digest INTO STRICT input_value FROM public.zasp_security_agent_steps
 WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,link_row.step_id,link_row.action_key);
 IF step_value->>'action' IS DISTINCT FROM link_row.action_key
  OR step_value->'arguments'->>'target_id' IS DISTINCT FROM link_row.test_definition_id
  OR step_value->'arguments'->'expected_version' IS DISTINCT FROM to_jsonb(link_row.test_definition_version)
  OR input_value IS DISTINCT FROM link_row.input_digest OR effect_row.input_digest IS DISTINCT FROM link_row.input_digest
  OR effect_row.outcome_id IS NULL
  OR step_value->'effect'->>'outcome_id' IS DISTINCT FROM effect_row.outcome_id
  OR step_value->'effect'->>'result_digest' IS DISTINCT FROM 'sha256:'||encode(effect_row.result_digest,'hex') THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test public proof unavailable';
 END IF;
 IF link_row.reconcile_state='settled' THEN
  proof_value:=link_row.reconcile_settlement->'proof';receipt_value:=link_row.reconcile_settlement->'receipt';
  snapshot_value:=link_row.reconcile_settlement->'snapshot';
  proof_bytes:=decode(link_row.reconcile_settlement->>'proof_hex','hex');
  IF proof_value IS NULL OR receipt_value IS NULL OR snapshot_value IS NULL OR proof_bytes IS NULL
   OR octet_length(proof_bytes) NOT BETWEEN 1 AND 65536
   OR convert_from(proof_bytes,'UTF8')::jsonb IS DISTINCT FROM proof_value
   OR digest(proof_bytes,'sha256') IS DISTINCT FROM effect_row.result_digest
   OR receipt_value->>'proof_sha256' IS DISTINCT FROM encode(effect_row.result_digest,'hex')
   OR receipt_value->>'run_id' IS DISTINCT FROM r OR receipt_value->>'step_id' IS DISTINCT FROM link_row.step_id
   OR receipt_value->>'effect_state' IS DISTINCT FROM effect_row.state
   OR receipt_value->>'outcome' IS DISTINCT FROM proof_value->>'outcome'
   OR receipt_value->>'reason' IS DISTINCT FROM proof_value->>'reason'
   OR snapshot_value->>'run_id' IS DISTINCT FROM r OR snapshot_value->>'step_id' IS DISTINCT FROM link_row.step_id
   OR snapshot_value->>'organization_id' IS DISTINCT FROM o OR snapshot_value->>'workspace_id' IS DISTINCT FROM w
   OR snapshot_value->>'environment_id' IS DISTINCT FROM e
   OR snapshot_value->>'definition_id' IS DISTINCT FROM link_row.test_definition_id
   OR snapshot_value->'definition_version' IS DISTINCT FROM to_jsonb(link_row.test_definition_version)
   OR snapshot_value->>'target_id' IS DISTINCT FROM link_row.target_id OR snapshot_value->>'target_kind' IS DISTINCT FROM link_row.target_kind
   OR snapshot_value->'categories' IS DISTINCT FROM link_row.test_categories
   OR snapshot_value->'after'->>'run_id' IS DISTINCT FROM link_row.test_run_id
   OR proof_value ? 'after' AND proof_value->'after'->>'run_id' IS DISTINCT FROM link_row.test_run_id
   OR proof_value ? 'before' AND proof_value->'before'->>'run_id' IS DISTINCT FROM link_row.baseline->>'run_id' THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test public proof unavailable';
  END IF;
  PERFORM public.zasp_production_security_agent_existing_tests_validate_proof(snapshot_value,proof_value,
   link_row.cancellation_outcome IS NOT DISTINCT FROM 'outcome_unknown'
   OR COALESCE((snapshot_value->'after'->>'outcome_unknown')::boolean,false)
   OR COALESCE((snapshot_value->'before'->>'outcome_unknown')::boolean,false));
  SELECT COALESCE(jsonb_agg(jsonb_build_object('category',item->'category','check_id',item->'check_id',
   'prompt_digest',item->'prompt_digest','assertion_digest',item->'assertion_digest',
   'before_protected',item->'before_protected','after_protected',item->'after_protected',
   'before_http_status',item->'before_http_status','after_http_status',item->'after_http_status') ORDER BY ord),'[]'::jsonb)
  INTO checks_value FROM jsonb_array_elements(COALESCE(proof_value->'checks','[]'::jsonb)) WITH ORDINALITY checks(item,ord);
  verification_value:=jsonb_build_object('outcome',proof_value->'outcome','reason',proof_value->'reason',
   'proof_digest','sha256:'||encode(effect_row.result_digest,'hex'),
   'before',public.zasp_production_security_agent_existing_tests_public_attempt(proof_value->'before'),
   'after',public.zasp_production_security_agent_existing_tests_public_attempt(proof_value->'after'),'checks',checks_value);
 ELSIF link_row.reconcile_settlement IS NOT NULL THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test public proof unavailable';
 END IF;
 RETURN step_value||jsonb_build_object('existing_test',jsonb_build_object(
  'definition_id',link_row.test_definition_id,'definition_version',link_row.test_definition_version,'test_run_id',link_row.test_run_id,
  'state',CASE WHEN link_row.reconcile_state='settled' THEN 'settled' ELSE 'pending' END,
  'cancellation_outcome',link_row.cancellation_outcome,'verification',verification_value));
EXCEPTION WHEN OTHERS THEN
 RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test public proof unavailable';
END
$step$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_public_step(text,text,text,text,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_public_step(text,text,text,text,jsonb) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.zasp_production_security_agent_existing_tests_run_context(o text,w text,e text,r text,expected_checksum text,expected_fingerprint text)
RETURNS SETOF jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $read$
DECLARE envelope jsonb;steps_value jsonb;
BEGIN
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false) THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent principal unavailable';
 END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test read release unavailable';
 END IF;
 FOR envelope IN SELECT * FROM public.zasp_production_security_agent_existing_tests_run_context_core(o,w,e,r) LOOP
  SELECT COALESCE(jsonb_agg(public.zasp_production_security_agent_existing_tests_public_step(o,w,e,r,item) ORDER BY ord),'[]'::jsonb)
  INTO steps_value FROM jsonb_array_elements(envelope->'action_details'->'steps') WITH ORDINALITY steps(item,ord);
  RETURN NEXT jsonb_set(envelope,'{action_details,steps}',steps_value);
 END LOOP;
END
$read$;
-- CREATE OR REPLACE retains the original guarded API-only ACL and owner.
