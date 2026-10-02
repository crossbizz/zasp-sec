-- Reuse the published lease, trigger, accounting, idempotency and savepoint
-- protocol by private clones. The new source snapshot is trusted SQL input;
-- the model candidate remains action/index/target_id only.
CREATE FUNCTION public.zasp_sa_attack_lab_planner_binding(o text,w text,e text,a text,v bigint) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $binding$
DECLARE b jsonb;ref jsonb;
BEGIN
 SELECT body INTO b FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,a,v) AND deleted_at IS NULL FOR SHARE;
 ref:=b->'existing_test';
 IF NOT COALESCE(b->'allowed_actions'='["start_attack_lab"]'::jsonb AND b->>'verification_kind'='attack_lab_run' AND jsonb_typeof(ref)='object' AND ref ?& ARRAY['definition_id','definition_version'] AND ref-ARRAY['definition_id','definition_version']='{}'::jsonb AND public.zasp_valid_product_id(ref->>'definition_id') AND ref->>'definition_version' ~ '^([1-9][0-9]{0,5}|1000000)$',false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab planner reference changed';END IF;
 RETURN public.zasp_sa_attack_lab_source(o,w,e,ref->>'definition_id',(ref->>'definition_version')::bigint,NULL);
END $binding$;

-- Only the initial trusted source lookup may produce this bounded terminal
-- reason. It grants no plan/effect authority and cannot turn an outage into it.
CREATE FUNCTION public.zasp_sa_attack_lab_preflight_stop(o text,w text,e text,r text,worker_value text,lease_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $stop$
DECLARE rr public.zasp_security_agent_runs%ROWTYPE;deadline timestamptz;body_value jsonb;
BEGIN
 IF NOT public.zasp_security_agent_principal_ready('zasp_security_agent_worker') OR NOT public.zasp_sa_attack_lab_guard() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='attack lab stop authority unavailable';END IF;
 IF NOT public.zasp_security_agent_budget_can_start(o,w,e,r,worker_value,lease_value) THEN RETURN public.zasp_security_agent_budget_context_stop(o,w,e,r);END IF;
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id,state,lease_owner,lease_token)=(o,w,e,r,'planning',worker_value,lease_value) AND lease_expires_at>clock_timestamp() FOR UPDATE;
 IF NOT FOUND OR EXISTS(SELECT 1 FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) OR EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab stop lease changed';END IF;
 SELECT deadline_at INTO STRICT deadline FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 body_value:=jsonb_build_object('reason','attack_lab_preflight_unavailable','run_id',r,'attempt',rr.attempt);
 INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,actor_id,event_kind,event_digest,body)
 VALUES(o,w,e,public.zasp_discovery_canonical_id(o,w,e,'attack_lab_preflight_stop_audit',r),public.zasp_discovery_canonical_id(o,w,e,'attack_lab_preflight_stop_correlation',r),r,worker_value,'preflight_unavailable',digest(convert_to(body_value::text,'UTF8'),'sha256'),body_value);
 IF rr.lease_expires_at<=clock_timestamp() OR deadline<=clock_timestamp() OR NOT public.zasp_sa_attack_lab_guard() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab stop authority expired';END IF;
 UPDATE public.zasp_security_agent_runs SET state='needs_human',last_error_code='attack_lab_preflight_unavailable',version=version+1,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=clock_timestamp(),completed_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) RETURNING * INTO rr;
 RETURN jsonb_build_object('attack_lab_preflight_stop',jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'attempt',rr.attempt,'version',rr.version,'state',rr.state,'reason',rr.last_error_code));
END $stop$;
DO $planner$
DECLARE p record;d text;name_value text;callee text;signature_value text;anchor text;oldprefix text:='zasp_production_security_agent_existing_tests_';newprefix text:='zasp_sa_attack_lab_';
 names text[]:=ARRAY['planner_context','reserve_core','reserve_planner','recheck_context','prepare_core','finish_prepare','prepare_run','accept_planner','fail_planner'];
BEGIN
 PERFORM set_config('check_function_bodies','off',true);
 FOREACH name_value IN ARRAY names LOOP
  SELECT oid,pg_get_function_identity_arguments(oid) args INTO STRICT p FROM pg_proc WHERE pronamespace='public'::regnamespace AND proname=oldprefix||name_value;
  d:=pg_get_functiondef(p.oid);
  FOREACH callee IN ARRAY names LOOP d:=replace(d,oldprefix||callee||'(',newprefix||callee||'(');END LOOP;
  d:=replace(d,'public.zasp_production_security_agent_run_context_test_binding(','public.zasp_sa_attack_lab_planner_binding(');
  d:=replace(d,'public.'||oldprefix||'readiness(
  (SELECT value FROM public.zasp_schema_metadata WHERE key=''production_security_agent_existing_tests_checksum''),
  (SELECT value FROM public.zasp_schema_metadata WHERE key=''production_security_agent_existing_tests_fingerprint''))','public.zasp_sa_attack_lab_guard()');
  d:=replace(d,'public.'||oldprefix||'readiness(expected_checksum,expected_fingerprint)','public.zasp_sa_attack_lab_readiness(expected_checksum,expected_fingerprint)');
  IF name_value IN('planner_context','recheck_context') THEN
   d:=replace(d,'action_value NOT IN(''run_test'',''rerun_test'')','action_value<>''start_attack_lab''');
   d:=replace(d,'''existing_test'',jsonb_build_object(','''attack_lab'',binding_value,''existing_test'',jsonb_build_object(');
   IF name_value='planner_context' THEN
    anchor:=' binding_value:=public.zasp_sa_attack_lab_planner_binding(o,w,e,run_row.definition_id,run_row.definition_version);';
    IF strpos(d,anchor)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack lab preflight stop predecessor rejected';END IF;
    d:=replace(d,anchor,' BEGIN'||chr(10)||anchor||chr(10)||' EXCEPTION WHEN no_data_found THEN'||chr(10)||'  IF SQLERRM IS DISTINCT FROM ''attack lab preflight unavailable'' THEN RAISE;END IF;'||chr(10)||'  RETURN public.zasp_sa_attack_lab_preflight_stop(o,w,e,r,worker_value,lease_value);'||chr(10)||' END;');
   END IF;
  ELSIF name_value='prepare_core' THEN
   d:=replace(d,'authorization_value:=CASE definition_row.activation WHEN ''autonomous'' THEN ''autonomous'' ELSE ''approval_required'' END;','authorization_value:=''approval_required'';');
   d:=replace(d,'state_value:=CASE definition_row.activation WHEN ''autonomous'' THEN ''queued'' ELSE ''waiting_approval'' END;','state_value:=''waiting_approval'';');
   d:=replace(d,'approval_result:=CASE definition_row.activation WHEN ''supervised'' THEN to_jsonb(approval_value) ELSE ''null''::jsonb END;','approval_result:=to_jsonb(approval_value);');
   d:=replace(d,'CASE definition_row.activation WHEN ''autonomous'' THEN ''authorized'' ELSE ''waiting_approval'' END','''waiting_approval''');
   d:=replace(d,'IF definition_row.activation=''supervised'' THEN','IF true THEN');
   d:=replace(d,'CASE definition_row.activation WHEN ''supervised'' THEN approval_value ELSE NULL END','approval_value');
   d:=replace(d,'CASE definition_row.activation WHEN ''autonomous'' THEN ''run_authorized'' ELSE ''approval_requested'' END','''approval_requested''');
   d:=replace(d,'''authorization'',authorization_value)),','''authorization'',authorization_value,''attack_lab'',binding_value)),');
   d:=replace(d,'''kind'',''test_run''','''kind'',''attack_lab_run''');
   d:=replace(d,' action_value:=context_value->''context''->''allowed_actions''->>0;', ' expires_value:=LEAST(expires_value,(binding_value->''preflight''->>''decision_expires_at'')::timestamptz);'||chr(10)||' action_value:=context_value->''context''->''allowed_actions''->>0;');
  END IF;
  IF strpos(d,oldprefix||'readiness(')>0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack lab planner pin rewrite incomplete';END IF;
  EXECUTE d;
  EXECUTE format('ALTER FUNCTION public.%I(%s) OWNER TO zasp_discovery_authority',newprefix||name_value,p.args);
  EXECUTE format('REVOKE ALL ON FUNCTION public.%I(%s) FROM PUBLIC',newprefix||name_value,p.args);
  IF name_value IN('planner_context','reserve_planner','prepare_run','accept_planner','fail_planner') THEN
   EXECUTE format('GRANT EXECUTE ON FUNCTION public.%I(%s) TO zasp_security_agent_worker',newprefix||name_value,p.args);
  END IF;
 END LOOP;
 PERFORM set_config('check_function_bodies','on',true);
END $planner$;
