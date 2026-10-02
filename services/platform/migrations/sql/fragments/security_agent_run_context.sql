-- Exact tenant/run prefix and audit ordering support bounded forward pages.
-- Row locking requires UPDATE privilege. Keep that privilege with each table's
-- owner and expose only these fixed, scoped private reads to the resolver owner.
CREATE FUNCTION public.zasp_production_security_agent_run_context_lock_env(o text,w text,e text)
RETURNS text LANGUAGE sql SECURITY DEFINER SET search_path TO pg_catalog,public
AS $lock_env$ SELECT environment_class FROM public.zasp_environments WHERE (organization_id,workspace_id,id)=(o,w,e) FOR SHARE $lock_env$;
CREATE FUNCTION public.zasp_production_security_agent_run_context_lock_target(o text,w text,e text,t text)
RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path TO pg_catalog,public
AS $lock_target$ SELECT jsonb_build_object('attributes',winning_attributes,'fresh_until',fresh_until,'state',state) FROM public.zasp_inventory_entities WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,t) FOR SHARE $lock_target$;
DO $lock_owners$
DECLARE owner_value text;
BEGIN
 SELECT relowner::regrole::text INTO STRICT owner_value FROM pg_class WHERE oid='public.zasp_environments'::regclass;
 EXECUTE format('ALTER FUNCTION public.zasp_production_security_agent_run_context_lock_env(text,text,text) OWNER TO %I',owner_value);
 SELECT relowner::regrole::text INTO STRICT owner_value FROM pg_class WHERE oid='public.zasp_inventory_entities'::regclass;
 EXECUTE format('ALTER FUNCTION public.zasp_production_security_agent_run_context_lock_target(text,text,text,text) OWNER TO %I',owner_value);
END
$lock_owners$;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_run_context_lock_env(text,text,text),public.zasp_production_security_agent_run_context_lock_target(text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_run_context_lock_env(text,text,text),public.zasp_production_security_agent_run_context_lock_target(text,text,text,text) TO zasp_discovery_authority;

-- Private resolution of operator-selected test intent. This does not enqueue,
-- authorize a worker lease, or replace admission-time budget and safety checks.
CREATE FUNCTION public.zasp_production_security_agent_run_context_test_binding(org_value text,workspace_value text,environment_value text,agent_value text,version_value bigint)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public
AS $test_binding$
DECLARE body_value jsonb;reference_value jsonb;test_row public.zasp_red_team_definitions%ROWTYPE;target_value jsonb;class_value text;credential_expires timestamptz;
BEGIN
 IF NOT COALESCE(public.zasp_valid_product_id(org_value) AND public.zasp_valid_product_id(workspace_value) AND public.zasp_valid_product_id(environment_value) AND public.zasp_valid_product_id(agent_value) AND version_value BETWEEN 1 AND 1000000,false) THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent test binding unavailable';
 END IF;
 SELECT definition.body INTO body_value FROM public.zasp_security_agent_definitions definition
 WHERE (definition.organization_id,definition.workspace_id,definition.environment_id,definition.definition_id,definition.version)=(org_value,workspace_value,environment_value,agent_value,version_value) AND definition.deleted_at IS NULL FOR SHARE;
 reference_value:=body_value->'existing_test';
 IF NOT COALESCE(body_value->'allowed_actions' IN ('["run_test"]'::jsonb,'["rerun_test"]'::jsonb) AND body_value->>'verification_kind'='test_run'
  AND jsonb_typeof(reference_value)='object' AND reference_value ?& ARRAY['definition_id','definition_version'] AND reference_value-ARRAY['definition_id','definition_version']='{}'::jsonb
  AND jsonb_typeof(reference_value->'definition_id')='string' AND public.zasp_valid_product_id(reference_value->>'definition_id')
  AND jsonb_typeof(reference_value->'definition_version')='number' AND reference_value->>'definition_version' ~ '^([1-9][0-9]{0,5}|1000000)$',false) THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent test binding unavailable';
 END IF;
 SELECT * INTO test_row FROM public.zasp_red_team_definitions definition
 WHERE (definition.organization_id,definition.workspace_id,definition.environment_id,definition.definition_id,definition.version,definition.enabled)=(org_value,workspace_value,environment_value,reference_value->>'definition_id',(reference_value->>'definition_version')::bigint,true) FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent test binding unavailable';END IF;
 class_value:=public.zasp_production_security_agent_run_context_lock_env(org_value,workspace_value,environment_value);
 IF NOT COALESCE(class_value IN('development','test','staging') AND class_value=test_row.safety->>'environment',false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent test binding unavailable';END IF;
 target_value:=public.zasp_production_security_agent_run_context_lock_target(org_value,workspace_value,environment_value,test_row.target_id);
 IF NOT COALESCE(target_value->>'state'='active',false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent test binding unavailable';END IF;
 SELECT binding.valid_until INTO credential_expires FROM public.zasp_attack_lab_credential_bindings binding
 WHERE (binding.organization_id,binding.workspace_id,binding.environment_id,binding.target_id,binding.credential_reference,binding.state)=(org_value,workspace_value,environment_value,test_row.target_id,target_value->'attributes'->'red_team'->>'credential_reference','active') AND binding.credential_class=test_row.safety->>'credential_class' FOR SHARE;
 IF NOT FOUND OR NOT COALESCE(credential_expires>clock_timestamp() AND (target_value->>'fresh_until')::timestamptz>clock_timestamp() AND public.zasp_red_team_safety_authorized(org_value,workspace_value,environment_value,test_row.target_id,test_row.target_kind,test_row.safety),false) THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent test binding unavailable';
 END IF;
 RETURN jsonb_build_object('definition_id',test_row.definition_id,'definition_version',test_row.version,'target_id',test_row.target_id,'target_kind',test_row.target_kind);
END
$test_binding$;
ALTER FUNCTION public.zasp_production_security_agent_run_context_test_binding(text,text,text,text,bigint) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_run_context_test_binding(text,text,text,text,bigint) FROM PUBLIC;

CREATE INDEX zasp_security_agent_activity_audit_v54_idx ON public.zasp_security_agent_audit
 (organization_id,workspace_id,environment_id,run_id,audit_id);

-- Reverse trigger lookup must not search every definition in the tenant.
CREATE INDEX zasp_security_agent_activity_trigger_v54_idx ON public.zasp_security_agent_trigger_receipts
 (organization_id,workspace_id,environment_id,trigger_kind,trigger_id) INCLUDE (run_id);

-- Typed action containment avoids reading every plan in the selected scope.
-- Full-scope predicates remain mandatory; this index does not grant authority.
CREATE INDEX zasp_security_agent_activity_plan_v54_idx ON public.zasp_security_agent_plans
 USING gin (plan jsonb_path_ops);

-- Reauthorize relation reads against current browser authority. This private
-- helper cannot be invoked by application roles independently of a scoped read.
CREATE FUNCTION public.zasp_production_security_agent_run_context_activity_browser(org_value text,workspace_value text,environment_value text,principal_value text,session_value bytea,csrf_value text,kind_value text)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public
AS $activity_browser$
DECLARE session_row public.zasp_product_sessions%ROWTYPE;membership_row public.zasp_identity_memberships%ROWTYPE;permission_value text;
BEGIN
 IF NOT COALESCE(public.zasp_production_security_agent_run_context_readiness(
  (SELECT value FROM public.zasp_schema_metadata WHERE key='production_security_agent_run_context_checksum'),
  (SELECT value FROM public.zasp_schema_metadata WHERE key='production_security_agent_run_context_fingerprint')),false) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent relation authority unavailable';
 END IF;
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false) THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent relation principal denied';
 END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(org_value) AND public.zasp_valid_product_id(workspace_value)
  AND public.zasp_valid_product_id(environment_value) AND public.zasp_valid_product_id(principal_value)
  AND octet_length(session_value)=32 AND session_value<>decode(repeat('00',32),'hex')
  AND octet_length(csrf_value) BETWEEN 32 AND 256 AND kind_value IN('finding','attack_path','session','audit'),false) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent relation request rejected';
 END IF;
 SELECT * INTO session_row FROM public.zasp_product_sessions
 WHERE (token_digest,principal_id,organization_id,workspace_id,environment_id)=(session_value,principal_value,org_value,workspace_value,environment_value) FOR SHARE;
 IF NOT FOUND OR session_row.revoked_at IS NOT NULL OR session_row.expires_at<=clock_timestamp() THEN
  RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='security agent relation session rejected';
 END IF;
 IF session_row.csrf_token IS DISTINCT FROM csrf_value THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent relation authorization rejected';
 END IF;
 SELECT * INTO membership_row FROM public.zasp_identity_memberships WHERE organization_id=org_value AND principal_id=principal_value FOR SHARE;
 IF NOT FOUND OR NOT membership_row.active THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent relation membership rejected';END IF;
 permission_value:=CASE kind_value WHEN 'session' THEN 'investigate_sessions' WHEN 'audit' THEN 'view_audit' ELSE 'view' END;
 IF NOT EXISTS(SELECT 1 FROM public.zasp_identity_admin_effective_scopes(principal_value,org_value) scope
  WHERE (scope.organization_id,scope.workspace_id,scope.environment_id)=(org_value,workspace_value,environment_value)
   AND scope.permissions ? 'view' AND scope.permissions ? permission_value) THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent relation scope rejected';
 END IF;
END
$activity_browser$;
ALTER FUNCTION public.zasp_production_security_agent_run_context_activity_browser(text,text,text,text,bytea,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_run_context_activity_browser(text,text,text,text,bytea,text,text) FROM PUBLIC;

-- Candidate envelopes are private API inputs. The repository must decode each
-- v54 envelope and validate its typed association before exposing a run summary.
CREATE FUNCTION public.zasp_production_security_agent_run_context_related_runs(org_value text,workspace_value text,environment_value text,principal_value text,session_value bytea,csrf_value text,kind_value text,entity_value text,before_created_value timestamptz,before_id_value text,limit_value integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public
AS $related_runs$
DECLARE candidate record;envelope jsonb;items_value jsonb:='[]'::jsonb;last_created timestamptz;last_id text;count_value integer:=0;more_value boolean:=false;partial_value boolean:=false;
BEGIN
 PERFORM public.zasp_production_security_agent_run_context_activity_browser(org_value,workspace_value,environment_value,principal_value,session_value,csrf_value,kind_value);
 IF NOT COALESCE(public.zasp_valid_product_id(entity_value) AND limit_value BETWEEN 1 AND 100,false)
  OR (before_created_value IS NULL)<>(before_id_value IS NULL)
  OR (before_id_value IS NOT NULL AND NOT COALESCE(public.zasp_valid_product_id(before_id_value) AND isfinite(before_created_value),false)) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent relation page rejected';
 END IF;
 IF kind_value<>'audit' THEN
  SELECT EXISTS(SELECT 1 FROM public.zasp_security_agent_runs run
   LEFT JOIN public.zasp_security_agent_trigger_receipts receipt USING(organization_id,workspace_id,environment_id,run_id)
   LEFT JOIN public.zasp_security_agent_plans plan USING(organization_id,workspace_id,environment_id,run_id)
   WHERE (run.organization_id,run.workspace_id,run.environment_id)=(org_value,workspace_value,environment_value) AND run.state<>'simulated'
    AND (receipt.run_id IS NULL
     OR (plan.run_id IS NULL AND (run.plan_hash IS NOT NULL OR EXISTS(SELECT 1 FROM public.zasp_security_agent_steps execution
      WHERE (execution.organization_id,execution.workspace_id,execution.environment_id,execution.run_id)=(run.organization_id,run.workspace_id,run.environment_id,run.run_id))))
     OR plan.run_id IS NOT NULL AND (
     plan.plan_hash IS DISTINCT FROM run.plan_hash
     OR plan.plan_hash IS DISTINCT FROM digest(convert_to(plan.plan::text,'UTF8'),'sha256')
     OR (plan.definition_id,plan.definition_version) IS DISTINCT FROM (run.definition_id,run.definition_version)
     OR jsonb_typeof(plan.plan->'steps') IS DISTINCT FROM 'array'
     OR CASE WHEN jsonb_typeof(plan.plan->'steps')='array' THEN jsonb_array_length(plan.plan->'steps') ELSE NULL END
      IS DISTINCT FROM (SELECT count(*) FROM public.zasp_security_agent_steps execution
       WHERE (execution.organization_id,execution.workspace_id,execution.environment_id,execution.run_id)=(run.organization_id,run.workspace_id,run.environment_id,run.run_id))
     OR EXISTS(SELECT 1 FROM public.zasp_security_agent_steps execution
      WHERE (execution.organization_id,execution.workspace_id,execution.environment_id,execution.run_id)=(run.organization_id,run.workspace_id,run.environment_id,run.run_id)
       AND ((plan.plan->'steps'->execution.step_index)->>'step_id' IS DISTINCT FROM execution.step_id
        OR (plan.plan->'steps'->execution.step_index)->'index' IS DISTINCT FROM to_jsonb(execution.step_index)
        OR (plan.plan->'steps'->execution.step_index)->>'action' IS DISTINCT FROM execution.action_key
        OR digest(convert_to((plan.plan->'steps'->execution.step_index)::text,'UTF8'),'sha256') IS DISTINCT FROM execution.input_digest))
     OR EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(plan.plan->'steps')='array' THEN plan.plan->'steps' ELSE '[]'::jsonb END) step(value)
      WHERE jsonb_typeof(step.value) IS DISTINCT FROM 'object'
       OR NOT COALESCE(step.value->>'action' IN('update_finding_response','create_temporary_policy','isolate_session','revoke_integration_connection'),false)
       OR (kind_value='finding' AND step.value->>'action'='update_finding_response'
        AND NOT COALESCE(jsonb_typeof(step.value->'target_id')='string' AND public.zasp_valid_product_id(step.value->>'target_id'),false))
       OR (kind_value='session' AND step.value->>'action'='isolate_session'
        AND NOT COALESCE(jsonb_typeof(step.value->'target_id')='string' AND public.zasp_valid_product_id(step.value->>'target_id')
         AND jsonb_typeof(step.value->'session_id')='string' AND step.value->>'session_id'=step.value->>'target_id',false)))))
    )
  INTO partial_value;
 END IF;
 FOR candidate IN
  WITH ids AS (
   SELECT receipt.run_id FROM public.zasp_security_agent_trigger_receipts receipt
   WHERE (receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.trigger_id)=(org_value,workspace_value,environment_value,entity_value)
    AND receipt.trigger_kind=CASE kind_value WHEN 'finding' THEN 'finding' WHEN 'attack_path' THEN 'attack_path' WHEN 'session' THEN 'runtime_decision' ELSE NULL END
   UNION
   SELECT plan.run_id FROM public.zasp_security_agent_plans plan
   WHERE (plan.organization_id,plan.workspace_id,plan.environment_id)=(org_value,workspace_value,environment_value)
    AND kind_value='finding' AND plan.plan @> jsonb_build_object('steps',jsonb_build_array(jsonb_build_object('action','update_finding_response','target_id',entity_value)))
   UNION
   SELECT plan.run_id FROM public.zasp_security_agent_plans plan
   WHERE (plan.organization_id,plan.workspace_id,plan.environment_id)=(org_value,workspace_value,environment_value)
    AND kind_value='session' AND plan.plan @> jsonb_build_object('steps',jsonb_build_array(jsonb_build_object('action','isolate_session','target_id',entity_value)))
   UNION
   SELECT audit.run_id FROM public.zasp_security_agent_audit audit
   WHERE kind_value='audit' AND (audit.organization_id,audit.workspace_id,audit.environment_id,audit.audit_id)=(org_value,workspace_value,environment_value,entity_value)
  )
  SELECT run.run_id,run.created_at FROM ids JOIN public.zasp_security_agent_runs run USING(run_id)
  WHERE (run.organization_id,run.workspace_id,run.environment_id)=(org_value,workspace_value,environment_value) AND run.state<>'simulated'
   AND (before_created_value IS NULL OR (run.created_at,run.run_id)<(before_created_value,before_id_value))
  ORDER BY run.created_at DESC,run.run_id DESC LIMIT limit_value+1
 LOOP
  count_value:=count_value+1;
  IF count_value>limit_value THEN more_value:=true;EXIT;END IF;
  SELECT value INTO envelope FROM public.zasp_security_agent_run_context_v54(org_value,workspace_value,environment_value,candidate.run_id) context(value);
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent relation context unavailable';END IF;
  items_value:=items_value||jsonb_build_array(envelope);last_created:=candidate.created_at;last_id:=candidate.run_id;
 END LOOP;
 RETURN jsonb_build_object('items',items_value,'coverage',CASE WHEN partial_value THEN 'partial' ELSE 'complete' END,
  'next_created_at',CASE WHEN more_value THEN to_char(last_created AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') ELSE NULL END,
  'next_id',CASE WHEN more_value THEN last_id ELSE NULL END);
END
$related_runs$;
ALTER FUNCTION public.zasp_production_security_agent_run_context_related_runs(text,text,text,text,bytea,text,text,text,timestamptz,text,integer) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_run_context_related_runs(text,text,text,text,bytea,text,text,text,timestamptz,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_run_context_related_runs(text,text,text,text,bytea,text,text,text,timestamptz,text,integer) TO zasp_security_agent_api;

-- Forward non-audit targets are projected by the API from this validated run
-- envelope. Audit IDs instead come only from exact scoped persisted audit rows.
CREATE FUNCTION public.zasp_production_security_agent_run_context_targets(org_value text,workspace_value text,environment_value text,principal_value text,session_value bytea,csrf_value text,kind_value text,run_value text,after_id_value text,limit_value integer)
RETURNS SETOF jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public
AS $activity_targets$
DECLARE envelope jsonb;ids_value jsonb:='[]'::jsonb;audit_value text;last_id text;count_value integer:=0;more_value boolean:=false;
BEGIN
 PERFORM public.zasp_production_security_agent_run_context_activity_browser(org_value,workspace_value,environment_value,principal_value,session_value,csrf_value,kind_value);
 IF NOT COALESCE(public.zasp_valid_product_id(run_value) AND limit_value BETWEEN 1 AND 100,false)
  OR (after_id_value IS NOT NULL AND NOT COALESCE(public.zasp_valid_product_id(after_id_value),false)) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent activity target page rejected';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_runs run
  WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id)=(org_value,workspace_value,environment_value,run_value) AND run.state<>'simulated') THEN RETURN;END IF;
 SELECT value INTO envelope FROM public.zasp_security_agent_run_context_v54(org_value,workspace_value,environment_value,run_value) context(value);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent activity target context unavailable';END IF;
 IF kind_value='audit' THEN
  -- Separate mutually exclusive cursor branches let generic plans retain the
  -- audit-ID range condition. Each branch is bounded before their ordered merge.
  FOR audit_value IN SELECT candidate.audit_id FROM (
   (SELECT audit.audit_id FROM public.zasp_security_agent_audit audit
    WHERE after_id_value IS NULL
     AND (audit.organization_id,audit.workspace_id,audit.environment_id,audit.run_id)=(org_value,workspace_value,environment_value,run_value)
    ORDER BY audit.audit_id LIMIT limit_value+1)
   UNION ALL
   (SELECT audit.audit_id FROM public.zasp_security_agent_audit audit
    WHERE after_id_value IS NOT NULL
     AND (audit.organization_id,audit.workspace_id,audit.environment_id,audit.run_id)=(org_value,workspace_value,environment_value,run_value)
     AND audit.audit_id>after_id_value
    ORDER BY audit.audit_id LIMIT limit_value+1)
  ) candidate ORDER BY candidate.audit_id LIMIT limit_value+1
  LOOP
   IF NOT COALESCE(public.zasp_valid_product_id(audit_value),false) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent activity audit target unavailable';
   END IF;
   count_value:=count_value+1;
   IF count_value>limit_value THEN more_value:=true;EXIT;END IF;
   ids_value:=ids_value||jsonb_build_array(audit_value);last_id:=audit_value;
  END LOOP;
 END IF;
 RETURN NEXT jsonb_build_object('context',envelope,'audit_ids',ids_value,'next_audit_id',CASE WHEN more_value THEN last_id ELSE NULL END);
END
$activity_targets$;
ALTER FUNCTION public.zasp_production_security_agent_run_context_targets(text,text,text,text,bytea,text,text,text,text,integer) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_run_context_targets(text,text,text,text,bytea,text,text,text,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_run_context_targets(text,text,text,text,bytea,text,text,text,text,integer) TO zasp_security_agent_api;

-- Exact Security Agent audit records have worker references, not necessarily
-- human Product IDs. Never expose the private audit body through this read.
CREATE FUNCTION public.zasp_production_security_agent_run_context_audit(organization_value text,workspace_value text,environment_value text,principal_value text,session_value bytea,csrf_value text,audit_value text)
RETURNS SETOF jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public
AS $activity_audit$
DECLARE audit_row public.zasp_security_agent_audit%ROWTYPE;
BEGIN
 IF NOT COALESCE(public.zasp_production_security_agent_run_context_readiness(
  (SELECT value FROM public.zasp_schema_metadata WHERE key='production_security_agent_run_context_checksum'),
  (SELECT value FROM public.zasp_schema_metadata WHERE key='production_security_agent_run_context_fingerprint')),false) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent audit authority unavailable';
 END IF;
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false) THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent audit principal denied';
 END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(organization_value) AND public.zasp_valid_product_id(workspace_value)
  AND public.zasp_valid_product_id(environment_value) AND public.zasp_valid_product_id(principal_value)
  AND public.zasp_valid_product_id(audit_value) AND octet_length(session_value)=32
  AND session_value<>decode(repeat('00',32),'hex') AND octet_length(csrf_value) BETWEEN 32 AND 256,false) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent audit request rejected';
 END IF;
 PERFORM public.zasp_audit_export_require_browser(organization_value,workspace_value,environment_value,principal_value,session_value,csrf_value,false);
 SELECT audit.* INTO audit_row FROM public.zasp_security_agent_audit audit
 JOIN public.zasp_security_agent_runs run ON
  (run.organization_id,run.workspace_id,run.environment_id,run.run_id)=
  (audit.organization_id,audit.workspace_id,audit.environment_id,audit.run_id)
 WHERE (audit.organization_id,audit.workspace_id,audit.environment_id,audit.audit_id)=
  (organization_value,workspace_value,environment_value,audit_value) AND run.state<>'simulated';
 IF NOT FOUND THEN RETURN;END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(audit_row.run_id) AND public.zasp_valid_product_id(audit_row.correlation_id)
  AND octet_length(audit_row.actor_id) BETWEEN 1 AND 128 AND audit_row.actor_id!~'[[:cntrl:]]'
  AND octet_length(audit_row.event_kind) BETWEEN 1 AND 128 AND audit_row.event_kind!~'[[:cntrl:]]'
  AND isfinite(audit_row.created_at),false) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent audit record unavailable';
 END IF;
 RETURN NEXT jsonb_build_object('id',audit_row.audit_id,'run_id',audit_row.run_id,
  'organization_id',audit_row.organization_id,'workspace_id',audit_row.workspace_id,'environment_id',audit_row.environment_id,
  'actor_reference',audit_row.actor_id,'event_kind',audit_row.event_kind,'correlation_id',audit_row.correlation_id,
  'occurred_at',to_char(audit_row.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
END
$activity_audit$;
ALTER FUNCTION public.zasp_production_security_agent_run_context_audit(text,text,text,text,bytea,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_run_context_audit(text,text,text,text,bytea,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_run_context_audit(text,text,text,text,bytea,text,text) TO zasp_security_agent_api;

-- Candidate54 private projection; not registered release acceptance.
CREATE FUNCTION public.zasp_security_agent_run_context_v54(organization_value text,workspace_value text,environment_value text,run_value text)
RETURNS SETOF jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public
AS $context$
DECLARE detail_value jsonb;trigger_value jsonb;receipt_value jsonb;receipt_count bigint;
 plan_value jsonb;step_value jsonb;planned_step jsonb;arguments_value jsonb;
 actions_value jsonb:='[]'::jsonb;effect_value jsonb;control_count bigint;expiry_value timestamptz;
 apply_value jsonb;cleanup_value jsonb;step_id_value text;action_value text;index_value integer;
BEGIN
 -- Reuse the existing principal-authorized scoped read before inspecting any
 -- private receipt. Missing/foreign/invisible runs return no private envelope.
 SELECT value INTO detail_value
 FROM public.zasp_security_agent_run_detail_v24(organization_value,workspace_value,environment_value,run_value) detail(value);
 IF NOT FOUND THEN RETURN;END IF;

 SELECT jsonb_build_object('kind',receipt.trigger_kind,'id',receipt.trigger_id,'version',receipt.trigger_version)
 INTO trigger_value FROM public.zasp_security_agent_trigger_receipts receipt
 WHERE (receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.run_id)=
       (organization_value,workspace_value,environment_value,run_value);

 -- Bind to the plan being displayed, never the most recent attempt. Execution
 -- retries can advance run.attempt after the accepted planner receipt exists.
 SELECT count(*),(jsonb_agg(jsonb_build_object(
   'run_id',receipt.response->'run_id','plan_hash',receipt.response->'plan_hash',
   'outcome',receipt.outcome,'summary',receipt.response->'planner_summary')))->0
 INTO receipt_count,receipt_value
 FROM public.zasp_security_agent_planner_receipts receipt
 WHERE (receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.run_id)=
       (organization_value,workspace_value,environment_value,run_value)
   AND receipt.outcome='accepted'
   AND receipt.response->>'run_id'=run_value
   AND receipt.response->>'plan_hash'=detail_value->'plan'->>'plan_hash';
 IF receipt_count>1 THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent run context authority unavailable';
 END IF;

 IF detail_value->'plan'<>'null'::jsonb THEN
  SELECT plan.plan INTO plan_value FROM public.zasp_security_agent_plans plan
  JOIN public.zasp_security_agent_runs run USING(organization_id,workspace_id,environment_id,run_id)
  WHERE (plan.organization_id,plan.workspace_id,plan.environment_id,plan.run_id)=
        (organization_value,workspace_value,environment_value,run_value)
    AND 'sha256:'||encode(plan.plan_hash,'hex')=detail_value->'plan'->>'plan_hash'
    AND run.plan_hash=plan.plan_hash;
  IF NOT FOUND THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent action detail authority unavailable';
  END IF;
  -- Old stored plans without argument-bearing steps remain explicitly unknown.
  -- Once steps exist, require their exact content hash and displayed bindings.
  IF plan_value ? 'steps' THEN
   IF jsonb_typeof(plan_value->'steps') IS DISTINCT FROM 'array' THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent action detail authority unavailable';
   END IF;
   IF jsonb_array_length(plan_value->'steps')<>jsonb_array_length(detail_value->'plan'->'steps')
      OR 'sha256:'||encode(digest(convert_to(plan_value::text,'UTF8'),'sha256'),'hex') IS DISTINCT FROM detail_value->'plan'->>'plan_hash' THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent action detail authority unavailable';
   END IF;
  END IF;
  FOR step_value IN SELECT value FROM jsonb_array_elements(detail_value->'plan'->'steps') LOOP
   step_id_value:=step_value->>'id';action_value:=step_value->>'action';index_value:=(step_value->>'index')::integer;
   IF action_value NOT IN('update_finding_response','create_temporary_policy','isolate_session','revoke_integration_connection') THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent action detail authority unavailable';
   END IF;
   arguments_value:=NULL;
   IF plan_value ? 'steps' THEN
    planned_step:=plan_value->'steps'->index_value;
    IF planned_step->>'step_id' IS DISTINCT FROM step_id_value OR planned_step->'index' IS DISTINCT FROM to_jsonb(index_value)
       OR planned_step->>'action' IS DISTINCT FROM action_value THEN
     RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent action detail authority unavailable';
    END IF;
    IF action_value IN('create_temporary_policy','isolate_session') AND planned_step->>'scope' IS DISTINCT FROM environment_value THEN
     RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent action detail authority unavailable';
    END IF;
    -- Never return the original plan step. Unknown keys can contain credentials.
    arguments_value:=CASE action_value
     WHEN 'update_finding_response' THEN jsonb_build_object('target_id',planned_step->'target_id','expected_version',planned_step->'expected_version','target_status',planned_step->'target_status')
     WHEN 'create_temporary_policy' THEN jsonb_build_object('target_id',planned_step->'target_id','mode',planned_step->'mode','scope',planned_step->'scope','ttl_seconds',planned_step->'ttl_seconds')
     WHEN 'isolate_session' THEN jsonb_build_object('target_id',planned_step->'target_id','session_id',planned_step->'session_id','device_id',planned_step->'device_id','scope',planned_step->'scope','ttl_seconds',planned_step->'ttl_seconds')
     WHEN 'revoke_integration_connection' THEN jsonb_build_object('target_id',planned_step->'target_id','integration_id',planned_step->'integration_id') END;
   END IF;
   SELECT jsonb_build_object('step_id',effect.step_id,'action',effect.action_key,'state',effect.state,'outcome_id',effect.outcome_id,
      'result_digest',CASE WHEN effect.result_digest IS NULL THEN NULL ELSE 'sha256:'||encode(effect.result_digest,'hex') END)
   INTO effect_value FROM public.zasp_security_agent_effects effect
   WHERE (effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id,effect.step_id,effect.action_key)=
         (organization_value,workspace_value,environment_value,run_value,step_id_value,action_value);
   SELECT count(*),max(control.expires_at) INTO control_count,expiry_value FROM public.zasp_security_agent_controls control
   WHERE (control.organization_id,control.workspace_id,control.environment_id,control.run_id,control.step_id,control.action_key)=
         (organization_value,workspace_value,environment_value,run_value,step_id_value,action_value);
   IF control_count>1 THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent action detail authority unavailable';
   END IF;
   SELECT jsonb_build_object('total',count(*) FILTER(WHERE target.phase='apply'),'verified',count(*) FILTER(WHERE target.phase='apply' AND target.state='verified')),
          jsonb_build_object('total',count(*) FILTER(WHERE target.phase='cleanup'),'verified',count(*) FILTER(WHERE target.phase='cleanup' AND target.state='verified'))
   INTO apply_value,cleanup_value FROM public.zasp_security_agent_temporary_policy_targets target
   WHERE (target.organization_id,target.workspace_id,target.environment_id,target.run_id,target.step_id,target.action_key)=
         (organization_value,workspace_value,environment_value,run_value,step_id_value,action_value);
   actions_value:=actions_value||jsonb_build_array(jsonb_build_object('step_id',step_id_value,'index',index_value,'action',action_value,
    'arguments',arguments_value,'effect',effect_value,'control_expires_at',CASE WHEN expiry_value IS NULL THEN NULL ELSE to_char(expiry_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END,
    'apply_targets',apply_value,'cleanup_targets',cleanup_value));
  END LOOP;
 END IF;
 RETURN NEXT jsonb_build_object('detail',detail_value,'context',jsonb_build_object(
   'trigger',trigger_value,'planner_receipt',receipt_value),'action_details',jsonb_build_object(
   'run_id',run_value,'plan_hash',detail_value->'plan'->'plan_hash','steps',actions_value));
END
$context$;
ALTER FUNCTION public.zasp_security_agent_run_context_v54(text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_run_context_v54(text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_security_agent_run_context_v54(text,text,text,text) TO zasp_security_agent_api;

-- Internal assembly only. Callers must first obtain authorized detail and a
-- verified run projection; no application role can supply those inputs.
CREATE FUNCTION public.zasp_production_security_agent_run_context_approval_assemble(organization_value text,workspace_value text,environment_value text,approval_value text,detail_value jsonb,run_context jsonb)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public
AS $approval_context$
DECLARE approval_row public.zasp_security_agent_approvals%ROWTYPE;
 step_value jsonb;step_count bigint;authorization_value text;
BEGIN
 SELECT * INTO approval_row FROM public.zasp_security_agent_approvals approval
 WHERE (approval.organization_id,approval.workspace_id,approval.environment_id,approval.approval_id)=
       (organization_value,workspace_value,environment_value,approval_value);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent approval context authority unavailable';END IF;
 IF run_context->'detail'->'run'->>'id' IS DISTINCT FROM approval_row.run_id
    OR detail_value->>'id' IS DISTINCT FROM approval_value
    OR run_context->'detail'->'plan'->>'plan_hash' IS DISTINCT FROM 'sha256:'||encode(approval_row.plan_hash,'hex')
    OR detail_value->>'run_id' IS DISTINCT FROM approval_row.run_id OR detail_value->>'step_id' IS DISTINCT FROM approval_row.step_id THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent approval context authority unavailable';
 END IF;
 SELECT count(*),(jsonb_agg(value))->0 INTO step_count,step_value
 FROM jsonb_array_elements(run_context->'action_details'->'steps') item(value)
 WHERE value->>'step_id'=approval_row.step_id;
 IF step_count<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent approval context authority unavailable';END IF;
 authorization_value:=run_context->'detail'->'plan'->'steps'->((step_value->>'index')::integer)->>'authorization';
 IF authorization_value IS DISTINCT FROM 'approval_required' THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent approval context authority unavailable';
 END IF;
 RETURN jsonb_build_object('detail',detail_value,'context',jsonb_build_object(
  'approval_id',approval_value,'run_id',approval_row.run_id,'step_id',approval_row.step_id,
  'agent_id',run_context->'detail'->'run'->'agent_id',
  'approval_plan_hash','sha256:'||encode(approval_row.plan_hash,'hex'),'plan_hash',run_context->'detail'->'plan'->'plan_hash',
  'catalog_version',run_context->'detail'->'plan'->'catalog_version','action',step_value->'action',
  'authorization',authorization_value,'arguments',step_value->'arguments','requester_id',approval_row.requester_id,
  'planner_receipt',run_context->'context'->'planner_receipt'));
END
$approval_context$;
ALTER FUNCTION public.zasp_production_security_agent_run_context_approval_assemble(text,text,text,text,jsonb,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_run_context_approval_assemble(text,text,text,text,jsonb,jsonb) FROM PUBLIC;

CREATE FUNCTION public.zasp_production_security_agent_run_context_approval(organization_value text,workspace_value text,environment_value text,approval_value text)
RETURNS SETOF jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public
AS $approval_detail_context$
DECLARE detail_value jsonb;run_context jsonb;
BEGIN
 SELECT value INTO detail_value FROM public.zasp_security_agent_approval_detail_v24(organization_value,workspace_value,environment_value,approval_value) detail(value);
 IF NOT FOUND THEN RETURN;END IF;
 SELECT value INTO run_context FROM public.zasp_security_agent_run_context_v54(organization_value,workspace_value,environment_value,detail_value->>'run_id') context(value);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent approval context authority unavailable';END IF;
 RETURN NEXT public.zasp_production_security_agent_run_context_approval_assemble(organization_value,workspace_value,environment_value,approval_value,detail_value,run_context);
END
$approval_detail_context$;
ALTER FUNCTION public.zasp_production_security_agent_run_context_approval(text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_run_context_approval(text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_run_context_approval(text,text,text,text) TO zasp_security_agent_api;

CREATE FUNCTION public.zasp_production_security_agent_run_context_approval_page(organization_value text,workspace_value text,environment_value text,state_value text,run_value text,before_created_value timestamptz,before_id_value text,limit_value integer)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public
AS $approval_page_context$
DECLARE page_value jsonb;item jsonb;context_value jsonb;items_value jsonb:='[]'::jsonb;
 run_context jsonb;run_cache jsonb:='{}'::jsonb;item_run text;
BEGIN
 page_value:=public.zasp_security_agent_approval_page_v24(organization_value,workspace_value,environment_value,state_value,run_value,before_created_value,before_id_value,limit_value);
 FOR item IN SELECT value FROM jsonb_array_elements(page_value->'items') LOOP
  item_run:=item->>'run_id';
  IF NOT (run_cache ? item_run) THEN
   SELECT value INTO run_context FROM public.zasp_security_agent_run_context_v54(organization_value,workspace_value,environment_value,item_run) context(value);
   IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent approval context authority unavailable';END IF;
   run_cache:=jsonb_set(run_cache,ARRAY[item_run],run_context,true);
  END IF;
  context_value:=public.zasp_production_security_agent_run_context_approval_assemble(organization_value,workspace_value,environment_value,item->>'id',item,run_cache->item_run);
  items_value:=items_value||jsonb_build_array(context_value);
 END LOOP;
 RETURN jsonb_set(page_value,'{items}',items_value,false);
END
$approval_page_context$;
ALTER FUNCTION public.zasp_production_security_agent_run_context_approval_page(text,text,text,text,text,timestamptz,text,integer) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_run_context_approval_page(text,text,text,text,text,timestamptz,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_run_context_approval_page(text,text,text,text,text,timestamptz,text,integer) TO zasp_security_agent_api;
