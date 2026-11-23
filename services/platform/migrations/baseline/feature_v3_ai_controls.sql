-- Policy is scoped to the organization and selected environment. No service login may access the rows directly.
CREATE TABLE IF NOT EXISTS public.zasp_organization_ai_controls (
 organization_id text PRIMARY KEY REFERENCES public.zasp_organizations(id),
 ai_enabled boolean NOT NULL DEFAULT false,
 allowed_modes text[] NOT NULL DEFAULT ARRAY['deterministic_only'],
 allowed_residency text NOT NULL DEFAULT 'customer_vpc_only',
 allow_private_code_egress boolean NOT NULL DEFAULT false,
 require_zero_retention boolean NOT NULL DEFAULT true,
 version bigint NOT NULL DEFAULT 1 CHECK(version > 0),
 CHECK(require_zero_retention AND allowed_residency IN ('customer_vpc_only','us_only','eu_only','us_eu')),
 CHECK(cardinality(allowed_modes)>=1 AND cardinality(allowed_modes)<=6 AND array_position(allowed_modes,NULL) IS NULL AND allowed_modes <@ ARRAY['deterministic_only','zasp_vpc_slm','privatelink_bedrock','privatelink_vertex','byoc_self_hosted','dev_openrouter'] AND 'deterministic_only'=ANY(allowed_modes))
);
CREATE TABLE IF NOT EXISTS public.zasp_environment_ai_controls (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL, environment_class text NOT NULL,
 mode text NOT NULL DEFAULT 'deterministic_only',
 tier2_prompt_injection_enabled boolean NOT NULL DEFAULT false,
 tier2_purpose_drift_enabled boolean NOT NULL DEFAULT false,
 tier2_heuristic_fp_suppression_enabled boolean NOT NULL DEFAULT false,
 tier3_discovery_purpose_enabled boolean NOT NULL DEFAULT false,
 tier3_addon_audit_enabled boolean NOT NULL DEFAULT false,
 tier3_security_agent_planner_enabled boolean NOT NULL DEFAULT false,
 allow_redacted_summaries boolean NOT NULL DEFAULT false,
 allow_approved_code_snippets boolean NOT NULL DEFAULT false,
 allow_private_addon_bytes boolean NOT NULL DEFAULT false,
 tier2_profile text NOT NULL DEFAULT '',
 tier3_provider text NOT NULL DEFAULT '',
 tier3_model_pin text NOT NULL DEFAULT '',
 credential_reference text NOT NULL DEFAULT '',
 credential_digest text NOT NULL DEFAULT '',
 monthly_budget_nano_credits bigint NOT NULL DEFAULT 0,
 version bigint NOT NULL DEFAULT 1 CHECK(version > 0),
 PRIMARY KEY(organization_id,workspace_id,environment_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id) REFERENCES public.zasp_data_controls,
 CHECK(mode=ANY(ARRAY['deterministic_only','zasp_vpc_slm','privatelink_bedrock','privatelink_vertex','byoc_self_hosted','dev_openrouter']) AND (environment_class<>'production' OR mode<>'dev_openrouter')),
 CHECK(environment_class IN ('development','test','staging','production') AND monthly_budget_nano_credits BETWEEN 0 AND 9007199254740991),
 CHECK((credential_reference='' AND credential_digest='') OR
  (starts_with(credential_reference,'secret_ref_planner/'||organization_id||'/'||workspace_id||'/'||environment_id||'/') AND credential_reference ~ '^secret_ref_planner/[A-Za-z0-9_/-]{1,220}$' AND credential_reference !~ '//|/$' AND credential_digest ~ '^sha256:[a-f0-9]{64}$')),
 CHECK(tier2_profile ~ '^[a-zA-Z0-9._:/-]{0,180}$' AND tier3_model_pin ~ '^[a-zA-Z0-9._:/-]{0,180}$' AND tier3_provider IN ('','privatelink_bedrock','privatelink_vertex','dev_openrouter'))
);
CREATE TABLE IF NOT EXISTS public.model_qualifications (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
 provider text NOT NULL, model text NOT NULL, purpose text NOT NULL, qualified boolean NOT NULL,
 checked_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 deployment_digest text CHECK(deployment_digest ~ '^sha256:[a-f0-9]{64}$'), expires_at timestamptz,
 evidence_digest text NOT NULL CHECK(evidence_digest ~ '^sha256:[a-f0-9]{64}$'),
 PRIMARY KEY(organization_id,workspace_id,environment_id,provider,model,purpose),
 FOREIGN KEY(organization_id,workspace_id,environment_id) REFERENCES public.zasp_data_controls
);
ALTER TABLE public.zasp_organization_ai_controls OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_organization_ai_controls ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_organization_ai_controls FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.zasp_organization_ai_controls FROM PUBLIC;
DROP POLICY IF EXISTS ai_policy_owner ON public.zasp_organization_ai_controls;
CREATE POLICY ai_policy_owner ON public.zasp_organization_ai_controls TO zasp_discovery_authority USING(true) WITH CHECK(true);
ALTER TABLE public.zasp_environment_ai_controls OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_environment_ai_controls ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_environment_ai_controls FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.zasp_environment_ai_controls FROM PUBLIC;
DROP POLICY IF EXISTS ai_policy_owner ON public.zasp_environment_ai_controls;
CREATE POLICY ai_policy_owner ON public.zasp_environment_ai_controls TO zasp_discovery_authority USING(true) WITH CHECK(true);
ALTER TABLE public.model_qualifications OWNER TO zasp_discovery_authority;
ALTER TABLE public.model_qualifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.model_qualifications FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.model_qualifications FROM PUBLIC;
DROP POLICY IF EXISTS ai_policy_owner ON public.model_qualifications;
CREATE POLICY ai_policy_owner ON public.model_qualifications TO zasp_discovery_authority USING(true) WITH CHECK(true);

CREATE OR REPLACE FUNCTION zasp_authorization80.ai_organization_defaults() RETURNS jsonb
 LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $defaults$
 SELECT '{"ai_enabled":false,"allowed_modes":["deterministic_only"],"allowed_residency":"customer_vpc_only","allow_private_code_egress":false,"require_zero_retention":true}'::jsonb
$defaults$;
ALTER FUNCTION zasp_authorization80.ai_organization_defaults() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.ai_organization_defaults() FROM PUBLIC;

CREATE OR REPLACE FUNCTION zasp_authorization80.ai_environment_defaults() RETURNS jsonb
 LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $defaults$
 SELECT '{"mode":"deterministic_only","tier2_prompt_injection_enabled":false,"tier2_purpose_drift_enabled":false,"tier2_heuristic_fp_suppression_enabled":false,"tier3_discovery_purpose_enabled":false,"tier3_addon_audit_enabled":false,"tier3_security_agent_planner_enabled":false,"allow_redacted_summaries":false,"allow_approved_code_snippets":false,"allow_private_addon_bytes":false,"tier2_profile":"","tier3_provider":"","tier3_model_pin":"","credential_reference":"","credential_digest":"","monthly_budget_nano_credits":0}'::jsonb
$defaults$;
ALTER FUNCTION zasp_authorization80.ai_environment_defaults() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.ai_environment_defaults() FROM PUBLIC;

-- Data controls use an operator-owned RLS policy. Expose the two non-secret
-- limits only to the policy owner, including a lock during a policy write.
CREATE OR REPLACE FUNCTION zasp_authorization80.ai_data_limits(o text,w text,e text,lock_row boolean) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $limits$
DECLARE limits jsonb;
BEGIN
 IF lock_row THEN
  SELECT jsonb_build_object('environment_class',d.environment_class,'collection_mode',d.collection_mode) INTO STRICT limits
  FROM public.zasp_data_controls d WHERE (d.organization_id,d.workspace_id,d.environment_id)=(o,w,e) FOR SHARE;
 ELSE
  SELECT jsonb_build_object('environment_class',d.environment_class,'collection_mode',d.collection_mode) INTO STRICT limits
  FROM public.zasp_data_controls d WHERE (d.organization_id,d.workspace_id,d.environment_id)=(o,w,e);
 END IF;
 RETURN limits;
END $limits$;
ALTER FUNCTION zasp_authorization80.ai_data_limits(text,text,text,boolean) OWNER TO zasp_operator;
REVOKE ALL ON FUNCTION zasp_authorization80.ai_data_limits(text,text,text,boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.ai_data_limits(text,text,text,boolean) TO zasp_discovery_authority;

CREATE OR REPLACE FUNCTION zasp_authorization80.ai_org_snapshot(o text) RETURNS jsonb
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $snapshot$
 SELECT coalesce((SELECT to_jsonb(c) FROM public.zasp_organization_ai_controls c WHERE c.organization_id=o),
  zasp_authorization80.ai_organization_defaults()||jsonb_build_object('organization_id',o,'version',1))
$snapshot$;

CREATE OR REPLACE FUNCTION zasp_authorization80.ai_env_snapshot(o text,w text,e text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $snapshot$
DECLARE limits jsonb:=zasp_authorization80.ai_data_limits(o,w,e,false);
 org jsonb:=zasp_authorization80.ai_org_snapshot(o); env jsonb;
BEGIN
 SELECT to_jsonb(c)-'workspace_id'-'organization_id' INTO env FROM public.zasp_environment_ai_controls c WHERE (c.organization_id,c.workspace_id,c.environment_id)=(o,w,e);
 env:=coalesce(env,zasp_authorization80.ai_environment_defaults()||jsonb_build_object('version',1,'environment_id',e));
 RETURN env||limits||jsonb_build_object('effective_mode',
  CASE WHEN (org->>'ai_enabled')::boolean AND (org->'allowed_modes') ? (env->>'mode')
   AND NOT (org->>'allowed_residency'='customer_vpc_only' AND env->>'mode' NOT IN ('deterministic_only','byoc_self_hosted'))
   AND NOT (env->>'mode'='dev_openrouter' AND (limits->>'environment_class' NOT IN ('development','test') OR org->>'allowed_residency'<>'us_eu'))
   THEN env->>'mode' ELSE 'deterministic_only' END);
END $snapshot$;

CREATE OR REPLACE FUNCTION zasp_authorization80.ai_controls_read(o text,w text,e text,op text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $read$
DECLARE items jsonb;
BEGIN
 IF op NOT IN ('getOrganizationAIControls','getEnvironmentAIControls','listModelQualifications') OR op IS NULL THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='unknown AI policy operation'; END IF;
 PERFORM zasp_authorization80.product_request(o,w,e,NULL,op,'view_compliance','environment',e,false,true,false,false);
 IF op='getOrganizationAIControls' THEN RETURN zasp_authorization80.ai_org_snapshot(o); END IF;
 IF op='getEnvironmentAIControls' THEN RETURN zasp_authorization80.ai_env_snapshot(o,w,e); END IF;
 SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY provider,model,purpose),'[]') INTO items FROM (
  SELECT provider,model,purpose,(qualified AND checked_at<=now() AND coalesce(expires_at>now(),false) AND deployment_digest IS NOT NULL) AS qualified,checked_at,evidence_digest FROM public.model_qualifications
  WHERE (organization_id,workspace_id,environment_id)=(o,w,e) ORDER BY provider,model,purpose LIMIT 256
 ) q;
 RETURN jsonb_build_object('items',items);
END $read$;

CREATE OR REPLACE FUNCTION zasp_authorization80.ai_validate_patch(defaults jsonb,patch jsonb) RETURNS void
 LANGUAGE plpgsql SET search_path=pg_catalog AS $validate$
BEGIN
 IF jsonb_typeof(patch) IS DISTINCT FROM 'object' OR patch='{}' OR octet_length(patch::text)>4096 OR EXISTS(
  SELECT FROM jsonb_each(patch) f WHERE jsonb_typeof(defaults->f.key) IS DISTINCT FROM jsonb_typeof(f.value)
   OR (jsonb_typeof(f.value)='number' AND f.value::text !~ '^[0-9]{1,16}$')
 ) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid AI policy fields'; END IF;
END $validate$;

CREATE OR REPLACE FUNCTION zasp_authorization80.ai_check_environment(org jsonb, env jsonb, limits jsonb) RETURNS void
 LANGUAGE plpgsql SET search_path=pg_catalog AS $bounds$
DECLARE mode text:=env->>'mode'; private_content boolean:=(env->>'allow_approved_code_snippets')::boolean OR (env->>'allow_private_addon_bytes')::boolean;
BEGIN
 IF NOT (org->'allowed_modes' ? mode) OR (mode<>'deterministic_only' AND NOT (org->>'ai_enabled')::boolean)
  OR (mode NOT IN ('deterministic_only','byoc_self_hosted') AND org->>'allowed_residency'='customer_vpc_only')
  OR (mode='dev_openrouter' AND (limits->>'environment_class' NOT IN ('development','test') OR org->>'allowed_residency'<>'us_eu'))
  OR (private_content AND (NOT (org->>'allow_private_code_egress')::boolean OR limits->>'collection_mode'<>'extended'))
  OR (mode='deterministic_only' AND EXISTS(SELECT FROM jsonb_each(env) item WHERE item.key LIKE 'tier%\_enabled' AND item.value='true'::jsonb))
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='environment settings exceed the AI ceiling or data controls'; END IF;
END $bounds$;

-- Each opt-in must have current evidence for the exact deployed model and purpose.
CREATE OR REPLACE FUNCTION zasp_authorization80.ai_check_qualifications(o text,w text,e text,env jsonb) RETURNS void
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $qualify$
DECLARE binding record; mode text:=env->>'mode'; pin text;
BEGIN
 FOR binding IN SELECT * FROM (VALUES
  ('tier2_prompt_injection_enabled','indirect_injection_screen'),('tier2_purpose_drift_enabled','purpose_alignment_check'),
  ('tier2_heuristic_fp_suppression_enabled','heuristic_fp_verify'),('tier3_discovery_purpose_enabled','agent_discovery_verify'),
  ('tier3_discovery_purpose_enabled','agent_purpose_draft'),('tier3_addon_audit_enabled','addon_semantic_audit'),
  ('tier3_security_agent_planner_enabled','security_agent_triage'),('tier3_security_agent_planner_enabled','security_agent_remediate')
 ) b(capability,purpose) WHERE (env->>b.capability)::boolean LOOP
  IF starts_with(binding.capability,'tier2_') THEN
   pin:=env->>'tier2_profile';
   IF mode NOT IN ('zasp_vpc_slm','byoc_self_hosted','dev_openrouter') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='capability needs a Tier 2 mode'; END IF;
  ELSE
   pin:=env->>'tier3_model_pin';
   IF mode NOT IN ('privatelink_bedrock','privatelink_vertex','dev_openrouter') OR env->>'tier3_provider'<>mode THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='capability needs a matching Tier 3 provider'; END IF;
  END IF;
  IF NOT EXISTS(SELECT FROM public.model_qualifications q
   WHERE (q.organization_id,q.workspace_id,q.environment_id,q.provider,q.model,q.purpose)=(o,w,e,mode,pin,binding.purpose)
   AND q.qualified AND q.checked_at<=now() AND q.expires_at>now() AND q.deployment_digest IS NOT NULL)
  THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='current deployment qualification required for the selected job'; END IF;
 END LOOP;
END $qualify$;
ALTER FUNCTION zasp_authorization80.ai_check_qualifications(text,text,text,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.ai_check_qualifications(text,text,text,jsonb) FROM PUBLIC;

CREATE OR REPLACE FUNCTION zasp_authorization80.ai_controls_update(o text,w text,e text,actor text,op text,expected bigint,patch jsonb,audit_id text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $write$
DECLARE is_org boolean:=op='updateOrganizationAIControls'; proof jsonb; prior jsonb; merged jsonb; result jsonb; limits jsonb;
BEGIN
 IF op IS NULL OR op NOT IN ('updateOrganizationAIControls','updateEnvironmentAIControls') OR NOT public.zasp_valid_product_id(audit_id)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='unknown AI policy mutation'; END IF;
 proof:=zasp_authorization80.product_request(o,w,e,actor,op,CASE WHEN is_org THEN 'manage_identity' ELSE 'manage_data_controls' END,
  CASE WHEN is_org THEN 'organization_identity' ELSE 'environment' END,CASE WHEN is_org THEN o ELSE e END,false,true,true,true);
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-ai-controls/'||o,0));
 IF is_org THEN
  prior:=zasp_authorization80.ai_org_snapshot(o);
  PERFORM zasp_authorization80.ai_validate_patch(zasp_authorization80.ai_organization_defaults(),patch);
 ELSE
  limits:=zasp_authorization80.ai_data_limits(o,w,e,true);
  prior:=zasp_authorization80.ai_env_snapshot(o,w,e);
  PERFORM zasp_authorization80.ai_validate_patch(zasp_authorization80.ai_environment_defaults(),patch);
 END IF;
 IF (prior->>'version')::bigint IS DISTINCT FROM expected THEN RETURN '{"_mutation_state":"conflict"}'; END IF;
 merged:=prior||patch||jsonb_build_object('version',expected+1);
 IF is_org THEN
  IF jsonb_array_length(merged->'allowed_modes')<>(SELECT count(DISTINCT mode) FROM jsonb_array_elements_text(merged->'allowed_modes') mode) THEN
   RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='hosting modes must be unique'; END IF;
  INSERT INTO public.zasp_organization_ai_controls
   SELECT * FROM jsonb_populate_record(NULL::public.zasp_organization_ai_controls,merged)
   ON CONFLICT(organization_id) DO UPDATE SET
   (ai_enabled,allowed_modes,allowed_residency,allow_private_code_egress,require_zero_retention,version)=
   (excluded.ai_enabled,excluded.allowed_modes,excluded.allowed_residency,excluded.allow_private_code_egress,excluded.require_zero_retention,excluded.version);
  result:=zasp_authorization80.ai_org_snapshot(o);
 ELSE
  PERFORM zasp_authorization80.ai_check_environment(zasp_authorization80.ai_org_snapshot(o),merged,limits);
  PERFORM zasp_authorization80.ai_check_qualifications(o,w,e,merged);
  INSERT INTO public.zasp_environment_ai_controls
   SELECT * FROM jsonb_populate_record(NULL::public.zasp_environment_ai_controls,merged||jsonb_build_object('organization_id',o,'workspace_id',w))
   ON CONFLICT(organization_id,workspace_id,environment_id) DO UPDATE SET
   (mode,tier2_prompt_injection_enabled,tier2_purpose_drift_enabled,tier2_heuristic_fp_suppression_enabled,
    tier3_discovery_purpose_enabled,tier3_addon_audit_enabled,tier3_security_agent_planner_enabled,
    allow_redacted_summaries,allow_approved_code_snippets,allow_private_addon_bytes,tier2_profile,tier3_provider,tier3_model_pin,credential_reference,credential_digest,monthly_budget_nano_credits,version)=
   (excluded.mode,excluded.tier2_prompt_injection_enabled,excluded.tier2_purpose_drift_enabled,excluded.tier2_heuristic_fp_suppression_enabled,
    excluded.tier3_discovery_purpose_enabled,excluded.tier3_addon_audit_enabled,excluded.tier3_security_agent_planner_enabled,
    excluded.allow_redacted_summaries,excluded.allow_approved_code_snippets,excluded.allow_private_addon_bytes,excluded.tier2_profile,excluded.tier3_provider,excluded.tier3_model_pin,excluded.credential_reference,excluded.credential_digest,excluded.monthly_budget_nano_credits,excluded.version);
  result:=zasp_authorization80.ai_env_snapshot(o,w,e);
 END IF;
 INSERT INTO public.zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata)
 VALUES(o,w,e,audit_id,actor,op,CASE WHEN is_org THEN o ELSE e END,'succeeded',jsonb_build_object('version',expected+1,'fields',(SELECT jsonb_agg(key ORDER BY key) FROM jsonb_object_keys(patch) key)));
 PERFORM zasp_authorization80.product_settled(proof);
 RETURN result;
END $write$;
ALTER FUNCTION zasp_authorization80.ai_org_snapshot(text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION zasp_authorization80.ai_env_snapshot(text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION zasp_authorization80.ai_validate_patch(jsonb,jsonb) OWNER TO zasp_discovery_authority;
ALTER FUNCTION zasp_authorization80.ai_check_environment(jsonb,jsonb,jsonb) OWNER TO zasp_discovery_authority;
ALTER FUNCTION zasp_authorization80.ai_controls_read(text,text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION zasp_authorization80.ai_controls_update(text,text,text,text,text,bigint,jsonb,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.ai_org_snapshot(text),zasp_authorization80.ai_env_snapshot(text,text,text),zasp_authorization80.ai_validate_patch(jsonb,jsonb),zasp_authorization80.ai_check_environment(jsonb,jsonb,jsonb),zasp_authorization80.ai_controls_read(text,text,text,text),zasp_authorization80.ai_controls_update(text,text,text,text,text,bigint,jsonb,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.ai_controls_read(text,text,text,text),zasp_authorization80.ai_controls_update(text,text,text,text,text,bigint,jsonb,text) TO zasp_discovery_api;
