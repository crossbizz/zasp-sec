-- SOURCE COMPONENT ONLY: no schema-version registration, production grants,
-- default constructor change, native packet rewrite, or capability admission.
CREATE SCHEMA zasp_sa_temporary81 AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_sa_temporary81 FROM PUBLIC;
CREATE FUNCTION zasp_sa_temporary81.ready(checksum_value text,fingerprint_value text) RETURNS boolean LANGUAGE sql IMMUTABLE AS $ready$ SELECT false $ready$;
CREATE FUNCTION zasp_sa_temporary81.definition_mode(body_value jsonb) RETURNS text LANGUAGE plpgsql IMMUTABLE SET search_path TO pg_catalog,public AS $mode$
DECLARE mode_value text;
BEGIN
 IF jsonb_typeof(body_value) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='temporary definition shape rejected';END IF;
 IF NOT body_value ? 'temporary_policy_mode' THEN RETURN 'block';END IF;
 mode_value:=body_value->>'temporary_policy_mode';
 IF jsonb_typeof(body_value->'temporary_policy_mode') IS DISTINCT FROM 'string' OR mode_value NOT IN('monitor','block') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='temporary definition mode rejected';END IF;
 IF mode_value='monitor' AND (body_value->>'autonomy' IS DISTINCT FROM 'supervised' OR body_value->'max_steps' IS DISTINCT FROM '1'::jsonb OR body_value->'allowed_actions' IS DISTINCT FROM '["create_temporary_policy"]'::jsonb OR body_value->>'verification_kind' IS DISTINCT FROM 'policy_state' OR jsonb_typeof(body_value->'temporary_policy_seconds') IS DISTINCT FROM 'number' OR (body_value->>'temporary_policy_seconds')!~'^[1-9][0-9]{1,3}$' OR (body_value->>'temporary_policy_seconds')::integer NOT BETWEEN 60 AND 3600) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Monitor definition family rejected';END IF;
 RETURN mode_value;
END
$mode$;
CREATE FUNCTION zasp_sa_temporary81.plan_mode(o text,w text,e text,r text,s text) RETURNS text LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $plan_mode$
DECLARE p zasp_security_agent_plans%ROWTYPE;item jsonb;expected_mode text;
BEGIN
 SELECT plan.* INTO STRICT p FROM zasp_security_agent_plans plan JOIN zasp_security_agent_runs run ON (run.organization_id,run.workspace_id,run.environment_id,run.run_id,run.plan_hash)=(plan.organization_id,plan.workspace_id,plan.environment_id,plan.run_id,plan.plan_hash) WHERE (plan.organization_id,plan.workspace_id,plan.environment_id,plan.run_id)=(o,w,e,r);
 item:=p.plan->'steps'->0;
 IF p.plan_hash IS DISTINCT FROM digest(convert_to(p.plan::text,'UTF8'),'sha256') OR jsonb_array_length(p.plan->'steps')<>1 OR item->>'step_id' IS DISTINCT FROM s OR item->>'action' IS DISTINCT FROM 'create_temporary_policy' OR item->>'scope' IS DISTINCT FROM e OR item->>'target_id' IS DISTINCT FROM e OR item->>'mode' NOT IN('monitor','block') OR jsonb_typeof(item->'mode') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='temporary immutable plan rejected';END IF;
 PERFORM 1 FROM zasp_security_agent_steps step WHERE (step.organization_id,step.workspace_id,step.environment_id,step.run_id,step.step_id,step.input_digest)=(o,w,e,r,s,digest(convert_to(item::text,'UTF8'),'sha256'));
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='temporary step digest rejected';END IF;
 SELECT zasp_sa_temporary81.definition_mode(d.definition) INTO STRICT expected_mode FROM zasp_security_agent_definition_versions d WHERE (d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.version)=(o,w,e,p.definition_id,p.definition_version) AND d.definition_digest=digest(convert_to(d.definition::text,'UTF8'),'sha256');
 IF EXISTS(SELECT 1 FROM zasp_security_agent_effects effect WHERE (effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id,effect.step_id,effect.action_key)=(o,w,e,r,s,'create_temporary_policy') AND effect.input_digest IS DISTINCT FROM digest(convert_to(item::text,'UTF8'),'sha256')) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='temporary effect digest changed';END IF;
 IF expected_mode IS DISTINCT FROM item->>'mode' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='temporary saved mode changed';END IF;
 RETURN expected_mode;
END
$plan_mode$;
