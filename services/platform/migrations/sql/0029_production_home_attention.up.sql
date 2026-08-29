DO $guard$
BEGIN
  IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>28)
     OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=28 AND name='production_policy_deployment' AND checksum='a8af6930e2c2ce76c7c694bfe81964a6b781b4fffee954fdc2cf07221d04a4a1')
     OR NOT public.zasp_policy_deployment_execution_readiness('a8af6930e2c2ce76c7c694bfe81964a6b781b4fffee954fdc2cf07221d04a4a1','9e1b9c6ca6764465b6208efd779e7ca197fd4fad84a71dab78b8a3925693b9e8') THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='home attention prerequisite rejected';
  END IF;
END
$guard$;

ALTER FUNCTION public.zasp_inventory_home_summary(text,text,text) RENAME TO zasp_inventory_home_summary_v28;

CREATE FUNCTION public.zasp_inventory_home_summary_v29(organization_value text,workspace_value text,environment_value text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $summary$
DECLARE
  agent_count_value bigint; high_risk_value bigint; pending_approval_value bigint; oldest_approval_value bigint;
  needs_human_value bigint; failed_value bigint; inconclusive_value bigint; contained_value bigint; remediated_value bigint;
BEGIN
  IF zasp_inventory_scope_state(organization_value,workspace_value,environment_value)->>'phase'<>'cutover' THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='typed inventory scope unavailable';
  END IF;
  SELECT count(*) INTO agent_count_value FROM zasp_inventory_entities entity_value WHERE (entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.state,entity_value.product_kind)=(organization_value,workspace_value,environment_value,'active','agent');
  SELECT count(*) INTO high_risk_value FROM zasp_risk_attack_paths path_value WHERE (path_value.organization_id,path_value.workspace_id,path_value.environment_id)=(organization_value,workspace_value,environment_value) AND path_value.state IN('observed','verified');
  SELECT count(*),COALESCE(floor(extract(epoch FROM transaction_timestamp()-min(approval.created_at)))::bigint,0)
    INTO pending_approval_value,oldest_approval_value
    FROM zasp_security_agent_approvals approval
   WHERE approval.organization_id=organization_value AND approval.workspace_id=workspace_value AND approval.environment_id=environment_value AND approval.state='pending';
  SELECT count(*) FILTER(WHERE run.state='needs_human'),count(*) FILTER(WHERE run.state='failed'),count(*) FILTER(WHERE run.state='inconclusive'),
         count(*) FILTER(WHERE run.state='contained' AND run.updated_at>=transaction_timestamp()-interval '24 hours'),count(*) FILTER(WHERE run.state='remediated' AND run.updated_at>=transaction_timestamp()-interval '24 hours')
    INTO needs_human_value,failed_value,inconclusive_value,contained_value,remediated_value
    FROM zasp_security_agent_runs run
   WHERE run.organization_id=organization_value AND run.workspace_id=workspace_value AND run.environment_id=environment_value;
  RETURN jsonb_build_object(
    'agent_count',agent_count_value,'high_risk_paths',high_risk_value,'verified_changes',0,'blocked_changes',0,
    'pending_approvals',pending_approval_value,'oldest_approval_age_seconds',oldest_approval_value,
    'needs_human_runs',needs_human_value,'failed_runs',failed_value,'inconclusive_runs',inconclusive_value,
    'recent_contained',contained_value,'recent_remediated',remediated_value,
    'healthy',high_risk_value=0 AND pending_approval_value=0 AND needs_human_value=0 AND failed_value=0 AND inconclusive_value=0,
    'attention_required',high_risk_value>0 OR pending_approval_value>0 OR needs_human_value>0 OR failed_value>0 OR inconclusive_value>0);
END
$summary$;

CREATE FUNCTION public.zasp_inventory_home_summary(organization_value text,workspace_value text,environment_value text) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $compatibility$
  SELECT public.zasp_inventory_home_summary_v29(organization_value,workspace_value,environment_value)
$compatibility$;

ALTER FUNCTION public.zasp_inventory_home_summary_v29(text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_inventory_home_summary(text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_inventory_home_summary_v29(text,text,text),public.zasp_inventory_home_summary(text,text,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_security_agent_api,zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION public.zasp_inventory_home_summary(text,text,text) TO zasp_discovery_api;

CREATE FUNCTION public.zasp_production_home_attention_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_policy_deployment_execution_security_ready()
 AND (SELECT count(*) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner
      WHERE namespace.nspname='public' AND procedure.proname IN('zasp_inventory_home_summary','zasp_inventory_home_summary_v29') AND owner.rolname='zasp_discovery_authority' AND procedure.prosecdef AND COALESCE(procedure.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'])=2
 AND has_function_privilege('zasp_discovery_api','public.zasp_inventory_home_summary(text,text,text)','EXECUTE')
 AND NOT has_function_privilege('zasp_security_agent_api','public.zasp_inventory_home_summary(text,text,text)','EXECUTE')
 AND NOT has_function_privilege('zasp_discovery_api','public.zasp_inventory_home_summary_v29(text,text,text)','EXECUTE')
$security$;

CREATE FUNCTION public.zasp_production_home_attention_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
  SELECT concat_ws('|','prior',zasp_policy_deployment_execution_live_fingerprint())
  UNION ALL SELECT concat_ws('|','function',procedure.proname,pg_get_function_identity_arguments(procedure.oid),owner.rolname,procedure.prosecdef,COALESCE(procedure.proconfig::text,''),COALESCE(procedure.proacl::text,''),pg_get_functiondef(procedure.oid)) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_inventory_home_summary','zasp_inventory_home_summary_v29')
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;

CREATE FUNCTION public.zasp_production_home_attention_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT length(expected_checksum)=64 AND expected_checksum~'^[a-f0-9]{64}$' AND length(expected_fingerprint)=64 AND expected_fingerprint~'^[a-f0-9]{64}$'
 AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=29 AND name='production_home_attention' AND checksum=expected_checksum)
 AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>29)
 AND zasp_production_home_attention_security_ready() AND zasp_production_home_attention_live_fingerprint()=expected_fingerprint
$readiness$;

ALTER FUNCTION public.zasp_production_home_attention_security_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_home_attention_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_home_attention_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_home_attention_security_ready(),public.zasp_production_home_attention_live_fingerprint(),public.zasp_production_home_attention_readiness(text,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control,zasp_red_team_worker,zasp_red_team_outbox_worker,zasp_red_team_adapter,zasp_attack_lab_controller,zasp_attack_lab_outbox_worker,zasp_attack_lab_proxy,zasp_recovery_worker,zasp_recovery_outbox_worker,zasp_policy_deployment_worker;

ALTER FUNCTION public.zasp_policy_deployment_execution_readiness(text,text) RENAME TO zasp_policy_deployment_execution_readiness_v28;
REVOKE ALL ON FUNCTION public.zasp_policy_deployment_execution_readiness_v28(text,text) FROM PUBLIC,zasp_discovery_api,zasp_security_agent_worker,zasp_security_agent_action_worker,zasp_runtime_gateway,zasp_policy_deployment_worker;
CREATE FUNCTION public.zasp_policy_deployment_execution_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $compatibility$
 SELECT length(expected_checksum)=64 AND expected_checksum~'^[a-f0-9]{64}$' AND length(expected_fingerprint)=64 AND expected_fingerprint~'^[a-f0-9]{64}$'
 AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=28 AND name='production_policy_deployment' AND checksum=expected_checksum)
 AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_policy_deployment_fingerprint' AND value=expected_fingerprint)
 AND zasp_production_home_attention_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=29 AND name='production_home_attention'),(SELECT value FROM zasp_schema_metadata WHERE key='production_home_attention_fingerprint'))
$compatibility$;
ALTER FUNCTION public.zasp_policy_deployment_execution_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_policy_deployment_execution_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_policy_deployment_execution_readiness(text,text) TO zasp_discovery_api,zasp_security_agent_worker,zasp_security_agent_action_worker,zasp_runtime_gateway,zasp_policy_deployment_worker;

INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_home_attention_fingerprint', '45a16f5d9eb8265c606796bea9d096bee4edb10826284e9e169a4bd911d9d93c') ON CONFLICT(key) DO UPDATE SET value=excluded.value;
