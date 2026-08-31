DO $guard$
BEGIN
  IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>33)
     OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=33 AND name='production_security_agent_attack_path')
     OR NOT public.zasp_production_security_agent_attack_path_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=33 AND name='production_security_agent_attack_path'),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_security_agent_attack_path_fingerprint')) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='production security agent attack path prerequisite rejected';
  END IF;
END
$guard$;

DO $compatibility$
DECLARE definition text;original_definition text;
BEGIN
  SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(definition,'later_release."version" > 33','later_release."version" > 34');
  IF definition=original_definition OR position('production-recovery-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v34 compatibility evolution failed';END IF;
  EXECUTE definition;
  SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(replace(definition,'later."version">33','later."version">34'),'later."version" > 33','later."version" > 34');
  IF definition=original_definition OR position('production-recovery-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v34 compatibility evolution failed';END IF;
  EXECUTE definition;
  SELECT pg_get_functiondef('public.zasp_production_security_agent_attack_path_security_ready()'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 33','later_release."version" > 34'),'later."version">33','later."version">34'),'later."version" > 33','later."version" > 34');
  IF definition=original_definition THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack path v34 compatibility evolution failed';END IF;
  EXECUTE definition;
END
$compatibility$;

CREATE OR REPLACE FUNCTION public.zasp_production_workflow_compatibility_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_production_approval_notification_security_ready()
 AND position('later_release."version" > 34' IN pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure))>0
 AND (position('later."version">34' IN pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure))>0
      OR position('later."version" > 34' IN pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure))>0)
$security$;

CREATE FUNCTION public.zasp_execution_integration_setup_status(organization_value text,workspace_value text,environment_value text,integration_value text,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $setup$
DECLARE integration_row zasp_integrations%ROWTYPE;connection_row zasp_integration_connections%ROWTYPE;subject_row zasp_discovery_connection_subjects%ROWTYPE;credential_row zasp_connector_credentials%ROWTYPE;authorization_state text:='pending';scope_kind_value text:='none';scope_label_value text;repository_selection_value text;permissions_value jsonb:='[]'::jsonb;sensor_count_value integer:=0;healthy_count_value integer:=0;missing_count_value integer:=0;unsupported_count_value integer:=0;coverage_state text:='not_applicable';coverage_reason text:='not_applicable';updated_value timestamptz;
BEGIN
  IF NOT zasp_production_integration_setup_readiness(expected_checksum,expected_fingerprint) OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(integration_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='integration setup status rejected';END IF;
  SELECT * INTO integration_row FROM zasp_integrations integration WHERE (integration.organization_id,integration.workspace_id,integration.environment_id,integration.id)=(organization_value,workspace_value,environment_value,integration_value) AND integration.kind IN('aws','kubernetes','github','okta') AND integration.state<>'deleted';
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='integration setup status missing';END IF;
  updated_value:=integration_row.updated_at;
  IF (SELECT count(*) FROM zasp_integration_connections connection WHERE (connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,connection.provider,connection.state)=(organization_value,workspace_value,environment_value,integration_value,integration_row.kind,'verified'))=1 THEN
    SELECT * INTO STRICT connection_row FROM zasp_integration_connections connection WHERE (connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,connection.provider,connection.state)=(organization_value,workspace_value,environment_value,integration_value,integration_row.kind,'verified');
    SELECT * INTO subject_row FROM zasp_discovery_connection_subjects subject WHERE (subject.organization_id,subject.workspace_id,subject.environment_id,subject.integration_id,subject.connection_id,subject.provider,subject.connection_version,subject.configuration_digest)=(organization_value,workspace_value,environment_value,integration_value,connection_row.id,integration_row.kind,connection_row.version,digest(convert_to(integration_row.configuration::text,'UTF8'),'sha256'));
    IF FOUND THEN
      updated_value:=greatest(updated_value,connection_row.updated_at,subject_row.verified_at);
      IF integration_row.kind IN('aws','kubernetes') THEN
        authorization_state:='verified';scope_kind_value:=subject_row.subject_kind;scope_label_value:=subject_row.subject_id;
      ELSIF (SELECT count(*) FROM zasp_connector_credentials credential WHERE (credential.organization_id,credential.workspace_id,credential.environment_id,credential.integration_id,credential.provider,credential.status,credential.credential_reference)=(organization_value,workspace_value,environment_value,integration_value,integration_row.kind,'active',connection_row.connection_reference))=1 THEN
        SELECT * INTO STRICT credential_row FROM zasp_connector_credentials credential WHERE (credential.organization_id,credential.workspace_id,credential.environment_id,credential.integration_id,credential.provider,credential.status,credential.credential_reference)=(organization_value,workspace_value,environment_value,integration_value,integration_row.kind,'active',connection_row.connection_reference);
        updated_value:=greatest(updated_value,credential_row.updated_at);
        IF integration_row.kind='github' AND subject_row.subject_kind='github_installation' AND credential_row.metadata->>'installation_id'=subject_row.subject_id AND credential_row.metadata->>'account_type'='Organization' AND credential_row.metadata->>'account_login'~'^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$' AND credential_row.metadata->>'repository_selection' IN('all','selected') AND credential_row.metadata->'permissions'='{"actions":"read","contents":"read","metadata":"read"}'::jsonb THEN
          authorization_state:='verified';scope_kind_value:='github_organization';scope_label_value:=credential_row.metadata->>'account_login';repository_selection_value:=credential_row.metadata->>'repository_selection';permissions_value:='["actions:read","contents:read","metadata:read"]'::jsonb;
        ELSIF integration_row.kind='okta' AND subject_row.subject_kind='okta_tenant' AND credential_row.metadata->>'tenant'=subject_row.subject_id AND credential_row.metadata->'scopes'='["offline_access","okta.apps.read","okta.groups.read","okta.users.read"]'::jsonb THEN
          authorization_state:='verified';scope_kind_value:='okta_tenant';scope_label_value:=subject_row.subject_id;permissions_value:=credential_row.metadata->'scopes';
        ELSE authorization_state:='degraded';END IF;
      ELSE authorization_state:='degraded';END IF;
    END IF;
  END IF;
  IF integration_row.kind='kubernetes' THEN
    SELECT count(*),count(*) FILTER(WHERE sensor.state='active' AND heartbeat.status='healthy' AND heartbeat.observed_at>=transaction_timestamp()-interval '5 minutes' AND COALESCE((heartbeat.metadata->>'btf')::boolean,false)),count(*) FILTER(WHERE heartbeat.sensor_id IS NULL OR heartbeat.observed_at<transaction_timestamp()-interval '5 minutes'),count(*) FILTER(WHERE heartbeat.observed_at>=transaction_timestamp()-interval '5 minutes' AND NOT COALESCE((heartbeat.metadata->>'btf')::boolean,false)),greatest(updated_value,COALESCE(max(sensor.updated_at),updated_value),COALESCE(max(heartbeat.observed_at),updated_value)) INTO sensor_count_value,healthy_count_value,missing_count_value,unsupported_count_value,updated_value
    FROM zasp_sensors sensor LEFT JOIN zasp_sensor_heartbeats heartbeat ON (heartbeat.organization_id,heartbeat.workspace_id,heartbeat.environment_id,heartbeat.sensor_id)=(sensor.organization_id,sensor.workspace_id,sensor.environment_id,sensor.id)
    WHERE (sensor.organization_id,sensor.workspace_id,sensor.environment_id,sensor.kind)=(organization_value,workspace_value,environment_value,'tetragon') AND sensor.state NOT IN('revoked','deleted');
    IF sensor_count_value=0 THEN coverage_state:='not_enrolled';coverage_reason:='not_enrolled';
    ELSIF missing_count_value>0 THEN coverage_state:='awaiting_heartbeat';coverage_reason:='missing_gateway';
    ELSIF unsupported_count_value>0 THEN coverage_state:='degraded';coverage_reason:='unsupported_kernel';
    ELSIF healthy_count_value=sensor_count_value THEN coverage_state:='healthy';coverage_reason:='verified';
    ELSE coverage_state:='degraded';coverage_reason:='degraded';END IF;
  END IF;
  RETURN jsonb_build_object('integration_id',integration_value,'connector_key',integration_row.kind,'authorization',jsonb_build_object('state',authorization_state,'scope_kind',scope_kind_value,'scope_label',scope_label_value,'repository_selection',repository_selection_value,'permissions',permissions_value),'runtime_coverage',jsonb_build_object('state',coverage_state,'reason',coverage_reason,'sensor_count',sensor_count_value,'healthy_sensor_count',healthy_count_value),'updated_at',to_char(updated_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
END
$setup$;

CREATE FUNCTION public.zasp_production_integration_setup_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_production_security_agent_attack_path_security_ready() AND zasp_production_workflow_compatibility_security_ready()
 AND EXISTS(SELECT 1 FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname='zasp_execution_integration_setup_status' AND pg_get_function_identity_arguments(procedure.oid)='organization_value text, workspace_value text, environment_value text, integration_value text, expected_checksum text, expected_fingerprint text' AND owner.rolname='zasp_discovery_authority' AND procedure.prosecdef AND COALESCE(procedure.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] AND NOT has_function_privilege('public',procedure.oid,'EXECUTE') AND has_function_privilege('zasp_discovery_api',procedure.oid,'EXECUTE') AND NOT has_function_privilege('zasp_discovery_worker',procedure.oid,'EXECUTE') AND NOT has_function_privilege('zasp_security_agent_worker',procedure.oid,'EXECUTE'))
 AND NOT has_table_privilege('zasp_discovery_api','public.zasp_connector_credentials','SELECT') AND NOT has_table_privilege('zasp_discovery_api','public.zasp_discovery_connection_subjects','SELECT') AND NOT has_table_privilege('zasp_discovery_api','public.zasp_sensor_heartbeats','SELECT')
$security$;

CREATE FUNCTION public.zasp_production_integration_setup_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
  SELECT concat_ws('|','prior',(SELECT value FROM zasp_schema_metadata WHERE key='production_security_agent_attack_path_fingerprint'))
  UNION ALL SELECT concat_ws('|','compatibility',zasp_production_workflow_compatibility_live_fingerprint())
  UNION ALL SELECT concat_ws('|','function',procedure.proname,pg_get_function_identity_arguments(procedure.oid),owner.rolname,procedure.prosecdef,COALESCE(procedure.proconfig::text,''),COALESCE(procedure.proacl::text,''),pg_get_functiondef(procedure.oid)) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_execution_integration_setup_status','zasp_production_integration_setup_security_ready')
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;

CREATE FUNCTION public.zasp_production_integration_setup_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT length(expected_checksum)=64 AND expected_checksum~'^[a-f0-9]{64}$' AND length(expected_fingerprint)=64 AND expected_fingerprint~'^[a-f0-9]{64}$'
 AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=34 AND name='production_integration_setup' AND checksum=expected_checksum)
 AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>34)
 AND zasp_production_integration_setup_security_ready() AND zasp_production_integration_setup_live_fingerprint()=expected_fingerprint
$readiness$;

ALTER FUNCTION public.zasp_execution_integration_setup_status(text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_integration_setup_security_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_integration_setup_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_integration_setup_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_execution_integration_setup_status(text,text,text,text,text,text),public.zasp_production_integration_setup_security_ready(),public.zasp_production_integration_setup_live_fingerprint(),public.zasp_production_integration_setup_readiness(text,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;
GRANT EXECUTE ON FUNCTION public.zasp_execution_integration_setup_status(text,text,text,text,text,text) TO zasp_discovery_api;

ALTER FUNCTION public.zasp_production_security_agent_attack_path_readiness(text,text) RENAME TO zasp_production_security_agent_attack_path_readiness_v33;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_attack_path_readiness_v33(text,text) FROM PUBLIC,zasp_security_agent_worker;
CREATE FUNCTION public.zasp_production_security_agent_attack_path_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $compatibility$
 SELECT length(expected_checksum)=64 AND expected_checksum~'^[a-f0-9]{64}$' AND length(expected_fingerprint)=64 AND expected_fingerprint~'^[a-f0-9]{64}$'
 AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=33 AND name='production_security_agent_attack_path' AND checksum=expected_checksum)
 AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_security_agent_attack_path_fingerprint' AND value=expected_fingerprint)
 AND zasp_production_integration_setup_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=34 AND name='production_integration_setup'),(SELECT value FROM zasp_schema_metadata WHERE key='production_integration_setup_fingerprint'))
$compatibility$;
ALTER FUNCTION public.zasp_production_security_agent_attack_path_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_attack_path_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_attack_path_readiness(text,text) TO zasp_security_agent_worker;

INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_integration_setup_fingerprint', '02b12cb41460db83cb28c45d25ccfc0a9e8648504a59e17bdcdbfefe8abbc73b') ON CONFLICT(key) DO UPDATE SET value=excluded.value;
