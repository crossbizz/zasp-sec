-- Release v12: first-party reference authorization for AWS and Kubernetes.
CREATE FUNCTION public.zasp_reference_authorization_configuration_valid(provider_value text,configuration_value jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$
  SELECT jsonb_typeof(configuration_value)='object' AND octet_length(configuration_value::text)<=4096 AND (
    provider_value='aws'
      AND (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(configuration_value) key)=ARRAY['external_id_reference','region','role_arn']::text[]
      AND configuration_value->>'role_arn' ~ '^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,128}$'
      AND configuration_value->>'external_id_reference' ~ '^ref:aws/external-id/[A-Za-z0-9][A-Za-z0-9._-]{7,127}$'
      AND configuration_value->>'region' ~ '^[a-z]{2}-[a-z]+-[1-9][0-9]?$'
    OR provider_value='kubernetes'
      AND (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(configuration_value) key)=ARRAY['connection_reference']::text[]
      AND configuration_value->>'connection_reference' ~ '^ref:kubernetes/connection/[A-Za-z0-9][A-Za-z0-9._-]{7,127}$'
  )
$$;

CREATE FUNCTION public.zasp_reference_authorization_replay(
  organization_value text,workspace_value text,environment_value text,principal_value text,
  integration_value text,idempotency_value text,expected_version_value bigint
) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE prior_response jsonb;
BEGIN
  IF NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value)
    OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(integration_value) OR NOT zasp_valid_product_id(principal_value)
    OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR expected_version_value NOT BETWEEN 1 AND 1000000 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid reference authorization replay';
  END IF;
  SELECT response INTO prior_response FROM zasp_workflow_idempotency
   WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value
     AND principal_id=principal_value AND operation='completeIntegrationReferenceAuthorization' AND idempotency_key=idempotency_value;
  IF NOT FOUND THEN RETURN jsonb_build_object('found',false,'result',NULL); END IF;
  IF prior_response->'body'->>'id'<>integration_value OR (prior_response->>'version')::bigint<>expected_version_value+1 THEN
    RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='reference authorization replay conflict';
  END IF;
  RETURN jsonb_build_object('found',true,'result',prior_response||jsonb_build_object('replayed',true));
END $$;

CREATE FUNCTION public.zasp_reference_authorization_exact_replay(
  organization_value text,workspace_value text,environment_value text,principal_value text,
  integration_value text,idempotency_value text,intent_value jsonb
) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE prior_digest bytea; prior_response jsonb; requested_digest bytea;
BEGIN
  requested_digest:=digest(convert_to(intent_value::text,'UTF8'),'sha256');
  SELECT request_digest,response INTO prior_digest,prior_response FROM zasp_workflow_idempotency
   WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value
     AND principal_id=principal_value AND operation='completeIntegrationReferenceAuthorization' AND idempotency_key=idempotency_value;
  IF NOT FOUND THEN RETURN jsonb_build_object('found',false,'result',NULL); END IF;
  IF prior_digest<>requested_digest OR prior_response->'body'->>'id'<>integration_value THEN
    RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='reference authorization replay conflict';
  END IF;
  RETURN jsonb_build_object('found',true,'result',prior_response||jsonb_build_object('replayed',true));
END $$;

CREATE FUNCTION public.zasp_complete_reference_authorization(
  organization_value text,workspace_value text,environment_value text,principal_value text,
  integration_value text,provider_value text,connection_value text,reference_value text,
  idempotency_value text,expected_version_value bigint,configuration_value jsonb,intent_value jsonb,
  audit_value text,correlation_value text,receipt_value text
) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE workflow_row zasp_workflow_records%ROWTYPE; integration_row zasp_integrations%ROWTYPE;
  connection_row zasp_integration_connections%ROWTYPE; desired_body jsonb; result_value jsonb; replay_value jsonb;
  expected_intent jsonb;
BEGIN
  IF NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value)
    OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(principal_value)
    OR NOT zasp_valid_product_id(integration_value) OR NOT zasp_valid_product_id(connection_value)
    OR NOT zasp_valid_product_id(audit_value) OR NOT zasp_valid_product_id(correlation_value) OR NOT zasp_valid_product_id(receipt_value)
    OR expected_version_value NOT BETWEEN 1 AND 1000000 OR length(idempotency_value) NOT BETWEEN 16 AND 128
    OR provider_value NOT IN('aws','kubernetes')
    OR NOT zasp_reference_authorization_configuration_valid(provider_value,configuration_value)
    OR reference_value<>(CASE provider_value WHEN 'aws' THEN configuration_value->>'external_id_reference' ELSE configuration_value->>'connection_reference' END) THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid reference authorization completion';
  END IF;
  expected_intent:=jsonb_build_object(
    'configuration',configuration_value,'expected_version',expected_version_value,'idempotency_key',idempotency_value,
    'integration_id',integration_value,'provider',provider_value,
    'scope',jsonb_build_object('environment_id',environment_value,'organization_id',organization_value,'workspace_id',workspace_value));
  IF intent_value<>expected_intent THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid reference authorization intent'; END IF;
  replay_value:=zasp_reference_authorization_exact_replay(organization_value,workspace_value,environment_value,principal_value,integration_value,idempotency_value,intent_value);
  IF (replay_value->>'found')::boolean THEN RETURN replay_value->'result'; END IF;

  SELECT * INTO workflow_row FROM zasp_workflow_records
   WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value
     AND kind='integration' AND id=integration_value AND deleted_at IS NULL FOR UPDATE;
  SELECT * INTO integration_row FROM zasp_integrations
   WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value
     AND id=integration_value FOR UPDATE;
  replay_value:=zasp_reference_authorization_exact_replay(organization_value,workspace_value,environment_value,principal_value,integration_value,idempotency_value,intent_value);
  IF (replay_value->>'found')::boolean THEN RETURN replay_value->'result'; END IF;
  IF workflow_row.id IS NULL OR integration_row.id IS NULL OR workflow_row.version<>expected_version_value
    OR integration_row.version<>expected_version_value OR workflow_row.body->>'connector_key'<>provider_value
    OR workflow_row.body->'configuration'<>configuration_value OR integration_row.kind<>provider_value
    OR integration_row.configuration<>configuration_value OR workflow_row.body->>'status' NOT IN('configured','pending_authorization','degraded')
    OR integration_row.state NOT IN('pending','authorizing','degraded') THEN
    RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='reference authorization intent changed';
  END IF;
  desired_body:=jsonb_set(jsonb_set(workflow_row.body,'{status}','"active"'::jsonb),'{updated_at}',to_jsonb(transaction_timestamp()));
  result_value:=zasp_connector_workflow_mutate(
    'update','integration',integration_value,organization_value,workspace_value,environment_value,principal_value,
    'completeIntegrationReferenceAuthorization',idempotency_value,expected_version_value,intent_value,desired_body,
    audit_value,correlation_value,receipt_value);
  UPDATE zasp_integrations SET state='active',version=(result_value->>'version')::bigint,updated_at=transaction_timestamp(),deleted_at=NULL
   WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=integration_value
     AND version=(result_value->>'version')::bigint AND state IN('pending','authorizing','degraded') RETURNING * INTO integration_row;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='typed reference authorization conflict'; END IF;
  INSERT INTO zasp_integration_connections(organization_id,workspace_id,environment_id,id,integration_id,provider,connection_reference,state,version,verified_at)
  VALUES(organization_value,workspace_value,environment_value,connection_value,integration_value,provider_value,reference_value,'verified',(result_value->>'version')::bigint,transaction_timestamp())
  ON CONFLICT(organization_id,workspace_id,environment_id,integration_id,provider) DO UPDATE
    SET state='verified',version=EXCLUDED.version,verified_at=COALESCE(zasp_integration_connections.verified_at,transaction_timestamp()),revoked_at=NULL,updated_at=transaction_timestamp()
    WHERE zasp_integration_connections.id=EXCLUDED.id AND zasp_integration_connections.connection_reference=EXCLUDED.connection_reference
      AND zasp_integration_connections.state IN('pending','invalid') RETURNING * INTO connection_row;
  IF NOT FOUND OR connection_row.id<>connection_value OR connection_row.version<>(result_value->>'version')::bigint THEN
    RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='reference connection conflict';
  END IF;
  RETURN result_value;
END $$;

CREATE FUNCTION public.zasp_reference_authorization_security_ready() RETURNS boolean LANGUAGE sql STABLE AS $$
 WITH expected(functions,api_functions) AS (SELECT
   ARRAY['zasp_complete_reference_authorization','zasp_reference_authorization_configuration_valid','zasp_reference_authorization_exact_replay','zasp_reference_authorization_readiness','zasp_reference_authorization_replay','zasp_reference_authorization_security_ready']::text[],
   ARRAY[
     'zasp_complete_reference_authorization(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)',
     'zasp_reference_authorization_readiness(text,text)',
     'zasp_reference_authorization_replay(text,text,text,text,text,text,bigint)',
     'zasp_reference_authorization_security_ready()'
   ]::text[])
 SELECT zasp_connector_security_ready()
   AND (SELECT array_agg(p.proname::text ORDER BY p.proname) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace,expected WHERE n.nspname='public' AND p.proname=ANY(expected.functions))=(SELECT functions FROM expected)
   AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace,expected
     WHERE n.nspname='public' AND p.proname=ANY(expected.functions)
       AND (p.proowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') OR NOT p.prosecdef
         OR NOT COALESCE(p.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public']
         OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
           WHERE a.privilege_type='EXECUTE' AND a.grantee NOT IN(p.proowner,(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_api')))))
   AND (SELECT COALESCE(array_agg(p.proname||'('||replace(oidvectortypes(p.proargtypes),', ',',')||')' ORDER BY p.proname||'('||replace(oidvectortypes(p.proargtypes),', ',',')||')'),'{}'::text[])
     FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a,expected
     WHERE n.nspname='public' AND p.proname=ANY(expected.functions) AND a.privilege_type='EXECUTE' AND a.grantee=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_api'))=(SELECT api_functions FROM expected)
$$;

CREATE FUNCTION public.zasp_reference_authorization_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE AS $$
 WITH semantic_objects AS (
   SELECT 'table'::text object_kind,class.relname::text object_identity,jsonb_build_object('row_security',class.relrowsecurity,'force_row_security',class.relforcerowsecurity,'persistence',class.relpersistence) definition FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND left(class.relname,5)='zasp_' AND class.relkind IN ('r','p')
   UNION ALL SELECT 'column',class.relname||'.'||attribute.attnum||'.'||attribute.attname,jsonb_build_object('type',format_type(attribute.atttypid,attribute.atttypmod),'not_null',attribute.attnotnull,'default',COALESCE(regexp_replace(pg_get_expr(default_value.adbin,default_value.adrelid,true),E'\\s+',' ','g'),''),'identity',attribute.attidentity,'generated',attribute.attgenerated,'collation',CASE WHEN attribute.attcollation=0 THEN '' ELSE attribute.attcollation::regcollation::text END) FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum WHERE namespace.nspname='public' AND left(class.relname,5)='zasp_' AND class.relkind IN ('r','p') AND attribute.attnum>0 AND NOT attribute.attisdropped
   UNION ALL SELECT 'constraint',class.relname||'.'||constraint_value.conname,jsonb_build_object('type',constraint_value.contype,'definition',regexp_replace(pg_get_constraintdef(constraint_value.oid,true),E'\\s+',' ','g'),'deferrable',constraint_value.condeferrable,'deferred',constraint_value.condeferred,'validated',constraint_value.convalidated) FROM pg_constraint constraint_value JOIN pg_class class ON class.oid=constraint_value.conrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND left(class.relname,5)='zasp_'
   UNION ALL SELECT 'index',table_class.relname||'.'||index_class.relname,jsonb_build_object('definition',regexp_replace(pg_get_indexdef(index_value.indexrelid,0,true),E'\\s+',' ','g'),'unique',index_value.indisunique,'primary',index_value.indisprimary,'exclusion',index_value.indisexclusion,'valid',index_value.indisvalid,'ready',index_value.indisready) FROM pg_index index_value JOIN pg_class table_class ON table_class.oid=index_value.indrelid JOIN pg_class index_class ON index_class.oid=index_value.indexrelid JOIN pg_namespace namespace ON namespace.oid=table_class.relnamespace WHERE namespace.nspname='public' AND left(table_class.relname,5)='zasp_'
   UNION ALL SELECT 'function',procedure.proname||'('||pg_get_function_identity_arguments(procedure.oid)||')',jsonb_build_object('result',pg_get_function_result(procedure.oid),'language',language.lanname,'kind',procedure.prokind,'volatility',procedure.provolatile,'strict',procedure.proisstrict,'security_definer',procedure.prosecdef,'leakproof',procedure.proleakproof,'parallel',procedure.proparallel,'config',COALESCE(to_jsonb(procedure.proconfig),'[]'::jsonb),'body',regexp_replace(btrim(procedure.prosrc),E'\\s+',' ','g')) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_language language ON language.oid=procedure.prolang WHERE namespace.nspname='public' AND left(procedure.proname,5)='zasp_'
   UNION ALL SELECT 'trigger',table_class.relname||'.'||trigger_value.tgname,jsonb_build_object('definition',regexp_replace(pg_get_triggerdef(trigger_value.oid,true),E'\\s+',' ','g'),'enabled',trigger_value.tgenabled,'function',trigger_value.tgfoid::regprocedure::text) FROM pg_trigger trigger_value JOIN pg_class table_class ON table_class.oid=trigger_value.tgrelid JOIN pg_namespace namespace ON namespace.oid=table_class.relnamespace WHERE namespace.nspname='public' AND table_class.relname='zasp_connector_effects' AND NOT trigger_value.tgisinternal
 ), live AS (SELECT encode(digest(convert_to(COALESCE(jsonb_agg(jsonb_build_array(object_kind,object_identity,definition) ORDER BY object_kind,object_identity)::text,'[]'),'UTF8'),'sha256'),'hex') value FROM semantic_objects)
 SELECT EXISTS(SELECT 1 FROM zasp_schema_versions v JOIN zasp_schema_metadata m ON m.key='production_core_schema' AND m.value='reference-authorization-v1' JOIN zasp_schema_metadata fingerprint ON fingerprint.key='reference_authorization_fingerprint' AND fingerprint.value=expected_fingerprint CROSS JOIN live
 WHERE v.version=12 AND v.name='reference_authorization' AND v.checksum=expected_checksum AND live.value=expected_fingerprint
   AND zasp_reference_authorization_security_ready() AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions newer WHERE newer.version>12))
$$;

DO $authority$ DECLARE procedure_oid oid; BEGIN
  FOR procedure_oid IN SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname LIKE 'zasp_%reference_authorization%' LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway',procedure_oid::regprocedure);
    EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER',procedure_oid::regprocedure);
    EXECUTE format('ALTER FUNCTION %s SET search_path TO pg_catalog, public',procedure_oid::regprocedure);
    EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',procedure_oid::regprocedure);
  END LOOP;
END $authority$;
GRANT EXECUTE ON FUNCTION zasp_reference_authorization_replay(text,text,text,text,text,text,bigint),zasp_complete_reference_authorization(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text),zasp_reference_authorization_security_ready(),zasp_reference_authorization_readiness(text,text) TO zasp_discovery_api;

DO $release_evolution$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO definition;
 definition:=replace(definition,'connector-authorization-v1','reference-authorization-v1'); definition:=replace(definition,'release."version" = 11','release."version" = 12'); definition:=replace(definition,'release."name" = ''connector_authorization''','release."name" = ''reference_authorization'''); definition:=replace(definition,'later_release."version" > 11','later_release."version" > 12'); EXECUTE definition;
 SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO definition;
 definition:=replace(definition,'connector-authorization-v1','reference-authorization-v1'); definition:=replace(replace(definition,'release."version"=11','release."version"=12'),'release."version" = 11','release."version" = 12'); definition:=replace(replace(definition,'release."name"=''connector_authorization''','release."name"=''reference_authorization'''),'release."name" = ''connector_authorization''','release."name" = ''reference_authorization'''); definition:=replace(replace(definition,'later."version">11','later."version">12'),'later."version" > 11','later."version" > 12'); EXECUTE definition;
END $release_evolution$;

CREATE OR REPLACE FUNCTION public.zasp_connector_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM zasp_schema_versions connector JOIN zasp_schema_versions current_release ON current_release.version=12 AND current_release.name='reference_authorization'
 JOIN zasp_schema_metadata marker ON marker.key='production_core_schema' AND marker.value='reference-authorization-v1'
 JOIN zasp_schema_metadata fingerprint ON fingerprint.key='connector_authorization_fingerprint' AND fingerprint.value=expected_fingerprint
 WHERE connector.version=11 AND connector.name='connector_authorization' AND connector.checksum=expected_checksum AND zasp_connector_security_ready() AND zasp_reference_authorization_security_ready() AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions newer WHERE newer.version>12))
$$;
ALTER FUNCTION zasp_connector_readiness(text,text) SECURITY DEFINER;
ALTER FUNCTION zasp_connector_readiness(text,text) SET search_path TO pg_catalog, public;
ALTER FUNCTION zasp_connector_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_connector_readiness(text,text) FROM PUBLIC,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway;
GRANT EXECUTE ON FUNCTION zasp_connector_readiness(text,text) TO zasp_discovery_api,zasp_discovery_worker;

INSERT INTO zasp_schema_metadata(key,value) VALUES ('reference_authorization_fingerprint', '7df2066d41071e3a21e3df8968eeae6cadf4489b2a8b7c45c43bac7aeb47696c');
UPDATE zasp_schema_metadata SET value='reference-authorization-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='connector-authorization-v1';
