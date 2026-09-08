DO $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>34)
 OR NOT public.zasp_production_integration_setup_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=34 AND name='production_integration_setup'),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_integration_setup_fingerprint')) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='integration webhook prerequisite rejected';
 END IF;
END
$guard$;

DO $compatibility$
DECLARE definition text; prior text; function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 34','later_release."version" > 35'),'later."version">34','later."version">35'),'later."version" > 34','later."version" > 35');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='integration webhook compatibility rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;

CREATE TABLE public.zasp_integration_webhook_tests (
 organization_id text NOT NULL CHECK(zasp_valid_product_id(organization_id)),
 workspace_id text NOT NULL CHECK(zasp_valid_product_id(workspace_id)),
 environment_id text NOT NULL CHECK(zasp_valid_product_id(environment_id)),
 integration_id text NOT NULL CHECK(zasp_valid_product_id(integration_id)),
 principal_id text NOT NULL CHECK(zasp_valid_product_id(principal_id)),
 idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9._:-]{16,128}$'),
 delivery_id text NOT NULL CHECK(zasp_valid_product_id(delivery_id)),
 integration_version bigint NOT NULL CHECK(integration_version BETWEEN 1 AND 1000000),
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 configuration_digest bytea NOT NULL CHECK(octet_length(configuration_digest)=32),
 destination_url text NOT NULL CHECK(length(destination_url) BETWEEN 10 AND 2048),
 secret_reference text NOT NULL CHECK(secret_reference ~ '^secret_ref_[A-Za-z0-9][A-Za-z0-9._/-]{0,115}$' AND position('..' IN secret_reference)=0 AND position('//' IN secret_reference)=0),
 payload text NOT NULL CHECK(octet_length(payload) BETWEEN 2 AND 16384),
 payload_digest text NOT NULL CHECK(payload_digest ~ '^sha256:[0-9a-f]{64}$' AND payload_digest='sha256:'||encode(digest(convert_to(payload,'UTF8'),'sha256'),'hex')),
 state text NOT NULL CHECK(state IN('leased','succeeded','failed')),
 lease_token text NOT NULL CHECK(lease_token ~ '^[0-9a-f]{64}$'),
 lease_expires_at timestamptz NOT NULL,
 attempt integer NOT NULL CHECK(attempt BETWEEN 1 AND 3),
 audit_id text NOT NULL CHECK(zasp_valid_product_id(audit_id)),
 correlation_id text NOT NULL CHECK(zasp_valid_product_id(correlation_id)),
 attempted_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 completed_at timestamptz,
 PRIMARY KEY(organization_id,workspace_id,environment_id,delivery_id),
 UNIQUE(organization_id,workspace_id,environment_id,principal_id,idempotency_key),
 CHECK(lease_expires_at>attempted_at),
 CHECK(state='leased' AND completed_at IS NULL OR state IN('succeeded','failed') AND completed_at>=attempted_at)
);
CREATE INDEX zasp_integration_webhook_tests_status_idx ON public.zasp_integration_webhook_tests(organization_id,workspace_id,environment_id,integration_id,attempted_at DESC,delivery_id);
ALTER TABLE public.zasp_integration_webhook_tests OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_integration_webhook_tests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_integration_webhook_tests FORCE ROW LEVEL SECURITY;
CREATE POLICY integration_webhook_authority ON public.zasp_integration_webhook_tests TO zasp_discovery_authority USING(true) WITH CHECK(true);
REVOKE ALL ON public.zasp_integration_webhook_tests FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;

CREATE FUNCTION public.zasp_integration_webhook_test_public(item public.zasp_integration_webhook_tests) RETURNS jsonb LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $public$
 SELECT jsonb_build_object('integration_id',item.integration_id,'delivery_id',item.delivery_id,'delivery_status',CASE WHEN item.state='leased' THEN 'pending' ELSE item.state END,'signature_status',CASE WHEN item.state='succeeded' THEN 'signed' ELSE 'unconfirmed' END,'attempted_at',to_char(item.attempted_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'completed_at',CASE WHEN item.completed_at IS NULL THEN NULL ELSE to_char(item.completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END,'error_code',CASE WHEN item.state='failed' THEN 'delivery_failed' ELSE '' END,'audit_id',item.audit_id)
$public$;

CREATE FUNCTION public.zasp_integration_webhook_test_reserve(organization_value text,workspace_value text,environment_value text,principal_value text,integration_value text,expected_version bigint,key_value text,audit_value text,correlation_value text,delivery_value text,token_value text,lease_seconds integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $reserve$
DECLARE item zasp_integration_webhook_tests%ROWTYPE;workflow zasp_workflow_records%ROWTYPE;request_digest_value bytea;payload_value text;destination_value text;secret_value text;
BEGIN
 IF NOT COALESCE(zasp_production_integration_webhook_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=35),(SELECT value FROM zasp_schema_metadata WHERE key='production_integration_webhook_fingerprint')),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='integration webhook unavailable';END IF;
 IF NOT COALESCE(zasp_valid_product_id(organization_value) AND zasp_valid_product_id(workspace_value) AND zasp_valid_product_id(environment_value) AND zasp_valid_product_id(principal_value) AND zasp_valid_product_id(integration_value) AND zasp_valid_product_id(audit_value) AND zasp_valid_product_id(correlation_value) AND audit_value<>correlation_value AND zasp_valid_product_id(delivery_value) AND expected_version BETWEEN 1 AND 1000000 AND key_value ~ '^[A-Za-z0-9._:-]{16,128}$' AND token_value ~ '^[0-9a-f]{64}$' AND lease_seconds BETWEEN 5 AND 30,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='integration webhook rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),'integration-webhook',organization_value,workspace_value,environment_value,principal_value,key_value),0));
 request_digest_value:=digest(convert_to(jsonb_build_object('integration_id',integration_value,'expected_version',expected_version)::text,'UTF8'),'sha256');
 SELECT * INTO item FROM zasp_integration_webhook_tests WHERE (organization_id,workspace_id,environment_id,principal_id,idempotency_key)=(organization_value,workspace_value,environment_value,principal_value,key_value) FOR UPDATE;
 IF FOUND THEN
  IF item.request_digest<>request_digest_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='integration webhook conflict';END IF;
  IF item.state IN('succeeded','failed') THEN RETURN jsonb_build_object('state',item.state,'delivery_id',item.delivery_id,'status',zasp_integration_webhook_test_public(item));END IF;
  IF item.lease_expires_at>transaction_timestamp() THEN RETURN jsonb_build_object('state','busy','delivery_id',item.delivery_id,'lease_expires_at',to_char(item.lease_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));END IF;
 END IF;
 SELECT * INTO workflow FROM zasp_workflow_records WHERE (organization_id,workspace_id,environment_id,kind,id)=(organization_value,workspace_value,environment_value,'integration',integration_value) AND deleted_at IS NULL FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='integration webhook missing';END IF;
 IF workflow.version<>expected_version OR workflow.body->>'connector_key' IS DISTINCT FROM 'generic-webhook' OR workflow.body->>'status' IS DISTINCT FROM 'configured' THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='integration webhook configuration changed';END IF;
 destination_value:=workflow.body->'configuration'->>'destination_url';secret_value:=workflow.body->'configuration'->>'signing_secret_reference';
 IF jsonb_typeof(workflow.body->'configuration') IS DISTINCT FROM 'object' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='integration webhook configuration rejected';END IF;
 IF (SELECT count(*) FROM jsonb_object_keys(workflow.body->'configuration'))<>2 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='integration webhook configuration rejected';END IF;
 IF NOT COALESCE(length(destination_value)<=2048 AND destination_value ~ '^https://[a-z0-9][a-z0-9.-]*[a-z0-9](:443)?(/[^?#[:cntrl:] ]*)?$' AND position('..' IN destination_value)=0 AND secret_value ~ '^secret_ref_[A-Za-z0-9][A-Za-z0-9._/-]{0,115}$' AND position('..' IN secret_value)=0 AND position('//' IN secret_value)=0,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='integration webhook configuration rejected';END IF;
 IF item.delivery_id IS NOT NULL THEN
  IF item.configuration_digest<>digest(convert_to((workflow.body->'configuration')::text,'UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='integration webhook configuration changed';END IF;
  IF item.attempt=3 THEN
   UPDATE zasp_integration_webhook_tests SET state='failed',completed_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,delivery_id)=(organization_value,workspace_value,environment_value,item.delivery_id) RETURNING * INTO item;
   RETURN jsonb_build_object('state','failed','delivery_id',item.delivery_id,'status',zasp_integration_webhook_test_public(item));
  END IF;
  UPDATE zasp_integration_webhook_tests SET lease_token=token_value,lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),attempt=attempt+1 WHERE (organization_id,workspace_id,environment_id,delivery_id)=(organization_value,workspace_value,environment_value,item.delivery_id) RETURNING * INTO item;
 ELSE
  IF EXISTS(SELECT 1 FROM zasp_integration_webhook_tests WHERE (organization_id,workspace_id,environment_id,integration_id)=(organization_value,workspace_value,environment_value,integration_value) AND attempted_at>transaction_timestamp()-interval '10 seconds') THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='integration webhook test busy';END IF;
  payload_value:=jsonb_build_object('delivery_id',delivery_value,'event','integration.webhook.test','integration',jsonb_build_object('id',integration_value,'version',expected_version),'scope',jsonb_build_object('organization_id',organization_value,'workspace_id',workspace_value,'environment_id',environment_value),'sent_at',to_char(transaction_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'version',1)::text;
  INSERT INTO zasp_integration_webhook_tests(organization_id,workspace_id,environment_id,integration_id,principal_id,idempotency_key,delivery_id,integration_version,request_digest,configuration_digest,destination_url,secret_reference,payload,payload_digest,state,lease_token,lease_expires_at,attempt,audit_id,correlation_id)
  VALUES(organization_value,workspace_value,environment_value,integration_value,principal_value,key_value,delivery_value,expected_version,request_digest_value,digest(convert_to((workflow.body->'configuration')::text,'UTF8'),'sha256'),destination_value,secret_value,payload_value,'sha256:'||encode(digest(convert_to(payload_value,'UTF8'),'sha256'),'hex'),'leased',token_value,transaction_timestamp()+make_interval(secs=>lease_seconds),1,audit_value,correlation_value) RETURNING * INTO item;
  INSERT INTO zasp_workflow_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,principal_id,operation,resource_kind,resource_id,resource_version) VALUES(organization_value,workspace_value,environment_value,audit_value,correlation_value,principal_value,'testIntegrationWebhook','integration',integration_value,expected_version);
 END IF;
 RETURN jsonb_build_object('state','dispatch','delivery_id',item.delivery_id,'payload',item.payload,'payload_digest',item.payload_digest,'destination_url',item.destination_url,'secret_reference',item.secret_reference,'lease_expires_at',to_char(item.lease_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
END
$reserve$;

CREATE FUNCTION public.zasp_integration_webhook_test_complete(organization_value text,workspace_value text,environment_value text,delivery_value text,token_value text,digest_value text,succeeded_value boolean) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $complete$
DECLARE item zasp_integration_webhook_tests%ROWTYPE;next_state text:=CASE WHEN succeeded_value THEN 'succeeded' ELSE 'failed' END;
BEGIN
 IF NOT COALESCE(zasp_production_integration_webhook_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=35),(SELECT value FROM zasp_schema_metadata WHERE key='production_integration_webhook_fingerprint')),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='integration webhook unavailable';END IF;
 SELECT * INTO item FROM zasp_integration_webhook_tests WHERE (organization_id,workspace_id,environment_id,delivery_id,lease_token,payload_digest)=(organization_value,workspace_value,environment_value,delivery_value,token_value,digest_value) FOR UPDATE;
 IF NOT FOUND OR succeeded_value IS NULL OR item.state<>next_state AND (item.state<>'leased' OR item.lease_expires_at<=transaction_timestamp()) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='integration webhook completion rejected';END IF;
 IF item.state='leased' THEN UPDATE zasp_integration_webhook_tests SET state=next_state,completed_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,delivery_id)=(organization_value,workspace_value,environment_value,delivery_value) RETURNING * INTO item;END IF;
 RETURN zasp_integration_webhook_test_public(item);
END
$complete$;

CREATE FUNCTION public.zasp_integration_webhook_test_status(organization_value text,workspace_value text,environment_value text,integration_value text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $status$
DECLARE item zasp_integration_webhook_tests%ROWTYPE;
BEGIN
 IF NOT COALESCE(zasp_production_integration_webhook_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=35),(SELECT value FROM zasp_schema_metadata WHERE key='production_integration_webhook_fingerprint')),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='integration webhook unavailable';END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_workflow_records WHERE (organization_id,workspace_id,environment_id,kind,id)=(organization_value,workspace_value,environment_value,'integration',integration_value) AND deleted_at IS NULL AND body->>'connector_key'='generic-webhook') THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='integration webhook missing';END IF;
 SELECT tests.* INTO item FROM zasp_integration_webhook_tests tests JOIN zasp_workflow_records workflow ON (workflow.organization_id,workflow.workspace_id,workflow.environment_id,workflow.kind,workflow.id,workflow.version)=(tests.organization_id,tests.workspace_id,tests.environment_id,'integration',tests.integration_id,tests.integration_version) WHERE (tests.organization_id,tests.workspace_id,tests.environment_id,tests.integration_id)=(organization_value,workspace_value,environment_value,integration_value) AND tests.configuration_digest=digest(convert_to((workflow.body->'configuration')::text,'UTF8'),'sha256') ORDER BY tests.attempted_at DESC,tests.delivery_id LIMIT 1;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='integration webhook test missing';END IF;
 RETURN zasp_integration_webhook_test_public(item);
END
$status$;

ALTER FUNCTION public.zasp_integration_webhook_test_public(public.zasp_integration_webhook_tests) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_integration_webhook_test_reserve(text,text,text,text,text,bigint,text,text,text,text,text,integer) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_integration_webhook_test_complete(text,text,text,text,text,text,boolean) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_integration_webhook_test_status(text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_integration_webhook_test_public(public.zasp_integration_webhook_tests),public.zasp_integration_webhook_test_reserve(text,text,text,text,text,bigint,text,text,text,text,text,integer),public.zasp_integration_webhook_test_complete(text,text,text,text,text,text,boolean),public.zasp_integration_webhook_test_status(text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_integration_webhook_test_reserve(text,text,text,text,text,bigint,text,text,text,text,text,integer),public.zasp_integration_webhook_test_complete(text,text,text,text,text,text,boolean),public.zasp_integration_webhook_test_status(text,text,text,text) TO zasp_discovery_api;

CREATE FUNCTION public.zasp_production_integration_webhook_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_production_integration_setup_security_ready()
 AND (SELECT count(*)=4 AND bool_and(owner.rolname='zasp_discovery_authority' AND COALESCE(procedure.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] AND NOT has_function_privilege('public',procedure.oid,'EXECUTE') AND NOT has_function_privilege('zasp_discovery_worker',procedure.oid,'EXECUTE') AND (procedure.proname='zasp_integration_webhook_test_public' OR procedure.prosecdef AND has_function_privilege('zasp_discovery_api',procedure.oid,'EXECUTE'))) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_integration_webhook_test_public','zasp_integration_webhook_test_reserve','zasp_integration_webhook_test_complete','zasp_integration_webhook_test_status'))
 AND EXISTS(SELECT 1 FROM pg_class table_value JOIN pg_roles owner ON owner.oid=table_value.relowner WHERE table_value.oid='public.zasp_integration_webhook_tests'::regclass AND owner.rolname='zasp_discovery_authority' AND table_value.relrowsecurity AND table_value.relforcerowsecurity)
 AND NOT has_table_privilege('public','public.zasp_integration_webhook_tests','SELECT,INSERT,UPDATE,DELETE') AND NOT has_table_privilege('zasp_discovery_api','public.zasp_integration_webhook_tests','SELECT,INSERT,UPDATE,DELETE')
$security$;

CREATE FUNCTION public.zasp_production_integration_webhook_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','prior',zasp_production_integration_setup_live_fingerprint())
 UNION ALL SELECT concat_ws('|','function',procedure.proname,pg_get_function_identity_arguments(procedure.oid),owner.rolname,procedure.prosecdef,COALESCE(procedure.proconfig::text,''),COALESCE(procedure.proacl::text,''),pg_get_functiondef(procedure.oid)) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_integration_webhook_test_public','zasp_integration_webhook_test_reserve','zasp_integration_webhook_test_complete','zasp_integration_webhook_test_status','zasp_production_integration_webhook_security_ready')
 UNION ALL SELECT concat_ws('|','table',table_value.relname,owner.rolname,table_value.relrowsecurity,table_value.relforcerowsecurity,COALESCE(table_value.relacl::text,'')) FROM pg_class table_value JOIN pg_roles owner ON owner.oid=table_value.relowner WHERE table_value.oid='public.zasp_integration_webhook_tests'::regclass
 UNION ALL SELECT concat_ws('|','column',attribute.attnum,attribute.attname,format_type(attribute.atttypid,attribute.atttypmod),attribute.attnotnull,COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),'')) FROM pg_attribute attribute LEFT JOIN pg_attrdef default_value ON (default_value.adrelid,default_value.adnum)=(attribute.attrelid,attribute.attnum) WHERE attribute.attrelid='public.zasp_integration_webhook_tests'::regclass AND attribute.attnum>0 AND NOT attribute.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',constraint_value.conname,pg_get_constraintdef(constraint_value.oid,true)) FROM pg_constraint constraint_value WHERE constraint_value.conrelid='public.zasp_integration_webhook_tests'::regclass
 UNION ALL SELECT concat_ws('|','index',pg_get_indexdef(index_value.indexrelid)) FROM pg_index index_value WHERE index_value.indrelid='public.zasp_integration_webhook_tests'::regclass
 UNION ALL SELECT concat_ws('|','policy',policy.polname,policy.polcmd,policy.polpermissive,ARRAY(SELECT rolname FROM pg_roles WHERE oid=ANY(policy.polroles) ORDER BY rolname)::text,pg_get_expr(policy.polqual,policy.polrelid),pg_get_expr(policy.polwithcheck,policy.polrelid)) FROM pg_policy policy WHERE policy.polrelid='public.zasp_integration_webhook_tests'::regclass
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;

CREATE FUNCTION public.zasp_production_integration_webhook_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=35 AND name='production_integration_webhook' AND checksum=expected_checksum) AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>35) AND zasp_production_integration_webhook_security_ready() AND zasp_production_integration_webhook_live_fingerprint()=expected_fingerprint
$readiness$;
ALTER FUNCTION public.zasp_production_integration_webhook_security_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_integration_webhook_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_integration_webhook_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_integration_webhook_security_ready(),public.zasp_production_integration_webhook_live_fingerprint(),public.zasp_production_integration_webhook_readiness(text,text) FROM PUBLIC;

ALTER FUNCTION public.zasp_production_integration_setup_readiness(text,text) RENAME TO zasp_production_integration_setup_readiness_v34;
CREATE FUNCTION public.zasp_production_integration_setup_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $compatibility$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=34 AND name='production_integration_setup' AND checksum=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_integration_setup_fingerprint' AND value=expected_fingerprint) AND zasp_production_integration_webhook_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=35),(SELECT value FROM zasp_schema_metadata WHERE key='production_integration_webhook_fingerprint'))
$compatibility$;
ALTER FUNCTION public.zasp_production_integration_setup_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_integration_setup_readiness(text,text) FROM PUBLIC;

INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_integration_webhook_fingerprint', 'b9456ee67062bae82d7ddd8d277a4c4d8e137801fd5e95e06657eaf524d67b81');
