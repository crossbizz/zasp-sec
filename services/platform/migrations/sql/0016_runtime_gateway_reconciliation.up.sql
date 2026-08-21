DO $release_guard$ BEGIN
 IF NOT zasp_runtime_data_plane_readiness(
  '35da4753c96ead82651ac120b4c0c5768cac34025af6a03fa7c706028e0eeaae',
  'd34e9701e73bd3bff93abb12fdd094a6023d77d371d9eebe9cfbd9637ceeb57c'
 ) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime data plane release required';END IF;
END $release_guard$;

DO $product_release_evolution$ DECLARE definition text;original_definition text;BEGIN
 SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;
 original_definition:=definition;
 definition:=replace(definition,'release."version" = 15','release."version" = 16');
 definition:=replace(definition,'release."name" = ''runtime_data_plane''','release."name" = ''runtime_gateway_reconciliation''');
 definition:=replace(definition,'later_release."version" > 15','later_release."version" > 16');
 IF definition=original_definition OR position('release."version" = 16' IN definition)=0 OR position('release."name" = ''runtime_gateway_reconciliation''' IN definition)=0 OR position('later_release."version" > 16' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v16 compatibility evolution failed';END IF;
 EXECUTE definition;
 SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;
 original_definition:=definition;
 definition:=replace(replace(definition,'release."version"=15','release."version"=16'),'release."version" = 15','release."version" = 16');
 definition:=replace(replace(definition,'release."name"=''runtime_data_plane''','release."name"=''runtime_gateway_reconciliation'''),'release."name" = ''runtime_data_plane''','release."name" = ''runtime_gateway_reconciliation''');
 definition:=replace(replace(definition,'later."version">15','later."version">16'),'later."version" > 15','later."version" > 16');
 IF definition=original_definition OR position('runtime_gateway_reconciliation' IN definition)=0 OR position('release."version"=16' IN definition)=0 AND position('release."version" = 16' IN definition)=0 OR position('later."version">16' IN definition)=0 AND position('later."version" > 16' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v16 compatibility evolution failed';END IF;
 EXECUTE definition;
END $product_release_evolution$;

CREATE TABLE public.zasp_runtime_gateway_reconciliation_state(
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 used_at timestamptz
);
INSERT INTO public.zasp_runtime_gateway_reconciliation_state(singleton) VALUES(true);
ALTER TABLE public.zasp_runtime_gateway_reconciliation_state OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_runtime_gateway_reconciliation_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_gateway_reconciliation_state FORCE ROW LEVEL SECURITY;
CREATE POLICY zasp_runtime_gateway_reconciliation_state_authority ON public.zasp_runtime_gateway_reconciliation_state TO zasp_discovery_authority USING(true) WITH CHECK(true);
REVOKE ALL ON TABLE public.zasp_runtime_gateway_reconciliation_state FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control;

CREATE OR REPLACE FUNCTION public.zasp_runtime_gateway_record_event(credential_value text,event_value text,expected_floor_value bigint,next_floor_value bigint,request_digest_value bytea,policy_version_value bigint,decision_value text,action_kind_value text,classification_value jsonb,occurred_value timestamptz) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE authority_value jsonb;organization_value text;workspace_value text;environment_value text;device_value text;existing_value zasp_runtime_gateway_events%ROWTYPE;canonical_digest bytea;result_value jsonb;
BEGIN
 IF NOT zasp_valid_product_id(event_value) OR expected_floor_value<0 OR next_floor_value<=expected_floor_value OR octet_length(request_digest_value)<>32 OR policy_version_value<1 OR decision_value NOT IN('allow','monitor','block') OR action_kind_value NOT IN('http','mcp') OR jsonb_typeof(classification_value)<>'object' OR classification_value='{}'::jsonb OR classification_value-ARRAY['category','route_class','resource_class','outcome']<>'{}'::jsonb OR octet_length(convert_to(classification_value::text,'UTF8'))>16384 OR EXISTS(SELECT 1 FROM jsonb_each_text(classification_value) item WHERE length(item.value) NOT BETWEEN 1 AND 128 OR item.value<>btrim(item.value) OR item.value~'[[:cntrl:]]') OR occurred_value IS NULL OR occurred_value>transaction_timestamp()+interval '30 seconds' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='gateway event rejected';END IF;
 authority_value:=zasp_runtime_gateway_credential_authority(credential_value,'runtime-gateway');organization_value:=authority_value->>'organization_id';workspace_value:=authority_value->>'workspace_id';environment_value:=authority_value->>'environment_id';device_value:=authority_value->>'device_id';
 canonical_digest:=digest(convert_to(jsonb_build_object('credential_id',credential_value,'device_id',device_value,'event_id',event_value,'expected_floor',expected_floor_value,'next_floor',next_floor_value,'policy_version',policy_version_value,'decision',decision_value,'action_kind',action_kind_value,'classification',classification_value,'occurred_at',to_char(occurred_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))::text,'UTF8'),'sha256');
 IF canonical_digest<>request_digest_value THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='gateway event rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,device_value),0));
 SELECT * INTO existing_value FROM zasp_runtime_gateway_events event_row WHERE (event_row.organization_id,event_row.workspace_id,event_row.environment_id,event_row.event_id)=(organization_value,workspace_value,environment_value,event_value);
 IF FOUND THEN
  IF (existing_value.device_id,existing_value.credential_id,existing_value.sequence,existing_value.request_digest,existing_value.policy_version,existing_value.decision,existing_value.action_kind,existing_value.classification,existing_value.occurred_at) IS DISTINCT FROM (device_value,credential_value,next_floor_value,request_digest_value,policy_version_value,decision_value,action_kind_value,classification_value,occurred_value) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='gateway event rejected';END IF;
  UPDATE zasp_runtime_gateway_reconciliation_state SET used_at=COALESCE(used_at,transaction_timestamp()) WHERE singleton;
  RETURN jsonb_build_object('event_id',event_value,'device_id',device_value,'sequence',next_floor_value,'recorded_at',existing_value.recorded_at,'replayed',true);
 END IF;
 IF occurred_value<transaction_timestamp()-interval '24 hours' THEN
  UPDATE zasp_runtime_gateway_reconciliation_state SET used_at=COALESCE(used_at,transaction_timestamp()) WHERE singleton;
  RETURN jsonb_build_object('event_id',event_value,'outcome','record_window_expired');
 END IF;
 PERFORM zasp_runtime_gateway_advance_replay(credential_value,expected_floor_value,next_floor_value,request_digest_value);
 INSERT INTO zasp_runtime_gateway_events(organization_id,workspace_id,environment_id,device_id,credential_id,event_id,sequence,request_digest,policy_version,decision,action_kind,classification,occurred_at) VALUES(organization_value,workspace_value,environment_value,device_value,credential_value,event_value,next_floor_value,request_digest_value,policy_version_value,decision_value,action_kind_value,classification_value,occurred_value)
 RETURNING jsonb_build_object('event_id',event_id,'device_id',device_id,'sequence',sequence,'recorded_at',recorded_at,'replayed',false) INTO result_value;
 UPDATE zasp_runtime_gateway_reconciliation_state SET used_at=COALESCE(used_at,transaction_timestamp()) WHERE singleton;
 RETURN result_value;
END $$;
ALTER FUNCTION public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamptz) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamptz) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamptz) TO zasp_gateway_control;

CREATE FUNCTION public.zasp_runtime_gateway_reconciliation_live_fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $$ SELECT ''::text $$;
CREATE FUNCTION public.zasp_runtime_gateway_reconciliation_security_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $$ SELECT false $$;
CREATE FUNCTION public.zasp_runtime_gateway_reconciliation_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
 SELECT length(expected_checksum)=64 AND length(expected_fingerprint)=64
  AND EXISTS(SELECT 1 FROM zasp_schema_versions release WHERE (release.version,release.name,release.checksum)=(16,'runtime_gateway_reconciliation',expected_checksum) AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions later WHERE later.version>16))
  AND EXISTS(SELECT 1 FROM zasp_schema_versions release WHERE (release.version,release.name,release.checksum)=(15,'runtime_data_plane','35da4753c96ead82651ac120b4c0c5768cac34025af6a03fa7c706028e0eeaae'))
  AND EXISTS(SELECT 1 FROM zasp_schema_metadata metadata WHERE (metadata.key,metadata.value)=('production_core_schema','runtime-data-plane-v1'))
  AND EXISTS(SELECT 1 FROM zasp_schema_metadata metadata WHERE (metadata.key,metadata.value)=('runtime_gateway_reconciliation_fingerprint',expected_fingerprint))
  AND zasp_runtime_gateway_reconciliation_live_fingerprint()=expected_fingerprint
  AND zasp_runtime_gateway_reconciliation_security_ready()
$$;

CREATE OR REPLACE FUNCTION public.zasp_runtime_gateway_reconciliation_security_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
 SELECT zasp_runtime_data_plane_security_ready()
  AND zasp_inventory_security_ready()
  AND NOT EXISTS(SELECT 1 FROM pg_class class_value JOIN pg_namespace namespace_value ON namespace_value.oid=class_value.relnamespace WHERE namespace_value.nspname='public' AND class_value.relname='zasp_runtime_gateway_reconciliation_state' AND (class_value.relowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') OR NOT class_value.relrowsecurity OR NOT class_value.relforcerowsecurity OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(class_value.relacl,acldefault('r',class_value.relowner))) acl WHERE acl.grantee<>class_value.relowner)))
  AND NOT EXISTS(SELECT 1 FROM pg_proc procedure_value CROSS JOIN aclexplode(COALESCE(procedure_value.proacl,acldefault('f',procedure_value.proowner))) acl WHERE procedure_value.oid IN('zasp_runtime_gateway_reconciliation_live_fingerprint()'::regprocedure,'zasp_runtime_gateway_reconciliation_security_ready()'::regprocedure) AND acl.grantee<>procedure_value.proowner)
  AND NOT EXISTS(SELECT 1 FROM pg_proc procedure_value CROSS JOIN aclexplode(COALESCE(procedure_value.proacl,acldefault('f',procedure_value.proowner))) acl WHERE procedure_value.oid='zasp_runtime_gateway_reconciliation_readiness(text,text)'::regprocedure AND acl.grantee=0)
  AND has_function_privilege('zasp_gateway_control','zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamptz)','EXECUTE')
$$;

CREATE OR REPLACE FUNCTION public.zasp_runtime_gateway_reconciliation_live_fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
 WITH semantic_object(kind,identity,definition) AS (
  SELECT 'runtime_data_plane','live',zasp_runtime_data_plane_live_fingerprint()
  UNION ALL SELECT 'column',table_name||'.'||column_name,concat_ws('|',data_type,udt_name,is_nullable,column_default) FROM information_schema.columns WHERE table_schema='public' AND table_name='zasp_runtime_gateway_reconciliation_state'
  UNION ALL SELECT 'constraint',constraint_value.conrelid::regclass::text||'.'||constraint_value.conname,pg_get_constraintdef(constraint_value.oid,true) FROM pg_constraint constraint_value WHERE constraint_value.conrelid='public.zasp_runtime_gateway_reconciliation_state'::regclass
  UNION ALL SELECT 'policy',policy_value.schemaname||'.'||policy_value.tablename||'.'||policy_value.policyname,concat_ws('|',policy_value.roles::text,policy_value.cmd,policy_value.qual,policy_value.with_check) FROM pg_policies policy_value WHERE policy_value.schemaname='public' AND policy_value.tablename='zasp_runtime_gateway_reconciliation_state'
  UNION ALL SELECT 'inherited_function',procedure_value.oid::regprocedure::text,pg_get_functiondef(procedure_value.oid) FROM pg_proc procedure_value WHERE procedure_value.oid IN('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure,'public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure)
  UNION ALL SELECT 'function',procedure_value.oid::regprocedure::text,pg_get_functiondef(procedure_value.oid) FROM pg_proc procedure_value JOIN pg_namespace namespace_value ON namespace_value.oid=procedure_value.pronamespace WHERE namespace_value.nspname='public' AND procedure_value.proname IN('zasp_runtime_gateway_reconciliation_security_ready','zasp_runtime_gateway_reconciliation_readiness')
  UNION ALL SELECT 'function_acl',procedure_value.oid::regprocedure::text,COALESCE(array_to_string(procedure_value.proacl,','),'') FROM pg_proc procedure_value JOIN pg_namespace namespace_value ON namespace_value.oid=procedure_value.pronamespace WHERE namespace_value.nspname='public' AND procedure_value.proname IN('zasp_runtime_gateway_reconciliation_live_fingerprint','zasp_runtime_gateway_reconciliation_security_ready','zasp_runtime_gateway_reconciliation_readiness')
 ) SELECT encode(digest(convert_to(string_agg(kind||chr(31)||identity||chr(31)||definition,chr(30) ORDER BY kind,identity,definition),'UTF8'),'sha256'),'hex') FROM semantic_object
$$;

ALTER FUNCTION public.zasp_runtime_gateway_reconciliation_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_gateway_reconciliation_security_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_gateway_reconciliation_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_gateway_reconciliation_live_fingerprint(),public.zasp_runtime_gateway_reconciliation_security_ready(),public.zasp_runtime_gateway_reconciliation_readiness(text,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_gateway_reconciliation_readiness(text,text) TO zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control;

INSERT INTO public.zasp_schema_metadata(key,value) VALUES('runtime_gateway_reconciliation_fingerprint', 'baf48507379aeb75fddff0df0549e90b88e578d8d667770d17cdd350c268a1e5');
