DO $reconciliation_guard$ BEGIN
 IF zasp_runtime_gateway_reconciliation_live_fingerprint()<>'a124de1fb24806a16ec92c590b2cee79748ffbdf721c360c9e7f02b9a6ba00f2' OR NOT zasp_runtime_gateway_reconciliation_security_ready() THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime gateway reconciliation drift blocks rollback';
 END IF;
 IF EXISTS(SELECT 1 FROM zasp_runtime_gateway_reconciliation_state WHERE used_at IS NOT NULL) THEN
  RAISE EXCEPTION USING ERRCODE='2BP01',MESSAGE='runtime gateway reconciliation use blocks rollback';
 END IF;
END $reconciliation_guard$;

DO $product_release_restore$ DECLARE definition text;original_definition text;BEGIN
 SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;
 original_definition:=definition;
 definition:=replace(definition,'release."version" = 16','release."version" = 15');
 definition:=replace(definition,'release."name" = ''runtime_gateway_reconciliation''','release."name" = ''runtime_data_plane''');
 definition:=replace(definition,'later_release."version" > 16','later_release."version" > 15');
 IF definition=original_definition OR position('release."version" = 15' IN definition)=0 OR position('release."name" = ''runtime_data_plane''' IN definition)=0 OR position('later_release."version" > 15' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v15 compatibility restoration failed';END IF;
 EXECUTE definition;
 SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;
 original_definition:=definition;
 definition:=replace(replace(definition,'release."version"=16','release."version"=15'),'release."version" = 16','release."version" = 15');
 definition:=replace(replace(definition,'release."name"=''runtime_gateway_reconciliation''','release."name"=''runtime_data_plane'''),'release."name" = ''runtime_gateway_reconciliation''','release."name" = ''runtime_data_plane''');
 definition:=replace(replace(definition,'later."version">16','later."version">15'),'later."version" > 16','later."version" > 15');
 IF definition=original_definition OR position('runtime_data_plane' IN definition)=0 OR position('release."version"=15' IN definition)=0 AND position('release."version" = 15' IN definition)=0 OR position('later."version">15' IN definition)=0 AND position('later."version" > 15' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v15 compatibility restoration failed';END IF;
 EXECUTE definition;
END $product_release_restore$;

DELETE FROM public.zasp_schema_metadata WHERE (key,value)=('runtime_gateway_reconciliation_fingerprint','a124de1fb24806a16ec92c590b2cee79748ffbdf721c360c9e7f02b9a6ba00f2');
DROP FUNCTION public.zasp_runtime_gateway_reconciliation_readiness(text,text);
DROP FUNCTION public.zasp_runtime_gateway_reconciliation_live_fingerprint();
DROP FUNCTION public.zasp_runtime_gateway_reconciliation_security_ready();

CREATE OR REPLACE FUNCTION public.zasp_runtime_gateway_record_event(credential_value text,event_value text,expected_floor_value bigint,next_floor_value bigint,request_digest_value bytea,policy_version_value bigint,decision_value text,action_kind_value text,classification_value jsonb,occurred_value timestamptz) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE authority_value jsonb;organization_value text;workspace_value text;environment_value text;device_value text;existing_value zasp_runtime_gateway_events%ROWTYPE;canonical_digest bytea;result_value jsonb;
BEGIN
 IF NOT zasp_valid_product_id(event_value) OR expected_floor_value<0 OR next_floor_value<=expected_floor_value OR octet_length(request_digest_value)<>32 OR policy_version_value<1 OR decision_value NOT IN('allow','monitor','block') OR action_kind_value NOT IN('http','mcp') OR jsonb_typeof(classification_value)<>'object' OR classification_value='{}'::jsonb OR classification_value-ARRAY['category','route_class','resource_class','outcome']<>'{}'::jsonb OR octet_length(convert_to(classification_value::text,'UTF8'))>16384 OR EXISTS(SELECT 1 FROM jsonb_each_text(classification_value) item WHERE length(item.value) NOT BETWEEN 1 AND 128 OR item.value<>btrim(item.value) OR item.value~'[[:cntrl:]]') OR occurred_value<transaction_timestamp()-interval '24 hours' OR occurred_value>transaction_timestamp()+interval '30 seconds' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='gateway event rejected';END IF;
 authority_value:=zasp_runtime_gateway_credential_authority(credential_value,'runtime-gateway');organization_value:=authority_value->>'organization_id';workspace_value:=authority_value->>'workspace_id';environment_value:=authority_value->>'environment_id';device_value:=authority_value->>'device_id';
 canonical_digest:=digest(convert_to(jsonb_build_object('credential_id',credential_value,'device_id',device_value,'event_id',event_value,'expected_floor',expected_floor_value,'next_floor',next_floor_value,'policy_version',policy_version_value,'decision',decision_value,'action_kind',action_kind_value,'classification',classification_value,'occurred_at',to_char(occurred_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))::text,'UTF8'),'sha256');
 IF canonical_digest<>request_digest_value THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='gateway event rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,device_value),0));
 SELECT * INTO existing_value FROM zasp_runtime_gateway_events event_row WHERE (event_row.organization_id,event_row.workspace_id,event_row.environment_id,event_row.event_id)=(organization_value,workspace_value,environment_value,event_value);
 IF FOUND THEN
  IF (existing_value.device_id,existing_value.credential_id,existing_value.sequence,existing_value.request_digest,existing_value.policy_version,existing_value.decision,existing_value.action_kind,existing_value.classification,existing_value.occurred_at) IS DISTINCT FROM (device_value,credential_value,next_floor_value,request_digest_value,policy_version_value,decision_value,action_kind_value,classification_value,occurred_value) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='gateway event rejected';END IF;
  RETURN jsonb_build_object('event_id',event_value,'device_id',device_value,'sequence',next_floor_value,'recorded_at',existing_value.recorded_at,'replayed',true);
 END IF;
 PERFORM zasp_runtime_gateway_advance_replay(credential_value,expected_floor_value,next_floor_value,request_digest_value);
 INSERT INTO zasp_runtime_gateway_events(organization_id,workspace_id,environment_id,device_id,credential_id,event_id,sequence,request_digest,policy_version,decision,action_kind,classification,occurred_at) VALUES(organization_value,workspace_value,environment_value,device_value,credential_value,event_value,next_floor_value,request_digest_value,policy_version_value,decision_value,action_kind_value,classification_value,occurred_value)
 RETURNING jsonb_build_object('event_id',event_id,'device_id',device_id,'sequence',sequence,'recorded_at',recorded_at,'replayed',false) INTO result_value;
 RETURN result_value;
END $$;
ALTER FUNCTION public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamptz) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamptz) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamptz) TO zasp_gateway_control;

DROP TABLE public.zasp_runtime_gateway_reconciliation_state;
