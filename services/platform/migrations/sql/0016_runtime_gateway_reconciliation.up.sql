DO $release_guard$ BEGIN
 IF NOT zasp_runtime_data_plane_readiness(
  '6a5e4b76a120cfda89f1afb8461d9c1b1f19fabc38565058b63b91956932e9b5',
  'f1d2ed7c174d55bc64c41bd72ddd567e263010b239750b85ce19060757ca6b0d'
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

CREATE INDEX zasp_inventory_entities_global_search_v16_idx
ON public.zasp_inventory_entities(organization_id,workspace_id,environment_id,(lower(display_name) COLLATE "C") text_pattern_ops,id)
WHERE state='active';

CREATE INDEX zasp_risk_findings_global_search_v16_idx
ON public.zasp_risk_findings(organization_id,workspace_id,environment_id,(lower(title) COLLATE "C") text_pattern_ops,id);

CREATE FUNCTION public.zasp_global_search(organization_value text,workspace_value text,environment_value text,query_value text,limit_value integer) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE normalized_query text:=lower(query_value);result_value jsonb;
BEGIN
 IF NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value)
  OR query_value IS NULL OR char_length(query_value) NOT BETWEEN 2 AND 128 OR octet_length(query_value)>128 OR query_value<>btrim(query_value)
  OR query_value!~'^[A-Za-z0-9 .:_/-]+$' OR limit_value NOT BETWEEN 1 AND 100
  OR zasp_inventory_scope_state(organization_value,workspace_value,environment_value)->>'phase' IS DISTINCT FROM 'cutover'
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='global search rejected';END IF;
 WITH candidates AS (
  SELECT entity_value.id,entity_value.product_kind type_value,entity_value.display_name name_value,
   CASE WHEN entity_value.id=query_value THEN 0 WHEN entity_value.product_kind=normalized_query THEN 1 WHEN lower(entity_value.display_name)=normalized_query THEN 2 ELSE 3 END rank_value
  FROM zasp_inventory_entities entity_value
  WHERE (entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.state)=(organization_value,workspace_value,environment_value,'active')
   AND (entity_value.id=query_value OR entity_value.product_kind=normalized_query OR lower(entity_value.display_name) COLLATE "C" LIKE normalized_query COLLATE "C"||'%')
  UNION ALL
  SELECT finding_value.id,'finding',finding_value.title,
   CASE WHEN finding_value.id=query_value THEN 0 WHEN normalized_query='finding' THEN 1 WHEN lower(finding_value.title)=normalized_query THEN 2 ELSE 3 END
  FROM zasp_risk_findings finding_value
  WHERE (finding_value.organization_id,finding_value.workspace_id,finding_value.environment_id)=(organization_value,workspace_value,environment_value)
   AND (finding_value.id=query_value OR normalized_query='finding' OR lower(finding_value.title) COLLATE "C" LIKE normalized_query COLLATE "C"||'%')
 ),visible AS (
  SELECT id,type_value,name_value FROM candidates ORDER BY rank_value,type_value,lower(name_value),id LIMIT limit_value
 )
 SELECT jsonb_build_object('items',COALESCE(jsonb_agg(jsonb_build_object('id',id,'type',type_value,'name',name_value) ORDER BY type_value,lower(name_value),id),'[]'::jsonb)) INTO result_value FROM visible;
 RETURN result_value;
END $$;
ALTER FUNCTION public.zasp_global_search(text,text,text,text,integer) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_global_search(text,text,text,text,integer) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control;
GRANT EXECUTE ON FUNCTION public.zasp_global_search(text,text,text,text,integer) TO zasp_discovery_api;

CREATE TABLE public.zasp_finding_ticket_deliveries(
 organization_id text NOT NULL,
 workspace_id text NOT NULL,
 environment_id text NOT NULL,
 delivery_id text NOT NULL CHECK(zasp_valid_product_id(delivery_id)),
 principal_id text NOT NULL CHECK(zasp_valid_product_id(principal_id)),
 finding_id text NOT NULL CHECK(zasp_valid_product_id(finding_id)),
 expected_version bigint NOT NULL CHECK(expected_version>0),
 idempotency_key text NOT NULL CHECK(char_length(idempotency_key) BETWEEN 16 AND 128 AND idempotency_key~'^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$'),
 correlation_id text NOT NULL CHECK(zasp_valid_product_id(correlation_id)),
 payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object' AND octet_length(convert_to(payload::text,'UTF8'))<=16384),
 payload_digest bytea NOT NULL CHECK(octet_length(payload_digest)=32),
 destination_url text NOT NULL CHECK(char_length(destination_url) BETWEEN 12 AND 2048),
 secret_reference text NOT NULL CHECK(secret_reference~'^secret_ref_[A-Za-z0-9][A-Za-z0-9._/-]{0,115}$'),
 state text NOT NULL CHECK(state IN('reserved','retryable','completed')),
 attempt integer NOT NULL DEFAULT 1 CHECK(attempt BETWEEN 1 AND 10),
 lease_token text CHECK(lease_token IS NULL OR lease_token~'^[0-9a-f]{64}$'),
 lease_expires_at timestamptz,
 ticket_id text CHECK(ticket_id IS NULL OR ticket_id~'^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'),
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 completed_at timestamptz,
 PRIMARY KEY(organization_id,workspace_id,environment_id,delivery_id),
 UNIQUE(organization_id,workspace_id,environment_id,principal_id,idempotency_key),
 FOREIGN KEY(organization_id,workspace_id,environment_id,finding_id) REFERENCES public.zasp_risk_findings(organization_id,workspace_id,environment_id,id) ON DELETE RESTRICT,
 CHECK((state='reserved')=(lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)),
 CHECK((state='completed')=(ticket_id IS NOT NULL AND completed_at IS NOT NULL))
);
CREATE INDEX zasp_finding_ticket_deliveries_retry_v16_idx ON public.zasp_finding_ticket_deliveries(organization_id,workspace_id,environment_id,lease_expires_at,delivery_id) WHERE state IN('reserved','retryable');
ALTER TABLE public.zasp_finding_ticket_deliveries OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_finding_ticket_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_finding_ticket_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY zasp_finding_ticket_deliveries_authority ON public.zasp_finding_ticket_deliveries TO zasp_discovery_authority USING(true) WITH CHECK(true);
REVOKE ALL ON TABLE public.zasp_finding_ticket_deliveries FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control;

CREATE FUNCTION public.zasp_finding_ticket_reserve(organization_value text,workspace_value text,environment_value text,principal_value text,finding_value text,expected_version_value bigint,idempotency_value text,correlation_value text,delivery_value text,lease_token_value text,lease_seconds_value integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE delivery_row zasp_finding_ticket_deliveries%ROWTYPE;finding_row zasp_risk_findings%ROWTYPE;webhook_count integer;webhook_body jsonb;configuration_value jsonb;payload_value jsonb;payload_digest_value bytea;
BEGIN
 IF NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(principal_value) OR NOT zasp_valid_product_id(finding_value) OR expected_version_value<1 OR expected_version_value>1000000
  OR idempotency_value IS NULL OR char_length(idempotency_value) NOT BETWEEN 16 AND 128 OR idempotency_value!~'^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$' OR NOT zasp_valid_product_id(correlation_value) OR NOT zasp_valid_product_id(delivery_value) OR lease_token_value!~'^[0-9a-f]{64}$' OR lease_seconds_value NOT BETWEEN 5 AND 30
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='finding ticket rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,principal_value,idempotency_value),0));
 SELECT * INTO delivery_row FROM zasp_finding_ticket_deliveries row_value WHERE (row_value.organization_id,row_value.workspace_id,row_value.environment_id,row_value.principal_id,row_value.idempotency_key)=(organization_value,workspace_value,environment_value,principal_value,idempotency_value) FOR UPDATE;
 IF FOUND THEN
  IF (delivery_row.finding_id,delivery_row.expected_version) IS DISTINCT FROM (finding_value,expected_version_value) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='finding ticket intent conflict';END IF;
  IF delivery_row.state='completed' THEN RETURN jsonb_build_object('state','completed','delivery_id',delivery_row.delivery_id,'ticket_id',delivery_row.ticket_id,'lease_expires_at',NULL);END IF;
  IF delivery_row.state='reserved' AND delivery_row.lease_expires_at>transaction_timestamp() THEN RETURN jsonb_build_object('state','busy','delivery_id',delivery_row.delivery_id,'lease_expires_at',delivery_row.lease_expires_at,'ticket_id',NULL);END IF;
  IF delivery_row.attempt>=10 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='finding ticket retry exhausted';END IF;
  UPDATE zasp_finding_ticket_deliveries SET state='reserved',attempt=attempt+1,lease_token=lease_token_value,lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds_value),updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,delivery_id)=(delivery_row.organization_id,delivery_row.workspace_id,delivery_row.environment_id,delivery_row.delivery_id) RETURNING * INTO delivery_row;
  RETURN jsonb_build_object('state','dispatch','delivery_id',delivery_row.delivery_id,'payload',delivery_row.payload::text,'payload_digest','sha256:'||encode(delivery_row.payload_digest,'hex'),'destination_url',delivery_row.destination_url,'secret_reference',delivery_row.secret_reference,'lease_expires_at',delivery_row.lease_expires_at,'ticket_id',NULL);
 END IF;
 SELECT * INTO finding_row FROM zasp_risk_findings row_value WHERE (row_value.organization_id,row_value.workspace_id,row_value.environment_id,row_value.id)=(organization_value,workspace_value,environment_value,finding_value) AND row_value.version=expected_version_value AND row_value.status IN('open','under_review') FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='02000',MESSAGE='finding ticket target unavailable';END IF;
 SELECT count(*),(jsonb_agg(record_value.body ORDER BY record_value.id)->0) INTO webhook_count,webhook_body FROM zasp_workflow_records record_value WHERE (record_value.organization_id,record_value.workspace_id,record_value.environment_id,record_value.kind)=(organization_value,workspace_value,environment_value,'integration') AND record_value.deleted_at IS NULL AND record_value.body->>'connector_key'='generic-webhook' AND record_value.body->>'status'='configured';
 IF webhook_count<>1 OR jsonb_typeof(webhook_body->'configuration')<>'object' OR (webhook_body->'configuration')-ARRAY['destination_url','signing_secret_reference']<>'{}'::jsonb THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='finding ticket webhook unavailable';END IF;
 configuration_value:=webhook_body->'configuration';
 IF configuration_value->>'destination_url' IS NULL OR char_length(configuration_value->>'destination_url') NOT BETWEEN 12 AND 2048 OR configuration_value->>'destination_url'!~'^https://[a-z0-9][a-z0-9.-]*(:443)?(/[^?#]*)?$' OR configuration_value->>'signing_secret_reference'!~'^secret_ref_[A-Za-z0-9][A-Za-z0-9._/-]{0,115}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='finding ticket webhook rejected';END IF;
 payload_value:=jsonb_build_object('delivery_id',delivery_value,'event','finding.ticket.requested','finding',jsonb_build_object('id',finding_row.id,'severity',finding_row.severity,'title',finding_row.title,'version',finding_row.version),'requested_at',to_char(transaction_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'requested_by',principal_value,'scope',jsonb_build_object('environment_id',environment_value,'organization_id',organization_value,'workspace_id',workspace_value),'version',1);
 payload_digest_value:=digest(convert_to(payload_value::text,'UTF8'),'sha256');
 INSERT INTO zasp_finding_ticket_deliveries(organization_id,workspace_id,environment_id,delivery_id,principal_id,finding_id,expected_version,idempotency_key,correlation_id,payload,payload_digest,destination_url,secret_reference,state,lease_token,lease_expires_at)
 VALUES(organization_value,workspace_value,environment_value,delivery_value,principal_value,finding_value,expected_version_value,idempotency_value,correlation_value,payload_value,payload_digest_value,configuration_value->>'destination_url',configuration_value->>'signing_secret_reference','reserved',lease_token_value,transaction_timestamp()+make_interval(secs=>lease_seconds_value)) RETURNING * INTO delivery_row;
 RETURN jsonb_build_object('state','dispatch','delivery_id',delivery_row.delivery_id,'payload',delivery_row.payload::text,'payload_digest','sha256:'||encode(delivery_row.payload_digest,'hex'),'destination_url',delivery_row.destination_url,'secret_reference',delivery_row.secret_reference,'lease_expires_at',delivery_row.lease_expires_at,'ticket_id',NULL);
END $$;

CREATE FUNCTION public.zasp_finding_ticket_complete(organization_value text,workspace_value text,environment_value text,delivery_value text,lease_token_value text,payload_digest_value text,ticket_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE delivery_row zasp_finding_ticket_deliveries%ROWTYPE;decoded_digest bytea;
BEGIN
 IF NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(delivery_value) OR lease_token_value!~'^[0-9a-f]{64}$' OR payload_digest_value!~'^sha256:[0-9a-f]{64}$' OR ticket_value!~'^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='finding ticket completion rejected';END IF;
 decoded_digest:=decode(substr(payload_digest_value,8),'hex');
 SELECT * INTO delivery_row FROM zasp_finding_ticket_deliveries row_value WHERE (row_value.organization_id,row_value.workspace_id,row_value.environment_id,row_value.delivery_id)=(organization_value,workspace_value,environment_value,delivery_value) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='02000',MESSAGE='finding ticket unavailable';END IF;
 IF delivery_row.state='completed' THEN IF (delivery_row.payload_digest,delivery_row.ticket_id) IS DISTINCT FROM (decoded_digest,ticket_value) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='finding ticket completion conflict';END IF;RETURN jsonb_build_object('ticket_id',delivery_row.ticket_id);END IF;
 IF delivery_row.state<>'reserved' OR delivery_row.lease_token<>lease_token_value OR delivery_row.lease_expires_at<=transaction_timestamp() OR delivery_row.payload_digest<>decoded_digest THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding ticket lease lost';END IF;
 UPDATE zasp_finding_ticket_deliveries SET state='completed',ticket_id=ticket_value,completed_at=transaction_timestamp(),lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,delivery_id)=(organization_value,workspace_value,environment_value,delivery_value) RETURNING * INTO delivery_row;
 RETURN jsonb_build_object('ticket_id',delivery_row.ticket_id);
END $$;

CREATE FUNCTION public.zasp_finding_ticket_release(organization_value text,workspace_value text,environment_value text,delivery_value text,lease_token_value text,payload_digest_value text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE released_count integer;
BEGIN
 IF NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(delivery_value) OR lease_token_value!~'^[0-9a-f]{64}$' OR payload_digest_value!~'^sha256:[0-9a-f]{64}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='finding ticket release rejected';END IF;
 UPDATE zasp_finding_ticket_deliveries SET state='retryable',lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,delivery_id,state,lease_token,payload_digest)=(organization_value,workspace_value,environment_value,delivery_value,'reserved',lease_token_value,decode(substr(payload_digest_value,8),'hex')) AND lease_expires_at>transaction_timestamp();
 GET DIAGNOSTICS released_count=ROW_COUNT;
 RETURN released_count=1;
END $$;

ALTER FUNCTION public.zasp_finding_ticket_reserve(text,text,text,text,text,bigint,text,text,text,text,integer) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_finding_ticket_complete(text,text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_finding_ticket_release(text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_finding_ticket_reserve(text,text,text,text,text,bigint,text,text,text,text,integer),public.zasp_finding_ticket_complete(text,text,text,text,text,text,text),public.zasp_finding_ticket_release(text,text,text,text,text,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control;
GRANT EXECUTE ON FUNCTION public.zasp_finding_ticket_reserve(text,text,text,text,text,bigint,text,text,text,text,integer),public.zasp_finding_ticket_complete(text,text,text,text,text,text,text),public.zasp_finding_ticket_release(text,text,text,text,text,text) TO zasp_discovery_api;

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
 IF NOT zasp_valid_product_id(event_value) OR expected_floor_value<0 OR next_floor_value<=expected_floor_value OR octet_length(request_digest_value)<>32 OR policy_version_value<1 OR decision_value NOT IN('allow','monitor','block') OR action_kind_value NOT IN('http','mcp') OR jsonb_typeof(classification_value)<>'object'
  OR NOT classification_value ?& ARRAY['category','route_class','resource_class','outcome']
  OR classification_value-ARRAY['category','route_class','resource_class','outcome','agent_id','target_id','capability_category','capability_outcome']<>'{}'::jsonb
  OR octet_length(convert_to(classification_value::text,'UTF8'))>16384
  OR EXISTS(SELECT 1 FROM jsonb_each_text(classification_value) item WHERE length(item.value) NOT BETWEEN 1 AND 64 OR item.value<>btrim(item.value) OR item.value!~'^[a-z][a-z0-9._:-]{0,63}$')
  OR classification_value ?| ARRAY['agent_id','target_id','capability_category','capability_outcome'] AND (
   decision_value<>'block' OR NOT classification_value ?& ARRAY['agent_id','target_id','capability_category','capability_outcome']
   OR NOT zasp_valid_product_id(classification_value->>'agent_id') OR NOT zasp_valid_product_id(classification_value->>'target_id')
   OR (classification_value->>'capability_category',classification_value->>'capability_outcome') NOT IN(('data_read','read'),('data_write','write'),('action_execute','execute'),('identity_assume','assume'),('network_egress','connect'),('administration','administer'))
  )
  OR occurred_value IS NULL OR occurred_value>transaction_timestamp()+interval '30 seconds'
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='gateway event rejected';END IF;
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
 IF classification_value ? 'agent_id' THEN
  PERFORM zasp_inventory_record_capability_evidence(organization_value,workspace_value,environment_value,classification_value->>'agent_id',classification_value->>'target_id',classification_value->>'capability_category',classification_value->>'capability_outcome','runtime_policy',event_value,occurred_value);
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
  AND EXISTS(SELECT 1 FROM zasp_schema_versions release WHERE (release.version,release.name,release.checksum)=(15,'runtime_data_plane','6a5e4b76a120cfda89f1afb8461d9c1b1f19fabc38565058b63b91956932e9b5'))
  AND EXISTS(SELECT 1 FROM zasp_schema_metadata metadata WHERE (metadata.key,metadata.value)=('production_core_schema','runtime-data-plane-v1'))
  AND EXISTS(SELECT 1 FROM zasp_schema_metadata metadata WHERE (metadata.key,metadata.value)=('runtime_gateway_reconciliation_fingerprint',expected_fingerprint))
  AND zasp_runtime_gateway_reconciliation_live_fingerprint()=expected_fingerprint
  AND zasp_runtime_gateway_reconciliation_security_ready()
$$;

CREATE OR REPLACE FUNCTION public.zasp_runtime_gateway_reconciliation_security_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
 SELECT zasp_runtime_data_plane_security_ready()
  AND zasp_inventory_security_ready()
  AND NOT EXISTS(SELECT 1 FROM pg_class class_value JOIN pg_namespace namespace_value ON namespace_value.oid=class_value.relnamespace WHERE namespace_value.nspname='public' AND class_value.relname IN('zasp_runtime_gateway_reconciliation_state','zasp_finding_ticket_deliveries') AND (class_value.relowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') OR NOT class_value.relrowsecurity OR NOT class_value.relforcerowsecurity OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(class_value.relacl,acldefault('r',class_value.relowner))) acl WHERE acl.grantee<>class_value.relowner)))
  AND NOT EXISTS(SELECT 1 FROM pg_proc procedure_value CROSS JOIN aclexplode(COALESCE(procedure_value.proacl,acldefault('f',procedure_value.proowner))) acl WHERE procedure_value.oid IN('zasp_runtime_gateway_reconciliation_live_fingerprint()'::regprocedure,'zasp_runtime_gateway_reconciliation_security_ready()'::regprocedure) AND acl.grantee<>procedure_value.proowner)
  AND NOT EXISTS(SELECT 1 FROM pg_proc procedure_value CROSS JOIN aclexplode(COALESCE(procedure_value.proacl,acldefault('f',procedure_value.proowner))) acl WHERE procedure_value.oid='zasp_runtime_gateway_reconciliation_readiness(text,text)'::regprocedure AND acl.grantee=0)
  AND has_function_privilege('zasp_gateway_control','zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamptz)','EXECUTE')
  AND EXISTS(SELECT 1 FROM pg_proc procedure_value WHERE procedure_value.oid='zasp_global_search(text,text,text,text,integer)'::regprocedure AND procedure_value.proowner=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') AND procedure_value.prosecdef AND COALESCE(procedure_value.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] AND has_function_privilege('zasp_discovery_api',procedure_value.oid,'EXECUTE') AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(procedure_value.proacl,acldefault('f',procedure_value.proowner))) acl WHERE acl.grantee NOT IN(procedure_value.proowner,(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_api'))))
  AND NOT EXISTS(SELECT 1 FROM pg_proc procedure_value WHERE procedure_value.oid IN('zasp_finding_ticket_reserve(text,text,text,text,text,bigint,text,text,text,text,integer)'::regprocedure,'zasp_finding_ticket_complete(text,text,text,text,text,text,text)'::regprocedure,'zasp_finding_ticket_release(text,text,text,text,text,text)'::regprocedure) AND (procedure_value.proowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') OR NOT procedure_value.prosecdef OR NOT COALESCE(procedure_value.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] OR NOT has_function_privilege('zasp_discovery_api',procedure_value.oid,'EXECUTE') OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(procedure_value.proacl,acldefault('f',procedure_value.proowner))) acl WHERE acl.grantee NOT IN(procedure_value.proowner,(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_api')))))
$$;

CREATE OR REPLACE FUNCTION public.zasp_runtime_gateway_reconciliation_live_fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
 WITH semantic_object(kind,identity,definition) AS (
  SELECT 'runtime_data_plane','live',zasp_runtime_data_plane_live_fingerprint()
  UNION ALL SELECT 'column',table_name||'.'||column_name,concat_ws('|',data_type,udt_name,is_nullable,column_default) FROM information_schema.columns WHERE table_schema='public' AND table_name IN('zasp_runtime_gateway_reconciliation_state','zasp_finding_ticket_deliveries')
  UNION ALL SELECT 'constraint',constraint_value.conrelid::regclass::text||'.'||constraint_value.conname,pg_get_constraintdef(constraint_value.oid,true) FROM pg_constraint constraint_value WHERE constraint_value.conrelid IN('public.zasp_runtime_gateway_reconciliation_state'::regclass,'public.zasp_finding_ticket_deliveries'::regclass)
  UNION ALL SELECT 'policy',policy_value.schemaname||'.'||policy_value.tablename||'.'||policy_value.policyname,concat_ws('|',policy_value.roles::text,policy_value.cmd,policy_value.qual,policy_value.with_check) FROM pg_policies policy_value WHERE policy_value.schemaname='public' AND policy_value.tablename IN('zasp_runtime_gateway_reconciliation_state','zasp_finding_ticket_deliveries')
  UNION ALL SELECT 'index',index_value.oid::regclass::text,pg_get_indexdef(index_value.oid) FROM pg_class index_value WHERE index_value.oid IN('zasp_inventory_entities_global_search_v16_idx'::regclass,'zasp_risk_findings_global_search_v16_idx'::regclass,'zasp_finding_ticket_deliveries_retry_v16_idx'::regclass)
  UNION ALL SELECT 'inherited_function',procedure_value.oid::regprocedure::text,pg_get_functiondef(procedure_value.oid) FROM pg_proc procedure_value WHERE procedure_value.oid IN('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure,'public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure)
  UNION ALL SELECT 'function',procedure_value.oid::regprocedure::text,pg_get_functiondef(procedure_value.oid) FROM pg_proc procedure_value WHERE procedure_value.oid IN('public.zasp_global_search(text,text,text,text,integer)'::regprocedure,'public.zasp_finding_ticket_reserve(text,text,text,text,text,bigint,text,text,text,text,integer)'::regprocedure,'public.zasp_finding_ticket_complete(text,text,text,text,text,text,text)'::regprocedure,'public.zasp_finding_ticket_release(text,text,text,text,text,text)'::regprocedure)
  UNION ALL SELECT 'function',procedure_value.oid::regprocedure::text,pg_get_functiondef(procedure_value.oid) FROM pg_proc procedure_value JOIN pg_namespace namespace_value ON namespace_value.oid=procedure_value.pronamespace WHERE namespace_value.nspname='public' AND procedure_value.proname IN('zasp_runtime_gateway_reconciliation_security_ready','zasp_runtime_gateway_reconciliation_readiness')
  UNION ALL SELECT 'function_acl',procedure_value.oid::regprocedure::text,COALESCE(array_to_string(procedure_value.proacl,','),'') FROM pg_proc procedure_value JOIN pg_namespace namespace_value ON namespace_value.oid=procedure_value.pronamespace WHERE namespace_value.nspname='public' AND procedure_value.proname IN('zasp_global_search','zasp_finding_ticket_reserve','zasp_finding_ticket_complete','zasp_finding_ticket_release','zasp_runtime_gateway_reconciliation_live_fingerprint','zasp_runtime_gateway_reconciliation_security_ready','zasp_runtime_gateway_reconciliation_readiness')
 ) SELECT encode(digest(convert_to(string_agg(kind||chr(31)||identity||chr(31)||definition,chr(30) ORDER BY kind,identity,definition),'UTF8'),'sha256'),'hex') FROM semantic_object
$$;

ALTER FUNCTION public.zasp_runtime_gateway_reconciliation_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_gateway_reconciliation_security_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_gateway_reconciliation_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_gateway_reconciliation_live_fingerprint(),public.zasp_runtime_gateway_reconciliation_security_ready(),public.zasp_runtime_gateway_reconciliation_readiness(text,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_gateway_reconciliation_readiness(text,text) TO zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control;

INSERT INTO public.zasp_schema_metadata(key,value) VALUES('runtime_gateway_reconciliation_fingerprint', '625c5da616e2d069d35e80efbeaae60f5fd4132d8d1b5be73d0b33d5786f78be');
