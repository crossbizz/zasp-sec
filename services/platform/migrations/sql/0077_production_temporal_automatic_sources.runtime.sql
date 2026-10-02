CREATE TABLE zasp_temporal77.runtime_evaluations(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,event_id text NOT NULL,
 evaluation jsonb NOT NULL CHECK(jsonb_typeof(evaluation)='object'),
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 legacy_digest bytea NOT NULL CHECK(octet_length(legacy_digest)=32),
 PRIMARY KEY(organization_id,workspace_id,environment_id,event_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,event_id) REFERENCES public.zasp_runtime_gateway_events(organization_id,workspace_id,environment_id,event_id)
);
ALTER TABLE zasp_temporal77.runtime_evaluations OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_temporal77.runtime_evaluations ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_temporal77.runtime_evaluations FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_temporal77.runtime_evaluations USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal77.runtime_evaluations FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();

CREATE FUNCTION zasp_temporal77.evaluation_valid(j jsonb,decision_value text,policy_ids jsonb,classification_value jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path TO pg_catalog,public AS $evaluation$
BEGIN
 IF jsonb_typeof(j) IS DISTINCT FROM 'object' OR octet_length(j::text)>8192
  OR NOT zasp_sa_multistep_prior.closed(j,ARRAY['version','action','agent_id','session_id','contributing_policy_ids']||CASE WHEN j ? 'risk' THEN ARRAY['risk'] ELSE ARRAY[]::text[] END)
  OR NOT zasp_temporal77.rule_integer(j->'version',1) OR NOT zasp_temporal77.rule_text(j->'action')
  OR jsonb_typeof(j->'agent_id') IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(j->>'agent_id'),false)
  OR jsonb_typeof(j->'session_id') IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(j->>'session_id'),false)
  OR j->>'session_id' IS DISTINCT FROM classification_value->>'session_id'
  OR jsonb_typeof(j->'contributing_policy_ids') IS DISTINCT FROM 'array' THEN RETURN false;END IF;
 IF NOT COALESCE(public.zasp_policy_id_array_valid(j->'contributing_policy_ids'),false)
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(j->'contributing_policy_ids') x WHERE jsonb_typeof(x) IS DISTINCT FROM 'string')
  OR NOT COALESCE(j->'contributing_policy_ids' <@ policy_ids,false)
  OR decision_value='allow' AND jsonb_array_length(j->'contributing_policy_ids')<>0 THEN RETURN false;END IF;
 IF j ? 'risk' AND (jsonb_typeof(j->'risk') IS DISTINCT FROM 'string' OR NOT COALESCE(j->>'risk' IN('low','medium','high','critical'),false) OR jsonb_array_length(j->'contributing_policy_ids')=0) THEN RETURN false;END IF;
 RETURN true;
END $evaluation$;

CREATE FUNCTION zasp_temporal77.record_gateway_event(credential_value text,event_value text,expected_floor_value bigint,next_floor_value bigint,request_digest_value bytea,policy_version_value bigint,decision_value text,action_kind_value text,classification_value jsonb,policy_ids_value jsonb,occurred_value timestamptz,evaluation_value jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $record$
DECLARE authority_value jsonb;base_value jsonb;canonical_digest bytea;legacy_digest_value bytea;result_value jsonb;prior zasp_temporal77.runtime_evaluations%ROWTYPE;
BEGIN
 IF NOT zasp_temporal77.ready('-- automatic77 checksum','-- automatic77 fingerprint') OR NOT public.zasp_runtime_principal_ready('zasp_gateway_control') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='automatic runtime authority unavailable';END IF;
 IF NOT zasp_temporal77.evaluation_valid(evaluation_value,decision_value,policy_ids_value,classification_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='gateway evaluation rejected';END IF;
 authority_value:=public.zasp_runtime_gateway_credential_authority(credential_value,'runtime-gateway');
 base_value:=jsonb_build_object('credential_id',credential_value,'device_id',authority_value->>'device_id','event_id',event_value,'expected_floor',expected_floor_value,'next_floor',next_floor_value,'policy_version',policy_version_value,'decision',decision_value,'action_kind',action_kind_value,'classification',classification_value,'policy_ids',policy_ids_value,'occurred_at',to_char(occurred_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
 canonical_digest:=digest(convert_to((base_value||jsonb_build_object('evaluation',evaluation_value))::text,'UTF8'),'sha256');
 IF request_digest_value IS DISTINCT FROM canonical_digest THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='gateway evaluation digest rejected';END IF;
 legacy_digest_value:=digest(convert_to(base_value::text,'UTF8'),'sha256');
 -- The original writer validates credential/device/floor and takes its existing
 -- device lock. Keep its canonical event bytes and receipt contract unchanged.
 result_value:=public.zasp_runtime_gateway_record_event_v27(credential_value,event_value,expected_floor_value,next_floor_value,legacy_digest_value,policy_version_value,decision_value,action_kind_value,classification_value,policy_ids_value,occurred_value);
 IF result_value->>'outcome'='record_window_expired' THEN RETURN result_value;END IF;
 IF result_value->'replayed'='true'::jsonb THEN
  SELECT * INTO prior FROM zasp_temporal77.runtime_evaluations WHERE (organization_id,workspace_id,environment_id,event_id)=(authority_value->>'organization_id',authority_value->>'workspace_id',authority_value->>'environment_id',event_value);
  IF NOT FOUND OR (prior.evaluation,prior.request_digest,prior.legacy_digest) IS DISTINCT FROM (evaluation_value,canonical_digest,legacy_digest_value) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='gateway evaluation replay rejected';END IF;
 ELSE
  INSERT INTO zasp_temporal77.runtime_evaluations(organization_id,workspace_id,environment_id,event_id,evaluation,request_digest,legacy_digest) VALUES(authority_value->>'organization_id',authority_value->>'workspace_id',authority_value->>'environment_id',event_value,evaluation_value,canonical_digest,legacy_digest_value);
 END IF;
 RETURN result_value;
END $record$;
