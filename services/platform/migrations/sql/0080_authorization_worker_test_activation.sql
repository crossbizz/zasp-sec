-- Current human activation is separate from worker-forward authority. The
-- retained74 body keeps every original grant, history, receipt and replay check.
INSERT INTO zasp_authorization80_worker.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid='zasp_temporal74.activate(text,text,text,text,text,text,bigint,text,timestamp with time zone,text,text,text)'::regprocedure;
DO $activation_copy$ DECLARE d text;needle text:='FUNCTION zasp_temporal74.activate(';BEGIN
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_temporal74.activate(text,text,text,text,text,text,bigint,text,timestamp with time zone,text,text,text)' AND owner_name='zasp_discovery_authority';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker activation predecessor changed';END IF;
 EXECUTE replace(d,needle,'FUNCTION zasp_authorization80_worker.test74_activate_body(');
END $activation_copy$;

CREATE FUNCTION zasp_authorization80_worker.test74_activation_fence(p jsonb,o text,w text,e text,d text,a text,proof_version bigint,current_version bigint,delta bigint) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $fence$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='current activation isolation rejected';END IF;
 IF p IS NULL OR p IS DISTINCT FROM zasp_authorization80.context() OR delta NOT BETWEEN 0 AND 2
 OR NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal74.current_ready()
 OR NOT public.zasp_security_agent_principal_ready('zasp_security_agent_api')
 OR NOT COALESCE(zasp_authorization80.read_request(o,w,e,ARRAY['activateSecurityAgent'],'manage_workflows',true,a)
 AND p->'collection'='false'::jsonb AND p->'fresh_auth'='true'::jsonb AND p#>>'{path_parameters,id}'=d
 AND zasp_authorization80.allowed(o,w,e,'security_agent',d),false)
 OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p->'targets') t WHERE(t->>'organization_id',t->>'workspace_id',t->>'environment_id',t->>'kind',COALESCE(NULLIF(t->>'source_id',''),t->>'id'),(t->>'version')::bigint)=(o,w,e,'security_agent',d,proof_version))
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current test activation authority rejected';END IF;
 -- Organization precedes definition/receipt locks. The only admitted revision
 -- changes are the two exact installed definition triggers described below.
 PERFORM 1 FROM zasp_authorization79.organizations x WHERE x.organization_id=o
 AND(x.desired,x.applied,x.generation,x.store_id,x.model_id)=((p#>>'{revision,desired}')::bigint+delta,(p#>>'{revision,applied}')::bigint,(p#>>'{revision,generation}')::bigint,p#>>'{revision,store_id}',p#>>'{revision,model_id}') FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='current activation revision changed';END IF;
 PERFORM 1 FROM public.zasp_security_agent_definitions x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.definition_id,x.version)=(o,w,e,d,current_version) AND x.deleted_at IS NULL AND x.body->'allowed_actions' IN(' ["run_test"]'::jsonb,'["rerun_test"]'::jsonb) FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='current activation target changed';END IF;
 PERFORM zasp_authorization80.identity_fence(p);
 IF p IS DISTINCT FROM zasp_authorization80.context() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current activation proof expired';END IF;
END $fence$;

CREATE FUNCTION zasp_authorization80_worker.test74_activate(o text,w text,e text,d text,a text,k text,v bigint,activation_value text,fresh_value timestamptz,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $activate$
DECLARE p jsonb:=zasp_authorization80.context();row_value public.zasp_security_agent_definitions%ROWTYPE;prior public.zasp_security_agent_request_receipts%ROWTYPE;result jsonb;proof_version bigint;delta bigint;replay boolean;BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='current activation isolation rejected';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 SELECT(t->>'version')::bigint INTO STRICT proof_version FROM jsonb_array_elements(p->'targets') t WHERE(t->>'organization_id',t->>'workspace_id',t->>'environment_id',t->>'kind',COALESCE(NULLIF(t->>'source_id',''),t->>'id'))=(o,w,e,'security_agent',d);
 PERFORM zasp_authorization80_worker.test74_activation_fence(p,o,w,e,d,a,proof_version,proof_version,0);
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),o,w,e,a,'activateSecurityAgent',k),0));
 SELECT * INTO STRICT row_value FROM public.zasp_security_agent_definitions WHERE(organization_id,workspace_id,environment_id,definition_id)=(o,w,e,d) FOR UPDATE;
 SELECT * INTO prior FROM public.zasp_security_agent_request_receipts WHERE(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(o,w,e,a,'activateSecurityAgent',k) FOR SHARE;
 replay:=FOUND;
 IF replay THEN
  IF(prior.resource_id,prior.expected_version,row_value.version) IS DISTINCT FROM(d,v,v+1)
  OR prior.intent-'fresh_auth_expires_at'-'service_delegation' IS DISTINCT FROM jsonb_build_object('activation',activation_value,'expected_version',v,'resource_id',d)
  OR prior.intent?'service_delegation' AND prior.intent->'service_delegation'<>'74'::jsonb
  OR prior.intent_digest IS DISTINCT FROM digest(convert_to((prior.intent-'fresh_auth_expires_at')::text,'UTF8'),'sha256') OR prior.expires_at<=clock_timestamp()
  THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='current activation receipt changed';END IF;
  delta:=0;
 ELSE
  IF row_value.version<>v THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='current activation version changed';END IF;
  -- Ordinary transition changes activation and version:79+worker touches2.
  -- Same-state renewal changes version only:worker touch1. Replay touches0.
  delta:=CASE WHEN row_value.activation=activation_value AND activation_value IN('supervised','autonomous') THEN 1 ELSE 2 END;
 END IF;
 PERFORM zasp_authorization80_worker.test74_activation_fence(p,o,w,e,d,a,proof_version,proof_version,0);
 result:=zasp_authorization80_worker.test74_activate_body(o,w,e,d,a,k,v,activation_value,fresh_value,audit_value,correlation_value,receipt_value);
 IF result IS NULL OR NOT zasp_sa_multistep_prior.closed(result,ARRAY['id','activation','enabled','version','audit_id','correlation_id','receipt_id','replayed'])
 OR(result->>'id',result->>'activation',(result->>'version')::bigint,(result->>'enabled')::boolean,(result->>'replayed')::boolean) IS DISTINCT FROM(d,activation_value,v+1,activation_value IN('supervised','autonomous'),replay)
 OR NOT replay AND(result->>'audit_id',result->>'correlation_id',result->>'receipt_id') IS DISTINCT FROM(audit_value,correlation_value,receipt_value)
 OR replay AND result-'replayed' IS DISTINCT FROM prior.response-'replayed'
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='current activation result changed';END IF;
 PERFORM zasp_authorization80_worker.test74_activation_fence(p,o,w,e,d,a,proof_version,v+1,delta);
 RETURN result;
EXCEPTION WHEN no_data_found OR too_many_rows OR data_exception THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current activation binding rejected';
END $activate$;
CREATE OR REPLACE FUNCTION zasp_temporal74.activate(o text,w text,e text,d text,a text,k text,v bigint,activation_value text,fresh_value timestamptz,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $activate$
 SELECT zasp_authorization80_worker.test74_activate(o,w,e,d,a,k,v,activation_value,fresh_value,audit_value,correlation_value,receipt_value)
$activate$;
