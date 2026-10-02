-- Sensor effects retain native15/45 receipts, credentials and pairing facts.
-- Only this additive surface consumes the current checked request proof.
CREATE FUNCTION zasp_authorization80.sensor_source_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT COALESCE(zasp_authorization80.ready('-- authorization80 checksum')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=45 AND name='production_runtime_enrollment_pairing' AND checksum='-- authorization80 sensor45 checksum')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_runtime_enrollment_pairing_fingerprint' AND value='-- authorization80 sensor45 fingerprint')
 AND NOT EXISTS(SELECT 1 FROM pg_class WHERE oid IN('public.zasp_sensors'::regclass,'public.zasp_sensor_tokens'::regclass,'public.zasp_sensor_heartbeats'::regclass,'public.zasp_runtime_sensor_pairings'::regclass,'public.zasp_runtime_sensor_mutations'::regclass)
  AND(relowner<>'zasp_discovery_authority'::regrole OR NOT relrowsecurity OR NOT relforcerowsecurity))
 AND NOT has_table_privilege('zasp_discovery_api','public.zasp_runtime_sensor_pairings','SELECT')
 AND NOT has_table_privilege('zasp_discovery_api','public.zasp_runtime_sensor_mutations','SELECT')
 AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.zasp_runtime_sensor_pairings'::regclass AND tgname='zasp_runtime_sensor_pairings_immutable' AND tgenabled='O' AND NOT tgisinternal)
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname IN('zasp_runtime_public_sensor_page','zasp_runtime_public_sensor_detail','zasp_runtime_public_sensor_coverage','zasp_runtime_public_sensor_token_authority','zasp_runtime_public_sensor_value','zasp_runtime_public_sensor_value_v44','zasp_runtime_public_create_sensor','zasp_runtime_public_create_sensor_v44','zasp_runtime_public_update_sensor','zasp_runtime_public_delete_sensor','zasp_runtime_public_rotate_sensor')
  AND(p.proowner<>'zasp_discovery_authority'::regrole OR NOT p.prosecdef OR NOT COALESCE(p.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] OR has_function_privilege('public',p.oid,'EXECUTE'))),false)
$$;

CREATE FUNCTION zasp_authorization80.sensor_authorized(o text,w text,e text,op text,i text DEFAULT NULL,p text DEFAULT NULL) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT COALESCE(zasp_authorization80.sensor_source_ready() AND public.zasp_discovery_principal_ready('zasp_discovery_api')
 AND (proof->>'organization_id',proof->>'workspace_id',proof->>'environment_id',proof->>'operation_id')=(o,w,e,op)
 AND (p IS NULL OR proof->>'principal_id'=p)
 AND proof->>'permission'=CASE WHEN op IN('listSensors','getSensor','getSensorCoverage') THEN 'view' WHEN op IN('createSensorEnrollment','updateSensor','deleteSensor','rotateSensorToken') THEN 'manage_workflows' END
 AND (op NOT IN('createSensorEnrollment','rotateSensorToken') OR COALESCE((proof->>'fresh_auth')::boolean,false))
 AND CASE WHEN op='listSensors' THEN COALESCE((proof->>'collection')::boolean,false)
  WHEN op='createSensorEnrollment' THEN zasp_authorization80.allowed(o,w,e,'environment',e)
  ELSE zasp_authorization80.allowed(o,w,e,'sensor',i) END,false)
 FROM(SELECT zasp_authorization80.context() proof) current_proof
$$;

-- Called only by successful new mutation paths. Receipt time/version are the
-- event facts; no credential, token, enrollment binding or digest is public.
CREATE FUNCTION zasp_authorization80.sensor_audit(o text,w text,e text,p text,op text,key_value text,result_value jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE receipt public.zasp_runtime_sensor_mutations%ROWTYPE;audit_value text;action_value text;
BEGIN
 IF result_value->>'replayed' IS DISTINCT FROM 'false' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='sensor audit new receipt required';END IF;
 SELECT * INTO STRICT receipt FROM public.zasp_runtime_sensor_mutations WHERE(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(o,w,e,p,op,key_value);
 IF receipt.result IS DISTINCT FROM result_value OR receipt.sensor_id IS DISTINCT FROM result_value#>>'{body,id}' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='sensor audit receipt mismatch';END IF;
 action_value:=CASE op WHEN 'createSensorEnrollment' THEN 'sensor.create' WHEN 'updateSensor' THEN 'sensor.update' WHEN 'deleteSensor' THEN 'sensor.delete' WHEN 'rotateSensorToken' THEN 'sensor.token.rotate' END;
 IF action_value IS NULL THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='sensor audit operation rejected';END IF;
 audit_value:=public.zasp_discovery_canonical_id(o,w,e,'sensor_mutation_audit',jsonb_build_array(p,op,key_value)::text);
 INSERT INTO public.zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at)
 VALUES(o,w,e,audit_value,p,action_value,receipt.sensor_id,'succeeded',jsonb_build_object('sensor_version',(result_value#>>'{body,version}')::bigint),receipt.created_at);
END $$;

DO $sensors$
DECLARE entry record;definition text;needle text;replacement text;guard_value text;
BEGIN
 FOR entry IN SELECT * FROM(VALUES
 ('sensor_page','listSensors','text,text,text,text,integer',false),
 ('sensor_detail','getSensor','text,text,text,text',false),
 ('sensor_coverage','getSensorCoverage','text,text,text,text',false),
 ('sensor_token_authority','rotateSensorToken','text,text,text,text',false),
 ('create_sensor','createSensorEnrollment','text,text,text,text,text,text,text,text,text,bytea,text,bigint,bytea,bytea,bytea,timestamptz,text',true),
 ('update_sensor','updateSensor','text,text,text,text,text,bigint,text,text,text,bytea',true),
 ('delete_sensor','deleteSensor','text,text,text,text,text,bigint,text,bytea',true),
 ('rotate_sensor','rotateSensorToken','text,text,text,text,text,bigint,text,bytea,text,bigint,bytea,bytea,bytea,timestamptz',true)
 ) functions(name,operation,signature,mutation) LOOP
  SELECT pg_get_functiondef(('public.zasp_runtime_public_'||entry.name||'('||entry.signature||')')::regprocedure) INTO STRICT definition;
  needle:='FUNCTION public.zasp_runtime_public_'||entry.name||'(';
  IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='sensor predecessor rejected';END IF;
  definition:=replace(definition,needle,'FUNCTION zasp_authorization80.'||entry.name||'(');
  guard_value:='zasp_authorization80.sensor_authorized(organization_value,workspace_value,environment_value,'||quote_literal(entry.operation)||','||CASE WHEN entry.name IN('sensor_page','create_sensor') THEN 'NULL' ELSE 'sensor_value' END||','||CASE WHEN entry.mutation THEN 'principal_value' ELSE 'NULL' END||')';
  needle:=E'BEGIN\n';
  IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='sensor guard predecessor rejected';END IF;
  definition:=replace(definition,needle,needle||' IF NOT '||guard_value||' THEN RAISE EXCEPTION USING ERRCODE=''42501'',MESSAGE=''current sensor authorization required'';END IF;'||chr(10));
  IF entry.name='sensor_page' THEN
   needle:='AND (after_value IS NULL OR sensor_row.id>after_value)';
   IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='sensor pagination predecessor rejected';END IF;
   definition:=replace(definition,needle,'AND zasp_authorization80.allowed(organization_value,workspace_value,environment_value,''sensor'',sensor_row.id) '||needle);
  END IF;
  IF entry.name='create_sensor' THEN
   needle:='EXISTS(SELECT 1 FROM zasp_identity_admin_effective_scopes(principal_value,organization_value) effective WHERE (effective.organization_id,effective.workspace_id,effective.environment_id)=(organization_value,workspace_value,environment_value) AND effective.permissions ? ''manage_workflows'')';
   IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>5 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='sensor pairing authority predecessor rejected';END IF;
   definition:=replace(definition,needle,guard_value);
  END IF;
  IF entry.mutation THEN
   needle:='RETURN result_value;';
   IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='sensor receipt predecessor rejected';END IF;
   definition:=replace(definition,needle,'PERFORM zasp_authorization80.sensor_audit(organization_value,workspace_value,environment_value,principal_value,'||quote_literal(entry.operation)||',idempotency_value,result_value);'||needle);
  END IF;
  EXECUTE definition;
  EXECUTE 'GRANT EXECUTE ON FUNCTION zasp_authorization80.'||entry.name||'('||entry.signature||') TO zasp_discovery_api';
 END LOOP;
END
$sensors$;
CREATE FUNCTION zasp_authorization80.create_sensor(text,text,text,text,text,text,text,text,text,bytea,text,bigint,bytea,bytea,bytea,timestamptz) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT zasp_authorization80.create_sensor($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,NULL::text)
$$;
GRANT EXECUTE ON FUNCTION zasp_authorization80.create_sensor(text,text,text,text,text,text,text,text,text,bytea,text,bigint,bytea,bytea,bytea,timestamptz) TO zasp_discovery_api;
