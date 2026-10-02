-- Checked client component. Raw legacy writers are not closed by this fragment;
-- the separately reviewed all-caller writer cutover remains required.
CREATE FUNCTION zasp_authorization80.integration_current_ready() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed'
 OR NOT COALESCE(zasp_authorization80.ready('-- authorization80 checksum') AND public.zasp_discovery_principal_ready('zasp_discovery_api'),false)
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='integration client source unavailable';END IF;
END $$;

-- Keep public predecessors byte-for-byte intact. The installed receipt wrapper
-- has a source52 gate that is unavailable at canonical61 and a release60 bound.
-- Each private substitution is exact-count checked before installation.
DO $compatibility$
DECLARE d text;needle text;start_at integer;end_at integer;predicate text;
BEGIN
 d:=pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure);
 needle:='FUNCTION public.zasp_workflow_mutate(';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'integration receipt signature drift';END IF;
 d:=replace(d,needle,'FUNCTION zasp_authorization80.integration_receipt_mutate(');
 needle:='PERFORM public.zasp_audit_exports_require_ready();';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>4 THEN RAISE EXCEPTION 'integration receipt readiness drift';END IF;
 d:=replace(d,needle,'PERFORM zasp_authorization80.integration_current_ready();');
 start_at:=strpos(d,E'    IF NOT EXISTS (');end_at:=strpos(d,'    IF requested_receipt_id IS NOT NULL');
 IF start_at=0 OR end_at<=start_at THEN RAISE EXCEPTION 'integration receipt release predicate drift';END IF;
 predicate:=substr(d,start_at,end_at-start_at);
 IF strpos(predicate,'production-recovery-v1')=0 OR strpos(predicate,'release."version" = 27')=0 OR strpos(predicate,'release."name" = ''production_recovery''')=0 OR strpos(predicate,'workflow receipt provenance release unavailable')=0
 OR (length(predicate)-length(replace(predicate,'later_release."version" > 60','')))/length('later_release."version" > 60')<>1
 THEN RAISE EXCEPTION 'integration receipt release identity drift';END IF;
 d:=replace(d,predicate,E'    PERFORM zasp_authorization80.integration_current_ready();\n');
 EXECUTE d;
 d:=pg_get_functiondef('public.zasp_connector_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure);
 needle:='FUNCTION public.zasp_connector_workflow_mutate(';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'integration connector signature drift';END IF;
 d:=replace(d,needle,'FUNCTION zasp_authorization80.integration_connector_mutate(');
 needle:='mutation_response:=zasp_workflow_mutate(';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION 'integration connector receipt call drift';END IF;
 d:=replace(d,needle,'mutation_response:=zasp_authorization80.integration_receipt_mutate(');
 needle:='IF typed_row.display_name<>display_name_value OR typed_row.configuration<>configuration_value OR typed_row.version<>response_version THEN';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'integration typed condition drift';END IF;
 d:=replace(d,needle,'IF NOT COALESCE((mutation_response->>''replayed'')::boolean,false) THEN');
 needle:='configuration=configuration_value,version=response_version,updated_at=transaction_timestamp()';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'integration typed version drift';END IF;
 d:=replace(d,needle,'configuration=configuration_value,version=GREATEST(typed_row.version+1,response_version),updated_at=transaction_timestamp()');
 needle:='configuration_value:=requested_body->''configuration'';';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'integration typed configuration assignment drift';END IF;
 d:=replace(d,needle,'configuration_value:=zasp_authorization80.integration_typed_configuration(requested_body->>''connector_key'',requested_body->''configuration'');');
 EXECUTE d;
END $compatibility$;

CREATE FUNCTION zasp_authorization80.integration_setup_valid(k text,c jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,public AS $$
DECLARE keys text[];value text;url text;host text;path text;
BEGIN
 IF jsonb_typeof(c) IS DISTINCT FROM 'object' THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM jsonb_each(c) x WHERE jsonb_typeof(x.value)<>'string' OR octet_length(x.value#>>'{}') NOT BETWEEN 1 AND 2048 OR x.value#>>'{}'<>btrim(x.value#>>'{}',E' \t\r\n\v\f') OR x.value#>>'{}'~E'[\r\n]') THEN RETURN false;END IF;
 SELECT array_agg(key ORDER BY key) INTO keys FROM jsonb_object_keys(c) key;
 CASE k
 WHEN 'github' THEN RETURN keys=ARRAY['authorization_mode'] AND c->>'authorization_mode'='github_app';
 WHEN 'aws' THEN RETURN keys=ARRAY['external_id_reference','region','role_arn']
  AND c->>'role_arn'~'^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$' AND length(split_part(c->>'role_arn',':role/',2)) BETWEEN 1 AND 512
  AND octet_length(c->>'external_id_reference') BETWEEN 12 AND 512 AND c->>'external_id_reference'~'^ref:[a-z0-9_./:-]+$'
  AND c->>'region'~'^[a-z]{2}(-gov)?-[a-z]+-[0-9]$';
 WHEN 'kubernetes' THEN RETURN keys=ARRAY['connection_reference'] AND octet_length(c->>'connection_reference') BETWEEN 12 AND 512 AND c->>'connection_reference'~'^ref:[a-z0-9_./:-]+$';
 WHEN 'okta' THEN RETURN keys=ARRAY['issuer'] AND c->>'issuer'~'^https://[a-z0-9][a-z0-9-]{1,61}[a-z0-9]\.okta\.com$';
 WHEN 'slack' THEN RETURN keys=ARRAY['workspace_label'] AND octet_length(c->>'workspace_label')<=128;
 WHEN 'generic-webhook' THEN
  IF keys IS DISTINCT FROM ARRAY['destination_url','signing_secret_reference'] AND keys IS DISTINCT FROM ARRAY['destination_url','signing_secret_reference','signing_secret_version'] THEN RETURN false;END IF;
  IF c ? 'signing_secret_version' AND c->>'signing_secret_version'!~'^[A-Za-z0-9-]{32,64}$' THEN RETURN false;END IF;
  IF left(c->>'signing_secret_reference',11)<>'secret_ref_' OR octet_length(c->>'signing_secret_reference')>128 THEN RETURN false;END IF;
  url:=c->>'destination_url';
  IF url!~'^https://[^/?#@[:space:]]+(/[^?#[:space:]]*)?$' THEN RETURN false;END IF;
  host:=lower(split_part(substr(url,9),'/',1));
  IF host~'[[:cntrl:]|{}^`\\]' OR strpos(regexp_replace(host,'%(25|[89A-Fa-f][0-9A-Fa-f])','','g'),'%')>0 OR (strpos(host,':')>0 AND host!~'^[^:]+:[0-9]*$')
   OR strpos(regexp_replace(url,'%[0-9A-Fa-f]{2}','','g'),'%')>0 THEN RETURN false;END IF;
  -- Literal IP destinations and local hostnames never carry outbound authority.
  IF host~'^\[' OR host~'^[0-9.]+(:[0-9]+)?$' THEN RETURN false;END IF;
  host:=split_part(host,':',1);
  IF host='' OR host='localhost' OR host~'\.(localhost|local|internal)$' THEN RETURN false;END IF;
  path:=substr(url,9+length(split_part(substr(url,9),'/',1)));
  IF path LIKE '%\%%' AND path LIKE '%..%' THEN RETURN false;END IF;
  RETURN true;
 ELSE RETURN false;END CASE;
END $$;

CREATE FUNCTION zasp_authorization80.integration_typed_configuration(k text,c jsonb) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,public AS $$
BEGIN
 IF k='generic-webhook' THEN
  IF NOT COALESCE(zasp_authorization80.integration_setup_valid(k,c),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid typed webhook configuration';END IF;
  RETURN c-'signing_secret_version';
 END IF;
 RETURN c;
END $$;

CREATE FUNCTION zasp_authorization80.integration_value(o text,w text,e text,id_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE p jsonb;result jsonb;typed_version bigint;
BEGIN
 PERFORM zasp_authorization80.integration_current_ready();
 p:=zasp_authorization80.context();
 IF NOT COALESCE(zasp_authorization80.read_request(o,w,e,ARRAY['getIntegration'],'view') AND NOT(p->>'collection')::boolean AND p#>>'{path_parameters,id}'=id_value AND zasp_authorization80.allowed(o,w,e,'integration',id_value),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='integration read denied';END IF;
 SELECT jsonb_build_object('body',r.body,'version',r.version,'secret_generation',r.secret_generation),i.version INTO result,typed_version FROM public.zasp_workflow_records r JOIN public.zasp_integrations i
 ON(i.organization_id,i.workspace_id,i.environment_id,i.id)=(r.organization_id,r.workspace_id,r.environment_id,r.id)
 WHERE(r.organization_id,r.workspace_id,r.environment_id,r.kind,r.id)=(o,w,e,'integration',id_value) AND r.deleted_at IS NULL AND i.deleted_at IS NULL AND i.state<>'deleted' FOR SHARE OF r,i;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='integration unavailable';END IF;
 IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p->'targets') t WHERE(t->>'kind',t->>'id',(t->>'version')::bigint)=('integration',id_value,typed_version)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='integration target changed';END IF;
 PERFORM zasp_authorization79.revalidate(o,(p#>>'{revision,desired}')::bigint,(p#>>'{revision,generation}')::bigint,p#>>'{revision,store_id}',p#>>'{revision,model_id}');
 PERFORM zasp_authorization80.identity_fence(p);
 PERFORM zasp_authorization80.integration_current_ready();
 IF zasp_authorization80.context() IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='integration proof expired';END IF;
 RETURN result;
END $$;

CREATE FUNCTION zasp_authorization80.integration_mutate(action_value text,kind_value text,id_value text,o text,w text,e text,actor_value text,operation_value text,key_value text,expected_version bigint,intent_value jsonb,body_value jsonb,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE p jsonb;replay jsonb;result jsonb;old_workflow public.zasp_workflow_records%ROWTYPE;old_typed public.zasp_integrations%ROWTYPE;prepared jsonb;input jsonb;connector text;next_version bigint;next_typed bigint;revision_value bigint;clock_value text;
BEGIN
 PERFORM zasp_authorization80.integration_current_ready();
 p:=zasp_authorization80.require_integration_operation(o,w,e,actor_value,operation_value,CASE operation_value WHEN 'createIntegration' THEN e ELSE id_value END);
 IF NOT COALESCE(kind_value='integration' AND (action_value,operation_value) IN(('create','createIntegration'),('update','updateIntegration'))
  AND public.zasp_valid_product_id(id_value) AND public.zasp_valid_product_id(audit_value) AND public.zasp_valid_product_id(correlation_value)
  AND ((p->>'credential_kind'='1' AND public.zasp_valid_product_id(receipt_value)) OR (p->>'credential_kind'='2' AND receipt_value=''))
  AND jsonb_typeof(intent_value)='object' AND intent_value-ARRAY['resource_id','expected_version','body']='{}'::jsonb
  AND intent_value->'expected_version'=to_jsonb(expected_version)
  AND intent_value->>'resource_id'=CASE action_value WHEN 'create' THEN '' ELSE id_value END
  AND ((action_value='create' AND expected_version=0) OR (action_value='update' AND expected_version>0)),false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='integration mutation request rejected';END IF;
 replay:=zasp_authorization80.integration_replay(o,w,e,actor_value,operation_value,key_value,intent_value);
 IF (replay->>'found')::boolean THEN RETURN replay->'result';END IF;
 input:=intent_value->'body';
 IF NOT COALESCE(jsonb_typeof(input)='object' AND input-ARRAY['name','connector_key','configuration']='{}'::jsonb
  AND jsonb_typeof(input->'name')='string' AND octet_length(input->>'name') BETWEEN 1 AND 128
  AND jsonb_typeof(body_value)='object' AND body_value->>'id'=id_value AND body_value->'name'=input->'name' AND body_value->'configuration'=input->'configuration',false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='integration body rejected';END IF;
 IF action_value='update' THEN
  SELECT * INTO old_workflow FROM public.zasp_workflow_records r WHERE(r.organization_id,r.workspace_id,r.environment_id,r.kind,r.id)=(o,w,e,'integration',id_value) AND r.deleted_at IS NULL FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='integration unavailable';END IF;
  SELECT * INTO old_typed FROM public.zasp_integrations i WHERE(i.organization_id,i.workspace_id,i.environment_id,i.id)=(o,w,e,id_value) AND i.deleted_at IS NULL AND i.state<>'deleted' FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='integration unavailable';END IF;
  IF old_workflow.version<>expected_version OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p->'targets') t WHERE(t->>'kind',t->>'id',(t->>'version')::bigint)=('integration',id_value,old_typed.version))
  THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='integration version conflict';END IF;
  IF old_workflow.version=9223372036854775807 OR old_typed.version=9223372036854775807 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='integration version exhausted';END IF;
  connector:=old_workflow.body->>'connector_key';
  IF connector IS DISTINCT FROM old_typed.kind OR old_typed.configuration IS DISTINCT FROM zasp_authorization80.integration_typed_configuration(connector,old_workflow.body->'configuration') OR body_value-ARRAY['name','configuration','updated_at'] IS DISTINCT FROM old_workflow.body-ARRAY['name','configuration','updated_at']
  THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='integration server fields rejected';END IF;
  next_version:=old_workflow.version+1;next_typed:=GREATEST(old_typed.version+1,next_version);
 ELSE
  connector:=input->>'connector_key';
  IF NOT COALESCE(jsonb_typeof(input->'connector_key')='string' AND body_value->>'connector_key'=connector AND body_value->>'status'=CASE connector WHEN 'generic-webhook' THEN 'configured' ELSE 'pending_authorization' END
   AND body_value-ARRAY['id','name','connector_key','configuration','status','created_at','updated_at']='{}'::jsonb,false)
  THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='integration server fields rejected';END IF;
  IF EXISTS(SELECT 1 FROM public.zasp_integrations i WHERE(i.organization_id,i.workspace_id,i.environment_id,i.id)=(o,w,e,id_value)) OR EXISTS(SELECT 1 FROM public.zasp_workflow_records r WHERE(r.organization_id,r.workspace_id,r.environment_id,r.kind,r.id)=(o,w,e,'integration',id_value)) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='integration already exists';END IF;
  next_version:=1;next_typed:=1;
 END IF;
 IF NOT COALESCE(zasp_authorization80.integration_setup_valid(connector,input->'configuration'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='integration setup rejected';END IF;
 PERFORM zasp_authorization80.integration_rejection_classify(p);
 PERFORM zasp_authorization80.identity_fence(p);
 PERFORM zasp_authorization79.revalidate(o,(p#>>'{revision,desired}')::bigint,(p#>>'{revision,generation}')::bigint,p#>>'{revision,store_id}',p#>>'{revision,model_id}');
 clock_value:=to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"');
 prepared:=body_value||jsonb_build_object('updated_at',clock_value);
 IF action_value='create' THEN prepared:=prepared||jsonb_build_object('created_at',clock_value);END IF;
 result:=zasp_authorization80.integration_connector_mutate(action_value,kind_value,id_value,o,w,e,actor_value,operation_value,key_value,expected_version,intent_value,prepared,audit_value,correlation_value,receipt_value);
 -- Create inserts two captured resource rows; an update changes neither
 -- source79's membership columns nor lifecycle state. Retain the held revision
 -- lock and require this exact delta, never a caller-selected new revision.
 revision_value:=(p#>>'{revision,desired}')::bigint+CASE action_value WHEN 'create' THEN 2 ELSE 0 END;
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization79.organizations x WHERE x.organization_id=o AND x.desired=revision_value AND x.applied=(p#>>'{revision,applied}')::bigint AND x.generation=(p#>>'{revision,generation}')::bigint AND x.store_id=p#>>'{revision,store_id}' AND x.model_id=p#>>'{revision,model_id}')
 OR NOT EXISTS(SELECT 1 FROM public.zasp_integrations i WHERE(i.organization_id,i.workspace_id,i.environment_id,i.id,i.version,i.kind,i.configuration)=(o,w,e,id_value,next_typed,connector,zasp_authorization80.integration_typed_configuration(connector,prepared->'configuration')))
 OR NOT EXISTS(SELECT 1 FROM public.zasp_workflow_records r WHERE(r.organization_id,r.workspace_id,r.environment_id,r.kind,r.id,r.version,r.body)=(o,w,e,'integration',id_value,next_version,prepared))
 OR result->>'audit_id' IS DISTINCT FROM audit_value OR result->>'correlation_id' IS DISTINCT FROM correlation_value OR (result->>'version')::bigint IS DISTINCT FROM next_version
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='integration mutation accounting changed';END IF;
 PERFORM zasp_authorization80.integration_rejection_classify(p);
 PERFORM zasp_authorization80.identity_fence(p);
 PERFORM zasp_authorization80.integration_current_ready();
 IF zasp_authorization80.context() IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='integration proof expired';END IF;
 RETURN result;
END $$;

REVOKE ALL ON FUNCTION zasp_authorization80.integration_current_ready(),zasp_authorization80.integration_receipt_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text),zasp_authorization80.integration_connector_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text),zasp_authorization80.integration_setup_valid(text,jsonb),zasp_authorization80.integration_value(text,text,text,text),zasp_authorization80.integration_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.integration_value(text,text,text,text),zasp_authorization80.integration_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text) TO zasp_discovery_api;
REVOKE ALL ON FUNCTION zasp_authorization80.integration_typed_configuration(text,jsonb) FROM PUBLIC;
