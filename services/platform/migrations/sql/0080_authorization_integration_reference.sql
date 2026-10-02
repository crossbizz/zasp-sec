-- Checked consumers for the original browser reference-authorization operation.
-- Public source12/13 predecessors remain unchanged. These private dependencies
-- are reachable only through the closed endpoints below.
DO $reference_compatibility$
DECLARE d text;pair text[];spec jsonb;
BEGIN
 d:=pg_get_functiondef('public.zasp_complete_reference_authorization(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure);
 FOR spec IN SELECT value FROM jsonb_array_elements($patch$[
  ["FUNCTION public.zasp_complete_reference_authorization(","FUNCTION zasp_authorization80.integration_reference_native_complete("],
  ["OR integration_row.version<>expected_version_value OR workflow_row.body", "OR workflow_row.body"],
  ["result_value:=zasp_connector_workflow_mutate(","result_value:=zasp_authorization80.integration_connector_mutate("],
  ["SET state='active',version=(result_value->>'version')::bigint,updated_at", "SET state='active',version=GREATEST(integration_row.version+1,(result_value->>'version')::bigint),updated_at"],
  ["AND version=(result_value->>'version')::bigint AND state", "AND version=GREATEST(integration_row.version+1,(result_value->>'version')::bigint) AND state"],
  ["SET state='verified',version=EXCLUDED.version,verified_at", "SET state='verified',version=GREATEST(zasp_integration_connections.version+1,EXCLUDED.version),verified_at"],
  ["OR connection_row.version<>(result_value->>'version')::bigint", "OR connection_row.version<(result_value->>'version')::bigint"]
 ]$patch$::jsonb) LOOP
  IF (length(d)-length(replace(d,spec->>0,'')))/length(spec->>0)<>1 THEN RAISE EXCEPTION 'reference source12 substitution drift: %',spec->>0;END IF;
  d:=replace(d,spec->>0,spec->>1);
 END LOOP;
 EXECUTE d;
 d:=pg_get_functiondef('public.zasp_execution_complete_reference_authorization(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text,text,text)'::regprocedure);
 FOR spec IN SELECT value FROM jsonb_array_elements($patch$[
  ["FUNCTION public.zasp_execution_complete_reference_authorization(","FUNCTION zasp_authorization80.integration_reference_execution_complete("],
  ["DECLARE result_value jsonb;connection_version_value bigint;replay_value jsonb;", "DECLARE result_value jsonb;connection_version_value bigint;replay_value jsonb;typed_version_value bigint;old_connection_version bigint;"],
  ["BEGIN\n replay_value:=", "BEGIN\n SELECT version INTO STRICT typed_version_value FROM public.zasp_integrations WHERE (organization_id,workspace_id,environment_id,id)=(organization_value,workspace_value,environment_value,integration_value) FOR UPDATE;\n SELECT version INTO old_connection_version FROM public.zasp_integration_connections WHERE (organization_id,workspace_id,environment_id,integration_id,provider)=(organization_value,workspace_value,environment_value,integration_value,provider_value) FOR UPDATE;\n replay_value:="],
  ["AND connection.state='verified' AND connection.version=expected_version_value", "AND connection.state='verified' AND connection.version=old_connection_version"],
  ["result_value:=zasp_complete_reference_authorization(","result_value:=zasp_authorization80.integration_reference_native_complete("]
 ]$patch$::jsonb) LOOP
  IF (length(d)-length(replace(d,spec->>0,'')))/length(spec->>0)<>1 THEN RAISE EXCEPTION 'reference source13 substitution drift: %',spec->>0;END IF;
  d:=replace(d,spec->>0,spec->>1);
 END LOOP;
 IF (length(d)-length(replace(d,'provider_value,expected_version_value,''degraded''','')))/length('provider_value,expected_version_value,''degraded''')<>2 THEN RAISE EXCEPTION 'reference source13 typed predicate drift';END IF;
 d:=replace(d,'provider_value,expected_version_value,''degraded''','provider_value,typed_version_value,''degraded''');
 EXECUTE d;
END $reference_compatibility$;

CREATE FUNCTION zasp_authorization80.integration_reference_finish(p jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 PERFORM zasp_authorization80.identity_fence(p);
 PERFORM zasp_authorization80.integration_current_ready();
 IF zasp_authorization80.context() IS DISTINCT FROM p THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='reference authorization proof expired';END IF;
END $$;

CREATE FUNCTION zasp_authorization80.require_integration_reference(o text,w text,e text,actor_value text,id_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE p jsonb;typed_version bigint;
BEGIN
 PERFORM zasp_authorization80.integration_current_ready();
 p:=zasp_authorization80.context();
 IF NOT COALESCE((p->>'organization_id',p->>'workspace_id',p->>'environment_id',p->>'principal_id',p->>'operation_id',p->>'permission',p->>'credential_kind')=(o,w,e,actor_value,'authorizeIntegrationReference','manage_workflows','1')
  AND (p->>'fresh_auth')::boolean AND NOT(p->>'collection')::boolean AND p#>>'{path_parameters,id}'=id_value
  AND zasp_authorization80.allowed(o,w,e,'integration',id_value),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='reference authorization denied';END IF;
 PERFORM zasp_authorization79.revalidate(o,(p#>>'{revision,desired}')::bigint,(p#>>'{revision,generation}')::bigint,p#>>'{revision,store_id}',p#>>'{revision,model_id}');
 SELECT i.version INTO typed_version FROM public.zasp_integrations i JOIN public.zasp_workflow_records r
 ON(r.organization_id,r.workspace_id,r.environment_id,r.kind,r.id)=(i.organization_id,i.workspace_id,i.environment_id,'integration',i.id)
 WHERE(i.organization_id,i.workspace_id,i.environment_id,i.id)=(o,w,e,id_value) AND i.deleted_at IS NULL AND i.state<>'deleted' AND r.deleted_at IS NULL FOR SHARE OF i,r;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='reference integration unavailable';END IF;
 IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p->'targets') t WHERE(t->>'kind',t->>'id',(t->>'version')::bigint)=('integration',id_value,typed_version))
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='reference target changed';END IF;
 PERFORM zasp_authorization80.integration_reference_finish(p);
 RETURN p;
END $$;

CREATE FUNCTION zasp_authorization80.integration_reference_replay(o text,w text,e text,actor_value text,id_value text,key_value text,expected_version bigint) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE p jsonb;result jsonb;
BEGIN
 p:=zasp_authorization80.require_integration_reference(o,w,e,actor_value,id_value);
 IF NOT COALESCE(key_value~'^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$' AND expected_version BETWEEN 1 AND 1000000,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid reference replay';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),o,w,e,actor_value,'completeIntegrationReferenceAuthorization',key_value),0));
 result:=public.zasp_reference_authorization_replay(o,w,e,actor_value,id_value,key_value,expected_version);
 PERFORM zasp_authorization80.require_integration_reference(o,w,e,actor_value,id_value);
 RETURN result;
END $$;

CREATE FUNCTION zasp_authorization80.integration_reference_value(o text,w text,e text,id_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE p jsonb;result jsonb;
BEGIN
 p:=zasp_authorization80.context();
 p:=zasp_authorization80.require_integration_reference(o,w,e,p->>'principal_id',id_value);
 SELECT jsonb_build_object('body',r.body,'version',r.version,'secret_generation',r.secret_generation) INTO STRICT result FROM public.zasp_workflow_records r
 WHERE(r.organization_id,r.workspace_id,r.environment_id,r.kind,r.id)=(o,w,e,'integration',id_value) AND r.deleted_at IS NULL FOR SHARE;
 PERFORM zasp_authorization80.integration_reference_finish(p);
 RETURN result;
END $$;

CREATE FUNCTION zasp_authorization80.integration_reference_complete(o text,w text,e text,actor_value text,id_value text,provider_value text,connection_value text,reference_value text,key_value text,expected_version bigint,configuration_value jsonb,intent_value jsonb,audit_value text,correlation_value text,receipt_value text,subject_kind_value text,subject_id_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE p jsonb;result jsonb;replay jsonb;workflow_row public.zasp_workflow_records%ROWTYPE;typed_row public.zasp_integrations%ROWTYPE;connection_row public.zasp_integration_connections%ROWTYPE;next_typed bigint;next_connection bigint;revision_delta bigint;expected_intent jsonb;connection_digest bytea;connection_hex text;
BEGIN
 p:=zasp_authorization80.require_integration_reference(o,w,e,actor_value,id_value);
 -- Match connectorDeterministicID: scoped SHA256, first16 bytes, UUIDv4 and
 -- RFC4122 variant bits. The older discovery canonical ID fixes a different
 -- variant nibble and is not this public connection identity contract.
 connection_digest:=substring(public.digest(convert_to(concat_ws(chr(31),o,w,e,id_value,'reference-connection:'||provider_value),'UTF8'),'sha256') FROM 1 FOR 16);
 connection_digest:=set_byte(connection_digest,6,(get_byte(connection_digest,6)&15)|64);
 connection_digest:=set_byte(connection_digest,8,(get_byte(connection_digest,8)&63)|128);
 connection_hex:=encode(connection_digest,'hex');
 expected_intent:=jsonb_build_object('configuration',configuration_value,'expected_version',expected_version,'idempotency_key',key_value,'integration_id',id_value,'provider',provider_value,'scope',jsonb_build_object('environment_id',e,'organization_id',o,'workspace_id',w));
 IF NOT COALESCE(intent_value=expected_intent AND expected_version BETWEEN 1 AND 1000000 AND key_value~'^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$'
  AND provider_value IN('aws','kubernetes') AND connection_value='pid_'||substr(connection_hex,1,8)||'-'||substr(connection_hex,9,4)||'-'||substr(connection_hex,13,4)||'-'||substr(connection_hex,17,4)||'-'||substr(connection_hex,21,12) AND public.zasp_valid_product_id(audit_value) AND public.zasp_valid_product_id(correlation_value) AND public.zasp_valid_product_id(receipt_value)
  AND public.zasp_reference_authorization_configuration_valid(provider_value,configuration_value)
  AND public.zasp_execution_subject_valid(provider_value,subject_kind_value,subject_id_value),false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid reference completion';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),o,w,e,actor_value,'completeIntegrationReferenceAuthorization',key_value),0));
 replay:=public.zasp_reference_authorization_exact_replay(o,w,e,actor_value,id_value,key_value,intent_value);
 IF (replay->>'found')::boolean THEN
  PERFORM zasp_authorization80.require_integration_reference(o,w,e,actor_value,id_value);
  RETURN replay->'result';
 END IF;
 SELECT * INTO STRICT workflow_row FROM public.zasp_workflow_records WHERE(organization_id,workspace_id,environment_id,kind,id)=(o,w,e,'integration',id_value) AND deleted_at IS NULL FOR UPDATE;
 SELECT * INTO STRICT typed_row FROM public.zasp_integrations WHERE(organization_id,workspace_id,environment_id,id)=(o,w,e,id_value) AND deleted_at IS NULL FOR UPDATE;
 SELECT * INTO connection_row FROM public.zasp_integration_connections WHERE(organization_id,workspace_id,environment_id,integration_id,provider)=(o,w,e,id_value,provider_value) FOR UPDATE;
 PERFORM zasp_authorization80.require_integration_reference(o,w,e,actor_value,id_value);
 IF workflow_row.version<>expected_version OR typed_row.version=9223372036854775807 OR connection_row.version=9223372036854775807
 THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='reference version conflict';END IF;
 next_typed:=GREATEST(typed_row.version+1,expected_version+1);
 next_connection:=CASE WHEN connection_row.id IS NULL THEN expected_version+1 ELSE GREATEST(connection_row.version+1,expected_version+1) END;
 revision_delta:=CASE WHEN connection_row.id IS NULL THEN 2 WHEN typed_row.state='degraded' AND connection_row.state='verified' THEN 4 ELSE 3 END;
 result:=zasp_authorization80.integration_reference_execution_complete(o,w,e,actor_value,id_value,provider_value,connection_value,reference_value,key_value,expected_version,configuration_value,intent_value,audit_value,correlation_value,receipt_value,subject_kind_value,subject_id_value);
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization79.organizations x WHERE x.organization_id=o AND x.desired=(p#>>'{revision,desired}')::bigint+revision_delta AND x.applied=(p#>>'{revision,applied}')::bigint AND x.generation=(p#>>'{revision,generation}')::bigint AND x.store_id=p#>>'{revision,store_id}' AND x.model_id=p#>>'{revision,model_id}')
 OR NOT EXISTS(SELECT 1 FROM public.zasp_integrations i WHERE(i.organization_id,i.workspace_id,i.environment_id,i.id,i.version,i.state,i.configuration)=(o,w,e,id_value,next_typed,'active',configuration_value))
 OR NOT EXISTS(SELECT 1 FROM public.zasp_workflow_records r WHERE(r.organization_id,r.workspace_id,r.environment_id,r.kind,r.id,r.version,r.body)=(o,w,e,'integration',id_value,expected_version+1,result->'body'))
 OR NOT EXISTS(SELECT 1 FROM public.zasp_integration_connections c JOIN public.zasp_discovery_connection_subjects s ON(s.organization_id,s.workspace_id,s.environment_id,s.integration_id,s.connection_id)=(c.organization_id,c.workspace_id,c.environment_id,c.integration_id,c.id)
  WHERE(c.organization_id,c.workspace_id,c.environment_id,c.integration_id,c.id,c.provider,c.connection_reference,c.version,c.state)=(o,w,e,id_value,connection_value,provider_value,reference_value,next_connection,'verified')
  AND(s.provider,s.subject_kind,s.subject_id,s.connection_version,s.configuration_digest,s.source)=(provider_value,subject_kind_value,subject_id_value,next_connection,public.digest(convert_to(configuration_value::text,'UTF8'),'sha256'),'reference'))
 OR result->>'audit_id' IS DISTINCT FROM audit_value OR result->>'correlation_id' IS DISTINCT FROM correlation_value OR result->>'receipt_id' IS DISTINCT FROM receipt_value OR(result->>'version')::bigint IS DISTINCT FROM expected_version+1
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='reference mutation accounting changed';END IF;
 PERFORM zasp_authorization80.integration_reference_finish(p);
 RETURN result;
END $$;

REVOKE ALL ON FUNCTION zasp_authorization80.integration_reference_native_complete(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text),zasp_authorization80.integration_reference_execution_complete(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text,text,text),zasp_authorization80.integration_reference_finish(jsonb),zasp_authorization80.require_integration_reference(text,text,text,text,text),zasp_authorization80.integration_reference_replay(text,text,text,text,text,text,bigint),zasp_authorization80.integration_reference_value(text,text,text,text),zasp_authorization80.integration_reference_complete(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.integration_reference_replay(text,text,text,text,text,text,bigint),zasp_authorization80.integration_reference_value(text,text,text,text),zasp_authorization80.integration_reference_complete(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text,text,text) TO zasp_discovery_api;
