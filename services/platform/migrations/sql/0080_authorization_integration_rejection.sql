-- Original-operation rejection only. No integration mutation, audit-table
-- isolation, historical readiness replacement or permission-array allow path.
CREATE FUNCTION zasp_authorization80.integration_rejection_classify(p jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE credential jsonb;kind_value integer;target_value text;
BEGIN
 -- Every public entry reaches this check, even if its private proof context
 -- was installed through the shared fence. Post-wait source reads need a new
 -- READ COMMITTED snapshot; the Go transaction check alone is insufficient.
 IF current_setting('transaction_isolation')<>'read committed'
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='integration rejection isolation unavailable';END IF;
 IF NOT COALESCE(zasp_authorization80.source_ready(56,'-- authorization80 compliance56 checksum','-- authorization80 compliance56 fingerprint')
  AND public.zasp_discovery_principal_ready('zasp_discovery_api'),false)
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='integration rejection source unavailable';END IF;
 IF NOT COALESCE(p->>'operation_id' IN('createIntegration','updateIntegration') AND p->>'permission'='manage_workflows'
  AND p->>'credential_kind' IN('1','2') AND NOT(p->>'collection')::boolean,false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='integration rejection authorization denied';END IF;
 target_value:=CASE p->>'operation_id' WHEN 'createIntegration' THEN p->>'environment_id' ELSE p#>>'{path_parameters,id}' END;
 IF NOT COALESCE(public.zasp_valid_product_id(target_value) AND EXISTS(SELECT 1 FROM jsonb_array_elements(p->'allowed') a
  WHERE(a->>'organization_id',a->>'workspace_id',a->>'environment_id',a->>'kind',a->>'id')=
  (p->>'organization_id',p->>'workspace_id',p->>'environment_id',CASE p->>'operation_id' WHEN 'createIntegration' THEN 'environment' ELSE 'integration' END,target_value)),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='integration rejection authorization denied';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.zasp_identity_memberships m WHERE(m.organization_id,m.principal_id)=(p->>'organization_id',p->>'principal_id') AND m.active)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='integration rejection authorization denied';END IF;
 kind_value:=(p->>'credential_kind')::integer;
 IF kind_value=1 THEN
  SELECT to_jsonb(s) INTO credential FROM public.zasp_product_sessions s WHERE s.token_digest=decode(p->>'credential_digest','hex') AND s.session_id=p->>'credential_id';
 ELSE
  SELECT to_jsonb(s) INTO credential FROM public.zasp_product_api_tokens s WHERE s.token_digest=decode(p->>'credential_digest','hex') AND s.id=p->>'credential_id';
 END IF;
 IF credential IS NULL OR credential->>'revoked_at' IS NOT NULL
  OR(credential->>'principal_id',credential->>'organization_id',credential->>'workspace_id',credential->>'environment_id') IS DISTINCT FROM(p->>'principal_id',p->>'organization_id',p->>'workspace_id',p->>'environment_id')
 THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='integration rejection credential unavailable';END IF;
 -- These predicates can only deny. PAT permissions are a credential ceiling;
 -- effective-scope existence is not a replacement for the signed FGA decision.
 IF(kind_value=2 AND(NOT credential->'permissions' ? 'manage_workflows' OR credential->'permissions' IS DISTINCT FROM p->'pat_ceiling'))
  OR(kind_value=1 AND encode(public.digest(credential->>'csrf_token','sha256'),'hex') IS DISTINCT FROM p->>'csrf_digest')
  OR NOT EXISTS(SELECT 1 FROM public.zasp_identity_admin_effective_scopes(p->>'principal_id',p->>'organization_id') s WHERE(s.workspace_id,s.environment_id)=(p->>'workspace_id',p->>'environment_id'))
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='integration rejection authorization denied';END IF;
 IF p->>'operation_id'='updateIntegration' AND NOT EXISTS(
  SELECT 1 FROM public.zasp_integrations i JOIN public.zasp_workflow_records r
  ON(r.organization_id,r.workspace_id,r.environment_id,r.id,r.kind)=(i.organization_id,i.workspace_id,i.environment_id,i.id,'integration')
  WHERE(i.organization_id,i.workspace_id,i.environment_id,i.id)=(p->>'organization_id',p->>'workspace_id',p->>'environment_id',target_value)
  AND i.deleted_at IS NULL AND i.state<>'deleted' AND r.deleted_at IS NULL)
 THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='integration rejection target unavailable';END IF;
 IF (credential->>'expires_at')::timestamptz<=clock_timestamp()
 THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='integration rejection credential unavailable';END IF;
 IF NOT COALESCE((p->>'expires_at')::bigint>floor(extract(epoch FROM clock_timestamp())*1000)::bigint,false)
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='integration rejection proof expired';END IF;
END $$;

CREATE FUNCTION zasp_authorization80.integration_rejection_fence(envelope text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE p jsonb;
BEGIN
 p:=zasp_authorization80.verify_attestation(envelope);
 PERFORM zasp_authorization80.integration_rejection_classify(p);
 BEGIN
  PERFORM zasp_authorization80.fence(envelope);
 EXCEPTION WHEN serialization_failure THEN
  -- A lock wait can change the deny reason. This branch always raises: it
  -- never continues a failed fence into an audit write or a commit.
  PERFORM zasp_authorization80.integration_rejection_classify(p);
  RAISE;
 END;
 -- Shared fencing checks credentials before target locks. Recheck the wall
 -- clock after those waits while retaining all acquired authority locks.
 PERFORM zasp_authorization80.integration_rejection_classify(p);
END $$;

CREATE FUNCTION zasp_authorization80.require_integration_operation(o text,w text,e text,actor_value text,operation_value text,target_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE p jsonb;
BEGIN
 p:=zasp_authorization80.context();
 IF NOT COALESCE((p->>'organization_id',p->>'workspace_id',p->>'environment_id',p->>'principal_id',p->>'operation_id')=(o,w,e,actor_value,operation_value)
  AND operation_value IN('createIntegration','updateIntegration')
  AND target_value=CASE operation_value WHEN 'createIntegration' THEN e ELSE p#>>'{path_parameters,id}' END,false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='integration rejection authorization denied';END IF;
 PERFORM zasp_authorization80.integration_rejection_classify(p);
 RETURN p;
END $$;

CREATE FUNCTION zasp_authorization80.integration_replay(o text,w text,e text,actor_value text,operation_value text,key_value text,intent_value jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE p jsonb;target_value text;prior_digest bytea;prior_response jsonb;
BEGIN
 p:=zasp_authorization80.context();
 target_value:=CASE operation_value WHEN 'createIntegration' THEN e ELSE p#>>'{path_parameters,id}' END;
 PERFORM zasp_authorization80.require_integration_operation(o,w,e,actor_value,operation_value,target_value);
 IF NOT COALESCE(length(key_value) BETWEEN 16 AND 128 AND key_value~'^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$'
  AND jsonb_typeof(intent_value)='object'
  AND jsonb_typeof(intent_value->'body')='object'
  AND intent_value->>'resource_id'=CASE operation_value WHEN 'createIntegration' THEN '' ELSE target_value END,false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='integration replay request rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),o,w,e,actor_value,operation_value,key_value),0));
 PERFORM zasp_authorization80.integration_rejection_classify(p);
 SELECT request_digest,response INTO prior_digest,prior_response FROM public.zasp_workflow_idempotency
 WHERE(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(o,w,e,actor_value,operation_value,key_value);
 IF NOT FOUND THEN RETURN jsonb_build_object('found',false);END IF;
 IF prior_digest<>public.digest(convert_to(intent_value::text,'UTF8'),'sha256')
 THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='idempotency conflict';END IF;
 RETURN jsonb_build_object('found',true,'result',prior_response||jsonb_build_object('replayed',true));
END $$;

CREATE FUNCTION zasp_authorization80.integration_update_value(o text,w text,e text,id_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE p jsonb;result jsonb;
BEGIN
 p:=zasp_authorization80.context();
 PERFORM zasp_authorization80.require_integration_operation(o,w,e,p->>'principal_id','updateIntegration',id_value);
 SELECT jsonb_build_object('body',r.body,'version',r.version,'secret_generation',r.secret_generation) INTO result
 FROM public.zasp_workflow_records r JOIN public.zasp_integrations i
 ON(i.organization_id,i.workspace_id,i.environment_id,i.id)=(r.organization_id,r.workspace_id,r.environment_id,r.id)
 WHERE(r.organization_id,r.workspace_id,r.environment_id,r.kind,r.id)=(o,w,e,'integration',id_value)
 AND r.deleted_at IS NULL AND i.deleted_at IS NULL AND i.state<>'deleted' FOR SHARE OF r,i;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='integration rejection target unavailable';END IF;
 PERFORM zasp_authorization80.integration_rejection_classify(p);
 RETURN result;
END $$;

CREATE FUNCTION zasp_authorization80.integration_rejection(o text,w text,e text,actor_value text,credential_value bytea,operation_value text,target_value text,audit_value text,correlation_value text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE p jsonb;
BEGIN
 p:=zasp_authorization80.require_integration_operation(o,w,e,actor_value,operation_value,target_value);
 IF credential_value IS DISTINCT FROM decode(p->>'credential_digest','hex')
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='integration rejection authorization denied';END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(audit_value) AND public.zasp_valid_product_id(correlation_value),false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='integration rejection identifiers rejected';END IF;
 INSERT INTO public.zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at)
 VALUES(o,w,e,audit_value,actor_value,'integration.setup.rejected',target_value,'rejected',jsonb_build_object('operation',operation_value,'resource_kind','integration','reason','invalid_configuration','correlation_id',correlation_value),clock_timestamp());
 -- Native callers cannot skip post-wait classification by omitting the Go
 -- transaction's final fence. Any failure aborts this entire SQL statement.
 PERFORM zasp_authorization80.integration_rejection_classify(p);
 PERFORM zasp_authorization80.identity_fence(p);
END $$;

REVOKE ALL ON FUNCTION zasp_authorization80.integration_rejection_classify(jsonb),zasp_authorization80.require_integration_operation(text,text,text,text,text,text),zasp_authorization80.integration_rejection_fence(text),zasp_authorization80.integration_replay(text,text,text,text,text,text,jsonb),zasp_authorization80.integration_update_value(text,text,text,text),zasp_authorization80.integration_rejection(text,text,text,text,bytea,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.integration_rejection_fence(text),zasp_authorization80.integration_replay(text,text,text,text,text,text,jsonb),zasp_authorization80.integration_update_value(text,text,text,text),zasp_authorization80.integration_rejection(text,text,text,text,bytea,text,text,text,text) TO zasp_discovery_api;
