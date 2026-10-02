-- Unregistered release55 candidate, applied only by the owned fixture.
-- Preserve the exact predecessor for eventual release55 rollback wiring.
DO $definition_provenance$
DECLARE source_value text; anchor_value text; replacement_value text;
BEGIN
 SELECT pg_get_functiondef('public.zasp_security_agent_mutate_definition(text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT source_value;
 EXECUTE replace(source_value,'FUNCTION public.zasp_security_agent_mutate_definition(','FUNCTION zasp_existing_tests_predecessor.zasp_security_agent_mutate_definition(');
 ALTER FUNCTION zasp_existing_tests_predecessor.zasp_security_agent_mutate_definition(text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text) OWNER TO zasp_discovery_authority;
 REVOKE ALL ON FUNCTION zasp_existing_tests_predecessor.zasp_security_agent_mutate_definition(text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text) FROM PUBLIC;
 anchor_value:='  response_value:=response_value||jsonb_build_object(''body'',synchronized.body,''version'',synchronized.version);';
 IF (length(source_value)-length(replace(source_value,anchor_value,'')))/length(anchor_value)<>1 THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test definition predecessor rejected';
 END IF;
 replacement_value:=$provenance$
  IF mutation_value<>'delete' AND (synchronized.body ? 'existing_test'
    OR synchronized.body->'allowed_actions' ?| ARRAY['run_test','rerun_test']) THEN
    -- Resolve the exact persisted version under current scoped authority. Any
    -- refusal rolls back the workflow, mirror, history and audit together.
    PERFORM zasp_production_security_agent_run_context_test_binding(
      organization_value,workspace_value,environment_value,definition_value,synchronized.version);
  END IF;
  -- The inherited mirror trigger creates this version inside this transaction.
  -- Bind its provenance before returning or committing, never on a replay and
  -- never by rewriting an earlier version or trusting a caller-set session GUC.
  IF NOT COALESCE(zasp_valid_product_id(principal_value),false) THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent definition actor rejected';
  END IF;
  UPDATE zasp_security_agent_definition_versions SET actor_id=principal_value
  WHERE (organization_id,workspace_id,environment_id,definition_id,version)=
    (organization_value,workspace_value,environment_value,definition_value,synchronized.version)
    AND actor_id=session_user AND definition=synchronized.body
    AND definition_digest=digest(convert_to(synchronized.body::text,'UTF8'),'sha256');
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent definition provenance missing';END IF;
$provenance$;
 EXECUTE replace(source_value,anchor_value,replacement_value||anchor_value);
END
$definition_provenance$;
