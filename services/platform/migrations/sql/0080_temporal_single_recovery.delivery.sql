CREATE FUNCTION zasp_temporal_single_recovery.require_worker(role_value text) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $body$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='recovery isolation rejected';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF role_value NOT IN('zasp_temporal_executor','zasp_temporal_compensation') OR NOT zasp_temporal68.principal_ready(role_value) OR NOT zasp_temporal_single_recovery.ready('-- recovery checksum') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='recovery worker authority required';END IF;
END $body$;
CREATE FUNCTION zasp_temporal_single_recovery.reference(c zasp_temporal_single_recovery.commands) RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $body$
 SELECT jsonb_build_object('start',c.command->'start','command_id',c.command_id,'command_digest',encode(c.command_digest,'hex'))
$body$;
-- Progress authenticates the immutable command, never mutable completion facts.
-- Only checked() can authorize load, delivery, readback or settlement.
CREATE FUNCTION zasp_temporal_single_recovery.authenticated(q jsonb) RETURNS zasp_temporal_single_recovery.commands LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $body$
DECLARE s jsonb:=q->'start';r jsonb:=s->'ref';x zasp_temporal74.run_owners%ROWTYPE;c zasp_temporal_single_recovery.commands%ROWTYPE;ci zasp_temporal74.control_intents%ROWTYPE;verified zasp_temporal74.run_owners%ROWTYPE;b jsonb;proof jsonb;state_value text;history_digest bytea;
BEGIN
 IF octet_length(q::text)>4096 OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['start','command_id','command_digest']) OR NOT zasp_sa_multistep_prior.closed(s,ARRAY['ref','definition_version','input_digest']) OR NOT zasp_sa_multistep_prior.closed(r,ARRAY['organization_id','workspace_id','environment_id','run_id']) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery reference rejected';END IF;
 x:=zasp_temporal74.start_identity(r||jsonb_build_object('definition_version',s->'definition_version','input_digest',s->>'input_digest'));
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||x.organization_id,0));
 SELECT state INTO STRICT state_value FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) FOR UPDATE;
 x:=zasp_temporal_single_recovery.owner(r||jsonb_build_object('definition_version',s->'definition_version','input_digest',s->>'input_digest'));
 SELECT * INTO STRICT c FROM zasp_temporal_single_recovery.commands WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 SELECT definition_digest INTO STRICT history_digest FROM public.zasp_security_agent_definition_versions WHERE(organization_id,workspace_id,environment_id,definition_id,version)=(x.organization_id,x.workspace_id,x.environment_id,x.definition_id,x.definition_version);
 IF q IS DISTINCT FROM zasp_temporal_single_recovery.reference(c) OR c.command_digest IS DISTINCT FROM digest(convert_to(c.command::text,'UTF8'),'sha256') OR c.command_id IS DISTINCT FROM public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'single_test_cleanup_recovery',x.run_id)
 OR NOT zasp_sa_multistep_prior.closed(c.command,ARRAY['format','start','command_id','workflow_id','definition_id','definition_digest','step_id','child_run_id','admitted_parent_version','stop_binding','obligations'])
 OR(c.command->>'format',c.command->>'command_id',c.command->>'workflow_id',c.command->>'definition_id',c.command->>'definition_digest',c.command->>'step_id',c.command->>'child_run_id') IS DISTINCT FROM('single-test-cleanup-command-v1',c.command_id,x.workflow_id,x.definition_id,encode(history_digest,'hex'),x.step_id,x.test_run_id)
 OR c.command->'start' IS DISTINCT FROM zasp_temporal_single_recovery.start_wire(x) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery command changed';END IF;
 RETURN c;
END $body$;
CREATE FUNCTION zasp_temporal_single_recovery.checked(q jsonb) RETURNS zasp_temporal_single_recovery.commands LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $body$
DECLARE x zasp_temporal74.run_owners%ROWTYPE;c zasp_temporal_single_recovery.commands%ROWTYPE;ci zasp_temporal74.control_intents%ROWTYPE;verified zasp_temporal74.run_owners%ROWTYPE;b jsonb;proof jsonb;state_value text;
BEGIN
 c:=zasp_temporal_single_recovery.authenticated(q);
 SELECT * INTO STRICT x FROM zasp_temporal74.run_owners WHERE(organization_id,workspace_id,environment_id,run_id)=(c.organization_id,c.workspace_id,c.environment_id,c.run_id);
 SELECT state INTO STRICT state_value FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 IF c.command->'obligations' IS DISTINCT FROM zasp_temporal_single_recovery.obligations(x) OR state_value NOT IN('cancelled','failed','inconclusive','needs_human','contained','remediated') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery obligations changed';END IF;
 b:=c.command->'stop_binding';
 IF b->>'kind'='cancel' THEN
  IF NOT zasp_sa_multistep_prior.closed(b,ARRAY['kind','receipt_id','audit_id','digest']) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery stop binding rejected';END IF;
 ELSE
  IF NOT zasp_sa_multistep_prior.closed(b-ARRAY['receipt_id','audit_id'],ARRAY['kind','digest']) OR NOT b ?& ARRAY['receipt_id','audit_id'] OR b->'receipt_id' IS DISTINCT FROM 'null'::jsonb OR b->'audit_id' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery stop binding rejected';END IF;
 END IF;
 IF b->>'kind'='cancel' THEN
  SELECT * INTO STRICT ci FROM zasp_temporal74.control_intents WHERE(organization_id,workspace_id,environment_id,run_id,operation,receipt_id,audit_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,'cancelSecurityAgentRun',b->>'receipt_id',b->>'audit_id');verified:=zasp_temporal74.decision_owner(ci);
  IF verified IS DISTINCT FROM x OR b->>'digest' IS DISTINCT FROM encode(ci.response_digest,'hex') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery cancellation changed';END IF;
 ELSE
  IF b->>'kind'='stop' THEN proof:=jsonb_build_object('kind','stop','value',zasp_authorization80_worker.test74_stop_evidence(x.organization_id,x.workspace_id,x.environment_id,x.run_id));
  ELSIF b->>'kind' IN('parent','planning_terminal') THEN proof:=zasp_temporal_single_recovery.proof(x);
  ELSE RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery stop kind rejected';END IF;
  IF proof IS NULL OR b->>'kind' IS DISTINCT FROM proof->>'kind' OR b->>'digest' IS DISTINCT FROM encode(digest(convert_to(proof::text,'UTF8'),'sha256'),'hex') OR b->'receipt_id' IS DISTINCT FROM 'null'::jsonb OR b->'audit_id' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery retained proof changed';END IF;
 END IF;
 RETURN c;
END $body$;
CREATE FUNCTION zasp_temporal_single_recovery.load(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $body$
DECLARE c zasp_temporal_single_recovery.commands%ROWTYPE;
BEGIN PERFORM zasp_temporal_single_recovery.require_worker('zasp_temporal_compensation');c:=zasp_temporal_single_recovery.checked(q);RETURN zasp_temporal_single_recovery.reference(c);END $body$;
CREATE FUNCTION zasp_temporal_single_recovery.pending() RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $body$
DECLARE c zasp_temporal_single_recovery.commands%ROWTYPE;items jsonb:='[]';item jsonb;
BEGIN
 PERFORM zasp_temporal_single_recovery.require_worker('zasp_temporal_executor');
 FOR c IN SELECT command_row.* FROM zasp_temporal_single_recovery.commands command_row JOIN zasp_temporal_single_recovery.deliveries d USING(organization_id,workspace_id,environment_id,run_id,command_id) WHERE d.accepted_at IS NULL ORDER BY d.last_attempt_at NULLS FIRST,command_row.organization_id COLLATE "C",command_row.workspace_id COLLATE "C",command_row.environment_id COLLATE "C",command_row.command_id COLLATE "C" LIMIT 100 LOOP
  item:=zasp_temporal_single_recovery.reference(c);PERFORM zasp_temporal_single_recovery.checked(item);
  IF octet_length((items||jsonb_build_array(item))::text)>65536 THEN EXIT;END IF;items:=items||jsonb_build_array(item);
 END LOOP;RETURN items;
END $body$;
CREATE FUNCTION zasp_temporal_single_recovery.attempt(q jsonb) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $body$
DECLARE c zasp_temporal_single_recovery.commands%ROWTYPE;
BEGIN PERFORM zasp_temporal_single_recovery.require_worker('zasp_temporal_executor');c:=zasp_temporal_single_recovery.checked(q);UPDATE zasp_temporal_single_recovery.deliveries SET last_attempt_at=clock_timestamp() WHERE(organization_id,workspace_id,environment_id,run_id,command_id)=(c.organization_id,c.workspace_id,c.environment_id,c.run_id,c.command_id);IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery delivery missing';END IF;RETURN true;END $body$;
CREATE FUNCTION zasp_temporal_single_recovery.ack(q jsonb) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $body$
DECLARE c zasp_temporal_single_recovery.commands%ROWTYPE;
BEGIN PERFORM zasp_temporal_single_recovery.require_worker('zasp_temporal_executor');c:=zasp_temporal_single_recovery.checked(q);UPDATE zasp_temporal_single_recovery.deliveries SET accepted_at=COALESCE(accepted_at,clock_timestamp()) WHERE(organization_id,workspace_id,environment_id,run_id,command_id)=(c.organization_id,c.workspace_id,c.environment_id,c.run_id,c.command_id);IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery delivery missing';END IF;RETURN true;END $body$;
