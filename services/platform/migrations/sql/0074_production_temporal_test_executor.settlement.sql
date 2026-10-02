-- Child execution and parent verification are distinct durable receipts. No
-- claim, heartbeat, reconciliation lease, or caller-chosen owner is involved.
CREATE TABLE zasp_temporal74.child_receipts(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,step_id text NOT NULL,
 test_run_id text NOT NULL,effect_key text NOT NULL UNIQUE,output_manifest jsonb NOT NULL,output_body bytea NOT NULL CHECK(octet_length(output_body) BETWEEN 1 AND 1048576),
 snapshot jsonb NOT NULL,snapshot_digest bytea NOT NULL CHECK(octet_length(snapshot_digest)=32),response jsonb NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id),FOREIGN KEY(effect_key) REFERENCES zasp_temporal74.effects(effect_key));
CREATE TABLE zasp_temporal74.parent_receipts(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,step_id text NOT NULL,
 effect_key text NOT NULL UNIQUE,snapshot jsonb NOT NULL,proof_body bytea NOT NULL CHECK(octet_length(proof_body) BETWEEN 1 AND 65536),receipt jsonb NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id),FOREIGN KEY(effect_key) REFERENCES zasp_temporal74.effects(effect_key));
DO $tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['child_receipts','parent_receipts'] LOOP
  EXECUTE format('ALTER TABLE zasp_temporal74.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_temporal74.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_temporal74.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_temporal74.%I USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',n);
  EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal74.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n);
 END LOOP;
END $tables$;

-- Evidence reads choose exactly one journal from persisted ownership. This is
-- not a union of permissions, nor an adapter dispatch API.
CREATE FUNCTION zasp_temporal74.observations(o text,w text,e text,c text)
RETURNS TABLE(organization_id text,workspace_id text,environment_id text,test_run_id text,attempt integer,input_digest bytea,category text,state text,http_status integer,response_digest bytea,protected boolean,credential_version_digest bytea,target_resolution jsonb)
LANGUAGE plpgsql STABLE SET search_path TO pg_catalog,public AS $observations$
DECLARE r text;
BEGIN
 SELECT l.run_id INTO r FROM public.zasp_security_agent_test_links l WHERE (l.organization_id,l.workspace_id,l.environment_id,l.test_run_id)=(o,w,e,c);
 IF r IS NOT NULL AND zasp_temporal74.is_owned(o,w,e,r) THEN
  RETURN QUERY SELECT j.organization_id,j.workspace_id,j.environment_id,j.test_run_id,j.attempt,j.input_digest,j.category,j.state,j.http_status,j.response_digest,j.protected,j.credential_version_digest,j.target_resolution FROM zasp_temporal74.invocations j WHERE (j.organization_id,j.workspace_id,j.environment_id,j.test_run_id)=(o,w,e,c);
 ELSIF r IS NOT NULL AND zasp_temporal66.is_temporal(o,w,e,r) THEN
  RETURN QUERY SELECT j.organization_id,j.workspace_id,j.environment_id,j.test_run_id,j.attempt,j.input_digest,j.category,j.state,j.http_status,j.response_digest,j.protected,j.credential_version_digest,j.target_resolution FROM zasp_temporal68.invocations j WHERE (j.organization_id,j.workspace_id,j.environment_id,j.test_run_id)=(o,w,e,c);
 ELSE
  RETURN QUERY SELECT j.organization_id,j.workspace_id,j.environment_id,j.test_run_id,j.attempt,j.input_digest,j.category,j.state,j.http_status,j.response_digest,j.protected,j.credential_version_digest,j.target_resolution FROM public.zasp_security_agent_test_invocations j WHERE (j.organization_id,j.workspace_id,j.environment_id,j.test_run_id)=(o,w,e,c);
 END IF;
END $observations$;

INSERT INTO zasp_temporal74.predecessor_functions SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc WHERE oid=ANY(ARRAY[
 'zasp_temporal68.test_validate_output(text,text,text,text,text,jsonb,bytea,jsonb,bytea)'::regprocedure,
 'zasp_temporal68.test_snapshot(text,text,text,text,text,jsonb)'::regprocedure,
 'public.zasp_production_security_agent_existing_tests_evidence_snapshot(text,text,text,text,text)'::regprocedure]);
DO $domain$ DECLARE d text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_temporal74.predecessor_functions WHERE signature='zasp_temporal68.test_validate_output(text,text,text,text,text,jsonb,bytea,jsonb,bytea)';
 EXECUTE replace(d,'zasp_temporal68.','zasp_temporal74.');
 SELECT definition INTO STRICT d FROM zasp_temporal74.predecessor_functions WHERE signature='zasp_temporal68.test_snapshot(text,text,text,text,text,jsonb)';
 EXECUTE replace(d,'zasp_temporal68.','zasp_temporal74.');
 SELECT definition INTO STRICT d FROM zasp_temporal74.predecessor_functions WHERE signature='zasp_production_security_agent_existing_tests_evidence_snapshot(text,text,text,text,text)';
 d:=replace(d,'FUNCTION public.zasp_production_security_agent_existing_tests_evidence_snapshot(','FUNCTION zasp_temporal74.evidence_snapshot(');
 IF (length(d)-length(replace(d,'public.zasp_security_agent_test_invocations j','')))/length('public.zasp_security_agent_test_invocations j')<>3 THEN RAISE EXCEPTION 'single-test snapshot predecessor changed';END IF;
 EXECUTE replace(d,'public.zasp_security_agent_test_invocations j','zasp_temporal74.observations(o,w,e,run_row.run_id) j');
END $domain$;

CREATE FUNCTION zasp_temporal74.child_evidence(o text,w text,e text,r text,s text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $evidence$
DECLARE t zasp_temporal74.child_receipts%ROWTYPE;i zasp_temporal74.test_inputs%ROWTYPE;
BEGIN
 SELECT * INTO t FROM zasp_temporal74.child_receipts WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 SELECT * INTO i FROM zasp_temporal74.test_inputs WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 IF t.run_id IS NULL OR i.test_run_id IS DISTINCT FROM t.test_run_id OR t.effect_key IS DISTINCT FROM zasp_temporal74.effect_identity(o,w,e,r,s,1)
  OR t.snapshot IS DISTINCT FROM zasp_temporal74.test_snapshot(o,w,e,r,s,t.output_manifest)
  OR t.snapshot_digest IS DISTINCT FROM digest(convert_to(t.snapshot::text,'UTF8'),'sha256')
  OR t.snapshot->'child'->>'state' IS DISTINCT FROM 'complete' OR t.snapshot->'child'->'attempt' IS DISTINCT FROM '1'::jsonb
  OR t.response IS DISTINCT FROM jsonb_build_object('test_run_id',t.test_run_id,'state','complete','attempt',1,'effect_key',t.effect_key,'output_manifest',t.output_manifest,'snapshot_digest',encode(t.snapshot_digest,'hex'))
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test child receipt changed';END IF;
 PERFORM zasp_temporal74.test_validate_output(o,w,e,r,s,i.manifest,i.body,t.output_manifest,t.output_body);
 RETURN t.response;
END $evidence$;

CREATE FUNCTION zasp_temporal74.parent_evidence(o text,w text,e text,r text,s text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $evidence$
DECLARE t zasp_temporal74.parent_receipts%ROWTYPE;proof jsonb;proof_hash bytea;current_snapshot jsonb;unknown_value boolean;
BEGIN
 SELECT * INTO t FROM zasp_temporal74.parent_receipts WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 IF t.run_id IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test parent receipt absent';END IF;
 PERFORM zasp_temporal74.child_evidence(o,w,e,r,s);
 current_snapshot:=zasp_temporal74.evidence_snapshot(o,w,e,r,s);proof:=zasp_sa_multistep_prior.test_json(t.proof_body,65536);proof_hash:=digest(t.proof_body,'sha256');
 unknown_value:=COALESCE((current_snapshot->'before'->>'outcome_unknown')::boolean,false) OR COALESCE((current_snapshot->'after'->>'outcome_unknown')::boolean,false);
 PERFORM public.zasp_production_security_agent_existing_tests_validate_proof(current_snapshot,proof,unknown_value);
 IF t.effect_key IS DISTINCT FROM zasp_temporal74.effect_identity(o,w,e,r,s,1) OR current_snapshot IS DISTINCT FROM t.snapshot
  OR t.receipt->>'proof_sha256' IS DISTINCT FROM encode(proof_hash,'hex') OR t.receipt->>'outcome' IS DISTINCT FROM proof->>'outcome' OR t.receipt->>'reason' IS DISTINCT FROM proof->>'reason'
  OR NOT (CASE WHEN public.zasp_red_team_principal_ready('zasp_red_team_worker') THEN zasp_temporal74.delivery_parent_matches(zasp_temporal74.delivery_message(o,w,e,r)) ELSE EXISTS(SELECT 1 FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id,state,last_error_code)=(o,w,e,r,t.receipt->>'state',t.receipt->>'reason') AND completed_at IS NOT NULL AND lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL) END)
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id,state)=(o,w,e,r,s,t.receipt->>'step_state'))
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,state,result_digest,outcome_id)=(o,w,e,r,s,t.receipt->>'effect_state',proof_hash,t.receipt->>'invocation_id') AND lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)
  OR NOT EXISTS(SELECT 1 FROM zasp_temporal74.effects WHERE effect_key=t.effect_key AND state='verified' AND completed_at IS NOT NULL)
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id,reconcile_state,reconcile_version)=(o,w,e,r,s,'settled',2) AND reconcile_settlement=jsonb_build_object('effect_key',t.effect_key,'snapshot',t.snapshot,'proof_hex',encode(t.proof_body,'hex'),'proof',proof,'receipt',t.receipt) AND reconcile_worker IS NULL AND reconcile_token IS NULL AND reconcile_expires_at IS NULL)
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,step_id,event_kind,event_digest)=(o,w,e,r,s,'test_reconciled',proof_hash) AND body=t.receipt AND audit_id=public.zasp_discovery_canonical_id(o,w,e,'security_agent_test_settlement',r||chr(31)||s) AND correlation_id=audit_id)
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test parent receipt changed';END IF;
 RETURN t.receipt;
END $evidence$;

CREATE FUNCTION zasp_temporal74.test_settle(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $settle$
DECLARE o text:=q->>'organization_id';w text:=q->>'workspace_id';e text:=q->>'environment_id';r text:=q->>'run_id';s text:=q->>'step_id';op text:=q->>'operation';p jsonb:=q->'payload';intent jsonb;body bytea;summary jsonb;snapshot_value jsonb;snapshot_hash bytea;proof jsonb;proof_hash bytea;receipt jsonb;key_value text;audit_id text;invocation_id text;completed_value timestamptz;outcome text;parent_state text;step_state text;effect_state text;unknown_value boolean;
 rr public.zasp_security_agent_runs%ROWTYPE;c public.zasp_red_team_runs%ROWTYPE;i zasp_temporal74.test_inputs%ROWTYPE;t zasp_temporal74.child_receipts%ROWTYPE;pr zasp_temporal74.parent_receipts%ROWTYPE;
BEGIN
 IF NOT zasp_temporal68.principal_ready('zasp_temporal_executor') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test settlement principal rejected';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','step_id','generation','operation','payload']) OR octet_length(q::text)>1600000 OR NOT COALESCE(op IN('child','snapshot','complete'),false)
  OR NOT zasp_sa_multistep_prior.closed(p,CASE op WHEN 'child' THEN ARRAY['output_manifest','output_body'] WHEN 'complete' THEN ARRAY['snapshot','proof_body'] ELSE ARRAY[]::text[] END)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='single-test settlement request rejected';END IF;
 intent:=zasp_temporal74.effect(q||jsonb_build_object('operation','read','payload','{}'::jsonb));
 SELECT * INTO STRICT rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF NOT zasp_temporal74.test_intent_valid(o,w,e,r,s,to_jsonb(rr)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test settlement identity rejected';END IF;
 SELECT * INTO STRICT i FROM zasp_temporal74.test_inputs WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 SELECT * INTO STRICT c FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,i.test_run_id) FOR UPDATE NOWAIT;
 SELECT * INTO t FROM zasp_temporal74.child_receipts WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 IF op='child' THEN
  IF jsonb_typeof(p->'output_body') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='single-test child artifact absent';END IF;
  body:=decode(p->>'output_body','base64');
  IF t.run_id IS NOT NULL THEN
   IF (t.output_manifest,t.output_body) IS DISTINCT FROM(p->'output_manifest',body) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test child replay changed';END IF;
   RETURN zasp_temporal74.child_evidence(o,w,e,r,s);
  END IF;
  IF intent->>'state' NOT IN('started','unknown') OR c.state<>'queued' OR c.cancel_requested OR c.attempt<>0 OR c.worker_id IS NOT NULL OR c.lease_token IS NOT NULL OR c.lease_expires_at IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test child completion unavailable';END IF;
  summary:=zasp_temporal74.test_validate_output(o,w,e,r,s,i.manifest,i.body,p->'output_manifest',body);
  completed_value:=clock_timestamp();key_value:='organizations/'||o||'/workspaces/'||w||'/environments/'||e||'/artifacts/'||c.run_id;
  INSERT INTO public.zasp_red_team_attempts(organization_id,workspace_id,environment_id,run_id,attempt,input_digest,verdict,objective,behavior,error_code,evidence,evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size,input_artifact,completed_at)
  VALUES(o,w,e,c.run_id,1,c.input_digest,summary->>'verdict',summary->>'objective',summary->>'behavior',NULL,summary->'evidence',p->'output_manifest'->>'reference',key_value,p->'output_manifest'->>'version_id',digest(body,'sha256'),octet_length(body),i.manifest,completed_value);
  UPDATE public.zasp_red_team_runs SET state='complete',attempt=1,version=version+1,verdict=summary->>'verdict',evidence_reference=p->'output_manifest'->>'reference',evidence_key=key_value,evidence_version_id=p->'output_manifest'->>'version_id',evidence_checksum=digest(body,'sha256'),evidence_size=octet_length(body),started_at=(intent->>'started_at')::timestamptz,completed_at=completed_value,updated_at=completed_value WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,c.run_id);
  snapshot_value:=zasp_temporal74.test_snapshot(o,w,e,r,s,p->'output_manifest');snapshot_hash:=digest(convert_to(snapshot_value::text,'UTF8'),'sha256');
  receipt:=jsonb_build_object('test_run_id',c.run_id,'state','complete','attempt',1,'effect_key',intent->>'effect_key','output_manifest',p->'output_manifest','snapshot_digest',encode(snapshot_hash,'hex'));
  INSERT INTO zasp_temporal74.child_receipts VALUES(o,w,e,r,s,c.run_id,intent->>'effect_key',p->'output_manifest',body,snapshot_value,snapshot_hash,receipt);
  RETURN zasp_temporal74.child_evidence(o,w,e,r,s);
 END IF;
 PERFORM zasp_temporal74.child_evidence(o,w,e,r,s);
 -- Lock pinned historical evidence without waiting in inverse parent order.
 PERFORM 1 FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id)=(o,w,e) AND run_id=(SELECT baseline->>'run_id' FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s)) FOR SHARE NOWAIT;
 snapshot_value:=zasp_temporal74.evidence_snapshot(o,w,e,r,s);
 IF op='snapshot' THEN RETURN snapshot_value;END IF;
 IF jsonb_typeof(p->'proof_body') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='single-test proof absent';END IF;
 body:=decode(p->>'proof_body','base64');proof:=zasp_sa_multistep_prior.test_json(body,65536);proof_hash:=digest(body,'sha256');
 SELECT * INTO pr FROM zasp_temporal74.parent_receipts WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 IF pr.run_id IS NOT NULL THEN
  IF (pr.snapshot,pr.proof_body) IS DISTINCT FROM(p->'snapshot',body) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test parent replay changed';END IF;
  RETURN zasp_temporal74.parent_evidence(o,w,e,r,s);
 END IF;
 IF snapshot_value IS DISTINCT FROM p->'snapshot' OR rr.state NOT IN('running','verifying','cancelled','failed','inconclusive','needs_human') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test comparison snapshot changed';END IF;
 unknown_value:=COALESCE((snapshot_value->'before'->>'outcome_unknown')::boolean,false) OR COALESCE((snapshot_value->'after'->>'outcome_unknown')::boolean,false);
 PERFORM public.zasp_production_security_agent_existing_tests_validate_proof(snapshot_value,proof,unknown_value);
 outcome:=proof->>'outcome';parent_state:=CASE WHEN rr.state IN('cancelled','failed','inconclusive','needs_human') THEN rr.state ELSE outcome END;
 step_state:=CASE WHEN parent_state IN('remediated','needs_human') THEN 'succeeded' ELSE parent_state END;
 effect_state:=CASE WHEN unknown_value THEN 'unknown_outcome' WHEN parent_state='remediated' THEN 'verified' WHEN parent_state IN('failed','cancelled') THEN 'known_failure' ELSE 'succeeded' END;
 invocation_id:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_temporal_test_invocation',intent->>'effect_key');
 receipt:=jsonb_build_object('run_id',r,'step_id',s,'state',parent_state,'step_state',step_state,'effect_state',effect_state,'outcome',outcome,'reason',proof->>'reason','proof_sha256',encode(proof_hash,'hex'),'reconcile_version',2,'effect_key',intent->>'effect_key','invocation_id',invocation_id);
 UPDATE public.zasp_security_agent_effects SET state=effect_state,result_digest=proof_hash,outcome_id=invocation_id,version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 UPDATE public.zasp_security_agent_steps SET state=step_state,version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 UPDATE public.zasp_security_agent_runs SET state=parent_state,last_error_code=proof->>'reason',completed_at=COALESCE(completed_at,clock_timestamp()),version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 UPDATE zasp_temporal74.effects SET state='verified',completed_at=clock_timestamp() WHERE effect_key=intent->>'effect_key';
 UPDATE public.zasp_security_agent_test_links SET reconcile_state='settled',reconcile_version=2,reconcile_settlement=jsonb_build_object('effect_key',intent->>'effect_key','snapshot',snapshot_value,'proof_hex',encode(body,'hex'),'proof',proof,'receipt',receipt) WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 INSERT INTO zasp_temporal74.parent_receipts VALUES(o,w,e,r,s,intent->>'effect_key',snapshot_value,body,receipt);
 audit_id:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_test_settlement',r||chr(31)||s);
 INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,audit_id,audit_id,r,s,session_user,'test_reconciled',proof_hash,receipt);
 RETURN zasp_temporal74.parent_evidence(o,w,e,r,s);
END $settle$;
