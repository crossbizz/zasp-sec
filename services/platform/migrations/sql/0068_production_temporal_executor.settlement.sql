-- Aggregate evidence is separate from the adapter's one-send category journal.
CREATE TABLE zasp_temporal68.test_settlements(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,step_id text NOT NULL,test_run_id text NOT NULL,effect_key text NOT NULL,
 output_manifest jsonb NOT NULL,output_body bytea NOT NULL CHECK(octet_length(output_body) BETWEEN 1 AND 1048576),
 snapshot jsonb NOT NULL CHECK(octet_length(snapshot::text)<=262144),snapshot_digest bytea NOT NULL CHECK(octet_length(snapshot_digest)=32),
 response jsonb NOT NULL CHECK(octet_length(response::text)<=16384),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id),UNIQUE(effect_key),
 FOREIGN KEY(effect_key) REFERENCES zasp_temporal68.effects(effect_key),
 FOREIGN KEY(organization_id,workspace_id,environment_id,test_run_id) REFERENCES zasp_temporal68.test_inputs(organization_id,workspace_id,environment_id,test_run_id));
ALTER TABLE zasp_temporal68.test_settlements OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_temporal68.test_settlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_temporal68.test_settlements FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_temporal68.test_settlements USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal68.test_settlements FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();

-- Preserve the entire native engine/artifact validator. The new relation has
-- fixed attempt1 and carries the effect identity instead of a lease digest.
-- Retained replay compares pinned observations; first settlement separately
-- checks the current target and approvals before accepting the aggregate.
DO $validator$ DECLARE d text;needle text;BEGIN
 d:=pg_get_functiondef('zasp_sa_multistep_prior.test_validate_output(text,text,text,text,text,jsonb,bytea,jsonb,bytea)'::regprocedure);
 d:=replace(d,'FUNCTION zasp_sa_multistep_prior.test_validate_output(', 'FUNCTION zasp_temporal68.test_validate_output(');
 d:=replace(d,'public.zasp_security_agent_test_invocations','zasp_temporal68.invocations');
 needle:='target_value:=public.zasp_production_security_agent_existing_tests_invocation_target(o,w,e,link.target_id,link.target_kind,link.test_definition_id,link.test_definition_version);';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'executor settlement target predecessor rejected';END IF;
 d:=replace(d,needle,'SELECT snapshot->''targets''->''resolution'' INTO STRICT target_value FROM zasp_temporal68.effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,generation)=(o,w,e,r,s,1);');
 needle:='j.attempt<>child.attempt';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'executor settlement attempt predecessor rejected';END IF;
 EXECUTE replace(d,needle,'j.attempt<>1 OR j.effect_key IS DISTINCT FROM zasp_temporal68.effect_identity(o,w,e,r,s,1)');
END $validator$;

CREATE FUNCTION zasp_temporal68.test_snapshot(o text,w text,e text,r text,s text,output_manifest jsonb) RETURNS jsonb LANGUAGE sql VOLATILE SET search_path TO pg_catalog,public AS $snapshot$
 SELECT jsonb_build_object('intent',f.snapshot,'effect_key',f.effect_key,'generation',f.generation,'child',to_jsonb(c),
  'link',to_jsonb(l)-ARRAY['reconcile_state','reconcile_version','reconcile_worker','reconcile_token','reconcile_expires_at','reconcile_settlement'],
  'input_artifact',i.manifest,'output_artifact',output_manifest,
  'observations',(SELECT jsonb_agg(to_jsonb(x) ORDER BY category) FROM zasp_temporal68.invocations x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.test_run_id)=(o,w,e,c.run_id)),
  'attempt',(SELECT to_jsonb(x) FROM public.zasp_red_team_attempts x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.attempt)=(o,w,e,c.run_id,1)))
 FROM zasp_temporal68.effects f JOIN zasp_temporal68.test_inputs i USING(organization_id,workspace_id,environment_id,run_id,step_id)
 JOIN public.zasp_security_agent_test_links l USING(organization_id,workspace_id,environment_id,run_id,step_id,test_run_id)
 JOIN public.zasp_red_team_runs c ON(c.organization_id,c.workspace_id,c.environment_id,c.run_id)=(o,w,e,i.test_run_id)
 WHERE(f.organization_id,f.workspace_id,f.environment_id,f.run_id,f.step_id,f.generation)=(o,w,e,r,s,1)
$snapshot$;

CREATE FUNCTION zasp_temporal68.test_evidence(o text,w text,e text,r text,s text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $evidence$
DECLARE t zasp_temporal68.test_settlements%ROWTYPE;f zasp_temporal68.effects%ROWTYPE;proof bytea;result_hash bytea;
BEGIN
 SELECT * INTO t FROM zasp_temporal68.test_settlements WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor test terminal evidence absent';END IF;
 SELECT * INTO f FROM zasp_temporal68.effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,generation)=(o,w,e,r,s,1);
 proof:=digest(t.output_body,'sha256');result_hash:=digest(f.input_digest||t.snapshot_digest||proof,'sha256');
 IF NOT zasp_temporal68.test_intent_valid(o,w,e,r,s) OR t.effect_key IS DISTINCT FROM zasp_temporal68.effect_identity(o,w,e,r,s,1) OR f.effect_key IS DISTINCT FROM t.effect_key OR f.state IS DISTINCT FROM 'verified' OR f.completed_at IS NULL
  OR f.snapshot_digest IS DISTINCT FROM digest(convert_to(f.snapshot::text,'UTF8'),'sha256')
  OR t.snapshot IS DISTINCT FROM zasp_temporal68.test_snapshot(o,w,e,r,s,t.output_manifest) OR t.snapshot_digest IS DISTINCT FROM digest(convert_to(t.snapshot::text,'UTF8'),'sha256')
  OR t.response->>'result_digest' IS DISTINCT FROM 'sha256:'||encode(result_hash,'hex') OR t.response->>'effect_key' IS DISTINCT FROM t.effect_key
  OR t.response->'receipt'->>'snapshot_digest' IS DISTINCT FROM encode(t.snapshot_digest,'hex') OR t.response->'receipt'->>'proof_digest' IS DISTINCT FROM encode(proof,'hex')
  OR t.output_manifest->>'sha256' IS DISTINCT FROM encode(proof,'hex') OR t.output_manifest->'size_bytes' IS DISTINCT FROM to_jsonb(octet_length(t.output_body))
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id,state,action_key,input_digest)=(o,w,e,r,s,'succeeded','run_test',f.input_digest))
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,state,input_digest,result_digest,outcome_id)=(o,w,e,r,s,'verified',f.input_digest,result_hash,t.response->'receipt'->>'invocation_id') AND lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id,test_run_id,reconcile_state,reconcile_version)=(o,w,e,r,s,t.test_run_id,'settled',2) AND reconcile_settlement=t.response AND reconcile_worker IS NULL AND reconcile_token IS NULL AND reconcile_expires_at IS NULL)
  OR NOT EXISTS(SELECT 1 FROM public.zasp_sa_multistep_receipts WHERE (organization_id,workspace_id,environment_id,run_id,step_id,plan_hash,input_digest,result_digest,receipt_kind,receipt_version)=(o,w,e,r,s,f.plan_hash,f.input_digest,result_hash,'existing_test_settled.v1',1) AND body=t.response->'receipt')
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,step_id,event_kind,event_digest)=(o,w,e,r,s,'temporal_test_settled',result_hash) AND body=t.response AND audit_id=public.zasp_discovery_canonical_id(o,w,e,'security_agent_temporal_test_settlement',t.effect_key) AND correlation_id=audit_id)
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor test terminal evidence changed';END IF;
 RETURN jsonb_build_object('kind','settled','effect_key',t.effect_key,'snapshot',t.snapshot,'snapshot_digest',encode(t.snapshot_digest,'hex'),'response',t.response);
END $evidence$;

CREATE FUNCTION zasp_temporal68.test_settle(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $settle$
DECLARE o text;w text;e text;r text;s text;p jsonb;intent jsonb;body bytea;summary jsonb;snapshot_value jsonb;snapshot_hash bytea;result_hash bytea;receipt jsonb;result_value jsonb;outcome text;parent_state text;invocation_id text;audit_id text;key_value text;
 i zasp_temporal68.test_inputs%ROWTYPE;t zasp_temporal68.test_settlements%ROWTYPE;child public.zasp_red_team_runs%ROWTYPE;rr public.zasp_security_agent_runs%ROWTYPE;
BEGIN
 IF NOT zasp_temporal68.principal_ready('zasp_temporal_executor') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='executor settlement principal rejected';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','step_id','generation','operation','payload']) OR octet_length(q::text)>1500000 OR q->>'operation' IS DISTINCT FROM 'complete'
  OR NOT zasp_sa_multistep_prior.closed(q->'payload',ARRAY['output_manifest','output_body']) OR jsonb_typeof(q->'payload'->'output_body') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor settlement request rejected';END IF;
 o:=q->>'organization_id';w:=q->>'workspace_id';e:=q->>'environment_id';r:=q->>'run_id';s:=q->>'step_id';p:=q->'payload';body:=decode(p->>'output_body','base64');
 intent:=zasp_temporal68.effect(q||jsonb_build_object('operation','read','payload','{}'::jsonb));
 IF intent->>'action_key' IS DISTINCT FROM 'run_test' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor settlement action rejected';END IF;
 SELECT * INTO t FROM zasp_temporal68.test_settlements WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 IF FOUND THEN
  IF (t.output_manifest,t.output_body) IS DISTINCT FROM(p->'output_manifest',body) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor settlement replay changed';END IF;
  PERFORM zasp_temporal68.test_evidence(o,w,e,r,s);RETURN t.response;
 END IF;
 PERFORM zasp_sa_multistep_prior.test_lock(o,w,e,r);PERFORM zasp_sa_multistep_prior.test_current(o,w,e,r,s);
 SELECT * INTO STRICT i FROM zasp_temporal68.test_inputs WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 SELECT * INTO STRICT child FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,i.test_run_id) FOR UPDATE NOWAIT;
 SELECT * INTO STRICT rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF intent->>'state' NOT IN('started','unknown') OR child.state<>'queued' OR child.cancel_requested OR child.attempt<>0 OR child.worker_id IS NOT NULL OR child.lease_token IS NOT NULL OR child.lease_expires_at IS NOT NULL
  OR intent->'snapshot'->'targets'->>'test_run_id' IS DISTINCT FROM child.run_id
  OR intent->'snapshot'->'targets'->'resolution' IS DISTINCT FROM (SELECT zasp_temporal68.test_target(o,w,e,target_id,target_kind,test_definition_id,test_definition_version) FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor settlement association changed';END IF;
 summary:=zasp_temporal68.test_validate_output(o,w,e,r,s,i.manifest,i.body,p->'output_manifest',body);
 key_value:='organizations/'||o||'/workspaces/'||w||'/environments/'||e||'/artifacts/'||child.run_id;
 INSERT INTO public.zasp_red_team_attempts(organization_id,workspace_id,environment_id,run_id,attempt,input_digest,verdict,objective,behavior,error_code,evidence,evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size)
 VALUES(o,w,e,child.run_id,1,child.input_digest,summary->>'verdict',summary->>'objective',summary->>'behavior',NULL,summary->'evidence',p->'output_manifest'->>'reference',key_value,p->'output_manifest'->>'version_id',digest(body,'sha256'),octet_length(body));
 UPDATE public.zasp_red_team_runs SET state='complete',attempt=1,version=version+1,verdict=summary->>'verdict',evidence_reference=p->'output_manifest'->>'reference',evidence_key=key_value,evidence_version_id=p->'output_manifest'->>'version_id',evidence_checksum=digest(body,'sha256'),evidence_size=octet_length(body),started_at=(intent->>'started_at')::timestamptz,completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,child.run_id);
 snapshot_value:=zasp_temporal68.test_snapshot(o,w,e,r,s,p->'output_manifest');snapshot_hash:=digest(convert_to(snapshot_value::text,'UTF8'),'sha256');result_hash:=digest(decode(intent->'snapshot'->>'input_digest','hex')||snapshot_hash||digest(body,'sha256'),'sha256');
 outcome:=CASE WHEN summary->>'verdict'='pass' THEN 'not_reproduced' ELSE 'reproduced' END;parent_state:=CASE WHEN outcome='not_reproduced' THEN 'contained' ELSE 'needs_human' END;
 invocation_id:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_temporal_test_invocation',intent->>'effect_key');
 receipt:=jsonb_build_object('invocation_id',invocation_id,'snapshot_digest',encode(snapshot_hash,'hex'),'proof_digest',encode(digest(body,'sha256'),'hex'),'settlement_generation',1,'outcome',outcome);
 result_value:=jsonb_build_object('effect_key',intent->>'effect_key','generation',1,'test_run_id',child.run_id,'run_state',parent_state,'outcome',outcome,'result_digest','sha256:'||encode(result_hash,'hex'),'input_digest','sha256:'||(intent->'snapshot'->>'input_digest'),'plan_hash','sha256:'||encode(rr.plan_hash,'hex'),'receipt',receipt,'input_artifact',i.manifest,'output_artifact',p->'output_manifest');
 UPDATE zasp_temporal68.effects SET state='verified',completed_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id,generation)=(o,w,e,r,s,1);
 UPDATE public.zasp_security_agent_effects SET state='verified',version=version+1,result_digest=result_hash,outcome_id=invocation_id,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 UPDATE public.zasp_security_agent_steps SET state='succeeded',version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 UPDATE public.zasp_security_agent_runs SET state=parent_state,version=version+1,completed_at=clock_timestamp(),updated_at=clock_timestamp(),last_error_code=CASE WHEN parent_state='needs_human' THEN 'test_condition_persists' END WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 UPDATE public.zasp_security_agent_test_links SET reconcile_state='settled',reconcile_version=2,reconcile_settlement=result_value WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 INSERT INTO public.zasp_sa_multistep_receipts(organization_id,workspace_id,environment_id,run_id,plan_hash,step_id,action_key,input_digest,result_digest,receipt_kind,receipt_version,body) VALUES(o,w,e,r,rr.plan_hash,s,'run_test',decode(intent->'snapshot'->>'input_digest','hex'),result_hash,'existing_test_settled.v1',1,receipt);
 INSERT INTO zasp_temporal68.test_settlements(organization_id,workspace_id,environment_id,run_id,step_id,test_run_id,effect_key,output_manifest,output_body,snapshot,snapshot_digest,response) VALUES(o,w,e,r,s,child.run_id,intent->>'effect_key',p->'output_manifest',body,snapshot_value,snapshot_hash,result_value);
 audit_id:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_temporal_test_settlement',intent->>'effect_key');
 INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,audit_id,audit_id,r,s,session_user,'temporal_test_settled',result_hash,result_value);
 PERFORM zasp_temporal68.current_plan(o,w,e,r,false);PERFORM zasp_temporal68.test_evidence(o,w,e,r,s);
 IF NOT zasp_temporal68.current_ready() OR NOT zasp_temporal68.principal_ready('zasp_temporal_executor') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='executor settlement authority changed';END IF;
 RETURN result_value;
END $settle$;

CREATE TABLE zasp_temporal68.test_stops(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,step_id text NOT NULL,effect_key text NOT NULL,
 snapshot jsonb NOT NULL CHECK(octet_length(snapshot::text)<=262144),snapshot_digest bytea NOT NULL CHECK(octet_length(snapshot_digest)=32),response jsonb NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id),UNIQUE(effect_key),FOREIGN KEY(effect_key) REFERENCES zasp_temporal68.effects(effect_key));
ALTER TABLE zasp_temporal68.test_stops OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_temporal68.test_stops ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_temporal68.test_stops FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_temporal68.test_stops USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal68.test_stops FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();

CREATE FUNCTION zasp_temporal68.test_stop_snapshot(o text,w text,e text,r text,s text) RETURNS jsonb LANGUAGE sql VOLATILE SET search_path TO pg_catalog,public AS $snapshot$
 SELECT jsonb_build_object('intent',f.snapshot,'effect_key',f.effect_key,'generation',f.generation,'child',to_jsonb(c),'link',to_jsonb(l),'input',to_jsonb(i),
  'observations',COALESCE((SELECT jsonb_agg(to_jsonb(x) ORDER BY category) FROM zasp_temporal68.invocations x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.test_run_id)=(o,w,e,c.run_id)),'[]'::jsonb))
 FROM zasp_temporal68.effects f JOIN public.zasp_security_agent_test_links l USING(organization_id,workspace_id,environment_id,run_id,step_id)
 JOIN public.zasp_red_team_runs c ON(c.organization_id,c.workspace_id,c.environment_id,c.run_id)=(o,w,e,l.test_run_id)
 LEFT JOIN zasp_temporal68.test_inputs i ON(i.organization_id,i.workspace_id,i.environment_id,i.run_id,i.step_id,i.test_run_id)=(o,w,e,r,s,l.test_run_id)
 WHERE(f.organization_id,f.workspace_id,f.environment_id,f.run_id,f.step_id,f.generation)=(o,w,e,r,s,1)
$snapshot$;

-- The original unknown snapshot stays immutable. A late completion may fill
-- only an already-started category with the identical scope/request binding.
CREATE FUNCTION zasp_temporal68.test_stop_evidence(o text,w text,e text,r text,s text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $evidence$
DECLARE t zasp_temporal68.test_stops%ROWTYPE;current_value jsonb;item jsonb;observed jsonb;mutable text[]:=ARRAY['state','completed_at','http_status','response_digest','protected','credential_version_digest'];
BEGIN
 SELECT * INTO t FROM zasp_temporal68.test_stops WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor stopped evidence absent';END IF;
 current_value:=zasp_temporal68.test_stop_snapshot(o,w,e,r,s);
 IF NOT zasp_temporal68.test_intent_valid(o,w,e,r,s) OR t.snapshot_digest IS DISTINCT FROM digest(convert_to(t.snapshot::text,'UTF8'),'sha256') OR current_value-'observations' IS DISTINCT FROM t.snapshot-'observations'
  OR jsonb_array_length(current_value->'observations') IS DISTINCT FROM jsonb_array_length(t.snapshot->'observations')
  OR NOT EXISTS(SELECT 1 FROM zasp_temporal68.effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,generation,effect_key,state)=(o,w,e,r,s,1,t.effect_key,'stopped') AND completed_at IS NOT NULL)
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id,state)=(o,w,e,r,s,'inconclusive'))
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,state)=(o,w,e,r,s,'unknown_outcome') AND result_digest IS NULL AND outcome_id IS NULL AND lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)
  OR EXISTS(SELECT 1 FROM public.zasp_sa_multistep_receipts WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s))
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,step_id,event_kind)=(o,w,e,r,s,'temporal_test_stopped') AND audit_id=public.zasp_discovery_canonical_id(o,w,e,'security_agent_temporal_test_stop',t.effect_key) AND correlation_id=audit_id AND body=jsonb_build_object('snapshot',t.snapshot,'response',t.response) AND event_digest=digest(convert_to(body::text,'UTF8'),'sha256'))
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor stopped evidence changed';END IF;
 FOR item IN SELECT value FROM jsonb_array_elements(t.snapshot->'observations') LOOP
  SELECT value INTO observed FROM jsonb_array_elements(current_value->'observations') WHERE value->>'category'=item->>'category';
  IF observed IS NULL OR item-mutable IS DISTINCT FROM observed-mutable OR item->>'state'='completed' AND item IS DISTINCT FROM observed
   OR observed->>'state' NOT IN('started','completed') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor late observation association changed';END IF;
 END LOOP;
 RETURN jsonb_build_object('kind','stopped','effect_key',t.effect_key,'snapshot',t.snapshot,'snapshot_digest',encode(t.snapshot_digest,'hex'),'response',t.response);
END $evidence$;

CREATE FUNCTION zasp_temporal68.test_terminal_evidence(o text,w text,e text,r text,s text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $evidence$
BEGIN
 IF EXISTS(SELECT 1 FROM zasp_temporal68.test_settlements WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s)) THEN RETURN zasp_temporal68.test_evidence(o,w,e,r,s);END IF;
 RETURN zasp_temporal68.test_stop_evidence(o,w,e,r,s);
END $evidence$;

CREATE FUNCTION zasp_temporal68.test_stop(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $stop$
DECLARE o text;w text;e text;r text;s text;intent jsonb;snapshot_value jsonb;result_value jsonb;audit_id text;uncertain boolean;child public.zasp_red_team_runs%ROWTYPE;t zasp_temporal68.test_stops%ROWTYPE;
BEGIN
 IF NOT(zasp_temporal68.principal_ready('zasp_temporal_executor') OR zasp_temporal68.principal_ready('zasp_temporal_compensation')) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='executor stop principal rejected';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','step_id','generation','operation','payload']) OR q->>'operation' IS DISTINCT FROM 'stop' OR q->'payload' IS DISTINCT FROM '{}'::jsonb THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor stop request rejected';END IF;
 o:=q->>'organization_id';w:=q->>'workspace_id';e:=q->>'environment_id';r:=q->>'run_id';s:=q->>'step_id';
 intent:=zasp_temporal68.effect(q||jsonb_build_object('operation','read'));
 IF intent->>'action_key' IS DISTINCT FROM 'run_test' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor stop action rejected';END IF;
 PERFORM zasp_sa_multistep_prior.test_lock(o,w,e,r);
 SELECT * INTO t FROM zasp_temporal68.test_stops WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 IF FOUND THEN PERFORM zasp_temporal68.test_stop_evidence(o,w,e,r,s);RETURN t.response;END IF;
 IF intent->>'state' NOT IN('reserved','started','unknown') OR intent->>'state'='reserved' AND NOT zasp_sa_multistep_prior.orchestration_stop_required(o,w,e,r) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor stop not required';END IF;
 SELECT * INTO child FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,intent->'snapshot'->'targets'->>'test_run_id') FOR UPDATE NOWAIT;
 IF child.run_id IS NULL OR child.state<>'queued' OR child.attempt<>0 OR child.worker_id IS NOT NULL OR child.lease_token IS NOT NULL OR child.lease_expires_at IS NOT NULL
  OR EXISTS(SELECT 1 FROM public.zasp_red_team_attempts WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,child.run_id))
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id,test_run_id,reconcile_state,reconcile_version)=(o,w,e,r,s,child.run_id,'pending',1) AND reconcile_worker IS NULL AND reconcile_token IS NULL AND reconcile_expires_at IS NULL AND reconcile_settlement IS NULL)
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor stopped child association changed';END IF;
 uncertain:=intent->>'state'<>'reserved';
 UPDATE public.zasp_red_team_runs SET state=CASE WHEN uncertain THEN 'failed' ELSE 'cancelled' END,error_code=CASE WHEN uncertain THEN 'outcome_unknown' ELSE 'cancelled' END,version=version+1,completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,child.run_id);
 UPDATE public.zasp_security_agent_steps SET state='inconclusive',version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 UPDATE public.zasp_security_agent_effects SET state='unknown_outcome',version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 UPDATE zasp_temporal68.effects SET state='stopped',completed_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id,generation)=(o,w,e,r,s,1);
 UPDATE public.zasp_security_agent_runs SET state=CASE WHEN state='cancelled' THEN state ELSE 'needs_human' END,version=version+1,completed_at=COALESCE(completed_at,clock_timestamp()),updated_at=clock_timestamp(),last_error_code='test_outcome_unknown' WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 result_value:=jsonb_build_object('effect_key',intent->>'effect_key','generation',1,'test_run_id',child.run_id,'run_state',(SELECT state FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)),'reason',CASE WHEN uncertain THEN 'test_outcome_unknown' ELSE 'test_cancelled_before_dispatch' END);
 snapshot_value:=zasp_temporal68.test_stop_snapshot(o,w,e,r,s);
 INSERT INTO zasp_temporal68.test_stops VALUES(o,w,e,r,s,intent->>'effect_key',snapshot_value,digest(convert_to(snapshot_value::text,'UTF8'),'sha256'),result_value);
 audit_id:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_temporal_test_stop',intent->>'effect_key');
 INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,audit_id,audit_id,r,s,session_user,'temporal_test_stopped',digest(convert_to(jsonb_build_object('snapshot',snapshot_value,'response',result_value)::text,'UTF8'),'sha256'),jsonb_build_object('snapshot',snapshot_value,'response',result_value));
 PERFORM zasp_temporal68.test_stop_evidence(o,w,e,r,s);
 IF NOT zasp_temporal68.current_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='executor stop catalog changed';END IF;
 RETURN result_value;
END $stop$;
