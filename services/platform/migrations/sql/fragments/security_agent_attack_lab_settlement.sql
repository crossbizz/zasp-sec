-- Dispatch retries must keep their original admission reply after settlement.
ALTER TABLE public.zasp_sa_attack_lab_links ADD COLUMN settlement_result jsonb,
 ADD CONSTRAINT zasp_sa_attack_lab_settlement_result_present CHECK((settled_at IS NULL)=(settlement_result IS NULL));

CREATE FUNCTION public.zasp_sa_attack_lab_evidence_snapshot(o text,w text,e text,r text,s text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $snapshot$
DECLARE l public.zasp_sa_attack_lab_links%ROWTYPE;a public.zasp_attack_lab_runs%ROWTYPE;t public.zasp_attack_lab_attempts%ROWTYPE;c public.zasp_attack_lab_cleanup_checkpoints%ROWTYPE;source_value public.zasp_red_team_attempts%ROWTYPE;source_valid boolean;cleanup_complete boolean;artifact jsonb;
BEGIN
 SELECT * INTO STRICT l FROM public.zasp_sa_attack_lab_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 SELECT * INTO STRICT a FROM public.zasp_attack_lab_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,l.execution_id);
 SELECT * INTO t FROM public.zasp_attack_lab_attempts WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=(o,w,e,l.execution_id,a.attempt);
 SELECT * INTO c FROM public.zasp_attack_lab_cleanup_checkpoints WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=(o,w,e,l.execution_id,a.attempt);
 SELECT * INTO source_value FROM public.zasp_red_team_attempts WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=(o,w,e,l.source_run_id,l.source_attempt);
 source_valid:=COALESCE(source_value.verdict='fail' AND source_value.run_id=a.source_run_id AND source_value.attempt=l.source_attempt AND encode(source_value.input_digest,'hex')=l.source_snapshot->>'source_input_digest'
  AND jsonb_build_object('key',source_value.evidence_key,'version',source_value.evidence_version_id,'sha256',encode(source_value.evidence_checksum,'hex'),'size',source_value.evidence_size,'reference',source_value.evidence_reference)=l.source_snapshot->'source_evidence'
  AND source_value.completed_at=(l.source_snapshot->>'source_completed_at')::timestamptz
  AND (a.definition_id,a.definition_version,a.target_id,a.target_kind)=(l.source_snapshot->>'definition_id',(l.source_snapshot->>'definition_version')::bigint,l.source_snapshot->>'target_id',l.source_snapshot->>'target_kind'),false);
 cleanup_complete:=COALESCE(a.state IN('complete','failed','cancelled') AND a.cleanup_state='complete' AND
  -- Claim records started_at before Create. The existing controller's definite
  -- no-sandbox denial/cancellation is terminal without a cleanup checkpoint.
  (a.sandbox_name IS NULL AND a.sandbox_reference IS NULL AND (a.started_at IS NULL OR a.state IN('failed','cancelled') AND a.error_code IN('denied','malformed','exhausted','cancelled')) AND NOT EXISTS(SELECT 1 FROM public.zasp_attack_lab_cleanup_checkpoints WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,a.run_id))
   OR t.cleanup_completed AND c.finished_at IS NOT NULL AND c.finish_result IS NOT NULL AND c.input_digest=a.input_digest AND t.input_digest=a.input_digest AND c.sandbox_reference=a.sandbox_reference),false);
 IF a.evidence_reference IS NOT NULL AND t.evidence_state='complete' AND (a.evidence_reference,a.evidence_key,a.evidence_version_id,a.evidence_checksum,a.evidence_size)=(t.evidence_reference,t.evidence_key,t.evidence_version_id,t.evidence_checksum,t.evidence_size)
  AND (c.evidence_reference,c.evidence_key,c.evidence_version_id,c.evidence_checksum,c.evidence_size)=(t.evidence_reference,t.evidence_key,t.evidence_version_id,t.evidence_checksum,t.evidence_size) THEN
  artifact:=jsonb_build_object('reference',a.evidence_reference,'key',a.evidence_key,'version_id',a.evidence_version_id,'sha256',encode(a.evidence_checksum,'hex'),'size_bytes',a.evidence_size);
 END IF;
 RETURN jsonb_build_object('schema_version','security-agent-attack-lab-snapshot-v1','organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'step_id',s,'source',l.source_snapshot,'source_valid',source_valid,
  'execution',jsonb_build_object('run_id',a.run_id,'attempt',a.attempt,'input_digest',encode(a.input_digest,'hex'),'state',a.state,'verdict',a.verdict,'error_code',a.error_code,'cancel_requested',a.cancel_requested,'cleanup_state',a.cleanup_state,'cleanup_complete',cleanup_complete,'sandbox_reference',a.sandbox_reference,'artifact',artifact,
   'outcome_unknown',a.error_code IS NOT DISTINCT FROM 'outcome_unknown' OR a.verdict IS NOT DISTINCT FROM 'inconclusive','pre_execution_denied',a.state='failed' AND a.error_code IS NOT DISTINCT FROM 'denied' AND a.attempt=1 AND a.sandbox_name IS NULL AND a.sandbox_reference IS NULL AND NOT EXISTS(SELECT 1 FROM public.zasp_attack_lab_cleanup_checkpoints WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,a.run_id))));
END $snapshot$;

CREATE FUNCTION public.zasp_sa_attack_lab_reconcile_evidence(o text,w text,e text,r text,s text,worker_value text,lease_value bytea,version_value bigint,generation_value uuid,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $evidence$
DECLARE deadline timestamptz;snapshot_value jsonb;
BEGIN
 deadline:=public.zasp_sa_attack_lab_reconcile_lock(o,w,e,r,s,worker_value,lease_value,version_value,generation_value,expected_checksum,expected_fingerprint);
 snapshot_value:=public.zasp_sa_attack_lab_evidence_snapshot(o,w,e,r,s);
 PERFORM public.zasp_sa_attack_lab_reconcile_authorize(worker_value,expected_checksum,expected_fingerprint);
 IF deadline<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab evidence lease expired';END IF;
 RETURN jsonb_build_object('version',version_value,'generation',generation_value,'lease_expires_at',to_char(deadline AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'snapshot',snapshot_value);
END $evidence$;

CREATE FUNCTION public.zasp_sa_attack_lab_reconcile_settle(o text,w text,e text,r text,s text,worker_value text,lease_value bytea,version_value bigint,generation_value uuid,expected_snapshot jsonb,proof_bytes bytea,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $settle$
DECLARE l public.zasp_sa_attack_lab_links%ROWTYPE;p public.zasp_security_agent_runs%ROWTYPE;deadline timestamptz;snapshot_value jsonb;x jsonb;proof_json json;proof_value jsonb;proof_text text;unsigned_text text;receipt jsonb;outcome_value text;reason_value text;step_state text;effect_state text;audit_value text;
BEGIN
 PERFORM public.zasp_sa_attack_lab_reconcile_authorize(worker_value,expected_checksum,expected_fingerprint);
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(r) AND public.zasp_valid_product_id(s) AND octet_length(lease_value)=32 AND version_value>0 AND generation_value<>'00000000-0000-0000-0000-000000000000'::uuid AND octet_length(proof_bytes) BETWEEN 1 AND 65536 AND jsonb_typeof(expected_snapshot)='object',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab settlement rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 PERFORM 1 FROM public.zasp_security_agent_org_admissions WHERE organization_id=o FOR UPDATE;
 SELECT * INTO STRICT p FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 SELECT * INTO STRICT l FROM public.zasp_sa_attack_lab_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s) FOR UPDATE;
 IF l.settled_at IS NOT NULL THEN
  IF (l.lease_owner,l.lease_token,l.version,l.generation,l.settlement_snapshot,l.settlement_proof) IS DISTINCT FROM (worker_value,digest(lease_value,'sha256'),version_value,generation_value,expected_snapshot,proof_bytes) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab settlement replay conflict';END IF;
  PERFORM public.zasp_sa_attack_lab_reconcile_authorize(worker_value,expected_checksum,expected_fingerprint);
  RETURN l.settlement_result;
 END IF;
 deadline:=public.zasp_sa_attack_lab_reconcile_lock(o,w,e,r,s,worker_value,lease_value,version_value,generation_value,expected_checksum,expected_fingerprint);
 PERFORM 1 FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest)=(o,w,e,r,s,'start_attack_lab',l.input_digest) AND state IN('executing','verifying','cancelled','failed','inconclusive') FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab step changed';END IF;
 PERFORM 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest)=(o,w,e,r,s,'start_attack_lab',l.input_digest) AND state IN('pending','known_failure','unknown_outcome') FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab effect changed';END IF;
 PERFORM 1 FROM public.zasp_attack_lab_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,l.execution_id) FOR SHARE;
 PERFORM 1 FROM public.zasp_red_team_attempts WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=(o,w,e,l.source_run_id,l.source_attempt) FOR SHARE NOWAIT;
 snapshot_value:=public.zasp_sa_attack_lab_evidence_snapshot(o,w,e,r,s);x:=snapshot_value->'execution';
 IF snapshot_value IS DISTINCT FROM expected_snapshot THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab settlement evidence changed';END IF;
 IF x->>'state' NOT IN('complete','failed','cancelled') OR x->'cleanup_complete' IS DISTINCT FROM 'true'::jsonb THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab execution or cleanup pending';END IF;
 BEGIN proof_text:=convert_from(proof_bytes,'UTF8');proof_json:=proof_text::json;proof_value:=proof_json::jsonb;
 EXCEPTION WHEN OTHERS THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab proof encoding rejected';END;
 IF EXISTS(WITH RECURSIVE nodes(value,depth) AS (SELECT proof_json,0 UNION ALL SELECT child.value,n.depth+1 FROM nodes n CROSS JOIN LATERAL (
  SELECT value FROM json_each(CASE WHEN json_typeof(n.value)='object' THEN n.value ELSE '{}'::json END) UNION ALL SELECT value FROM json_array_elements(CASE WHEN json_typeof(n.value)='array' THEN n.value ELSE '[]'::json END)) child WHERE n.depth<=16)
  SELECT 1 FROM nodes n WHERE depth>16 OR (SELECT count(*)<>count(DISTINCT key) FROM json_each(CASE WHEN json_typeof(n.value)='object' THEN n.value ELSE '{}'::json END))) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab proof ambiguity rejected';END IF;
 -- Canonical client bytes append the digest last. The digest covers those
 -- exact UTF8 bytes with this single final field omitted, not JSONB rewriting.
 unsigned_text:=regexp_replace(proof_text,',"sha256":"[0-9a-f]{64}"[}]$','}');
 IF proof_value->>'schema_version' IS DISTINCT FROM 'security-agent-attack-lab-verification-v1' OR proof_value-ARRAY['schema_version','outcome','reason','verdict','execution_id','attempt','input_digest','artifact','cleanup_complete','sha256']<>'{}'::jsonb
  OR NOT proof_value ?& ARRAY['schema_version','outcome','reason','verdict','execution_id','attempt','input_digest','artifact','cleanup_complete','sha256']
  OR unsigned_text=proof_text OR proof_value->>'sha256' IS DISTINCT FROM encode(digest(convert_to(unsigned_text,'UTF8'),'sha256'),'hex')
  OR (proof_value->'execution_id',proof_value->'attempt',proof_value->'input_digest',proof_value->'artifact',proof_value->'verdict',proof_value->'cleanup_complete') IS DISTINCT FROM (x->'run_id',x->'attempt',x->'input_digest',x->'artifact',x->'verdict','true'::jsonb) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab proof identity rejected';END IF;
 outcome_value:=proof_value->>'outcome';reason_value:=proof_value->>'reason';
 IF (outcome_value,reason_value)=('inconclusive','attack_lab_evidence_unavailable') THEN NULL;
 ELSIF (outcome_value,reason_value)=('inconclusive','attack_lab_outcome_unknown') AND (x->'outcome_unknown'='true'::jsonb OR snapshot_value->'source_valid'='false'::jsonb OR x->>'state'='failed') THEN NULL;
 ELSIF (outcome_value,reason_value)=('cancelled','attack_lab_cancelled') AND x->>'state'='cancelled' AND x->'cancel_requested'='true'::jsonb THEN NULL;
 ELSIF (outcome_value,reason_value)=('failed','attack_lab_pre_execution_denied') AND x->'pre_execution_denied'='true'::jsonb THEN NULL;
 ELSIF outcome_value='needs_human' AND x->>'state'='complete' AND snapshot_value->'source_valid'='true'::jsonb AND x->'outcome_unknown'='false'::jsonb AND jsonb_typeof(x->'artifact')='object'
  AND ((reason_value,x->>'verdict')=('attack_lab_unsafe_condition_reproduced','verified') OR (reason_value,x->>'verdict')=('attack_lab_not_reproduced_in_bounded_run','not_reproduced')) THEN NULL;
 ELSE RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab outcome rejected';END IF;
 step_state:=CASE WHEN outcome_value='needs_human' THEN 'succeeded' ELSE outcome_value END;
 effect_state:=CASE WHEN outcome_value='needs_human' THEN 'succeeded' WHEN outcome_value='inconclusive' THEN 'unknown_outcome' ELSE 'known_failure' END;
 UPDATE public.zasp_security_agent_effects SET state=effect_state,result_digest=digest(proof_bytes,'sha256'),version=version+1,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,s,'start_attack_lab');
 UPDATE public.zasp_security_agent_steps SET state=step_state,version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 IF p.state IN('running','verifying') THEN UPDATE public.zasp_security_agent_runs SET state=outcome_value,version=version+1,completed_at=clock_timestamp(),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);p.state:=outcome_value;END IF;
 receipt:=jsonb_build_object('run_id',r,'step_id',s,'state',p.state,'step_state',step_state,'effect_state',effect_state,'outcome',outcome_value,'reason',reason_value,'cleanup_complete',true,'proof_sha256',encode(digest(proof_bytes,'sha256'),'hex'),'version',version_value,'generation',generation_value);
 -- Keep settled ownership for exact-byte replay even after lease expiry. No
 -- settled link can be claimed or used to read new mutable evidence.
 UPDATE public.zasp_sa_attack_lab_links SET settled_at=clock_timestamp(),settlement_snapshot=expected_snapshot,settlement_proof=proof_bytes,settlement_digest=digest(proof_bytes,'sha256'),settlement_result=receipt WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 audit_value:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_attack_lab_settlement',r||chr(31)||s);
 INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,audit_value,audit_value,r,s,worker_value,'attack_lab_reconciled',digest(proof_bytes,'sha256'),receipt);
 PERFORM public.zasp_sa_attack_lab_reconcile_authorize(worker_value,expected_checksum,expected_fingerprint);
 IF deadline<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab settlement lease expired';END IF;
 RETURN receipt;
END $settle$;
GRANT EXECUTE ON FUNCTION public.zasp_sa_attack_lab_reconcile_evidence(text,text,text,text,text,text,bytea,bigint,uuid,text,text),public.zasp_sa_attack_lab_reconcile_settle(text,text,text,text,text,text,bytea,bigint,uuid,jsonb,bytea,text,text) TO zasp_security_agent_attack_lab_reconciler;
