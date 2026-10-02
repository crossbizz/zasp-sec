CREATE FUNCTION zasp_temporal_single_recovery.observe(q jsonb,reason_value text) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $body$
DECLARE c zasp_temporal_single_recovery.commands%ROWTYPE;
BEGIN
 PERFORM zasp_temporal_single_recovery.require_worker('zasp_temporal_compensation');c:=zasp_temporal_single_recovery.authenticated(q);
 IF NOT COALESCE(reason_value IN('cleanup_pending','dependency_unavailable','evidence_conflict'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery observation rejected';END IF;
 UPDATE zasp_temporal_single_recovery.progress SET status=CASE WHEN reason_value='evidence_conflict' THEN 'repair_required' ELSE 'pending' END,reason=reason_value,version=version+1,updated_at=clock_timestamp() WHERE(organization_id,workspace_id,environment_id,run_id,command_id)=(c.organization_id,c.workspace_id,c.environment_id,c.run_id,c.command_id);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery progress unavailable';END IF;RETURN true;
END $body$;
CREATE FUNCTION zasp_temporal_single_recovery.finish(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $body$
DECLARE c zasp_temporal_single_recovery.commands%ROWTYPE;x zasp_temporal74.run_owners%ROWTYPE;prior zasp_temporal_single_recovery.completion_receipts%ROWTYPE;proof jsonb;body_value jsonb;rid text;outcome_value text;stamp timestamptz;actor_value text;
BEGIN
 PERFORM zasp_temporal_single_recovery.require_worker('zasp_temporal_compensation');c:=zasp_temporal_single_recovery.checked(q);
 SELECT * INTO STRICT x FROM zasp_temporal74.run_owners WHERE(organization_id,workspace_id,environment_id,run_id)=(c.organization_id,c.workspace_id,c.environment_id,c.run_id);
 proof:=zasp_temporal_single_recovery.proof(x);
 IF proof IS NULL OR zasp_temporal74.unresolved(x.organization_id,x.workspace_id,x.environment_id,x.run_id) THEN RETURN jsonb_build_object('complete',false,'reference',q);END IF;
 SELECT state INTO STRICT outcome_value FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 IF outcome_value NOT IN('cancelled','failed','inconclusive','needs_human','contained','remediated') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery outcome not settled';END IF;
 rid:=public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'single_test_recovery_completion',c.command_id);
 body_value:=jsonb_build_object('reference',q,'proof',proof,'outcome',outcome_value,'receipt_id',rid);
 SELECT * INTO prior FROM zasp_temporal_single_recovery.completion_receipts WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 IF FOUND THEN
  IF(prior.command_id,prior.receipt_id,prior.command_digest,prior.evidence_digest,prior.evidence_kind,prior.outcome,prior.body,prior.body_digest) IS DISTINCT FROM(c.command_id,rid,c.command_digest,digest(convert_to(proof::text,'UTF8'),'sha256'),proof->>'kind',outcome_value,body_value,digest(convert_to(body_value::text,'UTF8'),'sha256')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery completion changed';END IF;
 ELSE
  stamp:=clock_timestamp();SELECT actor_id INTO STRICT actor_value FROM zasp_temporal_single_recovery.request_receipts WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
  INSERT INTO zasp_temporal_single_recovery.completion_receipts VALUES(x.organization_id,x.workspace_id,x.environment_id,x.run_id,c.command_id,rid,c.command_digest,digest(convert_to(proof::text,'UTF8'),'sha256'),proof->>'kind',outcome_value,stamp,body_value,digest(convert_to(body_value::text,'UTF8'),'sha256'));
  INSERT INTO zasp_temporal_single_recovery.audit VALUES(x.organization_id,x.workspace_id,x.environment_id,x.run_id,rid,rid,actor_value,'cleanup_recovery_completed',body_value,digest(convert_to(body_value::text,'UTF8'),'sha256'),stamp);
 END IF;
 PERFORM zasp_temporal_single_recovery.require_worker('zasp_temporal_compensation');RETURN jsonb_build_object('complete',true,'reference',q);
END $body$;
CREATE FUNCTION zasp_temporal_single_recovery.value_without_request(x zasp_temporal74.run_owners,receipt_value text,accepted_value timestamptz) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $body$
DECLARE c zasp_temporal_single_recovery.commands%ROWTYPE;t zasp_temporal_single_recovery.completion_receipts%ROWTYPE;p zasp_temporal_single_recovery.progress%ROWTYPE;proof jsonb;completion_value jsonb;ref jsonb;status_value text;reason_value text;version_value bigint;outcome_value text;stamp timestamptz;expected_body jsonb;
BEGIN
 SELECT version,state INTO STRICT version_value,outcome_value FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 SELECT * INTO c FROM zasp_temporal_single_recovery.commands WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 IF FOUND THEN
  ref:=zasp_temporal_single_recovery.reference(c);PERFORM zasp_temporal_single_recovery.checked(ref);stamp:=c.created_at;
  SELECT * INTO t FROM zasp_temporal_single_recovery.completion_receipts WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
  IF FOUND THEN
   proof:=zasp_temporal_single_recovery.proof(x);expected_body:=jsonb_build_object('reference',ref,'proof',proof,'outcome',outcome_value,'receipt_id',t.receipt_id);
   IF proof IS NULL OR zasp_temporal74.unresolved(x.organization_id,x.workspace_id,x.environment_id,x.run_id) OR t.receipt_id IS DISTINCT FROM public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'single_test_recovery_completion',c.command_id)
   OR(t.command_id,t.command_digest,t.evidence_digest,t.evidence_kind,t.outcome,t.body,t.body_digest) IS DISTINCT FROM(c.command_id,c.command_digest,digest(convert_to(proof::text,'UTF8'),'sha256'),proof->>'kind',outcome_value,expected_body,digest(convert_to(expected_body::text,'UTF8'),'sha256'))
   OR NOT EXISTS(SELECT 1 FROM zasp_temporal_single_recovery.audit WHERE(organization_id,workspace_id,environment_id,run_id,audit_id,correlation_id,event_kind,body,body_digest)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,t.receipt_id,t.receipt_id,'cleanup_recovery_completed',t.body,t.body_digest)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery completion source changed';END IF;
   completion_value:=jsonb_build_object('receipt_id',t.receipt_id,'evidence_kind',t.evidence_kind,'evidence_digest',encode(t.evidence_digest,'hex'),'outcome',t.outcome,'completed_at',to_char(t.completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));status_value:='complete';reason_value:='verified';
  ELSE
   SELECT * INTO STRICT p FROM zasp_temporal_single_recovery.progress WHERE(organization_id,workspace_id,environment_id,run_id,command_id)=(c.organization_id,c.workspace_id,c.environment_id,c.run_id,c.command_id);status_value:=p.status;reason_value:=p.reason;
  END IF;
 ELSE
  proof:=zasp_temporal_single_recovery.proof(x);
  IF proof IS NULL OR zasp_temporal74.unresolved(x.organization_id,x.workspace_id,x.environment_id,x.run_id) OR receipt_value IS NULL OR accepted_value IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery not accepted';END IF;
  stamp:=accepted_value;status_value:='complete';reason_value:='verified';
  completion_value:=jsonb_build_object('receipt_id',receipt_value,'evidence_kind','already_complete','evidence_digest',encode(digest(convert_to(proof::text,'UTF8'),'sha256'),'hex'),'outcome',outcome_value,'completed_at',to_char(stamp AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
 END IF;
 RETURN jsonb_build_object('run_id',x.run_id,'request_identity',jsonb_build_object('definition_version',x.definition_version,'input_digest',x.input_digest),'status',status_value,'reason',reason_value,'parent_version',version_value,'command',ref,'accepted_at',to_char(stamp AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'completion',completion_value);
END $body$;
CREATE FUNCTION zasp_temporal_single_recovery.value(o text,w text,e text,r text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $body$
DECLARE x zasp_temporal74.run_owners%ROWTYPE;rc zasp_temporal_single_recovery.request_receipts%ROWTYPE;v jsonb;version_value bigint;
BEGIN
 SELECT * INTO STRICT x FROM zasp_temporal74.run_owners WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF NOT pg_try_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0)) THEN RAISE EXCEPTION USING ERRCODE='55P03',MESSAGE='recovery busy';END IF;
 PERFORM 1 FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE NOWAIT;
 x:=zasp_temporal_single_recovery.owner(jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'definition_version',x.definition_version,'input_digest',x.input_digest));
 SELECT * INTO rc FROM zasp_temporal_single_recovery.request_receipts WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) ORDER BY created_at,receipt_id COLLATE "C" LIMIT 1;
 IF NOT FOUND THEN
  IF EXISTS(SELECT 1 FROM zasp_temporal_single_recovery.commands WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery acceptance unavailable';END IF;
  SELECT version INTO STRICT version_value FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
  RETURN jsonb_build_object('run_id',r,'request_identity',jsonb_build_object('definition_version',x.definition_version,'input_digest',x.input_digest),'status','not_requested','reason','not_requested','parent_version',version_value,'command',NULL,'accepted_at',NULL,'completion',NULL);
 END IF;
 IF rc.intent_digest IS DISTINCT FROM digest(convert_to(rc.intent::text,'UTF8'),'sha256') OR NOT EXISTS(SELECT 1 FROM zasp_temporal_single_recovery.audit a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.audit_id,a.actor_id,a.correlation_id,a.event_kind,a.body,a.body_digest)=(o,w,e,r,rc.audit_id,rc.actor_id,rc.correlation_id,'cleanup_recovery_requested',rc.intent,rc.intent_digest)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery acceptance unavailable';END IF;
 v:=zasp_temporal_single_recovery.value_without_request(x,rc.receipt_id,rc.created_at);
 IF rc.response->'body'->'command' IS DISTINCT FROM v->'command' OR v->'command'='null'::jsonb AND rc.response->'body'->'completion' IS DISTINCT FROM v->'completion' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery acceptance changed';END IF;RETURN v;
END $body$;
CREATE FUNCTION zasp_temporal_single_recovery.get(o text,w text,e text,r text,a text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $body$
DECLARE q jsonb:=jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'actor_id',a);v jsonb;
BEGIN PERFORM zasp_temporal_single_recovery.human(q,false,true);v:=zasp_temporal_single_recovery.value(o,w,e,r);PERFORM zasp_temporal_single_recovery.human(q,false,true);IF octet_length(v::text)>16384 THEN RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='recovery view bound exceeded';END IF;RETURN v;END $body$;
