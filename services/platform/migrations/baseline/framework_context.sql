-- Accept optional content-free observations from the bound context adapter.
CREATE OR REPLACE FUNCTION zasp_authorization80.workload_outcome(o text,w text,e text,actor text,a text,q jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $workload_outcome$
DECLARE p jsonb; binding text; prior public.zasp_workload_actions%ROWTYPE;
BEGIN
 p:=zasp_authorization80.product_request(o,w,e,actor,'recordWorkloadActionOutcome','decide_actions','environment',e,false,false,false,true);
 binding:=p->>'credential_id';
 IF p->>'credential_kind' IS DISTINCT FROM '2' OR binding IS NULL OR NOT COALESCE(p->'pat_ceiling' ? 'decide_actions',false) OR p#>>'{path_parameters,actionId}' IS DISTINCT FROM a THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='workload binding required'; END IF;
 IF NOT COALESCE(jsonb_typeof(q)='object' AND (q-ARRAY['schema_version','action_id','decision_id','status','context_evidence'])='{}'::jsonb
  AND q->>'schema_version'='action-outcome.v1' AND q->>'action_id'=a AND public.zasp_valid_product_id(q->>'decision_id')
  AND q->>'status' IN('not_dispatched','returned','raised','cancelled')
  AND (NOT q?'context_evidence' OR (
    jsonb_typeof(q->'context_evidence')='object'
    AND (q->'context_evidence') ?& ARRAY['kind','collection_ref','record_ref','version','result']
    AND ((q->'context_evidence')-ARRAY['kind','collection_ref','record_ref','version','digest','result'])='{}'::jsonb
    AND q#>>'{context_evidence,kind}' IN('memory_write','memory_recall','retrieval','artifact_promotion','grounded_decision','hidden_context_check','workflow_purpose','workflow_approval','workflow_handoff','workflow_child','workflow_budget')
    AND q#>>'{context_evidence,collection_ref}'~'^[a-f0-9]{64}$' AND q#>>'{context_evidence,record_ref}'~'^[a-f0-9]{64}$'
    AND jsonb_typeof(q#>'{context_evidence,version}')='number' AND q#>>'{context_evidence,version}'~'^(0|[1-9][0-9]{0,15})$'
    AND (q#>>'{context_evidence,version}')::numeric < 9007199254740992
    AND ((q#>>'{context_evidence,version}'='0' AND NOT (q->'context_evidence')?'digest')
         OR (q#>>'{context_evidence,version}'<>'0' AND q#>>'{context_evidence,digest}'~'^[a-f0-9]{64}$'))
    AND (q->>'status',q#>>'{context_evidence,result}') IN (('returned','allowed'),('raised','rejected')))),false) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid workload outcome'; END IF;
 SELECT * INTO prior FROM public.zasp_workload_actions WHERE(organization_id,workspace_id,environment_id,credential_id,action_id)=(o,w,e,binding,a) FOR UPDATE;
 IF NOT FOUND OR prior.receipt->>'decision_id' IS DISTINCT FROM q->>'decision_id' THEN RETURN '{"error":"unknown_action"}'::jsonb; END IF;
 IF q?'context_evidence' AND (prior.request->>'operation' IS DISTINCT FROM CASE WHEN left(q#>>'{context_evidence,kind}',9)='workflow_'
       THEN 'workflow.'||substr(q#>>'{context_evidence,kind}',10) ELSE 'context.'||(q#>>'{context_evidence,kind}') END
  OR prior.request#>>'{resource,kind}' IS DISTINCT FROM CASE WHEN left(q#>>'{context_evidence,kind}',9)='workflow_' THEN 'sqlite_workflow' ELSE 'sqlite_context' END
  OR prior.request->>'source_call_ref' IS DISTINCT FROM q#>>'{context_evidence,record_ref}'
  OR prior.receipt->>'verdict' IS DISTINCT FROM 'allow') THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='context receipt does not match admitted action'; END IF;
 IF prior.outcome IS NOT NULL AND prior.outcome<>q THEN RETURN '{"error":"action_outcome_conflict"}'::jsonb; END IF;
 IF prior.outcome IS NULL THEN
  UPDATE public.zasp_workload_actions SET outcome=q,observed_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,credential_id,action_id)=(o,w,e,binding,a); END IF;
 PERFORM zasp_authorization80.product_settled(p); RETURN '{"recorded":true}'::jsonb;
END $workload_outcome$;
ALTER FUNCTION zasp_authorization80.workload_outcome(text,text,text,text,text,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.workload_outcome(text,text,text,text,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.workload_outcome(text,text,text,text,text,jsonb) TO zasp_discovery_api;
