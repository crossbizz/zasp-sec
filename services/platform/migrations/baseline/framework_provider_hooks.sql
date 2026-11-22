-- Provider inference frames use the existing tenant/PAT-scoped decision ledger.
-- Select runtime policies for prompt frames and the existing tool policies for
-- whole tool-call frames. The public API admits these kinds only after verifying
-- the provider signature, actual tenant and dedicated workload credential.
DO $provider_frames$
DECLARE
 original regprocedure := 'zasp_authorization80.workload_policy_snapshot(text,text,text)'::regprocedure;
 action regprocedure := 'zasp_authorization80.workload_action(text,text,text,text,jsonb,jsonb)'::regprocedure;
 outcome regprocedure := 'zasp_authorization80.workload_outcome(text,text,text,text,text,jsonb)'::regprocedure;
 old_outcome text := $old$IF NOT FOUND OR prior.receipt->>'decision_id'$old$;
 new_outcome text := $new$IF NOT FOUND OR prior.request->>'action_kind' IN ('provider_prompt','provider_tool_frame') OR prior.receipt->>'decision_id'$new$;
 src text;
 old_kind text := $old$q->>'action_kind'='tool_call'$old$;
 new_kind text := $new$(q->>'action_kind'='tool_call' OR (q->>'action_kind' IN ('provider_prompt','provider_tool_frame') AND p->'pat_ceiling'='["decide_actions"]'::jsonb))$new$;
 old_snapshot text := 'snapshot:=zasp_authorization80.workload_policy_snapshot(o,w,e);';
 new_snapshot text := $new$snapshot:=CASE WHEN q->>'action_kind'='provider_prompt' THEN zasp_authorization80.provider_prompt_policy_snapshot(o,w,e) ELSE zasp_authorization80.workload_policy_snapshot(o,w,e) END;$new$;
BEGIN
 src := pg_get_functiondef(original);
 IF position($t$body->>'trigger'='tool'$t$ IN src)=0 THEN RAISE EXCEPTION 'unsupported workload policy snapshot'; END IF;
 EXECUTE replace(replace(src,'FUNCTION zasp_authorization80.workload_policy_snapshot','FUNCTION zasp_authorization80.provider_prompt_policy_snapshot'),
    $t$body->>'trigger'='tool'$t$, $t$body->>'trigger'='runtime'$t$);
 ALTER FUNCTION zasp_authorization80.provider_prompt_policy_snapshot(text,text,text) OWNER TO zasp_discovery_authority;
 REVOKE ALL ON FUNCTION zasp_authorization80.provider_prompt_policy_snapshot(text,text,text) FROM PUBLIC;
 src := pg_get_functiondef(action);
 IF position(new_kind IN src)=0 THEN
  IF position(old_kind IN src)=0 OR position(old_snapshot IN src)=0 THEN RAISE EXCEPTION 'unsupported workload admission'; END IF;
  EXECUTE replace(replace(src,old_kind,new_kind),old_snapshot,new_snapshot);
 END IF;
 src := pg_get_functiondef(outcome);
 IF position(new_outcome IN src)=0 THEN
  IF position(old_outcome IN src)=0 THEN RAISE EXCEPTION 'unsupported workload outcome'; END IF;
  EXECUTE replace(src,old_outcome,new_outcome);
 END IF;
END $provider_frames$;

-- A tenant-wide ingress credential must never identify its many callers as
-- one managed agent/session. Serialize its first delivery with assignment.
DO $provider_binding$
DECLARE
 admission regprocedure := 'zasp_authorization80.workload_action(text,text,text,text,jsonb,jsonb)'::regprocedure;
 assignment regprocedure := 'zasp_authorization80.workload_binding(text,text,text,text,text,text)'::regprocedure;
 admission_anchor text := 'PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),o,w,e,binding,a),0));';
 admission_guard text := $guard$IF q->>'action_kind' IN ('provider_prompt','provider_tool_frame') THEN
  PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),'provider-binding',o,w,e,binding),0));
  IF EXISTS(SELECT FROM public.zasp_workload_bindings b WHERE (b.organization_id,b.workspace_id,b.environment_id,b.credential_id)=(o,w,e,binding)) THEN
   RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='provider credential already bound to workload'; END IF;
 END IF;
 $guard$;
 assignment_anchor text := 'IF agent_value IS NOT NULL THEN';
 assignment_guard text := $guard$IF agent_value IS NOT NULL THEN
  PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),'provider-binding',o,w,e,token_value),0));
  IF EXISTS(SELECT FROM public.zasp_workload_actions x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.credential_id)=(o,w,e,token_value)
    AND x.request->>'action_kind' IN ('provider_prompt','provider_tool_frame')) THEN RETURN '{"error":"ineligible_binding"}'::jsonb; END IF;
 END IF;
 $guard$;
 src text; pos integer;
BEGIN
 src:=pg_get_functiondef(admission);
 IF position(admission_guard IN src)=0 THEN
  IF position(admission_anchor IN src)=0 THEN RAISE EXCEPTION 'unsupported workload admission locking'; END IF;
  EXECUTE replace(src,admission_anchor,admission_guard||admission_anchor);
 END IF;
 src:=pg_get_functiondef(assignment);
 IF position(assignment_guard IN src)=0 THEN
  pos:=position(assignment_anchor IN src);
  IF pos=0 THEN RAISE EXCEPTION 'unsupported workload credential binding'; END IF;
  EXECUTE overlay(src placing assignment_guard||assignment_anchor from pos for length(assignment_anchor));
 END IF;
END $provider_binding$;
