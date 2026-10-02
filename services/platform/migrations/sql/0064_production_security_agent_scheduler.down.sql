DO $unresolved$
DECLARE d record;
BEGIN
 IF EXISTS(SELECT 1 FROM zasp_ordered_scheduler64.schedule_leases retained WHERE state<>'reconciled' OR retained.evidence_digest IS DISTINCT FROM zasp_ordered_scheduler64.evidence_digest(retained)) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='scheduler ownership unresolved';END IF;
 FOR d IN SELECT * FROM zasp_ordered_scheduler64.schedule_leases ORDER BY organization_id,workspace_id,environment_id,run_id,schedule_id LOOP
  IF NOT zasp_ordered_scheduler64.clean_terminal(d.organization_id,d.workspace_id,d.environment_id,d.run_id) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='scheduler predecessor unresolved';END IF;
 END LOOP;
END $unresolved$;
DROP FUNCTION zasp_ordered_scheduler64.scheduler(text,text,jsonb);
DROP FUNCTION zasp_ordered_scheduler64.mutate(jsonb);
DROP FUNCTION zasp_ordered_scheduler64.claim(jsonb);
DROP FUNCTION zasp_ordered_scheduler64.inspect(text,text,text,text,jsonb);
DROP FUNCTION zasp_ordered_scheduler64.ready(text,text);
DROP FUNCTION zasp_ordered_scheduler64.fingerprint();
DROP TABLE zasp_ordered_scheduler64.registration;
DROP FUNCTION zasp_ordered_scheduler64.evidence_digest(zasp_ordered_scheduler64.schedule_leases);
DROP TABLE zasp_ordered_scheduler64.schedule_leases;
DROP FUNCTION zasp_ordered_scheduler64.retain_binding();
DROP FUNCTION zasp_ordered_scheduler64.clean_terminal(text,text,text,text);
DROP FUNCTION zasp_ordered_scheduler64.terminal_evidence(text,text,text,text,public.zasp_security_agent_runs,jsonb);
DROP SCHEMA zasp_ordered_scheduler64;
