-- WS3-C1. Compliance export jobs on the installed baseline.
--
-- The export jobs (POST /compliance/exports, its status, download grants and
-- the worker that captures, renders, stores and expires a package) could not
-- run on a baseline installation, for three reasons:
--
--   * zasp_compliance_readiness, which every job function asks first, pins a
--     60-release catalog (and the Attack Lab release pin behind it). The
--     baseline has 61 releases, so it was false for ever. On the baseline the
--     question the pins asked reduces to the catalog integrity check, which
--     zasp_authorization80.source_ready(56,...) already answers for the
--     compliance reads: the compliance release row and its recorded identity,
--     the audit and compliance role shapes, and the current authorization
--     release (zasp_baseline.intact()). Readiness keeps the two compiled
--     constants the caller must present and asks that. It is still false for
--     a wrong identity, a missing release row, a changed role shape or a
--     catalog that is no longer the sealed one.
--   * the API role could not execute the request functions (create, get,
--     grant). They get the treatment of section X3: their first statement is
--     the checked-request guard (the request's own Organization, Workspace,
--     Environment and principal), and the API role may execute them. Their own
--     checks (the session, the membership, the three permissions, fresh
--     authentication, quotas, idempotency) follow unchanged.
--   * no login was bound to the worker roles. The chain registered them with
--     a migration command that accepts releases 56 to 58 only. The two fixed
--     service logins zasp_svc_compliance_worker and zasp_svc_compliance_cleanup
--     are created here when absent (no password; a deployment sets one, as for
--     every other service login) and bound exactly as
--     zasp_compliance_register_workers binds them, so the binding is part of
--     the sealed catalog. A different login already bound to a role is left
--     as it is.
--
-- The reference is compiled before zasp_baseline.intact() is installed.
-- The scoped readiness function below is evaluated at service startup on the
-- sealed installation. Both fail-closed authorization primitives must exist.
DO $ws3_compliance_export_baseline$
DECLARE d text;constants text[];f record;guarded text;binding record;
BEGIN
 IF to_regprocedure('zasp_authorization80.source_ready(integer,text,text)') IS NULL OR to_regprocedure('zasp_authorization80.direct_guard(text,text,text,text)') IS NULL THEN RAISE EXCEPTION 'compliance export authorization predecessor missing'; END IF;
 -- Readiness.
 d:=pg_get_functiondef('public.zasp_compliance_readiness(text,text)'::regprocedure);
 IF position('zasp_authorization80.source_ready(56,' in d)=0 THEN
  constants:=regexp_match(d,$r$expected_checksum = '([a-f0-9]{64})'\s+AND expected_fingerprint = '([a-f0-9]{64})'$r$);
  IF constants IS NULL OR position('count(*)=60' in d)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='compliance readiness predecessor changed';END IF;
  EXECUTE format($f$CREATE OR REPLACE FUNCTION public.zasp_compliance_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $readiness$
 SELECT COALESCE(expected_checksum = %L AND expected_fingerprint = %L AND zasp_authorization80.source_ready(56,expected_checksum,expected_fingerprint),false)
$readiness$$f$,constants[1],constants[2]);
 END IF;
 -- The request functions.
 FOR f IN SELECT * FROM(VALUES
  ('public.zasp_compliance_export_create(text,text,text,text,bytea,text,jsonb,text,text)'),
  ('public.zasp_compliance_export_get(text,text,text,text,bytea,text,text,text)'),
  ('public.zasp_compliance_export_grant(text,text,text,text,bytea,text,text,text,text,text,text)')
 ) v(signature) LOOP
  d:=pg_get_functiondef(f.signature::regprocedure);
  IF position('zasp_authorization80.direct_guard' in d)=0 THEN
   guarded:=regexp_replace(d,'\mBEGIN\M','BEGIN PERFORM zasp_authorization80.direct_guard(org_value,workspace_value,environment_value,principal_value);');
   IF guarded=d OR position('org_value' in d)=0 OR position('principal_value' in d)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='compliance export api predecessor changed';END IF;
   EXECUTE guarded;
  END IF;
  EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zasp_discovery_api',f.signature);
 END LOOP;
 -- The worker logins and their bindings.
 FOR binding IN SELECT * FROM(VALUES('zasp_svc_compliance_worker','zasp_compliance_worker'),('zasp_svc_compliance_cleanup','zasp_compliance_cleanup')) v(login,authority) LOOP
  IF EXISTS(SELECT 1 FROM public.zasp_compliance_worker_bindings b WHERE b.authority_role=binding.authority) THEN CONTINUE;END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=binding.login) THEN
   EXECUTE format('CREATE ROLE %I LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',binding.login);
  END IF;
  EXECUTE format('GRANT %I TO %I WITH INHERIT TRUE, SET FALSE',binding.authority,binding.login);
  INSERT INTO public.zasp_compliance_worker_bindings VALUES(binding.login,binding.authority);
 END LOOP;
 IF NOT public.zasp_compliance_worker_security_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='compliance worker security rejected';END IF;
END $ws3_compliance_export_baseline$;


-- Candidate metadata is internal to the reporting API. Before returning rows or
-- counting them, the API rechecks the corresponding product read on the same
-- authorization revision. The database checks the browser's scoped request and
-- never returns source code, runtime payloads, or vendor-supplied mappings.
CREATE OR REPLACE FUNCTION zasp_authorization80.framework_sources(
 o text,w text,e text,actor text,op text,source_filter text,id_filter text)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $report_sources$
DECLARE rows_value jsonb;
BEGIN
 IF op NOT IN ('listComplianceCoverage','listComplianceCoverageEvidence','createComplianceExport')
 OR source_filter NOT IN ('','finding','addon_version','runtime_action','ticket_test')
 OR (source_filter='') IS DISTINCT FROM (id_filter='') OR (id_filter<>'' AND NOT public.zasp_valid_product_id(id_filter))
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid framework selectors'; END IF;
 PERFORM zasp_authorization80.product_request(o,w,e,actor,op,'view_compliance','environment',e,false,true,false,false);
 WITH candidates(kind,id,rule,version,observed,agent,session,classification,proof) AS (
  SELECT 'finding',f.id,f.rule,'zasp-posture-map.v1',f.created_at,NULL::text,NULL::text,NULL::text,NULL::jsonb
   FROM public.zasp_risk_findings f WHERE (f.organization_id,f.workspace_id,f.environment_id)=(o,w,e)
   AND (f.source='posture' OR (f.source='prowler'
    AND split_part(f.compliance_context,':',2) IN ('aws','kubernetes','github','okta','microsoft','salesforce','saas','gcp')
    AND f.compliance_context='zasp-discovery:'||split_part(f.compliance_context,':',2)||':'||f.rule
    AND EXISTS(SELECT 1 FROM public.zasp_risk_finding_evidence ev
      WHERE (ev.organization_id,ev.workspace_id,ev.environment_id,ev.finding_id)=(o,w,e,f.id))))
   AND f.rule IS NOT NULL AND (source_filter='' OR (source_filter,id_filter)=('finding',f.id))
  UNION ALL
  SELECT 'addon_version',v.id,finding->>'rule_id',v.ruleset,v.created_at,NULL,NULL,NULL,NULL
   FROM public.zasp_addon_versions v CROSS JOIN LATERAL jsonb_array_elements(v.findings) AS finding
   WHERE (v.organization_id,v.workspace_id,v.environment_id)=(o,w,e) AND (source_filter='' OR (source_filter,id_filter)=('addon_version',v.id))
  UNION ALL
  SELECT 'runtime_action',a.receipt->>'decision_id',CASE WHEN a.request#>>'{resource,kind}'='sqlite_workflow' THEN replace(a.outcome#>>'{context_evidence,kind}','workflow_','workflow.') ELSE 'context.'||(a.outcome#>>'{context_evidence,kind}') END,CASE WHEN a.request#>>'{resource,kind}'='sqlite_workflow' THEN 'zasp.sqlite-workflow.v1' ELSE 'zasp.sqlite-context.v1' END,
    a.observed_at,b.agent_id,b.session_id,a.request#>>'{resource,classification}',NULL
   FROM public.zasp_workload_actions a JOIN public.zasp_workload_bindings b
    ON (b.organization_id,b.workspace_id,b.environment_id,b.credential_id)=(a.organization_id,a.workspace_id,a.environment_id,a.credential_id)
   WHERE (a.organization_id,a.workspace_id,a.environment_id)=(o,w,e) AND a.outcome?'context_evidence'
   AND a.receipt->>'verdict'='allow' AND b.created_at<=a.created_at
   AND (source_filter='' OR (source_filter,id_filter)=('runtime_action',a.receipt->>'decision_id'))
  UNION ALL
  SELECT 'ticket_test',t.run_id,'ticket.control_pair','zasp-ticket-proof-v1',t.submitted_at,NULL,NULL,NULL,t.bundle
   FROM public.zasp_ticket_verification_imports t WHERE (t.organization_id,t.workspace_id,t.environment_id)=(o,w,e)
   AND (source_filter='' OR (source_filter,id_filter)=('ticket_test',t.run_id))
 ), bounded AS (SELECT * FROM candidates ORDER BY kind,id,rule LIMIT 2001)
 SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object('source_kind',kind,'source_id',id,'rule',rule,'rule_version',version,
  'occurred_at',observed,'agent_id',agent,'session_id',session,'classification',classification,'ticket',proof)) ORDER BY kind,id,rule),'[]'::jsonb) INTO rows_value FROM bounded;
 IF jsonb_array_length(rows_value)>2000 OR octet_length(rows_value::text)>8388608 THEN
  RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='framework aggregation budget exceeded'; END IF;
 RETURN rows_value;
END $report_sources$;
ALTER FUNCTION zasp_authorization80.framework_sources(text,text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.framework_sources(text,text,text,text,text,text,text) FROM PUBLIC,zasp_operator;
GRANT EXECUTE ON FUNCTION zasp_authorization80.framework_sources(text,text,text,text,text,text,text) TO zasp_discovery_api;

-- Snapshot the authorized report, including its exact upstream edition, when
-- the request is accepted. Worker retries and catalog upgrades read these bytes.
CREATE TABLE IF NOT EXISTS public.zasp_framework_export_snapshots (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL, export_id text NOT NULL,
 snapshot jsonb NOT NULL CHECK(jsonb_typeof(snapshot)='object' AND octet_length(snapshot::text)<=3145728),
 PRIMARY KEY(organization_id,workspace_id,environment_id,export_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,export_id) REFERENCES public.zasp_compliance_export_jobs(organization_id,workspace_id,environment_id,export_id) ON DELETE CASCADE
);
ALTER TABLE public.zasp_framework_export_snapshots OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_framework_export_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_framework_export_snapshots FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.zasp_framework_export_snapshots FROM PUBLIC;
DO $report_rls$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_policies WHERE schemaname='public' AND tablename='zasp_framework_export_snapshots' AND policyname='framework_snapshot_authority') THEN
 CREATE POLICY framework_snapshot_authority ON public.zasp_framework_export_snapshots TO zasp_discovery_authority USING(true) WITH CHECK(true);
 END IF;
END $report_rls$;

-- These edits preserve the existing queue, quotas, idempotency, frozen-reader,
-- grant and download functions. All unversioned export requests keep their
-- existing validation. A missing snapshot aborts the capture.
DO $framework_export_patch$
DECLARE t record; d text; step record;
BEGIN
 FOR t IN SELECT * FROM (VALUES
 ('public.zasp_compliance_export_create(text,text,text,text,bytea,text,jsonb,text,text)','create'),
 ('public.zasp_compliance_export_capture(text,text,text,text,text,text,bigint,jsonb,text,text)','capture'),
 ('zasp_authorization80.ticket_proof_put(text,text,text,text,text,jsonb)','ticket')) names(sig,op)
 LOOP
  d:=pg_get_functiondef(t.sig::regprocedure);
  IF (t.op='create' AND position('upstream_id' in d)>0) OR (t.op='capture' AND position('framework_coverage' in d)>0) OR (t.op='ticket' AND position('attestations' in d)>0) THEN CONTINUE;END IF;
  FOR step IN SELECT * FROM (VALUES
   ('create',$a$k NOT IN('framework','control_id','agent_id','pilot_cohort','device_id','endpoint_session_ref'))$a$,
    $b$k NOT IN('framework','control_id','agent_id','pilot_cohort','device_id','endpoint_session_ref','edition','upstream_id','evidence_kind')) OR request_value ?| ARRAY['edition','upstream_id','evidence_kind'] AND (NOT request_value ?& ARRAY['framework','edition'] OR request_value ?| ARRAY['control_id','agent_id','pilot_cohort','device_id','endpoint_session_ref'] OR jsonb_typeof(request_value->'edition')<>'string' OR jsonb_typeof(request_value->'framework')<>'string')$b$),
   ('create',$a$OR request_value ? 'framework' AND (jsonb_typeof$a$,$b$OR request_value ? 'framework' AND NOT request_value?'edition' AND (jsonb_typeof$b$),
   ('capture',$a$ARRAY['agent_id','pilot_cohort','device_id'] LIMIT 501$a$,$b$ARRAY['agent_id','pilot_cohort','device_id','edition'] LIMIT 501$b$),
   ('capture',$a$ELSE '{}'::jsonb END body,$a$,$b$WHEN j.request?'edition' THEN (SELECT jsonb_build_object('framework_coverage',fs.snapshot) FROM public.zasp_framework_export_snapshots fs WHERE (fs.organization_id,fs.workspace_id,fs.environment_id,fs.export_id)=(org_value,workspace_value,environment_value,j.export_id)) ELSE '{}'::jsonb END body,$b$),
   ('ticket',$a$b - ARRAY['scenario','adapter','recorder'] <> '{}'::jsonb$a$,$b$b - ARRAY['scenario','adapter','recorder','attestations'] <> '{}'::jsonb OR (b?'attestations' AND (jsonb_typeof(b->'attestations') IS DISTINCT FROM 'object' OR NOT ((b->'attestations') ?& ARRAY['adapter','recorder']) OR (b->'attestations')-ARRAY['adapter','recorder'] <> '{}'::jsonb))$b$)
  ) p(op,anchor,replacement) WHERE op=t.op LOOP
   IF length(d)-length(replace(d,step.anchor,''))<>length(step.anchor) THEN RAISE EXCEPTION 'framework reporting predecessor changed %',t.op; END IF;
   d:=replace(d,step.anchor,step.replacement);
  END LOOP;
  EXECUTE d;
 END LOOP;
END $framework_export_patch$;

CREATE OR REPLACE FUNCTION zasp_authorization80.framework_export_create(o text,w text,e text,actor text,s bytea,k text,selectors jsonb,pack jsonb,ck text,fp text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $report_export$
DECLARE j jsonb;
BEGIN
 PERFORM zasp_authorization80.product_request(o,w,e,actor,'createComplianceExport','view_compliance','environment',e,false,true,true,true);
 IF NOT COALESCE(pack->>'schema_version'='framework-coverage.v1' AND pack->'selector'=selectors AND
  pack->>'organization_id'=o AND pack->>'workspace_id'=w AND pack->>'environment_id'=e AND
  pack#>>'{coverage,framework}'=selectors->>'framework' AND pack#>>'{coverage,edition}'=selectors->>'edition'
  AND jsonb_typeof(pack#>'{coverage,items}')='array' AND jsonb_typeof(pack->'evidence')='array' AND octet_length(pack::text)<=3145728,false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid frozen framework snapshot'; END IF;
 j:=public.zasp_compliance_export_create(o,w,e,actor,s,k,selectors,ck,fp);
 INSERT INTO public.zasp_framework_export_snapshots(organization_id,workspace_id,environment_id,export_id,snapshot)
 VALUES(o,w,e,j->>'export_id',pack) ON CONFLICT DO NOTHING;
 RETURN j;
END $report_export$;
ALTER FUNCTION zasp_authorization80.framework_export_create(text,text,text,text,bytea,text,jsonb,jsonb,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.framework_export_create(text,text,text,text,bytea,text,jsonb,jsonb,text,text) FROM PUBLIC,zasp_operator;
GRANT EXECUTE ON FUNCTION zasp_authorization80.framework_export_create(text,text,text,text,bytea,text,jsonb,jsonb,text,text) TO zasp_discovery_api;
