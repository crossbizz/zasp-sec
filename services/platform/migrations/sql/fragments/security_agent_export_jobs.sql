-- PostgreSQL retains physical attnum slots after DROP COLUMN. Fingerprint
-- every live column's logical ordinal so unused down/up is repeatable, while
-- still covering its name/type/default/nullability/ACL and exact live order.
DO $catalog$
DECLARE d text;anchor text:='c.relname,a.attnum,a.attname';
BEGIN
 PERFORM public.zasp_sa_export_save('public.zasp_compliance_jobs_catalog()');
 d:=pg_get_functiondef('public.zasp_compliance_jobs_catalog()'::regprocedure);
 IF strpos(d,anchor)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export catalog predecessor changed';END IF;
 EXECUTE replace(d,anchor,'c.relname,(SELECT count(*) FROM pg_attribute live WHERE live.attrelid=a.attrelid AND live.attnum>0 AND live.attnum<=a.attnum AND NOT live.attisdropped),a.attname');
END $catalog$;
CREATE TABLE zasp_sa_export_prior.job_constraints(name text PRIMARY KEY,definition text NOT NULL);
ALTER TABLE zasp_sa_export_prior.job_constraints OWNER TO zasp_discovery_authority;
REVOKE ALL ON zasp_sa_export_prior.job_constraints FROM PUBLIC;
DO $replace_constraints$
DECLARE c record;
BEGIN
 FOR c IN SELECT conname,pg_get_constraintdef(oid) definition FROM pg_constraint WHERE conrelid='public.zasp_compliance_export_jobs'::regclass AND (contype='u' OR conname='zasp_compliance_export_jobs_mapping_revision_check') LOOP
  INSERT INTO zasp_sa_export_prior.job_constraints VALUES(c.conname,c.definition);
  EXECUTE format('ALTER TABLE public.zasp_compliance_export_jobs DROP CONSTRAINT %I',c.conname);
 END LOOP;
END $replace_constraints$;
ALTER TABLE public.zasp_compliance_export_jobs ALTER COLUMN session_digest DROP NOT NULL;
ALTER TABLE public.zasp_compliance_export_jobs ADD COLUMN job_origin text NOT NULL DEFAULT 'browser',ADD COLUMN agent_run_id text,ADD COLUMN agent_step_id text;
ALTER TABLE public.zasp_compliance_export_jobs ADD CONSTRAINT zasp_sa_export_origin CHECK(
 job_origin='browser' AND session_digest IS NOT NULL AND octet_length(session_digest)=32 AND session_digest<>decode(repeat('00',32),'hex') AND mapping_revision='product-evidence-v1' AND agent_run_id IS NULL AND agent_step_id IS NULL
 OR job_origin='agent_run' AND session_digest IS NULL AND mapping_revision='security-agent-run-evidence-v1' AND agent_run_id IS NOT NULL AND agent_step_id IS NOT NULL AND public.zasp_valid_product_id(agent_run_id) AND public.zasp_valid_product_id(agent_step_id));
ALTER TABLE public.zasp_compliance_export_jobs ADD CONSTRAINT zasp_sa_export_idempotency UNIQUE(organization_id,workspace_id,environment_id,principal_id,job_origin,idempotency_key),ADD CONSTRAINT zasp_sa_export_job_binding UNIQUE(organization_id,workspace_id,environment_id,export_id,job_origin,agent_run_id,agent_step_id);
CREATE TABLE public.zasp_sa_export_links(
 organization_id text NOT NULL CHECK(public.zasp_valid_product_id(organization_id)),workspace_id text NOT NULL CHECK(public.zasp_valid_product_id(workspace_id)),environment_id text NOT NULL CHECK(public.zasp_valid_product_id(environment_id)),run_id text NOT NULL CHECK(public.zasp_valid_product_id(run_id)),step_id text NOT NULL CHECK(public.zasp_valid_product_id(step_id)),
 export_id text NOT NULL CHECK(public.zasp_valid_product_id(export_id)),job_origin text NOT NULL DEFAULT 'agent_run' CHECK(job_origin='agent_run'),action_key text NOT NULL DEFAULT 'create_evidence_export' CHECK(action_key='create_evidence_export'),
 plan_hash bytea NOT NULL CHECK(octet_length(plan_hash)=32),input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32),
 definition_id text NOT NULL CHECK(public.zasp_valid_product_id(definition_id)),definition_version bigint NOT NULL CHECK(definition_version>0),definition_digest bytea NOT NULL CHECK(octet_length(definition_digest)=32),
 authority_principal_id text NOT NULL CHECK(public.zasp_valid_product_id(authority_principal_id)),requester_id text CHECK(requester_id IS NULL OR public.zasp_valid_product_id(requester_id)),
 selection jsonb NOT NULL CHECK(jsonb_typeof(selection)='array' AND jsonb_array_length(selection) BETWEEN 1 AND 100),dispatch_result jsonb NOT NULL,
 dispatch_worker text NOT NULL CHECK(length(dispatch_worker) BETWEEN 1 AND 128),dispatch_token_digest bytea NOT NULL CHECK(octet_length(dispatch_token_digest)=32),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 settlement_worker text,settlement_token_digest bytea CHECK(octet_length(settlement_token_digest)=32),settlement_lease_expires_at timestamptz,settlement_last_claimed_at timestamptz NOT NULL DEFAULT '-infinity',
 settled_at timestamptz,settlement_result jsonb,settlement_snapshot jsonb,settlement_audit_id text,settlement_correlation_id text,
 CHECK((settlement_worker IS NULL AND settlement_token_digest IS NULL AND settlement_lease_expires_at IS NULL) OR (settlement_worker IS NOT NULL AND length(settlement_worker) BETWEEN 1 AND 128 AND settlement_token_digest IS NOT NULL AND settlement_lease_expires_at IS NOT NULL)),
 CHECK((settled_at IS NULL AND settlement_result IS NULL AND settlement_snapshot IS NULL AND settlement_audit_id IS NULL AND settlement_correlation_id IS NULL) OR (settled_at IS NOT NULL AND settlement_result IS NOT NULL AND settlement_snapshot IS NOT NULL AND settlement_audit_id IS NOT NULL AND settlement_correlation_id IS NOT NULL)),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id),UNIQUE(organization_id,workspace_id,environment_id,export_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,export_id,job_origin,run_id,step_id) REFERENCES public.zasp_compliance_export_jobs(organization_id,workspace_id,environment_id,export_id,job_origin,agent_run_id,agent_step_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id,step_id,action_key) REFERENCES public.zasp_security_agent_effects(organization_id,workspace_id,environment_id,run_id,step_id,action_key),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES public.zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id)
);
ALTER TABLE public.zasp_sa_export_links OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_sa_export_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_sa_export_links FORCE ROW LEVEL SECURITY;
CREATE POLICY zasp_sa_export_links_authority ON public.zasp_sa_export_links TO zasp_discovery_authority USING(true) WITH CHECK(true);
REVOKE ALL ON public.zasp_sa_export_links FROM PUBLIC;
ALTER TABLE public.zasp_compliance_export_jobs ADD CONSTRAINT zasp_sa_export_parent FOREIGN KEY(organization_id,workspace_id,environment_id,agent_run_id,agent_step_id) REFERENCES public.zasp_sa_export_links(organization_id,workspace_id,environment_id,run_id,step_id) DEFERRABLE INITIALLY DEFERRED;
