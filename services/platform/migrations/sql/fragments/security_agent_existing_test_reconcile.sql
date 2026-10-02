-- Reconciliation ownership is separate from authority to invoke a target.
ALTER TABLE public.zasp_security_agent_test_links
 ADD COLUMN reconcile_version bigint NOT NULL DEFAULT 1 CHECK(reconcile_version BETWEEN 1 AND 1000000),
 ADD COLUMN reconcile_generation uuid NOT NULL DEFAULT gen_random_uuid(),
 ADD COLUMN reconcile_state text NOT NULL DEFAULT 'pending' CHECK(reconcile_state IN('pending','leased','settled')),
 ADD COLUMN reconcile_worker text,
 ADD COLUMN reconcile_token bytea CHECK(reconcile_token IS NULL OR octet_length(reconcile_token)=32),
 ADD COLUMN reconcile_expires_at timestamptz,
 ADD COLUMN reconcile_next_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 ADD CONSTRAINT zasp_existing_test_reconcile_lease CHECK(
  reconcile_state='leased' AND reconcile_worker IS NOT NULL AND reconcile_token IS NOT NULL AND reconcile_expires_at IS NOT NULL
  OR reconcile_state IN('pending','settled') AND reconcile_worker IS NULL AND reconcile_token IS NULL AND reconcile_expires_at IS NULL);
CREATE INDEX zasp_existing_test_reconcile_due ON public.zasp_security_agent_test_links(organization_id,workspace_id,environment_id,reconcile_next_at,run_id,step_id) WHERE reconcile_state<>'settled';

-- Discovery exposes one due scope, never a link or target invocation authority.
-- An exhausted cursor returns an empty array; only the caller starts a new pass.
CREATE FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_scopes(after_o text,after_w text,after_e text,worker_value text,expected_checksum text,expected_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $scopes$
DECLARE result_value jsonb;
BEGIN
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_worker') AND NOT pg_has_role(session_user,'zasp_security_agent_api','MEMBER'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='test reconciler principal rejected';END IF;
 IF NOT COALESCE(worker_value~'^[a-z][a-z0-9.-]{2,127}$'
  AND ((after_o,after_w,after_e)=('','','') OR public.zasp_valid_product_id(after_o) AND public.zasp_valid_product_id(after_w) AND public.zasp_valid_product_id(after_e) AND after_o<>after_w AND after_o<>after_e AND after_w<>after_e),false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='test reconciler scope input rejected';END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='test reconciler release unavailable';END IF;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('organization_id',s.organization_id,'workspace_id',s.workspace_id,'environment_id',s.environment_id)),'[]'::jsonb) INTO result_value
 FROM (
  SELECT DISTINCT l.organization_id COLLATE "C" AS organization_id,l.workspace_id COLLATE "C" AS workspace_id,l.environment_id COLLATE "C" AS environment_id
  FROM public.zasp_security_agent_test_links l JOIN public.zasp_security_agent_org_admissions a USING(organization_id)
  WHERE (l.organization_id COLLATE "C",l.workspace_id COLLATE "C",l.environment_id COLLATE "C")>(after_o COLLATE "C",after_w COLLATE "C",after_e COLLATE "C")
   AND (l.reconcile_state='pending' AND l.reconcile_next_at<=clock_timestamp() OR l.reconcile_state='leased' AND l.reconcile_expires_at<=clock_timestamp())
  ORDER BY organization_id,workspace_id,environment_id LIMIT 1
 ) s;
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_worker') AND NOT pg_has_role(session_user,'zasp_security_agent_api','MEMBER'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='test reconciler principal rejected';END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='test reconciler release unavailable';END IF;
 RETURN result_value;
END
$scopes$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_scopes(text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_scopes(text,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_scopes(text,text,text,text,text,text) TO zasp_security_agent_worker;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_authorize(o text,w text,e text,worker_value text,lease_value bytea,expected_checksum text,expected_fingerprint text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $authorize$
BEGIN
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_worker'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='test reconciler principal rejected';END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND worker_value~'^[a-z][a-z0-9.-]{2,127}$' AND octet_length(lease_value)=32,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='test reconciler input rejected';END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='test reconciler release unavailable';END IF;
END
$authorize$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_authorize(text,text,text,text,bytea,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_authorize(text,text,text,text,bytea,text,text) FROM PUBLIC;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_claim(o text,w text,e text,worker_value text,lease_value bytea,seconds_value integer,limit_value integer,expected_checksum text,expected_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $claim$
DECLARE candidate record;link_row public.zasp_security_agent_test_links%ROWTYPE;result_value jsonb:='[]'::jsonb;
BEGIN
 PERFORM public.zasp_production_security_agent_existing_tests_reconcile_authorize(o,w,e,worker_value,lease_value,expected_checksum,expected_fingerprint);
 IF NOT COALESCE(seconds_value BETWEEN 10 AND 300 AND limit_value BETWEEN 1 AND 25,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='test reconciler claim bounds rejected';END IF;
 -- Follow existing organization-before-parent-before-link order; a busy tenant
 -- or parent is skipped instead of blocking a polling worker.
 IF NOT pg_try_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0)) THEN RETURN result_value;END IF;
 PERFORM 1 FROM public.zasp_security_agent_org_admissions WHERE organization_id=o FOR UPDATE SKIP LOCKED;
 IF NOT FOUND THEN RETURN result_value;END IF;
 FOR candidate IN SELECT l.run_id,l.step_id FROM public.zasp_security_agent_test_links l
  JOIN public.zasp_security_agent_runs p ON (p.organization_id,p.workspace_id,p.environment_id,p.run_id)=(l.organization_id,l.workspace_id,l.environment_id,l.run_id)
  WHERE (l.organization_id,l.workspace_id,l.environment_id)=(o,w,e)
   AND (l.reconcile_state='pending' AND l.reconcile_next_at<=clock_timestamp() OR l.reconcile_state='leased' AND l.reconcile_expires_at<=clock_timestamp())
  ORDER BY l.reconcile_next_at,l.run_id,l.step_id LIMIT limit_value FOR UPDATE OF p SKIP LOCKED LOOP
  PERFORM 1 FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,candidate.run_id,candidate.step_id)
   AND (reconcile_state='pending' AND reconcile_next_at<=clock_timestamp() OR reconcile_state='leased' AND reconcile_expires_at<=clock_timestamp()) FOR UPDATE SKIP LOCKED;
  CONTINUE WHEN NOT FOUND;
  UPDATE public.zasp_security_agent_test_links SET reconcile_state='leased',reconcile_version=CASE WHEN reconcile_version=1000000 THEN 1 ELSE reconcile_version+1 END,reconcile_generation=gen_random_uuid(),reconcile_worker=worker_value,reconcile_token=digest(lease_value,'sha256'),reconcile_expires_at=clock_timestamp()+make_interval(secs=>seconds_value)
   WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,candidate.run_id,candidate.step_id) RETURNING * INTO link_row;
  result_value:=result_value||jsonb_build_array(jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'run_id',link_row.run_id,'step_id',link_row.step_id,'test_run_id',link_row.test_run_id,'version',link_row.reconcile_version,'generation',link_row.reconcile_generation,'lease_expires_at',to_char(link_row.reconcile_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')));
 END LOOP;
 PERFORM public.zasp_production_security_agent_existing_tests_reconcile_authorize(o,w,e,worker_value,lease_value,expected_checksum,expected_fingerprint);
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(result_value) item WHERE (item->>'lease_expires_at')::timestamptz<=clock_timestamp()) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test reconciler claim expired';END IF;
 RETURN result_value;
END
$claim$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_claim(text,text,text,text,bytea,integer,integer,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_claim(text,text,text,text,bytea,integer,integer,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_claim(text,text,text,text,bytea,integer,integer,text,text) TO zasp_security_agent_worker;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_lock(o text,w text,e text,r text,s text,worker_value text,lease_value bytea,version_value bigint,generation_value uuid,expected_checksum text,expected_fingerprint text)
RETURNS timestamptz LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $lock$
DECLARE deadline timestamptz;
BEGIN
 PERFORM public.zasp_production_security_agent_existing_tests_reconcile_authorize(o,w,e,worker_value,lease_value,expected_checksum,expected_fingerprint);
 IF NOT COALESCE(public.zasp_valid_product_id(r) AND public.zasp_valid_product_id(s) AND version_value BETWEEN 1 AND 1000000 AND generation_value<>'00000000-0000-0000-0000-000000000000'::uuid,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='test reconciler ownership input rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 PERFORM 1 FROM public.zasp_security_agent_org_admissions WHERE organization_id=o FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test reconciler organization changed';END IF;
 PERFORM 1 FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test reconciler parent changed';END IF;
 SELECT reconcile_expires_at INTO deadline FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id,reconcile_state,reconcile_worker,reconcile_token,reconcile_version,reconcile_generation)=(o,w,e,r,s,'leased',worker_value,digest(lease_value,'sha256'),version_value,generation_value) FOR UPDATE;
 IF NOT FOUND OR deadline<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test reconciler ownership changed';END IF;
 RETURN deadline;
END
$lock$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_lock(text,text,text,text,text,text,bytea,bigint,uuid,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_lock(text,text,text,text,text,text,bytea,bigint,uuid,text,text) FROM PUBLIC;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_cancel_stopped(o text,w text,e text,r text,s text,worker_value text,lease_value bytea,version_value bigint,generation_value uuid,expected_checksum text,expected_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $stop$
DECLARE deadline timestamptz;parent_state text;test_run text;run_row public.zasp_red_team_runs%ROWTYPE;outcome_value text;changed boolean:=false;
BEGIN
 deadline:=public.zasp_production_security_agent_existing_tests_reconcile_lock(o,w,e,r,s,worker_value,lease_value,version_value,generation_value,expected_checksum,expected_fingerprint);
 SELECT state INTO STRICT parent_state FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT test_run_id INTO STRICT test_run FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 SELECT * INTO STRICT run_row FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,test_run) FOR UPDATE;
 IF parent_state IN('cancelled','failed','inconclusive','needs_human') AND run_row.state NOT IN('complete','failed','cancelled') THEN
  SELECT * INTO STRICT run_row FROM public.zasp_production_security_agent_existing_tests_cancel_transition(o,w,e,test_run);
  changed:=true;
 END IF;
 SELECT cancellation_outcome INTO STRICT outcome_value FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 PERFORM public.zasp_production_security_agent_existing_tests_reconcile_authorize(o,w,e,worker_value,lease_value,expected_checksum,expected_fingerprint);
 IF deadline<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stopped test reconciliation expired';END IF;
 RETURN jsonb_build_object('test_run_id',test_run,'state',run_row.state,'cancellation_outcome',outcome_value,'changed',changed,'generation',generation_value);
END
$stop$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_cancel_stopped(text,text,text,text,text,text,bytea,bigint,uuid,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_cancel_stopped(text,text,text,text,text,text,bytea,bigint,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_cancel_stopped(text,text,text,text,text,text,bytea,bigint,uuid,text,text) TO zasp_security_agent_worker;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_evidence(o text,w text,e text,r text,s text,worker_value text,lease_value bytea,version_value bigint,generation_value uuid,expected_checksum text,expected_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $read$
DECLARE deadline timestamptz;value jsonb;
BEGIN
 deadline:=public.zasp_production_security_agent_existing_tests_reconcile_lock(o,w,e,r,s,worker_value,lease_value,version_value,generation_value,expected_checksum,expected_fingerprint);
 value:=public.zasp_production_security_agent_existing_tests_evidence_snapshot(o,w,e,r,s);
 PERFORM public.zasp_production_security_agent_existing_tests_reconcile_authorize(o,w,e,worker_value,lease_value,expected_checksum,expected_fingerprint);
 IF deadline<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test reconciler read expired';END IF;
 RETURN jsonb_build_object('version',version_value,'generation',generation_value,'lease_expires_at',to_char(deadline AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'snapshot',value);
END
$read$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_evidence(text,text,text,text,text,text,bytea,bigint,uuid,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_evidence(text,text,text,text,text,text,bytea,bigint,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_evidence(text,text,text,text,text,text,bytea,bigint,uuid,text,text) TO zasp_security_agent_worker;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_heartbeat(o text,w text,e text,r text,s text,worker_value text,lease_value bytea,version_value bigint,generation_value uuid,seconds_value integer,expected_checksum text,expected_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $heartbeat$
DECLARE deadline timestamptz;renewed timestamptz;
BEGIN
 IF NOT COALESCE(seconds_value BETWEEN 10 AND 300,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='test reconciler renewal bounds rejected';END IF;
 deadline:=public.zasp_production_security_agent_existing_tests_reconcile_lock(o,w,e,r,s,worker_value,lease_value,version_value,generation_value,expected_checksum,expected_fingerprint);
 UPDATE public.zasp_security_agent_test_links SET reconcile_expires_at=clock_timestamp()+make_interval(secs=>seconds_value)
  WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s) RETURNING reconcile_expires_at INTO renewed;
 PERFORM public.zasp_production_security_agent_existing_tests_reconcile_authorize(o,w,e,worker_value,lease_value,expected_checksum,expected_fingerprint);
 IF deadline<=clock_timestamp() OR renewed<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test reconciler renewal expired';END IF;
 RETURN jsonb_build_object('run_id',r,'step_id',s,'version',version_value,'generation',generation_value,'lease_expires_at',to_char(renewed AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
END
$heartbeat$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_heartbeat(text,text,text,text,text,text,bytea,bigint,uuid,integer,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_heartbeat(text,text,text,text,text,text,bytea,bigint,uuid,integer,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_heartbeat(text,text,text,text,text,text,bytea,bigint,uuid,integer,text,text) TO zasp_security_agent_worker;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_release(o text,w text,e text,r text,s text,worker_value text,lease_value bytea,version_value bigint,generation_value uuid,delay_value integer,expected_checksum text,expected_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $release$
DECLARE deadline timestamptz;next_value timestamptz;
BEGIN
 IF NOT COALESCE(delay_value BETWEEN 10 AND 300 AND version_value BETWEEN 1 AND 1000000,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='test reconciler release bounds rejected';END IF;
 deadline:=public.zasp_production_security_agent_existing_tests_reconcile_lock(o,w,e,r,s,worker_value,lease_value,version_value,generation_value,expected_checksum,expected_fingerprint);
 UPDATE public.zasp_security_agent_test_links SET reconcile_state='pending',reconcile_version=LEAST(reconcile_version+1,1000000),reconcile_worker=NULL,reconcile_token=NULL,reconcile_expires_at=NULL,reconcile_next_at=clock_timestamp()+make_interval(secs=>delay_value)
  WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s) RETURNING reconcile_next_at INTO next_value;
 PERFORM public.zasp_production_security_agent_existing_tests_reconcile_authorize(o,w,e,worker_value,lease_value,expected_checksum,expected_fingerprint);
 IF deadline<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test reconciler release expired';END IF;
 RETURN jsonb_build_object('run_id',r,'step_id',s,'version',LEAST(version_value+1,1000000),'generation',generation_value,'state','pending','next_check_at',to_char(next_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
END
$release$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_release(text,text,text,text,text,text,bytea,bigint,uuid,integer,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_release(text,text,text,text,text,text,bytea,bigint,uuid,integer,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_reconcile_release(text,text,text,text,text,text,bytea,bigint,uuid,integer,text,text) TO zasp_security_agent_worker;
