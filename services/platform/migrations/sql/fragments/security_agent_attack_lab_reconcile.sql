-- This capability drains existing links only. No execution/core/table grants.
CREATE FUNCTION public.zasp_sa_attack_lab_reconcile_authorize(worker_value text,expected_checksum text,expected_fingerprint text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $authorize$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.zasp_sa_attack_lab_principals WHERE principal_name=session_user AND authority_role='zasp_security_agent_attack_lab_reconciler') OR NOT pg_has_role(session_user,'zasp_security_agent_attack_lab_reconciler','USAGE') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='attack lab reconciler rejected';END IF;
 IF NOT COALESCE(worker_value~'^[a-z][a-z0-9.-]{2,127}$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab worker rejected';END IF;
 IF NOT public.zasp_sa_attack_lab_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack lab release unavailable';END IF;
END $authorize$;

CREATE FUNCTION public.zasp_sa_attack_lab_reconcile_scopes(after_o text,after_w text,after_e text,worker_value text,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $scopes$
DECLARE result_value jsonb;
BEGIN
 PERFORM public.zasp_sa_attack_lab_reconcile_authorize(worker_value,expected_checksum,expected_fingerprint);
 IF NOT COALESCE((after_o,after_w,after_e)=('','','') OR public.zasp_valid_product_id(after_o) AND public.zasp_valid_product_id(after_w) AND public.zasp_valid_product_id(after_e),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab cursor rejected';END IF;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id)),'[]'::jsonb) INTO result_value FROM (
  SELECT DISTINCT organization_id COLLATE "C" organization_id,workspace_id COLLATE "C" workspace_id,environment_id COLLATE "C" environment_id FROM public.zasp_sa_attack_lab_links
  WHERE settled_at IS NULL AND available_at<=clock_timestamp() AND (lease_expires_at IS NULL OR lease_expires_at<=clock_timestamp())
   AND (organization_id COLLATE "C",workspace_id COLLATE "C",environment_id COLLATE "C")>(after_o COLLATE "C",after_w COLLATE "C",after_e COLLATE "C")
  ORDER BY organization_id,workspace_id,environment_id LIMIT 1) due;
 RETURN result_value;
END $scopes$;

CREATE FUNCTION public.zasp_sa_attack_lab_claim_json(l public.zasp_sa_attack_lab_links) RETURNS jsonb LANGUAGE sql SET search_path TO pg_catalog,public AS $claim_json$
 SELECT jsonb_build_object('organization_id',l.organization_id,'workspace_id',l.workspace_id,'environment_id',l.environment_id,'run_id',l.run_id,'step_id',l.step_id,'execution_id',l.execution_id,'version',l.version,'generation',l.generation,'lease_expires_at',to_char(l.lease_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
$claim_json$;

CREATE FUNCTION public.zasp_sa_attack_lab_reconcile_claim(o text,w text,e text,worker_value text,lease_value bytea,seconds_value integer,batch_value integer,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $claim$
DECLARE candidate record;l public.zasp_sa_attack_lab_links%ROWTYPE;result_value jsonb:='[]'::jsonb;
BEGIN
 PERFORM public.zasp_sa_attack_lab_reconcile_authorize(worker_value,expected_checksum,expected_fingerprint);
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND octet_length(lease_value)=32 AND seconds_value=60 AND batch_value=1,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab claim rejected';END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0)) THEN RETURN result_value;END IF;
 PERFORM 1 FROM public.zasp_security_agent_org_admissions WHERE organization_id=o FOR UPDATE SKIP LOCKED;
 IF NOT FOUND THEN RETURN result_value;END IF;
 FOR candidate IN SELECT p.run_id,link.step_id FROM public.zasp_security_agent_runs p JOIN public.zasp_sa_attack_lab_links link USING(organization_id,workspace_id,environment_id,run_id)
  WHERE (link.organization_id,link.workspace_id,link.environment_id)=(o,w,e) AND link.settled_at IS NULL AND link.available_at<=clock_timestamp() AND (link.lease_expires_at IS NULL OR link.lease_expires_at<=clock_timestamp())
  ORDER BY link.available_at,link.run_id,link.step_id LIMIT 1 FOR UPDATE OF p SKIP LOCKED LOOP
  SELECT * INTO l FROM public.zasp_sa_attack_lab_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,candidate.run_id,candidate.step_id) AND settled_at IS NULL AND (lease_expires_at IS NULL OR lease_expires_at<=clock_timestamp()) FOR UPDATE SKIP LOCKED;
  CONTINUE WHEN NOT FOUND;
  UPDATE public.zasp_sa_attack_lab_links SET version=version+1,generation=gen_random_uuid(),lease_owner=worker_value,lease_token=digest(lease_value,'sha256'),lease_expires_at=clock_timestamp()+interval '60 seconds' WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,candidate.run_id,candidate.step_id) RETURNING * INTO l;
  result_value:=jsonb_build_array(public.zasp_sa_attack_lab_claim_json(l));
 END LOOP;
 PERFORM public.zasp_sa_attack_lab_reconcile_authorize(worker_value,expected_checksum,expected_fingerprint);
 IF l.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab claim expired';END IF;
 RETURN result_value;
END $claim$;

CREATE FUNCTION public.zasp_sa_attack_lab_reconcile_lock(o text,w text,e text,r text,s text,worker_value text,lease_value bytea,version_value bigint,generation_value uuid,expected_checksum text,expected_fingerprint text) RETURNS timestamptz LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $lock$
DECLARE deadline timestamptz;
BEGIN
 PERFORM public.zasp_sa_attack_lab_reconcile_authorize(worker_value,expected_checksum,expected_fingerprint);
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(r) AND public.zasp_valid_product_id(s) AND octet_length(lease_value)=32 AND version_value>0 AND generation_value<>'00000000-0000-0000-0000-000000000000'::uuid,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab ownership rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 PERFORM 1 FROM public.zasp_security_agent_org_admissions WHERE organization_id=o FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab organization unavailable';END IF;
 PERFORM 1 FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab parent unavailable';END IF;
 SELECT lease_expires_at INTO deadline FROM public.zasp_sa_attack_lab_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id,lease_owner,lease_token,version,generation)=(o,w,e,r,s,worker_value,digest(lease_value,'sha256'),version_value,generation_value) AND settled_at IS NULL FOR UPDATE;
 IF NOT FOUND OR deadline<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab ownership changed';END IF;
 RETURN deadline;
END $lock$;

CREATE FUNCTION public.zasp_sa_attack_lab_reconcile_heartbeat(o text,w text,e text,r text,s text,worker_value text,lease_value bytea,version_value bigint,generation_value uuid,seconds_value integer,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $heartbeat$
DECLARE deadline timestamptz;l public.zasp_sa_attack_lab_links%ROWTYPE;
BEGIN
 IF seconds_value IS DISTINCT FROM 60 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab renewal rejected';END IF;
 deadline:=public.zasp_sa_attack_lab_reconcile_lock(o,w,e,r,s,worker_value,lease_value,version_value,generation_value,expected_checksum,expected_fingerprint);
 UPDATE public.zasp_sa_attack_lab_links SET version=version+1,generation=gen_random_uuid(),lease_expires_at=clock_timestamp()+interval '60 seconds' WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s) RETURNING * INTO l;
 PERFORM public.zasp_sa_attack_lab_reconcile_authorize(worker_value,expected_checksum,expected_fingerprint);
 IF deadline<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab renewal expired';END IF;
 RETURN public.zasp_sa_attack_lab_claim_json(l);
END $heartbeat$;

CREATE FUNCTION public.zasp_sa_attack_lab_reconcile_cancel_stopped(o text,w text,e text,r text,s text,worker_value text,lease_value bytea,version_value bigint,generation_value uuid,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $cancel$
DECLARE deadline timestamptz;l public.zasp_sa_attack_lab_links%ROWTYPE;a public.zasp_attack_lab_runs%ROWTYPE;changed boolean:=false;stopped boolean;control_stopped boolean:=false;control_count integer:=0;control_value record;
BEGIN
 PERFORM public.zasp_sa_attack_lab_reconcile_authorize(worker_value,expected_checksum,expected_fingerprint);
 -- Match admission's controls-before-parent ordering. Disabled or missing
 -- controls stop execution, but cannot discard its retained cleanup link.
 FOR control_value IN SELECT execution_enabled FROM public.zasp_security_agent_kill_switches
  WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*') OR (organization_id,workspace_id,environment_id)=(o,w,e) AND action_key IN('*','start_attack_lab')
  ORDER BY organization_id,workspace_id,environment_id,action_key FOR SHARE LOOP
  control_count:=control_count+1;control_stopped:=control_stopped OR NOT control_value.execution_enabled;
 END LOOP;
 deadline:=public.zasp_sa_attack_lab_reconcile_lock(o,w,e,r,s,worker_value,lease_value,version_value,generation_value,expected_checksum,expected_fingerprint);
 SELECT * INTO STRICT l FROM public.zasp_sa_attack_lab_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 SELECT * INTO STRICT a FROM public.zasp_attack_lab_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,l.execution_id) FOR UPDATE;
 SELECT state IN('cancelled','failed','inconclusive','needs_human') INTO stopped FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 stopped:=stopped OR control_stopped OR control_count<>3 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND (stop_reason IS NOT NULL OR deadline_at<=clock_timestamp()));
 IF stopped AND a.state NOT IN('complete','failed','cancelled') AND NOT a.cancel_requested THEN
  PERFORM public.zasp_sa_attack_lab_cancel_run_core(o,w,e,l.approver_id,'agent-stop:'||l.execution_id,l.execution_id,a.version,public.zasp_discovery_canonical_id(o,w,e,'security_agent_attack_lab_cancel',r||chr(31)||s));
  changed:=true;
  SELECT * INTO STRICT a FROM public.zasp_attack_lab_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,l.execution_id);
 END IF;
 PERFORM public.zasp_sa_attack_lab_reconcile_authorize(worker_value,expected_checksum,expected_fingerprint);
 IF deadline<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab cancellation lease expired';END IF;
 RETURN jsonb_build_object('execution_id',l.execution_id,'state',a.state,'cancel_requested',a.cancel_requested,'changed',changed,'version',version_value,'generation',generation_value);
END $cancel$;

CREATE FUNCTION public.zasp_sa_attack_lab_reconcile_release(o text,w text,e text,r text,s text,worker_value text,lease_value bytea,version_value bigint,generation_value uuid,delay_value integer,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $release$
DECLARE deadline timestamptz;next_value timestamptz;
BEGIN
 IF NOT COALESCE(delay_value BETWEEN 10 AND 300,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab delay rejected';END IF;
 deadline:=public.zasp_sa_attack_lab_reconcile_lock(o,w,e,r,s,worker_value,lease_value,version_value,generation_value,expected_checksum,expected_fingerprint);
 UPDATE public.zasp_sa_attack_lab_links SET version=version+1,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,available_at=clock_timestamp()+make_interval(secs=>delay_value) WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s) RETURNING available_at INTO next_value;
 PERFORM public.zasp_sa_attack_lab_reconcile_authorize(worker_value,expected_checksum,expected_fingerprint);
 IF deadline<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab release expired';END IF;
 RETURN jsonb_build_object('run_id',r,'step_id',s,'version',version_value+1,'generation',generation_value,'state','pending','next_check_at',to_char(next_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
END $release$;

GRANT EXECUTE ON FUNCTION public.zasp_sa_attack_lab_reconcile_scopes(text,text,text,text,text,text),public.zasp_sa_attack_lab_reconcile_claim(text,text,text,text,bytea,integer,integer,text,text),public.zasp_sa_attack_lab_reconcile_heartbeat(text,text,text,text,text,text,bytea,bigint,uuid,integer,text,text),public.zasp_sa_attack_lab_reconcile_cancel_stopped(text,text,text,text,text,text,bytea,bigint,uuid,text,text),public.zasp_sa_attack_lab_reconcile_release(text,text,text,text,text,text,bytea,bigint,uuid,integer,text,text) TO zasp_security_agent_attack_lab_reconciler;
