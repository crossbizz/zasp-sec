CREATE ROLE zasp_temporal74_parent_lock NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT USAGE ON SCHEMA public,zasp_temporal74 TO zasp_temporal74_parent_lock;
GRANT SELECT,UPDATE(version) ON public.zasp_security_agent_runs TO zasp_temporal74_parent_lock;
CREATE POLICY zasp_temporal74_lock ON public.zasp_security_agent_runs FOR SELECT TO zasp_temporal74_parent_lock USING(true);
CREATE POLICY zasp_temporal74_lock_update ON public.zasp_security_agent_runs FOR UPDATE TO zasp_temporal74_parent_lock USING(true) WITH CHECK(false);
ALTER POLICY zasp_temporal74_owner ON public.zasp_security_agent_runs USING(current_user IN('zasp_temporal_accounting','zasp_temporal74_parent_lock') OR zasp_temporal74.visible(organization_id,workspace_id,environment_id,run_id));
ALTER POLICY zasp_temporal74_owner ON public.zasp_security_agent_effects USING(zasp_temporal74.visible(organization_id,workspace_id,environment_id,run_id) OR current_user='zasp_discovery_authority' AND (zasp_temporal68.adapter_principal_ready() OR zasp_temporal74.is_owned(organization_id,workspace_id,environment_id,run_id) AND public.zasp_red_team_principal_ready('zasp_red_team_worker')));
CREATE POLICY zasp_temporal74_effect_update ON public.zasp_security_agent_effects AS RESTRICTIVE FOR UPDATE USING(zasp_temporal74.visible(organization_id,workspace_id,environment_id,run_id)) WITH CHECK(zasp_temporal74.visible(organization_id,workspace_id,environment_id,run_id));
CREATE POLICY zasp_temporal74_effect_delete ON public.zasp_security_agent_effects AS RESTRICTIVE FOR DELETE USING(zasp_temporal74.visible(organization_id,workspace_id,environment_id,run_id));

CREATE FUNCTION zasp_temporal74.lock_identity(o text,w text,e text,r text,c text,k text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $identity$
 SELECT zasp_temporal68.adapter_principal_ready() AND EXISTS(SELECT 1 FROM zasp_temporal74.run_owners x JOIN zasp_temporal74.effects f USING(organization_id,workspace_id,environment_id,run_id,step_id,action_key) JOIN public.zasp_security_agent_test_links l USING(organization_id,workspace_id,environment_id,run_id,step_id,test_run_id,action_key)
 WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.test_run_id,f.effect_key)=(o,w,e,r,c,k) AND f.effect_key=zasp_temporal74.effect_identity(o,w,e,r,x.step_id,1) AND f.input_digest=l.input_digest AND f.snapshot->'targets'->>'test_run_id'=c)
$identity$;
-- Only the registered adapter's verified74 entry can reach this helper. This
-- role can lock the parent, but the mutation trigger rejects its actual writes.
CREATE FUNCTION zasp_temporal74.lock_parent(o text,w text,e text,r text,c text,k text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $lock$
DECLARE result_value jsonb;
BEGIN
 IF NOT zasp_temporal74.lock_identity(o,w,e,r,c,k) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test parent lock identity rejected';END IF;
 SELECT to_jsonb(rr) INTO STRICT result_value FROM public.zasp_security_agent_runs rr WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT zasp_temporal74.lock_identity(o,w,e,r,c,k) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test parent lock identity changed';END IF;
 RETURN result_value;
END $lock$;

CREATE TABLE zasp_temporal74.invocations(LIKE public.zasp_security_agent_test_invocations INCLUDING DEFAULTS INCLUDING CONSTRAINTS);
ALTER TABLE zasp_temporal74.invocations DROP COLUMN lease_digest,ADD effect_key text NOT NULL,
 ADD PRIMARY KEY(organization_id,workspace_id,environment_id,test_run_id,category),ADD CHECK(attempt=1),
 ADD FOREIGN KEY(effect_key) REFERENCES zasp_temporal74.effects(effect_key),
 ADD FOREIGN KEY(organization_id,workspace_id,environment_id,test_run_id) REFERENCES zasp_temporal74.test_inputs(organization_id,workspace_id,environment_id,test_run_id);
ALTER TABLE zasp_temporal74.invocations OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_temporal74.invocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_temporal74.invocations FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_temporal74.invocations USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
CREATE FUNCTION zasp_temporal74.adapter_ready(c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT zasp_temporal74.ready(c,f) AND zasp_temporal68.adapter_principal_ready()
$ready$;

CREATE FUNCTION zasp_temporal74.adapter_protocol(o text,w text,e text,c text,k text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $protocol$
DECLARE l public.zasp_security_agent_test_links%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='single-test adapter requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal74.current_ready() OR NOT zasp_temporal68.adapter_principal_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test adapter unavailable';END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(c) AND k~'^[a-f0-9]{64}$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='single-test adapter scope rejected';END IF;
 SELECT * INTO l FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,c);
 IF l.test_run_id IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='effect child unavailable';END IF;
 IF zasp_temporal74.is_owned(o,w,e,l.run_id) THEN
  IF NOT zasp_temporal74.lock_identity(o,w,e,l.run_id,c,k) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test adapter effect rejected';END IF;
  RETURN jsonb_build_object('protocol','single_test74');
 ELSIF zasp_temporal66.is_temporal(o,w,e,l.run_id) AND EXISTS(SELECT 1 FROM zasp_temporal68.effects f WHERE (f.organization_id,f.workspace_id,f.environment_id,f.run_id,f.step_id,f.generation,f.action_key,f.effect_key,f.input_digest)=(o,w,e,l.run_id,l.step_id,1,'run_test',k,l.input_digest) AND f.snapshot->'targets'->>'test_run_id'=c AND f.effect_key=zasp_temporal68.effect_identity(o,w,e,l.run_id,l.step_id,1)) THEN
  RETURN jsonb_build_object('protocol','ordered68');
 END IF;
 RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='effect adapter owner rejected';
END $protocol$;

INSERT INTO zasp_temporal74.predecessor_functions SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc WHERE oid=ANY(ARRAY[
 'public.zasp_sa_manual_provenance(text,text,text,text)'::regprocedure,'zasp_temporal68.linked(jsonb)'::regprocedure,
 'zasp_temporal68.test_intent_valid(text,text,text,text,text)'::regprocedure,'zasp_temporal68.invocation(jsonb)'::regprocedure]);
DO $copies$ DECLARE d text;needle text;BEGIN
 -- The adapter gets a locked row from lock_parent. These private predicates
 -- validate that row without reopening broad parent visibility to old71.
 d:=pg_get_functiondef('zasp_temporal74.authorize(text,text,text,text,bigint)'::regprocedure);
 d:=replace(d,'FUNCTION zasp_temporal74.authorize(','FUNCTION zasp_temporal74.service_current(');
 d:=replace(d,' OR NOT zasp_temporal68.principal_ready(''zasp_temporal_executor'')','');EXECUTE d;
 SELECT definition INTO STRICT d FROM zasp_temporal74.predecessor_functions WHERE signature='zasp_sa_manual_provenance(text,text,text,text)';
 d:=replace(d,'FUNCTION public.zasp_sa_manual_provenance(o text, w text, e text, r text)','FUNCTION zasp_temporal74.manual_parent(o text, w text, e text, r text, parent_value jsonb)');
 needle:='SELECT * INTO STRICT rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);';
 IF strpos(d,needle)=0 THEN RAISE EXCEPTION 'single-test manual parent predecessor changed';END IF;
 EXECUTE replace(d,needle,'rr:=jsonb_populate_record(NULL::public.zasp_security_agent_runs,parent_value);');
 d:=pg_get_functiondef('zasp_temporal74.context(text,text,text,text)'::regprocedure);
 d:=replace(d,'FUNCTION zasp_temporal74.context(o text, w text, e text, r text)','FUNCTION zasp_temporal74.context_parent(o text, w text, e text, r text, parent_value jsonb)');
 needle:='SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR SHARE;';
 IF strpos(d,needle)=0 THEN RAISE EXCEPTION 'single-test context parent changed';END IF;
 d:=replace(d,needle,'rr:=jsonb_populate_record(NULL::public.zasp_security_agent_runs,parent_value);');
 d:=replace(d,'public.zasp_sa_manual_provenance(o,w,e,r)','zasp_temporal74.manual_parent(o,w,e,r,parent_value)');
 EXECUTE replace(d,'zasp_temporal74.authorize(','zasp_temporal74.service_current(');
 d:=pg_get_functiondef('zasp_temporal74.current_step(text,text,text,text,text)'::regprocedure);
 d:=replace(d,'FUNCTION zasp_temporal74.current_step(o text, w text, e text, r text, s text)','FUNCTION zasp_temporal74.step_parent(o text, w text, e text, r text, s text, parent_value jsonb)');
 needle:='SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;';
 IF strpos(d,needle)=0 THEN RAISE EXCEPTION 'single-test step parent changed';END IF;
 d:=replace(d,needle,'rr:=jsonb_populate_record(NULL::public.zasp_security_agent_runs,parent_value);');
 d:=replace(d,'zasp_temporal74.authorize(','zasp_temporal74.service_current(');
 EXECUTE replace(d,'zasp_temporal74.context(o,w,e,r)','zasp_temporal74.context_parent(o,w,e,r,parent_value)');
 SELECT definition INTO STRICT d FROM zasp_temporal74.predecessor_functions WHERE signature='zasp_temporal68.linked(jsonb)';
 d:=replace(d,'zasp_temporal68.','zasp_temporal74.');d:=replace(d,'zasp_temporal74.principal_ready(','zasp_temporal68.principal_ready(');
 d:=replace(d,'zasp_sa_multistep_prior.test_current(','zasp_temporal74.current_step(');
 d:=replace(d,$old$intent->>'action_key' IS DISTINCT FROM 'run_test'$old$,$new$intent->>'action_key' NOT IN('run_test','rerun_test')$new$);
 d:=replace(d,$old$decode(intent->'snapshot'->>'input_digest','hex'),'run_test'::text$old$,$new$decode(intent->'snapshot'->>'input_digest','hex'),intent->>'action_key'$new$);EXECUTE d;
 SELECT definition INTO STRICT d FROM zasp_temporal74.predecessor_functions WHERE signature='zasp_temporal68.test_intent_valid(text,text,text,text,text)';
 d:=replace(d,'zasp_temporal68.','zasp_temporal74.');
 d:=replace(d,'FUNCTION zasp_temporal74.test_intent_valid(o text, w text, e text, r text, s text)','FUNCTION zasp_temporal74.test_intent_valid(o text, w text, e text, r text, s text, parent_value jsonb)');
 d:=replace(d,'JOIN public.zasp_security_agent_runs rr','JOIN jsonb_populate_record(NULL::public.zasp_security_agent_runs,parent_value) rr');
 d:=replace(d,$old$(f.organization_id,f.workspace_id,f.environment_id,f.run_id,f.step_id,f.generation,f.action_key)=(o,w,e,r,s,1,'run_test')$old$,$new$(f.organization_id,f.workspace_id,f.environment_id,f.run_id,f.step_id,f.generation)=(o,w,e,r,s,1) AND f.action_key IN('run_test','rerun_test')$new$);
 d:=replace(d,$old$r||chr(31)||'1'$old$,$new$r||chr(31)||'0'$new$);
 d:=replace(d,$old$s||chr(31)||'run_test'$old$,$new$s||chr(31)||f.action_key$new$);
 d:=replace(d,'st.step_index=1','st.step_index=0');
 d:=replace(d,$old$('run_test','run_test','run_test','run_test')$old$,$new$(f.action_key,f.action_key,f.action_key,f.action_key)$new$);EXECUTE d;
 SELECT definition INTO STRICT d FROM zasp_temporal74.predecessor_functions WHERE signature='zasp_temporal68.invocation(jsonb)';
 d:=replace(d,'zasp_temporal68.','zasp_temporal74.');d:=replace(d,'zasp_temporal74.adapter_principal_ready(','zasp_temporal68.adapter_principal_ready(');
 d:=replace(d,'zasp_temporal66.is_temporal(','zasp_temporal74.is_owned(');
 d:=replace(d,'new_start boolean:=false;','new_start boolean:=false;parent_value jsonb;');
 needle:='PERFORM zasp_sa_multistep_prior.test_lock(o,w,e,link.run_id);'||chr(10)||' PERFORM zasp_temporal74.current_plan(o,w,e,link.run_id,false);';
 IF strpos(d,needle)=0 THEN RAISE EXCEPTION 'single-test invocation parent predecessor changed';END IF;
 d:=replace(d,needle,$new$PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 parent_value:=zasp_temporal74.lock_parent(o,w,e,link.run_id,child_id,key_value);$new$);
 d:=replace(d,$old$(organization_id,workspace_id,environment_id,run_id,step_id,generation,effect_key,action_key)=(o,w,e,link.run_id,link.step_id,1,key_value,'run_test')$old$,$new$(organization_id,workspace_id,environment_id,run_id,step_id,generation,effect_key,action_key)=(o,w,e,link.run_id,link.step_id,1,key_value,link.action_key)$new$);
 d:=replace(d,'zasp_temporal74.test_intent_valid(o,w,e,link.run_id,link.step_id)','zasp_temporal74.test_intent_valid(o,w,e,link.run_id,link.step_id,parent_value)');
 d:=replace(d,'zasp_sa_multistep_prior.test_current(o,w,e,link.run_id,link.step_id)','zasp_temporal74.step_parent(o,w,e,link.run_id,link.step_id,parent_value)');
 EXECUTE d;
END $copies$;
