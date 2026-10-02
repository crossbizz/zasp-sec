-- Public admission is separate from settlement capability. These entrypoints
-- never infer worker health; the API's connected capability gates fresh work.
CREATE FUNCTION public.zasp_sa_export_workflow_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT public.zasp_sa_export_readiness(expected_checksum,expected_fingerprint)
$ready$;

CREATE FUNCTION public.zasp_sa_export_definition_authority(o text,w text,e text,actor text,permission_value text,checksum_value text,fingerprint_value text) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $authority$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR NOT public.zasp_sa_export_principal_ready('zasp_security_agent_api') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export definition principal unavailable';END IF;
 IF NOT public.zasp_sa_export_workflow_readiness(checksum_value,fingerprint_value) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export definition release unavailable';END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(actor),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export definition scope rejected';END IF;
 PERFORM 1 FROM public.zasp_identity_memberships WHERE (organization_id,principal_id,active)=(o,actor,true) FOR SHARE;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM public.zasp_identity_admin_effective_scopes(actor,o) s WHERE (s.organization_id,s.workspace_id,s.environment_id)=(o,w,e) AND s.permissions ?& ARRAY['view',permission_value]) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export definition permission rejected';END IF;
END $authority$;

CREATE FUNCTION public.zasp_sa_export_definition_shape(o text,w text,e text,d text,b jsonb) RETURNS void LANGUAGE plpgsql SET search_path TO pg_catalog,public AS $shape$
DECLARE k text;maximum bigint;
BEGIN
 IF NOT COALESCE(public.zasp_valid_product_id(d) AND jsonb_typeof(b)='object' AND b->>'id'=d AND b->'allowed_actions'='["create_evidence_export"]'::jsonb AND b->>'verification_kind'='export' AND b->'environment_ids'=jsonb_build_array(e) AND b->>'autonomy' IN('supervised','autonomous') AND b->'max_steps'='1'::jsonb AND jsonb_typeof(b->'enabled')='boolean',false)
 OR b-ARRAY['id','name','trigger_kind','trigger_source','environment_ids','autonomy','max_steps','max_duration_seconds','temporary_policy_seconds','ai_token_budget','max_ai_cost_nano_credits','concurrency_limit','allowed_actions','verification_kind','definition_version','enabled']<>'{}'::jsonb THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export definition shape rejected';END IF;
 FOREACH k IN ARRAY ARRAY['name','trigger_kind','trigger_source'] LOOP
  IF NOT COALESCE(jsonb_typeof(b->k)='string' AND length(b->>k) BETWEEN 1 AND CASE k WHEN 'name' THEN 256 ELSE 64 END AND btrim(b->>k)=b->>k AND b->>k !~ '[[:cntrl:]]',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export definition text rejected';END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['max_duration_seconds','temporary_policy_seconds','ai_token_budget','max_ai_cost_nano_credits','concurrency_limit','definition_version'] LOOP
  maximum:=CASE k WHEN 'max_duration_seconds' THEN 86400 WHEN 'temporary_policy_seconds' THEN 86400 WHEN 'ai_token_budget' THEN 12000 WHEN 'max_ai_cost_nano_credits' THEN 1000000000000 WHEN 'concurrency_limit' THEN 10 ELSE 1000000 END;
  IF NOT COALESCE(jsonb_typeof(b->k)='number' AND b->>k ~ '^[0-9]{1,13}$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export definition budget rejected';END IF;
  IF (b->>k)::bigint NOT BETWEEN 1 AND maximum THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export definition budget rejected';END IF;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM public.zasp_environments WHERE (organization_id,workspace_id,id)=(o,w,e)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export definition environment rejected';END IF;
END $shape$;

-- Clone the exact current predecessors before fencing their public paths.
-- Private schema access, not a caller-set GUC, distinguishes the new writer.
DO $clones$
DECLARE item record;d text;sig text;needle text;
BEGIN
 FOR item IN SELECT * FROM (VALUES
 ('zasp_workflow_mutate_v3','text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text','definition_workflow_core'),
 ('zasp_workflow_replay','text,text,text,text,text,text,jsonb','definition_replay_core'),
 ('zasp_security_agent_mutate_definition','text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text','definition_mutate_core'),
 ('zasp_security_agent_definition_value','text,text,text,text','definition_value_core'),
 ('zasp_security_agent_definition_detail','text,text,text,text','definition_detail_core'),
 ('zasp_security_agent_definition_page','text,text,text,text,integer','definition_page_core'),
 ('zasp_production_security_agent_existing_tests_activate_core','text,text,text,text,text,text,bigint,text,timestamptz,text,text,text','definition_activate_core'),
 ('zasp_production_security_agent_existing_tests_control_core','text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text','definition_control_core')
 ) AS x(name,args,clone) LOOP
  sig:='public.'||item.name||'('||item.args||')';d:=pg_get_functiondef(sig::regprocedure);
  d:=replace(d,'FUNCTION public.'||item.name||'(','FUNCTION zasp_sa_export_prior.'||item.clone||'(');
  IF item.clone='definition_mutate_core' THEN d:=replace(d,'zasp_workflow_mutate_v3(','zasp_sa_export_prior.definition_workflow_core(');END IF;
  IF item.clone='definition_activate_core' THEN
   -- Withdrawal is export-only. The unchanged core still owns CAS, fresh
   -- authentication, disabled body, version history and receipt replay.
   needle:='(definition_row.activation=''draft'' AND target_activation=''validated'')';
   IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export withdrawal predecessor changed';END IF;
   d:=replace(d,needle,'(definition_row.activation IN(''draft'',''supervised'',''autonomous'') AND target_activation=''validated'')');
  END IF;
  IF item.clone='definition_control_core' THEN
   IF strpos(d,'''start_attack_lab''')=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export controls predecessor changed';END IF;
   d:=replace(d,'''start_attack_lab''','''start_attack_lab'',''create_evidence_export''');
  END IF;
  EXECUTE d;
  EXECUTE format('ALTER FUNCTION zasp_sa_export_prior.%s(%s) OWNER TO zasp_discovery_authority',item.clone,item.args);
  EXECUTE format('REVOKE ALL ON FUNCTION zasp_sa_export_prior.%s(%s) FROM PUBLIC',item.clone,item.args);
 END LOOP;
END $clones$;

CREATE FUNCTION public.zasp_sa_export_legacy_definition_fence(o text,w text,e text,d text,b jsonb) RETURNS void LANGUAGE plpgsql SET search_path TO pg_catalog,public AS $fence$
BEGIN
 -- Same mirror-before-definition lock order as ordinary definition updates.
 PERFORM 1 FROM public.zasp_workflow_records WHERE (organization_id,workspace_id,environment_id,kind,id)=(o,w,e,'security_agent',d) FOR UPDATE;
 IF COALESCE(b->'allowed_actions' ? 'create_evidence_export',false) OR EXISTS(SELECT 1 FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=(o,w,e,d) AND body->'allowed_actions' ? 'create_evidence_export') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export definition requires versioned authority';END IF;
END $fence$;

DO $fences$
DECLARE sig text;d text;guard_value text;item record;
BEGIN
 sig:='public.zasp_workflow_mutate_v3(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text)';PERFORM public.zasp_sa_export_save(sig);d:=pg_get_functiondef(sig::regprocedure);
 guard_value:=$guard$IF requested_kind='security_agent' THEN PERFORM public.zasp_sa_export_legacy_definition_fence(requested_organization_id,requested_workspace_id,requested_environment_id,requested_id,requested_body);END IF;$guard$;
 IF strpos(d,E'\nBEGIN\n')=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export workflow fence anchor changed';END IF;
 EXECUTE replace(d,E'\nBEGIN\n',E'\nBEGIN\n'||guard_value||E'\n');
 sig:='public.zasp_workflow_replay(text,text,text,text,text,text,jsonb)';PERFORM public.zasp_sa_export_save(sig);d:=pg_get_functiondef(sig::regprocedure);
 guard_value:=$guard$IF requested_operation IN('createSecurityAgent','updateSecurityAgent','deleteSecurityAgent') AND (COALESCE(prior_response->'body'->'allowed_actions' ? 'create_evidence_export',false) OR COALESCE(requested_intent->'body'->'allowed_actions' ? 'create_evidence_export',false) OR EXISTS(SELECT 1 FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=(requested_organization_id,requested_workspace_id,requested_environment_id,requested_intent->>'resource_id') AND body->'allowed_actions' ? 'create_evidence_export')) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export definition replay requires versioned authority';END IF;
$guard$;
 IF strpos(d,'    IF prior_digest <> digest_value THEN')=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export replay fence anchor changed';END IF;
 EXECUTE replace(d,'    IF prior_digest <> digest_value THEN',guard_value||'    IF prior_digest <> digest_value THEN');
 FOREACH sig IN ARRAY ARRAY['public.zasp_security_agent_activate(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text)','public.zasp_production_security_agent_existing_tests_activate_core(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text)'] LOOP
  PERFORM public.zasp_sa_export_save(sig);d:=pg_get_functiondef(sig::regprocedure);
  IF strpos(d,E'\nBEGIN\n')=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export activation fence anchor changed';END IF;
  EXECUTE replace(d,E'\nBEGIN\n',E'\nBEGIN\n PERFORM public.zasp_sa_export_legacy_definition_fence(organization_value,workspace_value,environment_value,definition_value,NULL);\n');
 END LOOP;
 -- Old readers cannot accept a current human principal. Retain every ordinary
 -- row and its pagination, but do not expose export definitions through them.
 FOR item IN SELECT * FROM (VALUES
 ('public.zasp_security_agent_definition_value(text,text,text,text)','AND deleted_at IS NULL','body'),
 ('public.zasp_security_agent_definition_detail(text,text,text,text)','AND definition_row.deleted_at IS NULL','definition_row.body'),
 ('public.zasp_security_agent_definition_page(text,text,text,text,integer)','AND deleted_at IS NULL','body')
 ) AS x(signature,anchor,body_expression) LOOP
  PERFORM public.zasp_sa_export_save(item.signature);d:=pg_get_functiondef(item.signature::regprocedure);
  IF (length(d)-length(replace(d,item.anchor,'')))/length(item.anchor)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export retained reader predecessor changed';END IF;
  EXECUTE replace(d,item.anchor,item.anchor||' AND NOT COALESCE('||item.body_expression||'->''allowed_actions'' ? ''create_evidence_export'',false)');
 END LOOP;
END $fences$;

CREATE FUNCTION public.zasp_sa_export_mutate_definition(mutation_value text,definition_value text,organization_value text,workspace_value text,environment_value text,principal_value text,operation_value text,idempotency_value text,expected_version_value bigint,intent_value jsonb,body_value jsonb,audit_value text,correlation_value text,receipt_value text,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $mutate$
DECLARE prior public.zasp_security_agent_definitions%ROWTYPE;result_value jsonb;
BEGIN
 PERFORM public.zasp_sa_export_definition_authority(organization_value,workspace_value,environment_value,principal_value,'manage_workflows',expected_checksum,expected_fingerprint);
 IF NOT COALESCE(public.zasp_valid_product_id(audit_value) AND public.zasp_valid_product_id(correlation_value) AND public.zasp_valid_product_id(receipt_value),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export definition receipt rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,principal_value,operation_value,idempotency_value),0));
 PERFORM 1 FROM public.zasp_workflow_records WHERE (organization_id,workspace_id,environment_id,kind,id)=(organization_value,workspace_value,environment_value,'security_agent',definition_value) FOR UPDATE;
 SELECT * INTO prior FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=(organization_value,workspace_value,environment_value,definition_value) FOR UPDATE;
 IF FOUND AND NOT COALESCE(prior.body->'allowed_actions'='["create_evidence_export"]'::jsonb,false) OR NOT FOUND AND mutation_value<>'create' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export definition family rejected';END IF;
 IF mutation_value<>'delete' THEN PERFORM public.zasp_sa_export_definition_shape(organization_value,workspace_value,environment_value,definition_value,body_value);END IF;
 IF intent_value IS DISTINCT FROM jsonb_build_object('resource_id',CASE mutation_value WHEN 'create' THEN '' ELSE definition_value END,'expected_version',expected_version_value,'body',CASE mutation_value WHEN 'create' THEN body_value-'id' ELSE body_value END) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export definition intent rejected';END IF;
 PERFORM public.zasp_sa_export_definition_authority(organization_value,workspace_value,environment_value,principal_value,'manage_workflows',expected_checksum,expected_fingerprint);
 result_value:=zasp_sa_export_prior.definition_mutate_core(mutation_value,definition_value,organization_value,workspace_value,environment_value,principal_value,operation_value,idempotency_value,expected_version_value,intent_value,body_value,audit_value,correlation_value,receipt_value);
 PERFORM public.zasp_sa_export_definition_authority(organization_value,workspace_value,environment_value,principal_value,'manage_workflows',expected_checksum,expected_fingerprint);
 RETURN result_value;
END $mutate$;

CREATE FUNCTION public.zasp_sa_export_replay_definition(o text,w text,e text,actor text,operation_value text,key_value text,intent_value jsonb,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $replay$
DECLARE result_value jsonb;body_value jsonb;d text;v bigint;
BEGIN
 PERFORM public.zasp_sa_export_definition_authority(o,w,e,actor,'manage_workflows',expected_checksum,expected_fingerprint);
 IF operation_value NOT IN('createSecurityAgent','updateSecurityAgent','deleteSecurityAgent') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export definition replay operation rejected';END IF;
 result_value:=zasp_sa_export_prior.definition_replay_core(o,w,e,actor,operation_value,key_value,intent_value);
 body_value:=result_value->'result'->'body';
 IF body_value->'allowed_actions' ? 'create_evidence_export' THEN
  d:=body_value->>'id';v:=(result_value->'result'->>'version')::bigint;
  PERFORM public.zasp_sa_export_definition_shape(o,w,e,d,body_value);
  IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_definition_versions h WHERE (h.organization_id,h.workspace_id,h.environment_id,h.definition_id,h.version)=(o,w,e,d,v) AND h.definition=body_value AND h.actor_id=actor AND h.definition_digest=digest(convert_to(body_value::text,'UTF8'),'sha256')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export definition replay provenance changed';END IF;
 END IF;
 PERFORM public.zasp_sa_export_definition_authority(o,w,e,actor,'manage_workflows',expected_checksum,expected_fingerprint);
 RETURN result_value;
END $replay$;

CREATE FUNCTION public.zasp_sa_export_activate(o text,w text,e text,d text,actor text,key_value text,v bigint,target_value text,fresh_value timestamptz,audit_value text,correlation_value text,receipt_value text,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $activate$
DECLARE current_row public.zasp_security_agent_definitions%ROWTYPE;result_value jsonb;receipt_row public.zasp_security_agent_request_receipts%ROWTYPE;
BEGIN
 PERFORM public.zasp_sa_export_definition_authority(o,w,e,actor,'manage_workflows',expected_checksum,expected_fingerprint);
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),o,w,e,actor,'activateSecurityAgent',key_value),0));
 PERFORM 1 FROM public.zasp_workflow_records WHERE (organization_id,workspace_id,environment_id,kind,id)=(o,w,e,'security_agent',d) FOR UPDATE;
 SELECT * INTO current_row FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=(o,w,e,d) AND deleted_at IS NULL FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='export activation definition unavailable';END IF;
 PERFORM public.zasp_sa_export_definition_shape(o,w,e,d,current_row.body);
 IF target_value IN('supervised','autonomous') THEN
  PERFORM public.zasp_production_security_agent_existing_tests_controls_guard(o,w,e,'create_evidence_export');
 END IF;
 PERFORM public.zasp_sa_export_definition_authority(o,w,e,actor,'manage_workflows',expected_checksum,expected_fingerprint);
 result_value:=zasp_sa_export_prior.definition_activate_core(o,w,e,d,actor,key_value,v,target_value,fresh_value,audit_value,correlation_value,receipt_value);
 SELECT * INTO STRICT current_row FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=(o,w,e,d);
 SELECT * INTO STRICT receipt_row FROM public.zasp_security_agent_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(o,w,e,actor,'activateSecurityAgent',key_value);
 -- The retained21 trigger normalizes body.autonomy as activation advances.
 -- Preserve that staged transition instead of treating draft intent as a cap.
 IF current_row.version IS DISTINCT FROM (result_value->>'version')::bigint OR current_row.activation IS DISTINCT FROM target_value OR target_value IN('supervised','autonomous') AND current_row.body->>'autonomy' IS DISTINCT FROM target_value OR fresh_value<=clock_timestamp() OR (receipt_row.intent->>'fresh_auth_expires_at')::timestamptz IS NULL OR (receipt_row.intent->>'fresh_auth_expires_at')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export activation authority expired';END IF;
 PERFORM public.zasp_sa_export_definition_authority(o,w,e,actor,'manage_workflows',expected_checksum,expected_fingerprint);
 RETURN result_value;
END $activate$;

CREATE FUNCTION public.zasp_sa_export_controls(o text,w text,e text,actor text,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $controls$
DECLARE result_value jsonb;
BEGIN
 PERFORM public.zasp_sa_export_definition_authority(o,w,e,actor,'manage_identity',expected_checksum,expected_fingerprint);
 result_value:=public.zasp_security_agent_execution_control_detail(o,w,e);
 result_value:=jsonb_set(result_value,'{actions}',(SELECT jsonb_agg(jsonb_build_object('target','action','action_key',a,'enabled',COALESCE(c.execution_enabled,false),'version',COALESCE(c.version,0)) ORDER BY a) FROM unnest(ARRAY['create_evidence_export','create_temporary_policy','isolate_session','rerun_test','revoke_integration_connection','run_test','start_attack_lab','update_finding_response']) a LEFT JOIN public.zasp_security_agent_kill_switches c ON (c.organization_id,c.workspace_id,c.environment_id,c.action_key)=(o,w,e,a)));
 RETURN result_value;
END $controls$;

CREATE FUNCTION public.zasp_sa_export_set_control(o text,w text,e text,actor text,key_value text,target_value text,action_value text,enabled_value boolean,v bigint,fresh_value timestamptz,audit_value text,correlation_value text,receipt_value text,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $control$
DECLARE result_value jsonb;
BEGIN
 PERFORM public.zasp_sa_export_definition_authority(o,w,e,actor,'manage_identity',expected_checksum,expected_fingerprint);
 PERFORM 1 FROM public.zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*') FOR SHARE;
 IF target_value='action' THEN PERFORM 1 FROM public.zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=(o,w,e,'*') FOR SHARE;END IF;
 result_value:=zasp_sa_export_prior.definition_control_core(o,w,e,actor,key_value,target_value,action_value,enabled_value,v,fresh_value,audit_value,correlation_value,receipt_value);
 IF fresh_value<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export control authority expired';END IF;
 PERFORM public.zasp_sa_export_definition_authority(o,w,e,actor,'manage_identity',expected_checksum,expected_fingerprint);
 RETURN result_value;
END $control$;

CREATE FUNCTION public.zasp_sa_export_definition_value(o text,w text,e text,d text,actor text,expected_checksum text,expected_fingerprint text) RETURNS SETOF jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $value$
BEGIN
 PERFORM public.zasp_sa_export_definition_authority(o,w,e,actor,'view',expected_checksum,expected_fingerprint);
 RETURN QUERY SELECT zasp_sa_export_prior.definition_value_core(o,w,e,d);
END $value$;
CREATE FUNCTION public.zasp_sa_export_definition_detail(o text,w text,e text,d text,actor text,expected_checksum text,expected_fingerprint text) RETURNS SETOF jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $detail$
BEGIN
 PERFORM public.zasp_sa_export_definition_authority(o,w,e,actor,'view',expected_checksum,expected_fingerprint);
 RETURN QUERY SELECT zasp_sa_export_prior.definition_detail_core(o,w,e,d);
END $detail$;
CREATE FUNCTION public.zasp_sa_export_definition_page(o text,w text,e text,actor text,after_value text,limit_value integer,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $page$
BEGIN
 PERFORM public.zasp_sa_export_definition_authority(o,w,e,actor,'view',expected_checksum,expected_fingerprint);
 IF limit_value IS NULL OR limit_value NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export definition page rejected';END IF;
 RETURN zasp_sa_export_prior.definition_page_core(o,w,e,after_value,limit_value);
END $page$;

GRANT EXECUTE ON FUNCTION public.zasp_sa_export_workflow_readiness(text,text),public.zasp_sa_export_mutate_definition(text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text,text,text),public.zasp_sa_export_replay_definition(text,text,text,text,text,text,jsonb,text,text),public.zasp_sa_export_activate(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text,text,text),public.zasp_sa_export_controls(text,text,text,text,text,text),public.zasp_sa_export_set_control(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text,text,text),public.zasp_sa_export_definition_value(text,text,text,text,text,text,text),public.zasp_sa_export_definition_detail(text,text,text,text,text,text,text),public.zasp_sa_export_definition_page(text,text,text,text,text,integer,text,text) TO zasp_security_agent_api;
