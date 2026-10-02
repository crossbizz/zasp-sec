-- Save/transform only validated installed identities. Historical SQL and pins
-- remain untouched; the worker catalog independently hashes the live result.
CREATE FUNCTION zasp_authorization80_worker.discovery72_replace(d text,needle text,replacement text,n integer DEFAULT 1) RETURNS text LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,public AS $replace$
BEGIN
 IF needle='' OR(length(d)-length(replace(d,needle,'')))/length(needle)<>n THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='discovery predecessor source changed';END IF;
 RETURN replace(d,needle,replacement);
END $replace$;
DO $boundaries$ DECLARE p record;d text;phase text;extra text;call_value text;needle text:=E'BEGIN\n';BEGIN
 IF(SELECT count(*) FROM zasp_authorization80_worker.predecessor_functions WHERE signature LIKE 'zasp_temporal72.%')<>11 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='discovery predecessor set rejected';END IF;
 FOR p IN SELECT * FROM zasp_authorization80_worker.predecessor_functions WHERE signature LIKE 'zasp_temporal72.%' AND signature NOT LIKE 'zasp_temporal72.scheduled_admit(%' AND signature NOT LIKE 'zasp_temporal72.public_%' LOOP
  IF p.owner_name<>'zasp_discovery_authority' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='discovery predecessor owner rejected';END IF;
  phase:=split_part(split_part(p.signature,'.',2),'(',1);
  IF phase='guard_page_effect' THEN phase:='guard_page';END IF;
  extra:=CASE phase
   WHEN 'prepare_page' THEN 'jsonb_build_object(''integration_id'',i,''input_digest'',input_digest,''budget_us'',floor(extract(epoch FROM budget)*1000000)::bigint,''expected'',expected,''expected_digest'',expected_digest)'
   WHEN 'guard_page' THEN 'jsonb_build_object(''effect_id'',effect_value,''budget_us'',floor(extract(epoch FROM budget)*1000000)::bigint)'
   WHEN 'prepare_apply' THEN 'jsonb_build_object(''integration_id'',i,''input_digest'',input_digest,''budget_us'',floor(extract(epoch FROM budget)*1000000)::bigint,''complete_receipt'',complete_receipt)'
   WHEN 'commit_apply' THEN 'jsonb_build_object(''effect_id'',effect_value,''budget_us'',floor(extract(epoch FROM budget)*1000000)::bigint)'
   WHEN 'record_page' THEN 'jsonb_build_object(''effect_id'',effect_value,''details'',details)'
   WHEN 'settle' THEN 'jsonb_build_object(''integration_id'',i,''input_digest'',input_digest,''budget_us'',floor(extract(epoch FROM budget)*1000000)::bigint,''reason'',reason,''receipt'',receipt_value)'
   WHEN 'finish' THEN 'jsonb_build_object(''integration_id'',i,''input_digest'',input_digest,''outcome'',outcome_value,''receipt'',receipt_value)' END;
  call_value:=' PERFORM zasp_authorization80_worker.require_discovery72('''||phase||''',zasp_authorization80_worker.discovery72_request('''||phase||''',o,w,e,j,'||extra||'));'||E'\n';
  EXECUTE zasp_authorization80_worker.discovery72_replace(p.definition,needle,needle||call_value);
  IF phase IN('record_page','settle','finish') THEN
   -- Saved bodies retain every native capacity/checkpoint/evidence check.
   -- Only the exact registered principal predicate changes; finish's single
   -- nested settle target stays within this owner-only captured family.
   d:=zasp_authorization80_worker.discovery72_replace(p.definition,'FUNCTION zasp_temporal72.'||phase||'(', 'FUNCTION zasp_authorization80_worker.discovery72_'||phase||'(');
   d:=zasp_authorization80_worker.discovery72_replace(d,$old$ PERFORM zasp_temporal72.require_principal('zasp_discovery_worker');$old$,$new$ IF NOT zasp_authorization80_worker.discovery72_role(true) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery captured session rejected';END IF;$new$);
   IF phase='finish' THEN d:=zasp_authorization80_worker.discovery72_replace(d,'RETURN zasp_temporal72.settle(','RETURN zasp_authorization80_worker.discovery72_settle(');END IF;
   EXECUTE d;
  END IF;
 END LOOP;
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature LIKE 'zasp_temporal72.scheduled_admit(%';
 d:=zasp_authorization80_worker.discovery72_replace(d,$old$ SELECT * INTO schedule_row FROM zasp_temporal72.schedules WHERE (organization_id,workspace_id,environment_id,id,integration_id)=(o,w,e,s,i) FOR UPDATE;$old$,$new$ PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=o FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery scheduled organization missing';END IF;
 SELECT * INTO schedule_row FROM zasp_temporal72.schedules WHERE (organization_id,workspace_id,environment_id,id,integration_id)=(o,w,e,s,i) FOR UPDATE;$new$);
 EXECUTE zasp_authorization80_worker.discovery72_replace(d,E' RETURN result;\n',' PERFORM zasp_authorization80_worker.discovery72_capture_scheduled(o,w,e,job_value);'||E'\n RETURN result;\n');
 FOR p IN SELECT * FROM zasp_authorization80_worker.predecessor_functions WHERE signature LIKE 'zasp_temporal72.public_%' LOOP
  IF p.owner_name<>'zasp_discovery_authority' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='discovery API predecessor owner rejected';END IF;
  phase:=split_part(split_part(p.signature,'.',2),'(',1);
  extra:=CASE phase WHEN 'public_request_sync' THEN 'jsonb_build_object(''expected'',expected,''sync_id'',s,''job_id'',j,''outbox_id'',b,''request_digest'',encode(d,''hex''),''parser_version'',parser_value,''tool_version'',tool_value)'
   WHEN 'public_put_schedule' THEN 'jsonb_build_object(''expected'',expected,''cadence'',cadence,''state'',state_value)'
   WHEN 'public_delete_schedule' THEN 'jsonb_build_object(''expected'',expected)' END;
  call_value:=CASE phase WHEN 'public_request_sync' THEN 'syncIntegration' WHEN 'public_put_schedule' THEN 'putIntegrationSchedule' WHEN 'public_delete_schedule' THEN 'deleteIntegrationSchedule' END;
  IF extra IS NULL OR call_value IS NULL THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='discovery API predecessor set rejected';END IF;
  d:=zasp_authorization80_worker.discovery72_replace(p.definition,needle,needle||' PERFORM zasp_authorization80_worker.discovery72_human_begin('''||call_value||''',o,w,e,p,i,k,a,c,receipt_value,'||extra||');'||E'\n');
  d:=zasp_authorization80_worker.discovery72_replace(d,'RETURN public.zasp_execution_record_public_mutation(','RETURN zasp_authorization80_worker.discovery72_record_public_mutation(');
  d:=zasp_authorization80_worker.discovery72_replace(d,$old$IF (replay_value->>'found')::boolean THEN RETURN replay_value->'result';END IF;$old$,$new$IF (replay_value->>'found')::boolean THEN PERFORM zasp_authorization80_worker.discovery72_human_replay();RETURN replay_value->'result';END IF;$new$);
  EXECUTE d;
 END LOOP;
 -- The mutation capture relies on this audited ordering, not optional receipt
 -- retention. Its complete effective definition is also a pinned catalog row.
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature LIKE '%zasp_execution_record_public_mutation(%';
 IF position('INSERT INTO zasp_workflow_audit(' IN d)=0 OR position('INSERT INTO zasp_workflow_audit(' IN d)>=position('INSERT INTO zasp_workflow_idempotency(' IN d) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='discovery mutation audit order changed';END IF;
END $boundaries$;

DO $projections$ DECLARE d text;needle text;BEGIN
 -- Only bookkeeping state of this exact captured native sync is equivalent.
 -- Other configured columns, legacy rows and terminal transitions keep the
 -- original capture/touch path. Native run capture remains the authority.
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_authorization79.capture()';
 needle:=$old$ columns:=string_to_array(TG_ARGV[1],',');$old$;
 EXECUTE zasp_authorization80_worker.discovery72_replace(d,needle,needle||E'\n'||$skip$
 IF TG_RELID='public.zasp_discovery_syncs'::regclass AND TG_OP='UPDATE' AND old_value->>'state' IN('queued','running') AND new_value->>'state' IN('queued','running')
 AND NOT EXISTS(SELECT 1 FROM unnest(columns) k WHERE k<>'state' AND old_value->k IS DISTINCT FROM new_value->k)
 AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.discovery_associations a JOIN zasp_temporal72.runs r ON(r.organization_id,r.workspace_id,r.environment_id,r.job_id,r.sync_id,r.integration_id)=(a.organization_id,a.workspace_id,a.environment_id,a.job_id,a.sync_id,a.integration_id)
 JOIN zasp_authorization80_worker.discovery_state s ON(s.organization_id,s.workspace_id,s.environment_id,s.job_id)=(a.organization_id,a.workspace_id,a.environment_id,a.job_id)
 WHERE(a.organization_id,a.workspace_id,a.environment_id,a.sync_id,a.integration_id,a.source_kind)=(new_value->>'organization_id',new_value->>'workspace_id',new_value->>'environment_id',new_value->>'id',new_value->>'integration_id',new_value->>'trigger_kind')
 AND new_value->>'principal_id'=CASE a.source_kind WHEN 'manual' THEN a.grantor_id ELSE a.principal_id END AND a.admission=zasp_authorization80_worker.discovery72_admission_identity(r) AND s.present AND s.state=r.state AND s.state IN('admitted','collecting','partial','retryable','complete','applying')) THEN RETURN NEW;END IF;
$skip$);
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_authorization80_temporal.projected72()';
 d:=zasp_authorization80_worker.discovery72_replace(d,'FUNCTION zasp_authorization80_temporal.projected72()','FUNCTION zasp_authorization80_worker.projected72()');
 d:=zasp_authorization80_worker.discovery72_replace(d,'pg_get_functiondef(p.oid)',$definition$CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_authorization80_worker.predecessor_functions) THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END$definition$,3);
 EXECUTE zasp_authorization80_worker.discovery72_replace(d,'WHERE NOT t.tgisinternal AND c.relnamespace=', $triggers$WHERE NOT t.tgisinternal AND NOT(t.tgname IN('zasp_authorization80_worker_discovery_source','zasp_authorization80_worker_discovery_no_truncate') AND t.tgrelid IN('zasp_temporal72.runs'::regclass,'zasp_temporal72.schedules'::regclass)) AND c.relnamespace=$triggers$);
 SELECT pg_get_functiondef('zasp_authorization80_worker.projected_domain()'::regprocedure) INTO d;
 EXECUTE zasp_authorization80_worker.discovery72_replace(d,'WHERE NOT t.tgisinternal AND NOT(', $triggers$WHERE NOT t.tgisinternal AND NOT(t.tgname IN('zasp_authorization80_worker_discovery_source','zasp_authorization80_worker_discovery_no_truncate') AND t.tgrelid IN('public.zasp_integrations'::regclass,'public.zasp_integration_connections'::regclass,'public.zasp_discovery_connection_subjects'::regclass,'public.zasp_connector_credentials'::regclass) OR t.tgname='zasp_authorization80_worker_discovery_admission' AND t.tgrelid='public.zasp_workflow_idempotency'::regclass) AND NOT($triggers$);
 -- Extend the installed Test expiry hooks, never overwrite them from a prior
 -- definition; both families must continue to participate in reconciliation.
 SELECT pg_get_functiondef('zasp_authorization79.pending(integer)'::regprocedure) INTO d;
 EXECUTE zasp_authorization80_worker.discovery72_replace(d,' ORDER BY COALESCE(last_attempt_at,pending_since)', ' OR EXISTS(SELECT 1 FROM zasp_authorization80_worker.discovery_state s WHERE s.organization_id=zasp_authorization79.organizations.organization_id AND s.current_source AND s.authority_until<=clock_timestamp()) ORDER BY COALESCE(last_attempt_at,pending_since)');
 SELECT pg_get_functiondef('zasp_authorization79.snapshot(text)'::regprocedure) INTO d;
 needle:=$old$ IF EXISTS(SELECT 1 FROM public.zasp_environments WHERE organization_id=o GROUP BY id HAVING count(*)>1)$old$;
 EXECUTE zasp_authorization80_worker.discovery72_replace(d,needle,' PERFORM zasp_authorization80_worker.expire_discovery72(o);'||E'\n'||needle);
END $projections$;
CREATE OR REPLACE FUNCTION zasp_authorization80_temporal.projected72() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $discovery_gate$
 SELECT CASE WHEN EXISTS(SELECT 1 FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='zasp_authorization80_worker.catalog_ready()'::regprocedure AND encode(digest(convert_to(p.prosrc,'UTF8'),'sha256'),'hex')='-- worker catalog body digest' AND p.proowner='zasp_discovery_authority'::regrole AND p.prosecdef AND p.provolatile='s' AND l.lanname='sql' AND p.proconfig=ARRAY['search_path=pg_catalog, public'] AND p.proacl::text='{zasp_discovery_authority=X/zasp_discovery_authority}') AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE checksum='-- worker profile checksum') AND zasp_authorization80_worker.catalog_ready() THEN zasp_authorization80_worker.projected72() ELSE NULL END
$discovery_gate$;
