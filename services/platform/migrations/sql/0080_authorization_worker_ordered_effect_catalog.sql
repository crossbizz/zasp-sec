-- Pair these exact projections with independent live trigger rows
-- in the worker fingerprint. No prefix-wide trigger or function exclusion.
DO $ordered_effect_catalog$ DECLARE d text;needle text;BEGIN
 SELECT pg_get_functiondef('zasp_authorization80_worker.projected_domain()'::regprocedure) INTO STRICT d;
 needle:='WHERE NOT t.tgisinternal AND NOT(';
 d:=zasp_authorization80_worker.ordered62_replace(d,needle,$triggers$WHERE NOT t.tgisinternal AND NOT(
 (t.tgrelid IN('public.zasp_gateway_devices'::regclass,'public.zasp_gateway_credentials'::regclass) AND t.tgname IN('zasp_authorization80_worker_ordered_gateway','zasp_authorization80_worker_ordered_no_truncate'))
 OR(t.tgrelid IN('public.zasp_workflow_records'::regclass,'public.zasp_security_agent_temporary_policy_targets'::regclass) AND t.tgname IN('zasp_authorization80_worker_ordered_policy','zasp_authorization80_worker_ordered_policy_no_truncate')))
 AND NOT($triggers$);
 EXECUTE d;
 SELECT pg_get_functiondef('zasp_authorization80_worker.projected68()'::regprocedure) INTO STRICT d;
 needle:=$old$WHERE NOT t.tgisinternal AND c.relnamespace='zasp_temporal68'::regnamespace$old$;
 d:=zasp_authorization80_worker.ordered62_replace(d,needle,needle||$triggers$ AND NOT(t.tgrelid='zasp_temporal68.deliveries'::regclass AND t.tgname IN('ordered_policy_capture','ordered_policy_no_truncate'))$triggers$);
 EXECUTE d;

 SELECT pg_get_functiondef('zasp_authorization79.pending(integer)'::regprocedure) INTO STRICT d;
 needle:=' ORDER BY COALESCE(last_attempt_at,pending_since)';
 EXECUTE zasp_authorization80_worker.ordered62_replace(d,needle,$expiry$ OR EXISTS(SELECT 1 FROM zasp_authorization80_worker.ordered_effect_scope s WHERE s.organization_id=zasp_authorization79.organizations.organization_id AND s.target_current AND s.fresh_until<=clock_timestamp())
 OR EXISTS(SELECT 1 FROM zasp_authorization80_worker.ordered_policy_scope s WHERE s.organization_id=zasp_authorization79.organizations.organization_id AND s.target_current AND s.fresh_until<=clock_timestamp())$expiry$||needle);
 SELECT pg_get_functiondef('zasp_authorization79.snapshot(text)'::regprocedure) INTO STRICT d;
 needle:=$old$ IF EXISTS(SELECT 1 FROM public.zasp_environments WHERE organization_id=o GROUP BY id HAVING count(*)>1)$old$;
 EXECUTE zasp_authorization80_worker.ordered62_replace(d,needle,E' PERFORM zasp_authorization80_worker.expire_ordered_effects(o);\n PERFORM zasp_authorization80_worker.expire_ordered_policies(o);\n'||needle);
END $ordered_effect_catalog$;

-- Actual source methods authenticate purpose-specific registered sessions.
-- Private facts, proof parsers, native body copies and key readers stay private.
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.prepare_ordered68_effect(jsonb),zasp_authorization80_worker.prepare_ordered68_policy(text,jsonb) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.ordered68_effect_source(text,jsonb),zasp_authorization80_worker.ordered68_policy_source(text,jsonb),zasp_authorization80_worker.ordered68_operation_source(text,jsonb) TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.ordered68_policy_begin(text,jsonb,text),zasp_authorization80_worker.ordered68_policy_store(text,jsonb,text,bytea,bytea,text) TO zasp_temporal_executor,zasp_temporal_compensation;
