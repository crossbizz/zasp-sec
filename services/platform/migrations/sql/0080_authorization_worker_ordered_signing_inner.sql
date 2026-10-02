-- Every external source/begin/store call keeps a complete schema/readiness
-- bracket. Only this fixed private call graph shares that bracket; no cached
-- authority, caller flag, GUC or cross-request result is trusted.
CREATE FUNCTION zasp_authorization80_worker.ordered68_signing_boundary(operation_value text) RETURNS void
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $signing_boundary$
DECLARE purpose_value text;BEGIN
 purpose_value:=CASE WHEN operation_value='ordered68.delivery.apply.prepare' THEN 'worker-forward' ELSE zasp_authorization80_worker.ordered68_policy_purpose(operation_value) END;
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='ordered signing requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal68.current_ready()
 OR NOT zasp_temporal68.principal_ready(CASE purpose_value WHEN 'worker-forward' THEN 'zasp_temporal_executor' ELSE 'zasp_temporal_compensation' END)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered signing boundary unavailable';END IF;
END $signing_boundary$;
ALTER FUNCTION zasp_authorization80_worker.ordered68_signing_boundary(text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80_worker.ordered68_signing_boundary(text) FROM PUBLIC;

DO $ordered_signing_inner$ DECLARE p record;d text;needle text;signature_value regprocedure;n text;BEGIN
 -- Copy the already-fenced worker readers bottom-up. All shape, immutable
 -- association, native domain, lock, principal and expiry checks survive.
 FOR p IN SELECT * FROM(VALUES
  ('ordered68_effect_facts','boolean,jsonb','ordered68_signing_facts_inner',1,NULL::text,NULL::text),
  ('ordered68_effect_metadata','text,jsonb','ordered68_signing_effect_metadata_inner',1,'ordered68_effect_facts','ordered68_signing_facts_inner'),
  ('ordered68_effect_source','text,jsonb','ordered68_signing_effect_source_inner',0,'ordered68_effect_metadata','ordered68_signing_effect_metadata_inner'),
  ('ordered68_policy_metadata','text,jsonb','ordered68_signing_metadata_inner',1,'ordered68_effect_source','ordered68_signing_effect_source_inner'),
  ('ordered68_policy_source','text,jsonb','ordered68_signing_source_inner',0,'ordered68_policy_metadata','ordered68_signing_metadata_inner'),
  ('require_ordered68_policy','text,jsonb','ordered68_signing_proof_inner',0,'ordered68_policy_source','ordered68_signing_source_inner'),
  ('ordered68_effect_read','jsonb','ordered68_signing_read_inner',2,NULL::text,NULL::text)
 ) v(old_name,args,new_name,ready_count,old_callee,new_callee) LOOP
  d:=pg_get_functiondef(('zasp_authorization80_worker.'||p.old_name||'('||p.args||')')::regprocedure);
  d:=zasp_authorization80_worker.ordered62_replace(d,'FUNCTION zasp_authorization80_worker.'||p.old_name||'(','FUNCTION zasp_authorization80_worker.'||p.new_name||'(');
  needle:='zasp_temporal68.current_ready()';
  IF(length(d)-length(replace(d,needle,'')))/length(needle)<>p.ready_count THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered signing inner readiness count changed';END IF;
  d:=replace(d,needle,'zasp_authorization80_worker.catalog_ready()');
  IF p.old_callee IS NOT NULL THEN
   d:=zasp_authorization80_worker.ordered62_replace(d,'zasp_authorization80_worker.'||p.old_callee||'(','zasp_authorization80_worker.'||p.new_callee||'(');
  END IF;
  IF p.old_name='ordered68_effect_read' AND position($read$NOT COALESCE(q->>'operation' IN('read'),false)$read$ IN d)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered signing read-only restriction absent';END IF;
  EXECUTE d;
  signature_value:=('zasp_authorization80_worker.'||p.new_name||'('||p.args||')')::regprocedure;
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',signature_value);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',signature_value);
 END LOOP;

 -- These three existing owner-only copies are called only from the signed
 -- store below. Their fixed operation restrictions and all native mutations
 -- remain unchanged. The shared effect_read used by other families is intact.
 FOREACH n IN ARRAY ARRAY['ordered68_application_source','ordered68_cleanup_source','ordered68_delivery_store'] LOOP
  SELECT pg_get_functiondef(oid) INTO STRICT d FROM pg_proc WHERE oid=('zasp_authorization80_worker.'||n||'(jsonb)')::regprocedure
   AND proowner='zasp_discovery_authority'::regrole AND proacl::text='{zasp_discovery_authority=X/zasp_discovery_authority}';
  d:=zasp_authorization80_worker.ordered62_replace(d,'zasp_temporal68.current_ready()','zasp_authorization80_worker.catalog_ready()');
  d:=zasp_authorization80_worker.ordered62_replace(d,'zasp_authorization80_worker.ordered68_effect_read(','zasp_authorization80_worker.ordered68_signing_read_inner(');
  EXECUTE d;
 END LOOP;

 -- Each begin/store still independently authenticates the original proof,
 -- re-reads its full source, compares revision/facts and rechecks time. Only
 -- nested catalog traversal changes. Existing full exits remain after writes.
 FOREACH n IN ARRAY ARRAY['ordered68_policy_begin(text,jsonb,text)','ordered68_policy_store(text,jsonb,text,bytea,bytea,text)'] LOOP
  d:=pg_get_functiondef(('zasp_authorization80_worker.'||n)::regprocedure);
  needle:='proof:=zasp_authorization80_worker.require_ordered68_policy(operation_value,q);';
  d:=zasp_authorization80_worker.ordered62_replace(d,needle,E'PERFORM zasp_authorization80_worker.ordered68_signing_boundary(operation_value);\n proof:=zasp_authorization80_worker.ordered68_signing_proof_inner(operation_value,q);');
  needle:='NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal68.current_ready()';
  IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered signing outer exit changed';END IF;
  EXECUTE d;
 END LOOP;
END $ordered_signing_inner$;

-- The Go first/second source reads remain separate complete external calls.
-- No metadata survives from one call to another except the existing signed
-- proof, which begin and store each revalidate against fresh native rows.
CREATE OR REPLACE FUNCTION zasp_authorization80_worker.ordered68_policy_source(operation_value text,q jsonb) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $signing_source_outer$
DECLARE result_value jsonb;BEGIN
 PERFORM zasp_authorization80_worker.ordered68_signing_boundary(operation_value);
 result_value:=zasp_authorization80_worker.ordered68_signing_source_inner(operation_value,q);
 PERFORM zasp_authorization80_worker.ordered68_signing_boundary(operation_value);
 RETURN result_value;
END $signing_source_outer$;
