-- Only native74.plan calls this owner-only copy. Its full readiness fences
-- enclose all three lookups, including the last lookup's possible row wait.
DO $test_pricing_inner$ DECLARE d text;needle text;BEGIN
 d:=pg_get_functiondef('zasp_temporal74.pricing_lookup(text,text,jsonb)'::regprocedure);
 needle:='FUNCTION zasp_temporal74.pricing_lookup(';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='test pricing inner declaration changed';END IF;
 d:=replace(d,needle,'FUNCTION zasp_authorization80_worker.test74_pricing_inner(');
 needle:='public.zasp_sa_multistep_readiness(checksum_value,fingerprint_value)';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='test pricing inner readiness pair changed';END IF;
 EXECUTE replace(d,needle,$pins$COALESCE(checksum_value='-- worker pricing checksum' AND fingerprint_value='-- worker pricing fingerprint',false)$pins$);

 d:=pg_get_functiondef('zasp_temporal74.plan(jsonb)'::regprocedure);
 needle:=$entry$IF NOT zasp_temporal68.principal_ready('zasp_temporal_executor') OR NOT zasp_temporal74.current_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='executor planning unavailable';END IF;$entry$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='test pricing enclosing entry changed';END IF;
 needle:='zasp_temporal74.pricing_lookup(';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>3 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='test pricing enclosing calls changed';END IF;
 d:=replace(d,needle,'zasp_authorization80_worker.test74_pricing_inner(');
 needle:=$return$ IF op='admit' THEN RETURN job.receipt;END IF;$return$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='test pricing enclosing return changed';END IF;
 EXECUTE replace(d,needle,$exit$ IF NOT zasp_temporal74.current_ready() OR NOT zasp_temporal68.principal_ready('zasp_temporal_executor') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test planning authority changed after final lookup';END IF;
$exit$||needle);
END $test_pricing_inner$;
