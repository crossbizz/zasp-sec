SET LOCAL lock_timeout='3s';
SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0));
DO $guard$
BEGIN
 -- The advisory-lock SELECT can precede a writer's commit. Only READ COMMITTED
 -- gives the evidence inspection a fresh snapshot after the lock wait.
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='multistep rollback requires read committed isolation';END IF;
 PERFORM public.zasp_sa_multistep_assert_unused();
 IF NOT public.zasp_sa_multistep_readiness('-- compiled multistep checksum','-- compiled multistep fingerprint') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='multistep schema drift refuses rollback';END IF;
END $guard$;
DROP TABLE public.zasp_sa_multistep_receipts;
DROP TABLE public.zasp_sa_multistep_dependencies;
DROP TABLE public.zasp_sa_multistep_runs;
DROP TABLE public.zasp_sa_multistep_definitions;
DROP FUNCTION public.zasp_sa_multistep_assert_unused();
DROP FUNCTION public.zasp_sa_multistep_readiness(text,text);
DROP FUNCTION public.zasp_sa_multistep_live_fingerprint();
DROP FUNCTION public.zasp_sa_multistep_function_identity(oid);
DROP FUNCTION public.zasp_sa_multistep_bind();
DROP FUNCTION public.zasp_sa_multistep_body_valid(text,jsonb);
DROP TABLE public.zasp_sa_multistep_metadata;
