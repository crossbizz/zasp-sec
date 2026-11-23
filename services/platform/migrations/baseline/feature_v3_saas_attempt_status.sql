-- The original tab retains the attempt ID in memory. Only the same actor and
-- browser session may read the connection recorded by the provider callback.
CREATE OR REPLACE FUNCTION zasp_authorization80.saas_attempt_status(o text,w text,e text,a text,i text,x text,session_hash bytea) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $status$
DECLARE result jsonb; proof jsonb;
BEGIN
 proof:=zasp_authorization80.product_request(o,w,e,a,'getSaaSSignInAttempt','manage_workflows','integration',i,true,true,false,false);
 IF proof#>>'{path_parameters,attemptId}' IS DISTINCT FROM x THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='attempt does not match authorized route'; END IF;
 IF NOT public.zasp_valid_product_id(x) OR octet_length(session_hash) IS DISTINCT FROM 32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid sign-in read'; END IF;
 SELECT jsonb_build_object('attempt_id',r.id,'integration_id',r.integration_id,'integration_version',r.integration_version,'status',r.status,'connection_reference',r.connection_reference,'failure_code',r.failure_code)
 INTO result FROM public.zasp_saas_sign_in_attempts r
 WHERE (r.organization_id,r.workspace_id,r.environment_id,r.principal_id,r.integration_id,r.id,r.session_digest)=(o,w,e,a,i,x,session_hash)
 AND r.expires_at>transaction_timestamp();
 RETURN result;
END $status$;
ALTER FUNCTION zasp_authorization80.saas_attempt_status(text,text,text,text,text,text,bytea) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.saas_attempt_status(text,text,text,text,text,text,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.saas_attempt_status(text,text,text,text,text,text,bytea) TO zasp_discovery_api;
