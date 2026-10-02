CREATE FUNCTION zasp_authorization80_identity.require_pat_read(op text,o text,w text,e text,actor text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE proof jsonb:=zasp_authorization80.context();
BEGIN
 IF NOT zasp_authorization80_identity.api_ready() OR NOT COALESCE(op IN('listAPITokens','listAPITokenRevealGrants','revealAPIToken') AND zasp_authorization80.read_request(o,w,e,ARRAY[op],'manage_api_tokens',true,actor) AND zasp_authorization80.allowed(o,w,e,'environment',e) AND(op<>'revealAPIToken' OR(proof->>'fresh_auth')::boolean),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='checked PAT access required';END IF;
END $$;

CREATE FUNCTION zasp_authorization80_identity._pat_page(p1 text,p2 text,p3 text,p4 text,p5 integer) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $retained$
-- retained identity ListAPITokens
$retained$;
CREATE FUNCTION zasp_authorization80_identity.pat_page(p1 text,p2 text,p3 text,p4 text,p5 integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;
BEGIN
 PERFORM zasp_authorization80_identity.require_pat_read('listAPITokens',$1,$2,$3,zasp_authorization80.context()->>'principal_id');
 IF NOT COALESCE($5 BETWEEN 1 AND 101,false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='PAT selector rejected';END IF;
 result:=zasp_authorization80_identity._pat_page($1,$2,$3,$4,$5);
 IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='PAT grant not found';END IF;
 RETURN result;
END $$;
GRANT EXECUTE ON FUNCTION zasp_authorization80_identity.pat_page(text,text,text,text,integer) TO zasp_discovery_api;

CREATE FUNCTION zasp_authorization80_identity._reveal_page(p1 text,p2 text,p3 text,p4 text,p5 text,p6 integer) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $retained$
-- retained identity ListAPITokenRevealGrants
$retained$;
CREATE FUNCTION zasp_authorization80_identity.reveal_page(p1 text,p2 text,p3 text,p4 text,p5 text,p6 integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;
BEGIN
 PERFORM zasp_authorization80_identity.require_pat_read('listAPITokenRevealGrants',$1,$2,$3,$4);
 IF NOT COALESCE($6 BETWEEN 1 AND 101,false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='PAT selector rejected';END IF;
 result:=zasp_authorization80_identity._reveal_page($1,$2,$3,$4,$5,$6);
 IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='PAT grant not found';END IF;
 RETURN result;
END $$;
GRANT EXECUTE ON FUNCTION zasp_authorization80_identity.reveal_page(text,text,text,text,text,integer) TO zasp_discovery_api;

CREATE FUNCTION zasp_authorization80_identity._reveal_pat(p1 text,p2 text,p3 text,p4 text,p5 text) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $retained$
-- retained identity RevealAPIToken
$retained$;
CREATE FUNCTION zasp_authorization80_identity.reveal_pat(p1 text,p2 text,p3 text,p4 text,p5 text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;
BEGIN
 PERFORM zasp_authorization80_identity.require_pat_read('revealAPIToken',$1,$2,$3,$4);
 IF NOT COALESCE(public.zasp_valid_product_id($5) AND zasp_authorization80.context()->'path_parameters'->>'id'=$5,false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='PAT selector rejected';END IF;
 result:=zasp_authorization80_identity._reveal_pat($1,$2,$3,$4,$5);
 IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='PAT grant not found';END IF;
 RETURN result;
END $$;
GRANT EXECUTE ON FUNCTION zasp_authorization80_identity.reveal_pat(text,text,text,text,text) TO zasp_discovery_api;
