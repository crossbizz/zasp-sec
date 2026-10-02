-- Each consumer retains its exact source7/8 CTE. Only this closed admission
-- function can create an administration permit; the API cannot invoke it.
CREATE FUNCTION zasp_authorization80_identity.admit_admin(op text,o text,w text,e text,actor text,target text,audit text,value_body jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE proof jsonb:=zasp_authorization80.context();permission text;kind text;key text;
BEGIN
 permission:=CASE WHEN op IN('updateMemberRole','updateGroupMappings') THEN 'manage_identity' WHEN op IN('createAPIToken','rotateAPIToken','revokeAPIToken','acknowledgeAPITokenRevealGrant') THEN 'manage_api_tokens' WHEN op='revokeSession' THEN 'revoke_sessions' END;
 kind:=CASE WHEN op='updateMemberRole' THEN 'organization_identity' WHEN op='revokeSession' THEN 'product_session' ELSE 'environment' END;
 key:=CASE WHEN op='updateMemberRole' THEN o WHEN op='revokeSession' THEN target ELSE e END;
 IF NOT zasp_authorization80_identity.api_ready() OR permission IS NULL OR NOT COALESCE(
 (proof->>'operation_id',proof->>'permission',proof->>'organization_id',proof->>'workspace_id',proof->>'environment_id',proof->>'principal_id',proof->>'credential_kind')=(op,permission,o,w,e,actor,'1')
 AND(proof->>'fresh_auth')::boolean AND NOT(proof->>'collection')::boolean AND public.zasp_valid_product_id(audit)
 AND(op='createAPIToken' OR proof->'path_parameters'->>'id'=target)
 AND zasp_authorization80.allowed(o,w,e,kind,key),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='checked identity administration required';END IF;
 PERFORM zasp_authorization80.identity_fence(proof);
 PERFORM zasp_authorization80_identity.set_permit(jsonb_build_object('purpose','admin','operation',op,'organization_id',o,'workspace_id',w,'environment_id',e,'actor',actor,'target',target,'audit_id',audit,'values',value_body));
END $$;

CREATE FUNCTION zasp_authorization80_identity._member_role(p1 text,p2 text,p3 text,p4 bigint,p5 text,p6 text,p7 text,p8 text) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $retained$
 -- retained identity UpdateMemberRole
$retained$;
CREATE FUNCTION zasp_authorization80_identity.member_role(p1 text,p2 text,p3 text,p4 bigint,p5 text,p6 text,p7 text,p8 text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;
BEGIN
 IF NOT COALESCE($4>0 AND public.zasp_valid_product_id($2) AND $3 IN('organization_admin','security_admin','security_engineer','developer_owner','compliance_viewer','read_only_viewer'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='identity administration input rejected';END IF;
 PERFORM zasp_authorization80_identity.admit_admin('updateMemberRole',$1,$5,$6,$8,$2,$7,jsonb_build_object('role',$3,'version',$4));
 result:=zasp_authorization80_identity._member_role($1,$2,$3,$4,$5,$6,$7,$8);
 PERFORM zasp_authorization80_identity.clear_permit();RETURN result;
END $$;
GRANT EXECUTE ON FUNCTION zasp_authorization80_identity.member_role(text,text,text,bigint,text,text,text,text) TO zasp_discovery_api;

CREATE FUNCTION zasp_authorization80_identity._group_mapping(p1 text,p2 text,p3 text,p4 text,p5 text,p6 bigint,p7 text,p8 text,p9 text) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $retained$
 -- retained identity UpsertGroupMapping
$retained$;
CREATE FUNCTION zasp_authorization80_identity.group_mapping(p1 text,p2 text,p3 text,p4 text,p5 text,p6 bigint,p7 text,p8 text,p9 text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;
BEGIN
 IF NOT COALESCE($6>=0 AND $9=$4 AND $2~'^scim-group-(test|live)-[A-Za-z0-9_-]+$' AND length($2)<=128 AND $3 IN('organization_admin','security_admin','security_engineer','developer_owner','compliance_viewer','read_only_viewer'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='identity administration input rejected';END IF;
 PERFORM zasp_authorization80_identity.admit_admin('updateGroupMappings',$1,$4,$5,$8,$2,$7,jsonb_build_object('role',$3,'version',$6));
 result:=zasp_authorization80_identity._group_mapping($1,$2,$3,$4,$5,$6,$7,$8,$9);
 PERFORM zasp_authorization80_identity.clear_permit();RETURN result;
END $$;
GRANT EXECUTE ON FUNCTION zasp_authorization80_identity.group_mapping(text,text,text,text,text,bigint,text,text,text) TO zasp_discovery_api;

CREATE FUNCTION zasp_authorization80_identity._create_pat(p1 text,p2 text,p3 text,p4 bytea,p5 bytea,p6 text,p7 text,p8 text,p9 text,p10 jsonb,p11 timestamptz,p12 text,p13 text,p14 timestamptz,p15 bytea,p16 bytea,p17 bytea) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $retained$
 -- retained identity CreateAPIToken
$retained$;
CREATE FUNCTION zasp_authorization80_identity.create_pat(p1 text,p2 text,p3 text,p4 bytea,p5 bytea,p6 text,p7 text,p8 text,p9 text,p10 jsonb,p11 timestamptz,p12 text,p13 text,p14 timestamptz,p15 bytea,p16 bytea,p17 bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;
BEGIN
 IF NOT COALESCE(octet_length($4)=32 AND octet_length($5)=32 AND public.zasp_valid_product_id($6) AND length($9) BETWEEN 1 AND 128 AND jsonb_typeof($10)='array' AND jsonb_array_length($10) BETWEEN 1 AND 32 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements($10) p WHERE jsonb_typeof(p)<>'string' OR p#>>'{}' NOT IN('view','manage_findings','manage_workflows','manage_identity','manage_api_tokens','view_audit','investigate_sessions','revoke_sessions','view_compliance','manage_data_controls','run_tests')) AND (SELECT count(*)=count(DISTINCT value) FROM jsonb_array_elements_text($10)) AND $11>clock_timestamp() AND public.zasp_valid_product_id($13) AND $14>clock_timestamp() AND $14<=clock_timestamp()+interval '15 minutes' AND octet_length($15) BETWEEN 1 AND 8192 AND octet_length($16)=12 AND octet_length($17)=16 AND length($3) BETWEEN 16 AND 128,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='identity administration input rejected';END IF;
 PERFORM zasp_authorization80_identity.admit_admin('createAPIToken',$1,$7,$8,$2,$6,$12,jsonb_build_object('token_digest',encode($5,'hex'),'id',$6,'name',$9,'permissions',$10,'expires_at',$11,'grant_id',$13));
 result:=zasp_authorization80_identity._create_pat($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17);
 PERFORM zasp_authorization80_identity.clear_permit();RETURN result;
END $$;
GRANT EXECUTE ON FUNCTION zasp_authorization80_identity.create_pat(text,text,text,bytea,bytea,text,text,text,text,jsonb,timestamptz,text,text,timestamptz,bytea,bytea,bytea) TO zasp_discovery_api;

CREATE FUNCTION zasp_authorization80_identity._rotate_pat(p1 text,p2 text,p3 text,p4 bytea,p5 text,p6 bigint,p7 bytea,p8 text,p9 text,p10 text,p11 text,p12 text,p13 timestamptz,p14 bytea,p15 bytea,p16 bytea) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $retained$
 -- retained identity RotateAPIToken
$retained$;
CREATE FUNCTION zasp_authorization80_identity.rotate_pat(p1 text,p2 text,p3 text,p4 bytea,p5 text,p6 bigint,p7 bytea,p8 text,p9 text,p10 text,p11 text,p12 text,p13 timestamptz,p14 bytea,p15 bytea,p16 bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;
BEGIN
 IF NOT COALESCE(octet_length($4)=32 AND octet_length($7)=32 AND public.zasp_valid_product_id($5) AND public.zasp_valid_product_id($8) AND $5<>$8 AND $6>0 AND public.zasp_valid_product_id($12) AND $13>clock_timestamp() AND $13<=clock_timestamp()+interval '15 minutes' AND octet_length($14) BETWEEN 1 AND 8192 AND octet_length($15)=12 AND octet_length($16)=16 AND length($3) BETWEEN 16 AND 128,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='identity administration input rejected';END IF;
 PERFORM zasp_authorization80_identity.admit_admin('rotateAPIToken',$1,$10,$11,$2,$5,$9,jsonb_build_object('version',$6,'token_digest',encode($7,'hex'),'replacement_id',$8,'grant_id',$12));
 result:=zasp_authorization80_identity._rotate_pat($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16);
 PERFORM zasp_authorization80_identity.clear_permit();RETURN result;
END $$;
GRANT EXECUTE ON FUNCTION zasp_authorization80_identity.rotate_pat(text,text,text,bytea,text,bigint,bytea,text,text,text,text,text,timestamptz,bytea,bytea,bytea) TO zasp_discovery_api;

CREATE FUNCTION zasp_authorization80_identity._revoke_pat(p1 text,p2 text,p3 text,p4 text,p5 bigint,p6 text,p7 text) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $retained$
 -- retained identity RevokeAPIToken
$retained$;
CREATE FUNCTION zasp_authorization80_identity.revoke_pat(p1 text,p2 text,p3 text,p4 text,p5 bigint,p6 text,p7 text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;
BEGIN
 IF NOT COALESCE(public.zasp_valid_product_id($4) AND $5>0,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='identity administration input rejected';END IF;
 PERFORM zasp_authorization80_identity.admit_admin('revokeAPIToken',$1,$2,$3,$7,$4,$6,jsonb_build_object('version',$5));
 result:=zasp_authorization80_identity._revoke_pat($1,$2,$3,$4,$5,$6,$7);
 PERFORM zasp_authorization80_identity.clear_permit();RETURN result;
END $$;
GRANT EXECUTE ON FUNCTION zasp_authorization80_identity.revoke_pat(text,text,text,text,bigint,text,text) TO zasp_discovery_api;

CREATE FUNCTION zasp_authorization80_identity._ack_reveal(p1 text,p2 text,p3 text,p4 text,p5 text,p6 text) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $retained$
 -- retained identity AcknowledgeAPITokenReveal
$retained$;
CREATE FUNCTION zasp_authorization80_identity.ack_reveal(p1 text,p2 text,p3 text,p4 text,p5 text,p6 text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;
BEGIN
 IF NOT COALESCE(public.zasp_valid_product_id($5),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='identity administration input rejected';END IF;
 PERFORM zasp_authorization80_identity.admit_admin('acknowledgeAPITokenRevealGrant',$1,$2,$3,$4,$5,$6,'{}'::jsonb);
 result:=zasp_authorization80_identity._ack_reveal($1,$2,$3,$4,$5,$6);
 PERFORM zasp_authorization80_identity.clear_permit();RETURN result;
END $$;
GRANT EXECUTE ON FUNCTION zasp_authorization80_identity.ack_reveal(text,text,text,text,text,text) TO zasp_discovery_api;

CREATE FUNCTION zasp_authorization80_identity._revoke_investigated(p1 text,p2 text,p3 text,p4 text,p5 bigint,p6 text,p7 text,p8 text) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $retained$
 -- retained identity RevokeInvestigatedSession
$retained$;
CREATE FUNCTION zasp_authorization80_identity.revoke_investigated(p1 text,p2 text,p3 text,p4 text,p5 bigint,p6 text,p7 text,p8 text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;
BEGIN
 IF NOT COALESCE($4~'^session-[a-z0-9][a-z0-9-]*$' AND $5>0 AND $8=$3,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='identity administration input rejected';END IF;
 PERFORM zasp_authorization80_identity.admit_admin('revokeSession',$1,$2,$3,$7,$4,$6,jsonb_build_object('version',$5));
 result:=zasp_authorization80_identity._revoke_investigated($1,$2,$3,$4,$5,$6,$7,$8);
 PERFORM zasp_authorization80_identity.clear_permit();RETURN result;
END $$;
GRANT EXECUTE ON FUNCTION zasp_authorization80_identity.revoke_investigated(text,text,text,text,bigint,text,text,text) TO zasp_discovery_api;


GRANT SELECT(organization_id,group_reference,role,workspace_id,environment_id,version,updated_at),INSERT(organization_id,group_reference,role,workspace_id,environment_id,version),UPDATE(role,workspace_id,environment_id,version,updated_at) ON public.zasp_group_mappings TO zasp_discovery_authority;
GRANT INSERT(token_digest,id,name,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at,audit_correlation_id) ON public.zasp_product_api_tokens TO zasp_discovery_authority;
GRANT SELECT(organization_id,principal_id,operation,idempotency_key,request_digest,created_at,workspace_id,environment_id,grant_id,response),INSERT(organization_id,principal_id,operation,idempotency_key,request_digest,workspace_id,environment_id,grant_id,response) ON public.zasp_admin_idempotency TO zasp_discovery_authority;
GRANT SELECT(organization_id,workspace_id,environment_id,principal_id,token_id,grant_id,operation,ciphertext,nonce,authentication_tag,expires_at,acknowledged_at,created_at),INSERT(organization_id,workspace_id,environment_id,principal_id,token_id,grant_id,operation,ciphertext,nonce,authentication_tag,expires_at),UPDATE(acknowledged_at,ciphertext,nonce,authentication_tag) ON public.zasp_api_token_reveal_grants TO zasp_discovery_authority;
