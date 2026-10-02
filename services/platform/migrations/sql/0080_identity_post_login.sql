-- Self-only admission. Expected identity fields constrain, never choose, a tenant.
-- None of these entries sets product authorization context or a write permit.
CREATE FUNCTION zasp_authorization80_identity.post_login_binding(b jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE c jsonb;initial_org text;field text;kind integer;
BEGIN
 IF NOT zasp_authorization80_identity.api_ready() OR b IS NULL OR jsonb_typeof(b)<>'object' OR octet_length(b::text)>8192 OR(SELECT count(*) FROM jsonb_object_keys(b))<>9
 OR NOT b ?& ARRAY['credential_kind','credential_id','credential_digest','principal_id','organization_id','workspace_id','environment_id','csrf_digest','pat_ceiling'] THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='post-login binding rejected';END IF;
 FOREACH field IN ARRAY ARRAY['credential_id','credential_digest','principal_id','organization_id','workspace_id','environment_id','csrf_digest'] LOOP
  IF jsonb_typeof(b->field)<>'string' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='post-login binding rejected';END IF;
 END LOOP;
 IF NOT COALESCE(b->>'credential_kind' IN('1','2') AND jsonb_typeof(b->'credential_kind')='number' AND length(b->>'credential_id') BETWEEN 1 AND 128 AND b->>'credential_digest'~'^[a-f0-9]{64}$'
 AND public.zasp_valid_product_id(b->>'principal_id') AND public.zasp_valid_product_id(b->>'organization_id') AND public.zasp_valid_product_id(b->>'workspace_id') AND public.zasp_valid_product_id(b->>'environment_id') AND jsonb_typeof(b->'pat_ceiling')='array',false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='post-login binding rejected';END IF;
 kind:=(b->>'credential_kind')::integer;
 IF kind=1 THEN
  SELECT to_jsonb(s) INTO c FROM public.zasp_product_sessions s WHERE s.token_digest=decode(b->>'credential_digest','hex') AND s.session_id=b->>'credential_id';
 ELSE
  SELECT to_jsonb(t) INTO c FROM public.zasp_product_api_tokens t WHERE t.token_digest=decode(b->>'credential_digest','hex') AND t.id=b->>'credential_id';
 END IF;
 IF c IS NULL OR(c->>'organization_id',c->>'principal_id',c->>'workspace_id',c->>'environment_id') IS DISTINCT FROM(b->>'organization_id',b->>'principal_id',b->>'workspace_id',b->>'environment_id') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='post-login credential changed';END IF;
 initial_org:=c->>'organization_id';
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=initial_org FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='post-login projection changed';END IF;
 PERFORM 1 FROM public.zasp_identity_memberships WHERE organization_id=initial_org AND principal_id=c->>'principal_id' AND active FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='post-login membership changed';END IF;
 IF kind=1 THEN
  SELECT to_jsonb(s) INTO c FROM public.zasp_product_sessions s WHERE s.token_digest=decode(b->>'credential_digest','hex') AND s.session_id=b->>'credential_id' FOR SHARE;
 ELSE
  SELECT to_jsonb(t) INTO c FROM public.zasp_product_api_tokens t WHERE t.token_digest=decode(b->>'credential_digest','hex') AND t.id=b->>'credential_id' FOR SHARE;
 END IF;
 IF c IS NULL OR c->>'revoked_at' IS NOT NULL OR(c->>'expires_at')::timestamptz<=clock_timestamp()
 OR(c->>'organization_id',c->>'principal_id',c->>'workspace_id',c->>'environment_id') IS DISTINCT FROM(b->>'organization_id',b->>'principal_id',b->>'workspace_id',b->>'environment_id')
 OR NOT EXISTS(SELECT 1 FROM public.zasp_identity_admin_effective_scopes(c->>'principal_id',initial_org) s WHERE(s.workspace_id,s.environment_id)=(c->>'workspace_id',c->>'environment_id'))
 OR(kind=1 AND(b->'pat_ceiling'<>'[]'::jsonb OR encode(public.digest(c->>'csrf_token','sha256'),'hex') IS DISTINCT FROM b->>'csrf_digest'))
 OR(kind=2 AND(b->>'csrf_digest'<>'' OR c->'permissions' IS DISTINCT FROM b->'pat_ceiling')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='post-login credential changed';END IF;
 RETURN c;
END $$;

CREATE FUNCTION zasp_authorization80_identity.post_login_snapshot(b jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE c jsonb:=zasp_authorization80_identity.post_login_binding(b);principal jsonb;scopes jsonb;r jsonb;
BEGIN
 SELECT jsonb_build_object('id',principal_id,'organization_id',organization_id,'organization_reference',organization_reference,'member_reference',member_reference,'role',role,'active',active) INTO principal FROM public.zasp_identity_memberships WHERE organization_id=c->>'organization_id' AND principal_id=c->>'principal_id' AND active;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'label',label) ORDER BY label,workspace_id,environment_id),'[]') INTO scopes FROM(SELECT * FROM public.zasp_identity_admin_effective_scopes(c->>'principal_id',c->>'organization_id') LIMIT 10001) s;
 IF principal IS NULL OR jsonb_array_length(scopes)=0 OR jsonb_array_length(scopes)>10000 THEN RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='post-login scope snapshot unavailable';END IF;
 SELECT jsonb_build_object('organization_id',organization_id,'desired',desired,'applied',applied,'generation',generation,'store_id',store_id,'model_id',model_id) INTO r FROM zasp_authorization79.organizations WHERE organization_id=c->>'organization_id';
 IF(c->>'expires_at')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='post-login credential expired';END IF;
 RETURN jsonb_build_object('principal',principal,'scopes',scopes,'revision',r);
END $$;

CREATE FUNCTION zasp_authorization80_identity.post_login_read(b jsonb,r jsonb,correlation text,purpose text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE snap jsonb;result jsonb;
BEGIN
 IF NOT COALESCE(purpose IN('bootstrapSession','getCurrentPrincipal','listSessionScopes') AND public.zasp_valid_product_id(correlation) AND(purpose='getCurrentPrincipal' OR b->>'credential_kind'='1'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='post-login purpose rejected';END IF;
 snap:=zasp_authorization80_identity.post_login_snapshot(b);
 IF r IS NULL OR r IS DISTINCT FROM snap->'revision' OR(r->>'desired')::bigint<1 OR r->'desired' IS DISTINCT FROM r->'applied' OR(r->>'generation')::bigint<1 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='post-login authorization changed';END IF;
 PERFORM zasp_authorization79.revalidate(r->>'organization_id',(r->>'desired')::bigint,(r->>'generation')::bigint,r->>'store_id',r->>'model_id');
 result:=CASE WHEN purpose='listSessionScopes' THEN jsonb_build_object('items',snap->'scopes') ELSE jsonb_build_object('principal',snap->'principal','correlation_id',correlation) END;
 -- Expiry is checked again after the complete capture and any lock wait.
 PERFORM zasp_authorization80_identity.post_login_binding(b);
 RETURN result;
END $$;
