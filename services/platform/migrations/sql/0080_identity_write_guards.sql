-- INVOKER preserves the actual writer identity. A SECURITY DEFINER helper
-- without a private transaction permit has no authority here, even for zero rows.
CREATE FUNCTION zasp_authorization80_identity.write_guard() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $$
DECLARE b jsonb;v jsonb;old_row jsonb;new_row jsonb;r jsonb;purpose text;op text;allowed boolean:=false;member_match boolean;revocation boolean;original public.zasp_product_api_tokens%ROWTYPE;
BEGIN
 IF TG_NARGS<>1 OR TG_WHEN<>'BEFORE' OR TG_RELID NOT IN('public.zasp_identity_states'::regclass,'public.zasp_identity_memberships'::regclass,'public.zasp_identity_member_groups'::regclass,'public.zasp_product_sessions'::regclass,'public.zasp_product_api_tokens'::regclass,'public.zasp_group_mappings'::regclass)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity trigger contract rejected';END IF;
 -- Explicit registered migration-principal maintenance; no authority-role bypass.
 IF session_user=TG_ARGV[0] AND current_user=TG_ARGV[0] AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings b JOIN pg_roles p ON p.rolname=b.principal_name WHERE b.authority_role='zasp_discovery_authority' AND b.principal_name=TG_ARGV[0] AND p.rolcanlogin)
 THEN IF TG_LEVEL='STATEMENT' THEN RETURN NULL;ELSIF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;END IF;
 IF current_user<>'zasp_discovery_authority' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='checked identity writer required';END IF;
 SELECT body INTO b FROM zasp_authorization80_identity.permits WHERE pid=pg_backend_pid() AND tx=pg_current_xact_id() AND principal=session_user;
 IF b IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity permit required';END IF;
 purpose:=b->>'purpose';op:=b->>'operation';v:=b->'values';
 allowed:=CASE TG_TABLE_NAME
 WHEN 'zasp_identity_states' THEN (purpose='begin' AND TG_OP='INSERT') OR(purpose='consume' AND TG_OP='UPDATE')
 WHEN 'zasp_identity_memberships' THEN TG_OP='UPDATE' AND(purpose='deprovision' OR(purpose='admin' AND op='updateMemberRole'))
 WHEN 'zasp_identity_member_groups' THEN(purpose='resolve' AND TG_OP IN('INSERT','DELETE')) OR(purpose='deprovision' AND TG_OP='DELETE')
 WHEN 'zasp_product_sessions' THEN(purpose='issue' AND TG_OP IN('INSERT','UPDATE')) OR(TG_OP='UPDATE' AND(purpose IN('resolve','deprovision','logout','switch') OR(purpose='admin' AND op IN('updateMemberRole','updateGroupMappings','revokeSession'))))
 WHEN 'zasp_product_api_tokens' THEN(TG_OP='UPDATE' AND(purpose IN('pat_use','resolve','deprovision') OR(purpose='admin' AND op IN('rotateAPIToken','revokeAPIToken','updateGroupMappings')))) OR(TG_OP='INSERT' AND purpose='admin' AND op IN('createAPIToken','rotateAPIToken'))
 WHEN 'zasp_group_mappings' THEN purpose='admin' AND op='updateGroupMappings' AND TG_OP IN('INSERT','UPDATE') ELSE false END;
 IF NOT COALESCE(allowed,false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity statement effect rejected';END IF;
 IF TG_LEVEL='STATEMENT' THEN RETURN NULL;END IF;
 old_row:=to_jsonb(OLD);new_row:=to_jsonb(NEW);r:=CASE WHEN TG_OP='DELETE' THEN old_row ELSE new_row END;
 member_match:=(r->>'organization_id',r->>'principal_id')=(b->>'organization_id',b->>'principal_id');
 revocation:=TG_OP='UPDATE' AND old_row-'revoked_at'-'version'=new_row-'revoked_at'-'version' AND new_row->>'revoked_at' IS NOT NULL
 AND(new_row->>'revoked_at')::timestamptz=COALESCE((old_row->>'revoked_at')::timestamptz,transaction_timestamp())
 AND(new_row->>'version')::bigint=(old_row->>'version')::bigint+CASE WHEN old_row->>'revoked_at' IS NULL THEN 1 ELSE 0 END;
 allowed:=false;
 CASE TG_TABLE_NAME
 WHEN 'zasp_identity_states' THEN
  allowed:=r->>'state_digest'='\x'||(b->>'state_digest') AND CASE WHEN TG_OP='INSERT' THEN new_row->>'return_path'=b->>'return_path' AND new_row->>'consumed_at' IS NULL AND(new_row->>'expires_at')::timestamptz BETWEEN transaction_timestamp() AND clock_timestamp()+interval '10 minutes'
  ELSE old_row-'consumed_at'=new_row-'consumed_at' AND old_row->>'consumed_at' IS NULL AND(old_row->>'expires_at')::timestamptz>clock_timestamp() AND(new_row->>'consumed_at')::timestamptz BETWEEN transaction_timestamp() AND clock_timestamp() END;
 WHEN 'zasp_identity_memberships' THEN
  allowed:=CASE WHEN purpose='deprovision' THEN member_match AND old_row-'active'-'version'=new_row-'active'-'version' AND NOT(new_row->>'active')::boolean
  ELSE(r->>'organization_id',r->>'principal_id')=(b->>'organization_id',b->>'target') AND old_row-'role'-'version'=new_row-'role'-'version' AND(old_row->>'active')::boolean AND new_row->>'role'=v->>'role' AND old_row->>'version'=v->>'version' END
  AND(new_row->>'version')::bigint=(old_row->>'version')::bigint+1;
 WHEN 'zasp_identity_member_groups' THEN
  allowed:=member_match AND(purpose='deprovision' OR(TG_OP='INSERT' AND b->'groups' ? (r->>'group_reference')) OR(TG_OP='DELETE' AND NOT(b->'groups' ? (r->>'group_reference'))));
 WHEN 'zasp_product_sessions' THEN
  IF TG_OP='INSERT' THEN
   allowed:=member_match AND new_row->>'token_digest'='\x'||(b->>'token_digest') AND encode(public.digest(new_row->>'csrf_token','sha256'),'hex')=b->>'csrf_digest'
   AND(new_row->>'workspace_id',new_row->>'environment_id')=(b->'snapshot'->>'workspace_id',b->'snapshot'->>'environment_id') AND new_row->'permissions'=b->'snapshot'->'permissions'
   AND(new_row->>'expires_at')::timestamptz=zasp_authorization80_identity.body_time(b,'expires_at') AND(new_row->>'authenticated_at')::timestamptz=transaction_timestamp() AND new_row->>'version'='1' AND new_row->>'revoked_at' IS NULL;
  ELSIF purpose='switch' THEN
   allowed:=member_match AND old_row->>'token_digest'='\x'||(b->>'token_digest') AND old_row-ARRAY['workspace_id','environment_id','permissions']=new_row-ARRAY['workspace_id','environment_id','permissions'] AND(new_row->>'workspace_id',new_row->>'environment_id')=(b->>'workspace_id',b->>'environment_id') AND new_row->'permissions'=b->'permissions';
  ELSIF purpose IN('issue','logout') THEN
   allowed:=member_match AND old_row-'revoked_at'=new_row-'revoked_at' AND old_row->>'revoked_at' IS NULL AND CASE WHEN purpose='issue' THEN(new_row->>'revoked_at')::timestamptz=transaction_timestamp() ELSE old_row->>'token_digest'='\x'||(b->>'token_digest') AND(new_row->>'revoked_at')::timestamptz BETWEEN transaction_timestamp() AND clock_timestamp() END;
  ELSE
   allowed:=revocation AND CASE WHEN purpose IN('resolve','deprovision') THEN member_match WHEN op='updateMemberRole' THEN(r->>'organization_id',r->>'principal_id')=(b->>'organization_id',b->>'target') WHEN op='updateGroupMappings' THEN r->>'organization_id'=b->>'organization_id' WHEN op='revokeSession' THEN(r->>'organization_id',r->>'workspace_id',r->>'environment_id',r->>'session_id')=(b->>'organization_id',b->>'workspace_id',b->>'environment_id',b->>'target') AND old_row->>'version'=v->>'version' ELSE false END;
  END IF;
 WHEN 'zasp_product_api_tokens' THEN
  IF purpose='pat_use' THEN
   allowed:=member_match AND old_row->>'token_digest'='\x'||(b->>'token_digest') AND old_row-'last_used_at'=new_row-'last_used_at' AND(new_row->>'last_used_at')::timestamptz BETWEEN transaction_timestamp() AND clock_timestamp();
  ELSIF TG_OP='INSERT' THEN
   allowed:=(r->>'organization_id',r->>'workspace_id',r->>'environment_id')=(b->>'organization_id',b->>'workspace_id',b->>'environment_id') AND r->>'token_digest'='\x'||(v->>'token_digest') AND r->>'audit_correlation_id'=b->>'audit_id' AND r->>'version'='1' AND r->>'revoked_at' IS NULL AND r->>'last_used_at' IS NULL AND(r->>'created_at')::timestamptz=transaction_timestamp();
   IF op='createAPIToken' THEN allowed:=allowed AND r->>'principal_id'=b->>'actor' AND(r->>'id',r->>'name')=(v->>'id',v->>'name') AND r->'permissions'=v->'permissions' AND(r->>'expires_at')::timestamptz=(v->>'expires_at')::timestamptz;
   ELSE
    SELECT * INTO original FROM public.zasp_product_api_tokens WHERE organization_id=b->>'organization_id' AND workspace_id=b->>'workspace_id' AND environment_id=b->>'environment_id' AND id=b->>'target';
    allowed:=allowed AND FOUND AND r->>'id'=v->>'replacement_id' AND(r->>'principal_id',r->>'name')=(original.principal_id,original.name) AND r->'permissions'=original.permissions AND(r->>'expires_at')::timestamptz=original.expires_at;
   END IF;
  ELSE
   allowed:=revocation AND CASE WHEN purpose IN('resolve','deprovision') THEN member_match WHEN op='updateGroupMappings' THEN r->>'organization_id'=b->>'organization_id' WHEN op IN('rotateAPIToken','revokeAPIToken') THEN(r->>'organization_id',r->>'workspace_id',r->>'environment_id',r->>'id')=(b->>'organization_id',b->>'workspace_id',b->>'environment_id',b->>'target') AND old_row->>'version'=v->>'version' ELSE false END;
  END IF;
 WHEN 'zasp_group_mappings' THEN
  IF TG_OP='UPDATE' AND(old_row->>'workspace_id',old_row->>'environment_id') IS DISTINCT FROM(b->>'workspace_id',b->>'environment_id') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='foreign identity mapping rejected';END IF;
  allowed:=(r->>'organization_id',r->>'workspace_id',r->>'environment_id',r->>'group_reference',r->>'role')=(b->>'organization_id',b->>'workspace_id',b->>'environment_id',b->>'target',v->>'role') AND CASE WHEN TG_OP='INSERT' THEN v->>'version'='0' AND r->>'version'='1' ELSE old_row-ARRAY['role','workspace_id','environment_id','version','updated_at']=new_row-ARRAY['role','workspace_id','environment_id','version','updated_at'] AND old_row->>'version'=v->>'version' AND(new_row->>'version')::bigint=(old_row->>'version')::bigint+1 AND(new_row->>'updated_at')::timestamptz=transaction_timestamp() END;
 ELSE allowed:=false;
 END CASE;
 IF NOT COALESCE(allowed,false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity row effect rejected';END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
END $$;

CREATE FUNCTION zasp_authorization80_identity.scope_cleanup_allowed() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT EXISTS(SELECT 1 FROM zasp_authorization80_identity.permits WHERE pid=pg_backend_pid() AND tx=pg_current_xact_id() AND principal=session_user AND body->>'purpose'='deprovision' AND public.zasp_valid_product_id(body->>'organization_id') AND public.zasp_valid_product_id(body->>'principal_id'))
$$;

DO $identity_guards$
DECLARE owner_name text;relation_value regclass;
BEGIN
 SELECT principal_name INTO STRICT owner_name FROM public.zasp_discovery_principal_bindings WHERE authority_role='zasp_discovery_authority';
 IF owner_name IS DISTINCT FROM current_user THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='identity source owner rejected';END IF;
 FOREACH relation_value IN ARRAY ARRAY['public.zasp_identity_states'::regclass,'public.zasp_identity_memberships'::regclass,'public.zasp_identity_member_groups'::regclass,'public.zasp_product_sessions'::regclass,'public.zasp_product_api_tokens'::regclass,'public.zasp_group_mappings'::regclass] LOOP
  EXECUTE format('CREATE TRIGGER zasp_identity80_statement_guard BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION zasp_authorization80_identity.write_guard(%L)',relation_value,owner_name);
  EXECUTE format('CREATE TRIGGER zasp_identity80_row_guard BEFORE INSERT OR UPDATE OR DELETE ON %s FOR EACH ROW EXECUTE FUNCTION zasp_authorization80_identity.write_guard(%L)',relation_value,owner_name);
 END LOOP;
END $identity_guards$;
