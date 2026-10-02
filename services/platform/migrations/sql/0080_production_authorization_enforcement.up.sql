-- Registered request fences. Base mode has no extension78 dependency; the
-- explicitly installed composed mode cannot fall back to base readiness.
SET LOCAL lock_timeout='3s';
CREATE SCHEMA zasp_authorization80 AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_authorization80 FROM PUBLIC;
CREATE TABLE zasp_authorization80.registration(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),checksum text NOT NULL,fingerprint text NOT NULL);
CREATE TABLE zasp_authorization80.runtime_profile(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),name text NOT NULL CHECK(name IN('canonical61-authorization79-80-v1','canonical61-temporal78-authorization79-80-v1')),audit_mode text NOT NULL DEFAULT 'none' CHECK(audit_mode IN('none','source52-canonical61-audit-v1')),identity_mode text NOT NULL DEFAULT 'none' CHECK(identity_mode IN('none','source19-canonical61-identity-v1')));
INSERT INTO zasp_authorization80.runtime_profile(name) VALUES('canonical61-authorization79-80-v1');
ALTER TABLE zasp_authorization80.runtime_profile OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_authorization80.runtime_profile ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_authorization80.runtime_profile FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_authorization80.runtime_profile TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE FUNCTION zasp_authorization80.profile_immutable() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM zasp_authorization80.registration)
 OR NOT EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority')
 OR NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization runtime profile immutable';
 END IF;
 RETURN NULL;
END $$;
CREATE TRIGGER immutable BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON zasp_authorization80.runtime_profile FOR EACH STATEMENT EXECUTE FUNCTION zasp_authorization80.profile_immutable();

CREATE FUNCTION zasp_authorization80.runtime_profile_ready() RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE selected text;result boolean;
BEGIN
 IF(SELECT count(*) FROM zasp_authorization80.runtime_profile)<>1 THEN RETURN false;END IF;
 SELECT name INTO selected FROM zasp_authorization80.runtime_profile WHERE singleton;
 IF selected='canonical61-authorization79-80-v1' THEN
  RETURN to_regnamespace('zasp_temporal78') IS NULL AND to_regnamespace('zasp_authorization80_temporal') IS NULL;
 ELSIF selected='canonical61-temporal78-authorization79-80-v1' THEN
  IF to_regnamespace('zasp_temporal78') IS NULL OR to_regclass('zasp_authorization80_temporal.registration') IS NULL OR to_regprocedure('zasp_authorization80_temporal.catalog_ready()') IS NULL THEN RETURN false;END IF;
  -- Closed dispatch, not an identifier supplied by a caller or selector row.
  EXECUTE 'SELECT zasp_authorization80_temporal.catalog_ready()' INTO result;
  RETURN COALESCE(result,false);
 END IF;
 RETURN false;
EXCEPTION WHEN OTHERS THEN RETURN false;
END $$;

CREATE FUNCTION zasp_authorization80.runtime_audit_ready() RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE selected text;result boolean;
BEGIN
 IF(SELECT count(*) FROM zasp_authorization80.runtime_profile)<>1 THEN RETURN false;END IF;
 SELECT audit_mode INTO selected FROM zasp_authorization80.runtime_profile WHERE singleton;
 IF selected='none' THEN
  RETURN to_regnamespace('zasp_authorization80_audit') IS NULL AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.zasp_admin_audit'::regclass AND tgname='zasp_authorization80_audit_write_guard');
 ELSIF selected='source52-canonical61-audit-v1' THEN
  IF to_regclass('zasp_authorization80_audit.registration') IS NULL OR to_regprocedure('zasp_authorization80_audit.catalog_ready()') IS NULL THEN RETURN false;END IF;
  EXECUTE 'SELECT zasp_authorization80_audit.catalog_ready()' INTO result;
  RETURN COALESCE(result,false);
 END IF;
 RETURN false;
EXCEPTION WHEN OTHERS THEN RETURN false;
END $$;

CREATE FUNCTION zasp_authorization80.runtime_identity_ready() RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE selected text;result boolean;
BEGIN
 SELECT identity_mode INTO selected FROM zasp_authorization80.runtime_profile WHERE singleton;
 IF selected='none' THEN RETURN to_regnamespace('zasp_authorization80_identity') IS NULL;END IF;
 IF selected IS DISTINCT FROM 'source19-canonical61-identity-v1' OR to_regprocedure('zasp_authorization80_identity.catalog_ready()') IS NULL THEN RETURN false;END IF;
 -- Exact checksum-free body pin. An allow-valued gate cannot bypass its own
 -- catalog comparison, even if it also replaces a fingerprint helper.
 IF NOT EXISTS(SELECT 1 FROM pg_proc WHERE oid=to_regprocedure('zasp_authorization80_identity.catalog_ready()') AND prosrc='-- authorization80 identity catalog body' AND proowner='zasp_discovery_authority'::regrole AND prosecdef AND proconfig=ARRAY['search_path=pg_catalog, public'] AND provolatile='s' AND prolang=(SELECT oid FROM pg_language WHERE lanname='sql') AND proacl::text='{zasp_discovery_authority=X/zasp_discovery_authority}') THEN RETURN false;END IF;
 EXECUTE 'SELECT zasp_authorization80_identity.catalog_ready()' INTO result;
 RETURN COALESCE(result,false);
EXCEPTION WHEN OTHERS THEN RETURN false;
END $$;

CREATE FUNCTION zasp_authorization80.fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $$
 WITH facts(v) AS(
 SELECT concat_ws('|','schema',nspowner::regrole::text,nspacl::text) FROM pg_namespace WHERE nspname='zasp_authorization80'
 UNION ALL SELECT concat_ws('|','runtime-profile',singleton,name,audit_mode,identity_mode) FROM zasp_authorization80.runtime_profile
 UNION ALL SELECT concat_ws('|','runtime-profile-trigger',t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t WHERE t.tgrelid='zasp_authorization80.runtime_profile'::regclass AND NOT t.tgisinternal
 UNION ALL SELECT concat_ws('|','runtime-profile-column',a.attname,a.atttypid,a.atttypmod,a.attnotnull,a.attacl::text,pg_get_expr(d.adbin,d.adrelid)) FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid='zasp_authorization80.runtime_profile'::regclass AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','function',p.proname,p.proowner::regrole::text,p.proacl::text,pg_get_functiondef(p.oid)) FROM pg_proc p WHERE pronamespace='zasp_authorization80'::regnamespace
 UNION ALL SELECT concat_ws('|','home-source-function',p.proname,p.proowner::regrole::text,p.proacl::text,pg_get_functiondef(p.oid)) FROM pg_proc p WHERE oid IN('public.zasp_inventory_home_summary(text,text,text)'::regprocedure,'public.zasp_inventory_home_summary_v29(text,text,text)'::regprocedure,'public.zasp_inventory_scope_state(text,text,text)'::regprocedure)
 UNION ALL SELECT concat_ws('|','relation',c.relname,c.relkind,c.relowner::regrole::text,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity) FROM pg_class c WHERE relnamespace='zasp_authorization80'::regnamespace
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid)) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_authorization80'::regnamespace
 UNION ALL SELECT concat_ws('|','policy',c.relname,p.polname,p.polroles::regrole[]::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_authorization80'::regnamespace
 UNION ALL SELECT concat_ws('|','risk-relation',c.relname,c.relowner::regrole::text,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity) FROM pg_class c WHERE c.oid=ANY(ARRAY['public.zasp_risk_findings'::regclass,'public.zasp_risk_finding_evidence'::regclass,'public.zasp_risk_finding_factors'::regclass,'public.zasp_risk_attack_paths'::regclass,'public.zasp_risk_attack_path_nodes'::regclass,'public.zasp_risk_attack_path_evidence'::regclass,'public.zasp_risk_break_options'::regclass])
 UNION ALL SELECT concat_ws('|','risk-policy',c.relname,p.polname,p.polpermissive,p.polcmd,p.polroles::regrole[]::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.oid=ANY(ARRAY['public.zasp_risk_findings'::regclass,'public.zasp_risk_finding_evidence'::regclass,'public.zasp_risk_finding_factors'::regclass,'public.zasp_risk_attack_paths'::regclass,'public.zasp_risk_attack_path_nodes'::regclass,'public.zasp_risk_attack_path_evidence'::regclass,'public.zasp_risk_break_options'::regclass])
 UNION ALL SELECT concat_ws('|','data-controls-relation',c.relname,c.relowner::regrole::text,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity) FROM pg_class c WHERE c.oid='public.zasp_data_controls'::regclass
 UNION ALL SELECT concat_ws('|','data-controls-policy',p.polname,p.polpermissive,p.polcmd,p.polroles::regrole[]::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p WHERE p.polrelid='public.zasp_data_controls'::regclass
 UNION ALL SELECT concat_ws('|','data-controls-column',a.attname,a.atttypid,a.atttypmod,a.attnotnull,a.attacl::text,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid)) FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid='public.zasp_data_controls'::regclass AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','data-controls-constraint',c.conname,pg_get_constraintdef(c.oid)) FROM pg_constraint c WHERE c.conrelid='public.zasp_data_controls'::regclass
 UNION ALL SELECT concat_ws('|','hierarchy-relation',c.relname,c.relkind,c.relowner::regrole::text,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity) FROM pg_class c WHERE c.oid IN('public.zasp_workspaces'::regclass,'public.zasp_environments'::regclass,'public.zasp_authorized_scopes'::regclass,'public.zasp_core_payloads'::regclass)
 UNION ALL SELECT concat_ws('|','hierarchy-trigger',t.tgrelid::regclass::text,t.tgname,t.tgenabled,t.tgtype,t.tgisinternal,t.tgdeferrable,t.tginitdeferred,t.tgconstraint,t.tgconstrrelid,t.tgconstrindid,t.tgnargs,t.tgattr,t.tgqual,t.tgoldtable,t.tgnewtable,t.tgfoid::regprocedure::text,encode(t.tgargs,'hex'),pg_get_triggerdef(t.oid)) FROM pg_trigger t WHERE t.tgrelid IN('public.zasp_workspaces'::regclass,'public.zasp_environments'::regclass,'public.zasp_authorized_scopes'::regclass,'public.zasp_core_payloads'::regclass) AND NOT t.tgisinternal
 UNION ALL SELECT concat_ws('|','hierarchy-column',a.attrelid::regclass::text,a.attname,a.atttypid,a.atttypmod,a.attnotnull,a.attacl::text,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid)) FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid IN('public.zasp_workspaces'::regclass,'public.zasp_environments'::regclass,'public.zasp_authorized_scopes'::regclass,'public.zasp_core_payloads'::regclass) AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','hierarchy-constraint',c.conrelid::regclass::text,c.conname,pg_get_constraintdef(c.oid)) FROM pg_constraint c WHERE c.conrelid IN('public.zasp_workspaces'::regclass,'public.zasp_environments'::regclass,'public.zasp_authorized_scopes'::regclass,'public.zasp_core_payloads'::regclass)
 UNION ALL SELECT concat_ws('|','hierarchy-policy',p.polrelid::regclass::text,p.polname,p.polpermissive,p.polcmd,p.polroles::regrole[]::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p WHERE p.polrelid IN('public.zasp_workspaces'::regclass,'public.zasp_environments'::regclass,'public.zasp_authorized_scopes'::regclass,'public.zasp_core_payloads'::regclass)
 ) SELECT encode(digest(convert_to(string_agg(v,E'\n' ORDER BY v),'UTF8'),'sha256'),'hex') FROM facts
$$;
CREATE FUNCTION zasp_authorization80.ready(c text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT c='-- authorization80 checksum' AND EXISTS(SELECT 1 FROM zasp_authorization80.registration WHERE checksum=c AND fingerprint=zasp_authorization80.fingerprint())
 AND zasp_authorization80.runtime_profile_ready()
 AND zasp_authorization80.runtime_audit_ready()
 AND zasp_authorization80.runtime_identity_ready()
 AND zasp_authorization79.ready('-- authorization80 projection checksum')
 AND public.zasp_sa_multistep_readiness('-- authorization80 canonical checksum','-- authorization80 canonical fingerprint')
$$;

-- Current source rows come only from this closed product-owned registry. No
-- authorization80 attestation

-- Current source rows come only from this closed product-owned registry. No
-- caller may supply a table, SQL predicate, parent scope or object alias.
CREATE FUNCTION zasp_authorization80.source(k text) RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,public AS $$
 SELECT CASE k
 WHEN 'finding' THEN '["zasp_risk_findings","id"]'::jsonb
 WHEN 'attack_path' THEN '["zasp_risk_attack_paths","id"]'::jsonb
 WHEN 'agent' THEN '["zasp_inventory_entities","id"]'::jsonb
 WHEN 'tool' THEN '["zasp_inventory_entities","id"]'::jsonb
 WHEN 'identity' THEN '["zasp_inventory_entities","id"]'::jsonb
 WHEN 'runtime' THEN '["zasp_inventory_entities","id"]'::jsonb
 WHEN 'asset' THEN '["zasp_inventory_entities","id"]'::jsonb
 WHEN 'integration' THEN '["zasp_integrations","id"]'::jsonb
 WHEN 'sensor' THEN '["zasp_sensors","id"]'::jsonb
 WHEN 'discovery_sync' THEN '["zasp_discovery_syncs","id"]'::jsonb
 WHEN 'discovery_schedule' THEN '["zasp_discovery_schedules","id"]'::jsonb
 WHEN 'security_agent' THEN '["zasp_security_agent_definitions","definition_id"]'::jsonb
 WHEN 'security_agent_run' THEN '["zasp_security_agent_runs","run_id"]'::jsonb
 WHEN 'security_agent_approval' THEN '["zasp_security_agent_approvals","approval_id"]'::jsonb
 WHEN 'security_agent_audit' THEN '["zasp_security_agent_audit","audit_id"]'::jsonb
 WHEN 'test' THEN '["zasp_red_team_definitions","definition_id"]'::jsonb
 WHEN 'test_run' THEN '["zasp_red_team_runs","run_id"]'::jsonb
 WHEN 'attack_lab_run' THEN '["zasp_attack_lab_runs","run_id"]'::jsonb
 WHEN 'recovery_backup' THEN '["zasp_recovery_backups","backup_id"]'::jsonb
 WHEN 'recovery_restore' THEN '["zasp_recovery_restores","restore_id"]'::jsonb
 WHEN 'workflow_receipt' THEN '["zasp_workflow_receipts","receipt_id"]'::jsonb
 WHEN 'policy' THEN '["zasp_workflow_records","id"]'::jsonb
 WHEN 'session' THEN '["zasp_runtime_session_summaries","id"]'::jsonb
 WHEN 'product_session' THEN '["zasp_product_sessions","session_id"]'::jsonb
 WHEN 'audit_export' THEN '["zasp_audit_export_jobs","id"]'::jsonb
 WHEN 'compliance_export' THEN '["zasp_compliance_export_jobs","export_id"]'::jsonb
 WHEN 'audit_event' THEN '["zasp_admin_audit","id"]'::jsonb
 WHEN 'compliance_control' THEN '["zasp_compliance_controls","id"]'::jsonb
 WHEN 'compliance_evidence' THEN '["zasp_compliance_evidence","id"]'::jsonb
 ELSE NULL END
$$;

CREATE FUNCTION zasp_authorization80.source_rows(o text,w text,e text,k text,i text DEFAULT NULL,lock_rows boolean DEFAULT false) RETURNS SETOF jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE descriptor jsonb;query_value text;
BEGIN
 descriptor:=zasp_authorization80.source(k);
 IF descriptor IS NULL OR to_regclass('public.'||(descriptor->>0)) IS NULL THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authorization resource source unavailable';END IF;
 query_value:=format('SELECT to_jsonb(t) FROM public.%I t WHERE to_jsonb(t)->>''organization_id''=$1 AND to_jsonb(t)->>''workspace_id''=$2 AND to_jsonb(t)->>''environment_id''=$3 AND ($4 IS NULL OR to_jsonb(t)->>%L=$4) AND to_jsonb(t)->>''deleted_at'' IS NULL',descriptor->>0,descriptor->>1);
 IF descriptor->>0='zasp_inventory_entities' THEN query_value:=query_value||' AND to_jsonb(t)->>''state''=''active'' AND to_jsonb(t)->>''product_kind''=$5';END IF;
 IF descriptor->>0='zasp_workflow_records' THEN query_value:=query_value||' AND to_jsonb(t)->>''kind''=$5';END IF;
 query_value:=query_value||format(' ORDER BY to_jsonb(t)->>%L LIMIT 10001',descriptor->>1);
 IF lock_rows THEN query_value:=query_value||' FOR SHARE OF t';END IF;
 RETURN QUERY EXECUTE query_value USING o,w,e,i,k;
END $$;

CREATE FUNCTION zasp_authorization80.object_id(o text,w text,e text,k text,i text) RETURNS text LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,public AS $$
BEGIN
 IF public.zasp_valid_product_id(i) THEN RETURN i;END IF;
 IF(k='session' AND i='unattributed') OR(k='product_session' AND i~'^session-[a-z0-9][a-z0-9-]*$') OR(k='policy' AND i~'^policy-[a-z0-9][a-z0-9-]{0,120}$') THEN RETURN public.zasp_discovery_canonical_id(o,w,e,'authorization_'||k,i);END IF;
 RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authorization resource identity unavailable';
END $$;

CREATE FUNCTION zasp_authorization80.resolve(o text,w text,e text,k text,i text DEFAULT NULL,selector text DEFAULT NULL) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;descriptor jsonb;entry text;part jsonb;
BEGIN
 IF NOT zasp_authorization79.reader() OR NOT zasp_authorization80.ready('-- authorization80 checksum') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization resolver rejected';END IF;
 IF k='environment' AND i IS NULL THEN
  IF NOT EXISTS(SELECT 1 FROM public.zasp_workspaces x WHERE(x.organization_id,x.id)=(o,w)) THEN RETURN '[]'::jsonb;END IF;
 ELSIF NOT EXISTS(SELECT 1 FROM public.zasp_environments x WHERE(x.organization_id,x.workspace_id,x.id)=(o,w,e)) THEN RETURN '[]'::jsonb;END IF;
 IF k IN('workflow_receipt','security_agent_audit','audit_event','audit_export','compliance_export','compliance_evidence','compliance_control') THEN RETURN zasp_authorization80.parent_targets(o,w,e,k,i,selector);END IF;
 IF k='*' THEN
  result:=zasp_authorization80.resolve(o,w,e,'environment',e);
  FOREACH entry IN ARRAY ARRAY['agent','tool','identity','runtime','asset','finding','attack_path','policy','integration','sensor','security_agent','security_agent_run','security_agent_approval','test','test_run','attack_lab_run','recovery_backup','recovery_restore','session','product_session','discovery_sync','discovery_schedule'] LOOP
   part:=zasp_authorization80.resolve(o,w,e,entry,NULL);result:=result||part;
   IF jsonb_array_length(result)>10000 THEN RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='authorization candidates exceed bound';END IF;
  END LOOP;
  RETURN result;
 END IF;
 IF k IN('workspace','environment') THEN
  SELECT COALESCE(jsonb_agg(jsonb_build_object('organization_id',o,'workspace_id',x.workspace_id,'environment_id',x.id,'kind',k,'id',CASE k WHEN 'workspace' THEN x.workspace_id ELSE x.id END,'version',CASE k WHEN 'workspace' THEN parent.version ELSE x.version END) ORDER BY x.workspace_id,x.id),'[]'::jsonb) INTO result
  FROM public.zasp_environments x JOIN public.zasp_workspaces parent ON(parent.organization_id,parent.id)=(x.organization_id,x.workspace_id)
  WHERE x.organization_id=o AND(k='workspace' AND(i IS NULL OR(parent.id,x.id)=(i,e)) OR k='environment' AND x.workspace_id=w AND(i IS NULL OR x.id=i));
  IF jsonb_array_length(result)>10000 THEN RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='authorization candidates exceed bound';END IF;
  RETURN result;
 END IF;
 IF k IN('organization','organization_identity') THEN
  IF i IS DISTINCT FROM (CASE k WHEN 'organization' THEN o WHEN 'organization_identity' THEN o WHEN 'workspace' THEN w ELSE e END) THEN RETURN '[]'::jsonb;END IF;
  RETURN jsonb_build_array(jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'kind',k,'id',i,'version',0));
 END IF;
 descriptor:=zasp_authorization80.source(k);
 SELECT COALESCE(jsonb_agg(jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'kind',k,'id',zasp_authorization80.object_id(o,w,e,k,v->>(descriptor->>1)),'source_id',v->>(descriptor->>1),'version',COALESCE((v->>'version')::bigint,0))),'[]'::jsonb) INTO result FROM zasp_authorization80.source_rows(o,w,e,k,i) v;
 IF jsonb_array_length(result)>10000 THEN RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='authorization candidates exceed bound';END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(result) x WHERE NOT public.zasp_valid_product_id(x->>'id')) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authorization resource identity unavailable';END IF;
 RETURN result;
END $$;

CREATE FUNCTION zasp_authorization80.identity_fence(p jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE credential jsonb;kind integer;
BEGIN
 PERFORM 1 FROM public.zasp_identity_memberships m WHERE(m.principal_id,m.organization_id)=(p->>'principal_id',p->>'organization_id') AND m.active FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='current identity changed; retry from Check';END IF;
 kind:=(p->>'credential_kind')::integer;
 IF kind=1 THEN
  SELECT to_jsonb(s) INTO credential FROM public.zasp_product_sessions s WHERE s.token_digest=decode(p->>'credential_digest','hex') AND s.session_id=p->>'credential_id' FOR SHARE;
 ELSIF kind=2 THEN
  SELECT to_jsonb(t) INTO credential FROM public.zasp_product_api_tokens t WHERE t.token_digest=decode(p->>'credential_digest','hex') AND t.id=p->>'credential_id' FOR SHARE;
 ELSE RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='credential kind rejected';END IF;
 IF credential IS NULL OR credential->>'revoked_at' IS NOT NULL OR (credential->>'expires_at')::timestamptz<=clock_timestamp()
 OR (credential->>'principal_id',credential->>'organization_id',credential->>'workspace_id',credential->>'environment_id') IS DISTINCT FROM(p->>'principal_id',p->>'organization_id',p->>'workspace_id',p->>'environment_id')
 OR NOT EXISTS(SELECT 1 FROM public.zasp_identity_admin_effective_scopes(p->>'principal_id',p->>'organization_id') s WHERE(s.workspace_id,s.environment_id)=(p->>'workspace_id',p->>'environment_id'))
 OR(kind=2 AND(NOT credential->'permissions' ? (p->>'permission') OR credential->'permissions' IS DISTINCT FROM p->'pat_ceiling'))
 OR(kind=1 AND encode(public.digest(credential->>'csrf_token','sha256'),'hex') IS DISTINCT FROM p->>'csrf_digest')
 OR(kind=1 AND COALESCE((p->>'fresh_auth')::boolean,false) AND (credential->>'authenticated_at')::timestamptz<=clock_timestamp()-interval '5 minutes')
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='current credential changed; retry from Check';END IF;
END $$;

CREATE FUNCTION zasp_authorization80.fence(envelope text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE p jsonb;r jsonb;target jsonb;current_value jsonb;descriptor jsonb;
BEGIN
 IF NOT zasp_authorization79.reader() OR NOT zasp_authorization80.ready('-- authorization80 checksum') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization fence rejected';END IF;
 p:=zasp_authorization80.verify_attestation(envelope);
 r:=p->'revision';
 IF r->>'organization_id' IS DISTINCT FROM p->>'organization_id' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization scope rejected';END IF;
 PERFORM zasp_authorization79.revalidate(r->>'organization_id',(r->>'desired')::bigint,(r->>'generation')::bigint,r->>'store_id',r->>'model_id');
 PERFORM zasp_authorization80.identity_fence(p);
 FOR target IN SELECT value FROM jsonb_array_elements(p->'targets') ORDER BY value->>'kind',value->>'id' LOOP
  IF target->>'organization_id' IS DISTINCT FROM p->>'organization_id' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization target scope rejected';END IF;
  IF target->>'kind' IN('organization','organization_identity','workspace','environment') THEN
   PERFORM 1 FROM public.zasp_environments x WHERE(x.organization_id,x.workspace_id,x.id)=(target->>'organization_id',target->>'workspace_id',target->>'environment_id') FOR SHARE;
   IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='authorization target changed';END IF;
   IF target->>'kind'='workspace' THEN
    PERFORM 1 FROM public.zasp_workspaces x WHERE(x.organization_id,x.id,x.version)=(target->>'organization_id',target->>'id',(target->>'version')::bigint) FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='authorization workspace version changed';END IF;
   ELSIF target->>'kind'='environment' THEN
    PERFORM 1 FROM public.zasp_environments x WHERE(x.organization_id,x.workspace_id,x.id,x.version)=(target->>'organization_id',target->>'workspace_id',target->>'id',(target->>'version')::bigint) FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='authorization environment version changed';END IF;
   END IF;
  ELSE
   descriptor:=zasp_authorization80.source(target->>'kind');
   SELECT v INTO current_value FROM zasp_authorization80.source_rows(target->>'organization_id',target->>'workspace_id',target->>'environment_id',target->>'kind',COALESCE(NULLIF(target->>'source_id',''),target->>'id'),true) v;
   IF current_value IS NULL OR COALESCE((current_value->>'version')::bigint,0) IS DISTINCT FROM (target->>'version')::bigint THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='authorization target version changed';END IF;
  END IF;
 END LOOP;
 PERFORM set_config('zasp.authorization80',p::text,true);
 PERFORM txid_current();
 PERFORM set_config('zasp.authorization80_seal',zasp_authorization80.context_seal(p),true);
END $$;

CREATE FUNCTION zasp_authorization80.allowed(o text,w text,e text,k text,i text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT EXISTS(SELECT 1 FROM jsonb_array_elements(COALESCE(zasp_authorization80.context()->'allowed','[]'::jsonb)) x WHERE(x->>'organization_id',x->>'workspace_id',x->>'environment_id',x->>'kind',COALESCE(NULLIF(x->>'source_id',''),x->>'id'))=(o,w,e,k,i))
$$;

-- A target key is not a permission-free capability. Each native entry point
-- declares its closed read contract, independently of the Go classifier.
CREATE FUNCTION zasp_authorization80.read_request(o text,w text,e text,operations text[],permission_value text,browser_only boolean DEFAULT false,actor text DEFAULT NULL) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT COALESCE((p->>'organization_id',p->>'workspace_id',p->>'environment_id',p->>'permission')=(o,w,e,permission_value)
 AND p->>'operation_id'=ANY(operations) AND p->>'credential_kind'=ANY(CASE WHEN browser_only THEN ARRAY['1'] ELSE ARRAY['1','2'] END)
 AND(actor IS NULL OR p->>'principal_id'=actor),false) FROM(SELECT zasp_authorization80.context() p) proof
$$;
CREATE FUNCTION zasp_authorization80.require_read(o text,w text,e text,operations text[],permission_value text,browser_only boolean DEFAULT false,actor text DEFAULT NULL) RETURNS void LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF NOT zasp_authorization80.read_request(o,w,e,operations,permission_value,browser_only,actor) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current read purpose required';END IF;
END $$;

CREATE FUNCTION zasp_authorization80.risk_page(k text,o text,w text,e text,a text,n integer) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;
BEGIN
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY[CASE k WHEN 'finding' THEN 'listFindings' WHEN 'attack_path' THEN 'listAttackPaths' END],'view');
 IF n NOT BETWEEN 1 AND 100 OR k NOT IN('finding','attack_path') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization page rejected';END IF;
 IF k='finding' THEN
  WITH candidates AS(SELECT id FROM public.zasp_risk_findings f WHERE(f.organization_id,f.workspace_id,f.environment_id)=(o,w,e) AND(a IS NULL OR id>a) AND zasp_authorization80.allowed(o,w,e,k,id) AND public.zasp_risk_finding_visible(f) ORDER BY id LIMIT n+1),visible AS(SELECT id FROM candidates ORDER BY id LIMIT n)
  SELECT jsonb_build_object('items',COALESCE((SELECT jsonb_agg(public.zasp_risk_finding_get(id,o,w,e) ORDER BY id) FROM visible),'[]'::jsonb),'next_id',CASE WHEN(SELECT count(*) FROM candidates)>n THEN(SELECT max(id) FROM visible) END) INTO result;
 ELSE
  WITH candidates AS(SELECT id FROM public.zasp_risk_attack_paths p WHERE(p.organization_id,p.workspace_id,p.environment_id)=(o,w,e) AND(a IS NULL OR id>a) AND zasp_authorization80.allowed(o,w,e,k,id) AND public.zasp_risk_attack_path_valid(p) ORDER BY id LIMIT n+1),visible AS(SELECT id FROM candidates ORDER BY id LIMIT n)
  SELECT jsonb_build_object('items',COALESCE((SELECT jsonb_agg(public.zasp_risk_attack_path_get(id,o,w,e) ORDER BY id) FROM visible),'[]'::jsonb),'next_id',CASE WHEN(SELECT count(*) FROM candidates)>n THEN(SELECT max(id) FROM visible) END) INTO result;
 END IF;
 RETURN result;
END $$;
CREATE FUNCTION zasp_authorization80.high_path_count(o text,w text,e text) RETURNS bigint LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['listAttackPaths'],'view');
 RETURN(SELECT count(*) FROM public.zasp_risk_attack_paths p WHERE(p.organization_id,p.workspace_id,p.environment_id)=(o,w,e) AND state<>'blocked' AND zasp_authorization80.allowed(o,w,e,'attack_path',id) AND public.zasp_risk_attack_path_valid(p));
END
$$;

CREATE FUNCTION zasp_authorization80.inventory_page(o text,w text,e text,k text,a text,n integer) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;
BEGIN
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY[CASE k WHEN 'agent' THEN 'listAgents' WHEN 'tool' THEN 'listTools' WHEN 'identity' THEN 'listIdentities' WHEN 'runtime' THEN 'listRuntimes' WHEN 'asset' THEN 'listAssets' END],'view');
 IF n NOT BETWEEN 1 AND 100 OR k NOT IN('asset','agent','tool','identity','runtime') OR public.zasp_inventory_scope_state(o,w,e)->>'phase' IS DISTINCT FROM 'cutover' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization inventory page rejected';END IF;
 WITH candidates AS(SELECT id FROM public.zasp_inventory_entities v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.state,v.product_kind)=(o,w,e,'active',k) AND(a IS NULL OR id>a) AND zasp_authorization80.allowed(o,w,e,k,id) ORDER BY id LIMIT n+1),visible AS(SELECT id FROM candidates ORDER BY id LIMIT n)
 SELECT jsonb_build_object('items',COALESCE((SELECT jsonb_agg(public.zasp_inventory_detail(o,w,e,id,k)->'summary' ORDER BY id) FROM visible),'[]'::jsonb),'next_id',CASE WHEN(SELECT count(*) FROM candidates)>n THEN(SELECT max(id) FROM visible) END) INTO result;
 RETURN result;
END $$;

CREATE FUNCTION zasp_authorization80.global_search(o text,w text,e text,q text,n integer) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;normalized text:=lower(q);
BEGIN
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['globalSearch'],'view');
 IF q IS NULL OR char_length(q) NOT BETWEEN 2 AND 128 OR octet_length(q)>128 OR q<>btrim(q) OR q!~'^[A-Za-z0-9 .:_/-]+$' OR n NOT BETWEEN 1 AND 100 OR public.zasp_inventory_scope_state(o,w,e)->>'phase' IS DISTINCT FROM 'cutover' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization search rejected';END IF;
 WITH candidates AS(
 SELECT id,product_kind kind,display_name name,CASE WHEN id=q THEN 0 WHEN product_kind=normalized THEN 1 WHEN lower(display_name)=normalized THEN 2 ELSE 3 END rank
 FROM public.zasp_inventory_entities v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.state)=(o,w,e,'active') AND zasp_authorization80.allowed(o,w,e,product_kind,id) AND(id=q OR product_kind=normalized OR lower(display_name) COLLATE "C" LIKE normalized COLLATE "C"||'%')
 UNION ALL SELECT id,'finding',title,CASE WHEN id=q THEN 0 WHEN normalized='finding' THEN 1 WHEN lower(title)=normalized THEN 2 ELSE 3 END FROM public.zasp_risk_findings f WHERE(f.organization_id,f.workspace_id,f.environment_id)=(o,w,e) AND zasp_authorization80.allowed(o,w,e,'finding',id) AND(id=q OR normalized='finding' OR lower(title) COLLATE "C" LIKE normalized COLLATE "C"||'%')
 ),visible AS(SELECT id,kind,name FROM candidates ORDER BY rank,kind,lower(name),id LIMIT n)
 SELECT jsonb_build_object('items',COALESCE(jsonb_agg(jsonb_build_object('id',id,'type',kind,'name',name) ORDER BY kind,lower(name),id),'[]'::jsonb)) INTO result FROM visible;
 RETURN result;
END $$;

-- authorization80 parent reads
-- authorization80 session reads
-- authorization80 session search
-- authorization80 sensors
-- authorization80 recovery
-- authorization80 home
-- authorization80 risk isolation
-- authorization80 data controls
-- authorization80 hierarchy create

-- authorization80 integration rejection
-- authorization80 integration mutations
-- authorization80 integration reference

ALTER TABLE zasp_authorization80.registration OWNER TO zasp_discovery_authority;
-- PostgreSQL row-share locks require UPDATE privilege on at least one column;
-- these grants go only to the existing non-login SECURITY DEFINER authority.
GRANT UPDATE(id) ON public.zasp_environments TO zasp_discovery_authority;
GRANT UPDATE(id) ON public.zasp_workspaces TO zasp_discovery_authority;
ALTER TABLE zasp_authorization80.registration ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_authorization80.registration FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_authorization80.registration TO zasp_discovery_authority USING(true) WITH CHECK(true);
DO $$ DECLARE f regprocedure;BEGIN FOR f IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='zasp_authorization80'::regnamespace LOOP
 IF f NOT IN('zasp_authorization80.get_data_controls(text,text,text)'::regprocedure,'zasp_authorization80.update_data_controls(text,text,text,text,integer,boolean,bigint,text,text,text)'::regprocedure,'zasp_authorization80.create_workspace(text,text,text,text,text,text,text,text,jsonb)'::regprocedure,'zasp_authorization80.create_environment(text,text,text,text,text,text,text,text,jsonb)'::regprocedure) THEN EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',f);END IF;
 EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f);END LOOP;END $$;
GRANT USAGE ON SCHEMA zasp_authorization80 TO zasp_discovery_api,zasp_security_agent_api,zasp_outbox_worker,zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_authorization80.ready(text),zasp_authorization80.resolve(text,text,text,text,text,text),zasp_authorization80.fence(text),zasp_authorization80.allowed(text,text,text,text,text) TO zasp_discovery_api,zasp_security_agent_api,zasp_outbox_worker,zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_authorization80.risk_page(text,text,text,text,text,integer),zasp_authorization80.high_path_count(text,text,text) TO zasp_discovery_api,zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION zasp_authorization80.inventory_page(text,text,text,text,text,integer),zasp_authorization80.global_search(text,text,text,text,integer) TO zasp_discovery_api,zasp_security_agent_api;

-- Explicit approved organization identity administration: no permission other
-- than manage_identity, and no inheritance to descendant resources. Existing
-- source capture already includes membership role/active/provider linkage.
CREATE OR REPLACE VIEW zasp_authorization79.members AS
 SELECT organization_id,'user'::text kind,principal_id id,CASE WHEN role IN('organization_admin','security_admin') THEN role ELSE '' END organization_role FROM public.zasp_identity_memberships WHERE active
 UNION SELECT organization_id,'agent',definition_id,'' FROM public.zasp_security_agent_definitions WHERE deleted_at IS NULL AND activation IN('supervised','autonomous')
 UNION SELECT s.organization_id,'service',s.id,'' FROM public.zasp_discovery_schedules s JOIN public.zasp_integrations i ON(i.organization_id,i.workspace_id,i.environment_id,i.id)=(s.organization_id,s.workspace_id,s.environment_id,s.integration_id) WHERE s.state='enabled' AND i.state='active' AND i.deleted_at IS NULL AND EXISTS(SELECT 1 FROM public.zasp_integration_connections c WHERE(c.organization_id,c.workspace_id,c.environment_id,c.integration_id)=(s.organization_id,s.workspace_id,s.environment_id,s.integration_id) AND c.state='verified' AND c.revoked_at IS NULL);
-- Extend the registered snapshot from the supported canonical61 catalog. Every
-- source below is mandatory, not an optional future relation. Audit append rows
-- are deliberately absent: their authorization follows validated parent links.
CREATE OR REPLACE VIEW zasp_authorization79.resources AS
 SELECT organization_id,workspace_id,environment_id,'finding'::text kind,id FROM public.zasp_risk_findings
 UNION SELECT organization_id,workspace_id,environment_id,'attack_path',id FROM public.zasp_risk_attack_paths
 UNION SELECT organization_id,workspace_id,environment_id,'policy',zasp_authorization80.object_id(organization_id,workspace_id,environment_id,'policy',id) FROM public.zasp_workflow_records WHERE deleted_at IS NULL AND kind='policy'
 UNION SELECT organization_id,workspace_id,environment_id,'integration',id FROM public.zasp_integrations WHERE deleted_at IS NULL AND state<>'deleted'
 UNION SELECT organization_id,workspace_id,environment_id,'security_agent',definition_id FROM public.zasp_security_agent_definitions WHERE deleted_at IS NULL
 UNION SELECT organization_id,workspace_id,environment_id,'security_agent_run',run_id FROM public.zasp_security_agent_runs
 UNION SELECT organization_id,workspace_id,environment_id,'security_agent_approval',approval_id FROM public.zasp_security_agent_approvals
 UNION SELECT organization_id,workspace_id,environment_id,'discovery_schedule',id FROM public.zasp_discovery_schedules WHERE state<>'deleted'
 UNION SELECT organization_id,workspace_id,environment_id,'discovery_sync',id FROM public.zasp_discovery_syncs
 UNION SELECT organization_id,workspace_id,environment_id,product_kind,id FROM public.zasp_inventory_entities WHERE state='active'
 UNION SELECT organization_id,workspace_id,environment_id,'sensor',id FROM public.zasp_sensors WHERE state<>'deleted'
 UNION SELECT organization_id,workspace_id,environment_id,'test',definition_id FROM public.zasp_red_team_definitions
 UNION SELECT organization_id,workspace_id,environment_id,'test_run',run_id FROM public.zasp_red_team_runs
 UNION SELECT organization_id,workspace_id,environment_id,'attack_lab_run',run_id FROM public.zasp_attack_lab_runs
 UNION SELECT organization_id,workspace_id,environment_id,'recovery_backup',backup_id FROM public.zasp_recovery_backups
 UNION SELECT organization_id,workspace_id,environment_id,'recovery_restore',restore_id FROM public.zasp_recovery_restores
 UNION SELECT organization_id,workspace_id,environment_id,'session',zasp_authorization80.object_id(organization_id,workspace_id,environment_id,'session',id) FROM public.zasp_runtime_session_summaries
 UNION SELECT organization_id,workspace_id,environment_id,'product_session',zasp_authorization80.object_id(organization_id,workspace_id,environment_id,'product_session',session_id) FROM public.zasp_product_sessions;
DROP TRIGGER zasp_authorization79_capture ON public.zasp_inventory_entities;
CREATE TRIGGER zasp_authorization79_capture BEFORE INSERT OR UPDATE OR DELETE ON public.zasp_inventory_entities FOR EACH ROW EXECUTE FUNCTION zasp_authorization79.capture('organization_id','organization_id,workspace_id,environment_id,product_kind,id,state');
DO $capture$ DECLARE spec text[];BEGIN
 FOREACH spec SLICE 1 IN ARRAY ARRAY[
 ['zasp_security_agent_approvals','approval_id'],['zasp_sensors','id,state'],
 ['zasp_red_team_definitions','definition_id'],['zasp_red_team_runs','run_id'],
 ['zasp_attack_lab_runs','run_id'],['zasp_recovery_backups','backup_id'],['zasp_recovery_restores','restore_id'],
 ['zasp_runtime_session_summaries','id'],['zasp_product_sessions','session_id']]
 LOOP EXECUTE format('CREATE TRIGGER zasp_authorization79_capture BEFORE INSERT OR UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION zasp_authorization79.capture(%L,%L)',spec[1],'organization_id','organization_id,workspace_id,environment_id,'||spec[2]);END LOOP;
END $capture$;
UPDATE zasp_authorization79.registration SET fingerprint=zasp_authorization79.fingerprint();
SELECT zasp_authorization79.touch(id) FROM public.zasp_organizations ORDER BY id;
