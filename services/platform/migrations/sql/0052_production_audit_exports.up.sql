-- Compatibility-first draft. Export authority and its final identity are still
-- required before this release can be published or activated.
DO $guard$
BEGIN
 IF NOT COALESCE(public.zasp_production_runtime_precision_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=51),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_precision_fingerprint')),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='audit exports predecessor rejected';END IF;
END $guard$;

CREATE SCHEMA zasp_audit_exports_predecessor AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_audit_exports_predecessor FROM PUBLIC;
DO $save$
DECLARE signature text;definition text;function_name text;
BEGIN
 FOREACH signature IN ARRAY ARRAY['zasp_production_runtime_precision_readiness(text,text)','zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','zasp_production_security_agent_attack_path_security_ready()','zasp_production_workflow_compatibility_security_ready()'] LOOP
  definition:=pg_get_functiondef(('public.'||signature)::regprocedure);
  function_name:=split_part(signature,'(',1);
  EXECUTE replace(definition,'FUNCTION public.'||function_name||'(','FUNCTION zasp_audit_exports_predecessor.'||function_name||'(');
  EXECUTE 'ALTER FUNCTION zasp_audit_exports_predecessor.'||signature||' OWNER TO zasp_discovery_authority';
  EXECUTE 'REVOKE ALL ON FUNCTION zasp_audit_exports_predecessor.'||signature||' FROM PUBLIC';
 END LOOP;
END $save$;

CREATE FUNCTION public.zasp_audit_exports_predecessor_releases() RETURNS TABLE(version bigint,name text,checksum text) LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog, public AS $releases$
 VALUES
-- predecessor release values
$releases$;
ALTER FUNCTION public.zasp_audit_exports_predecessor_releases() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_audit_exports_predecessor_releases() FROM PUBLIC;

DO $worker_roles$
BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN('zasp_audit_export_worker','zasp_audit_export_outbox')) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export authority roles already exist';END IF;
 CREATE ROLE zasp_audit_export_worker NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 CREATE ROLE zasp_audit_export_outbox NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 GRANT zasp_audit_export_worker,zasp_audit_export_outbox TO zasp_discovery_authority WITH ADMIN OPTION;
END $worker_roles$;
CREATE TABLE public.zasp_audit_export_worker_bindings (
 principal_name text PRIMARY KEY CHECK(principal_name ~ '^[a-z][a-z0-9_]{2,62}$'),
 authority_role text NOT NULL UNIQUE CHECK(authority_role IN('zasp_audit_export_worker','zasp_audit_export_outbox'))
);
CREATE FUNCTION public.zasp_audit_export_worker_security_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $worker_security$
 SELECT (SELECT count(*)=2 FROM pg_roles WHERE rolname IN('zasp_audit_export_worker','zasp_audit_export_outbox') AND NOT rolcanlogin AND NOT rolinherit AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls AND rolconfig IS NULL)
 AND (SELECT count(*) IN(0,2) FROM public.zasp_audit_export_worker_bindings)
 AND NOT EXISTS(SELECT 1 FROM public.zasp_audit_export_worker_bindings b LEFT JOIN pg_roles r ON r.rolname=b.principal_name WHERE r.oid IS NULL OR NOT r.rolcanlogin OR NOT r.rolinherit OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR NOT pg_has_role(r.oid,b.authority_role,'MEMBER') OR EXISTS(SELECT 1 FROM pg_roles a WHERE starts_with(a.rolname,'zasp_') AND a.oid<>r.oid AND a.rolname<>b.authority_role AND pg_has_role(r.oid,a.oid,'MEMBER')) OR EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles a ON a.oid=m.roleid WHERE m.member=r.oid AND starts_with(a.rolname,'zasp_') AND (a.rolname<>b.authority_role OR m.admin_option OR NOT m.inherit_option OR m.set_option)))
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member WHERE r.rolname IN('zasp_audit_export_worker','zasp_audit_export_outbox'))
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles a ON a.oid=m.roleid JOIN pg_roles p ON p.oid=m.member WHERE a.rolname IN('zasp_audit_export_worker','zasp_audit_export_outbox') AND NOT (p.rolname='zasp_discovery_authority' AND m.admin_option OR EXISTS(SELECT 1 FROM public.zasp_audit_export_worker_bindings b WHERE b.principal_name=p.rolname AND b.authority_role=a.rolname AND NOT m.admin_option AND m.inherit_option AND NOT m.set_option)))
 AND (SELECT count(*)=2 FROM pg_auth_members m JOIN pg_roles a ON a.oid=m.roleid JOIN pg_roles p ON p.oid=m.member WHERE a.rolname IN('zasp_audit_export_worker','zasp_audit_export_outbox') AND p.rolname='zasp_discovery_authority' AND m.admin_option)
$worker_security$;

CREATE TABLE public.zasp_audit_export_source_acl (
 singleton boolean PRIMARY KEY CHECK(singleton),
 before_state jsonb NOT NULL CHECK(jsonb_typeof(before_state)='object'),
 after_state jsonb NOT NULL CHECK(jsonb_typeof(after_state)='object'),
 workflow_state jsonb NOT NULL CHECK(jsonb_typeof(workflow_state)='object')
);
CREATE FUNCTION public.zasp_audit_export_source_acl_snapshot() RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $source_acl$
 SELECT jsonb_build_object('owner',c.relowner::regrole::text,'grants',(SELECT jsonb_agg(jsonb_build_object('grantor',a.grantor::regrole::text,'grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END,'privilege',a.privilege_type,'grantable',a.is_grantable) ORDER BY a.grantor::regrole::text,CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END,a.privilege_type,a.is_grantable) FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a),'columns',(SELECT jsonb_agg(jsonb_build_object('number',column_row.attnum,'name',column_row.attname,'grants',CASE WHEN column_row.attacl IS NULL THEN 'null'::jsonb ELSE COALESCE((SELECT jsonb_agg(jsonb_build_object('grantor',a.grantor::regrole::text,'grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END,'privilege',a.privilege_type,'grantable',a.is_grantable) ORDER BY a.grantor::regrole::text,CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END,a.privilege_type,a.is_grantable) FROM aclexplode(column_row.attacl) a),'[]'::jsonb) END) ORDER BY column_row.attnum) FROM pg_attribute column_row WHERE column_row.attrelid=c.oid AND column_row.attnum>0 AND NOT column_row.attisdropped)) FROM pg_class c WHERE c.oid='public.zasp_admin_audit'::regclass
$source_acl$;
CREATE FUNCTION public.zasp_audit_export_workflow_acl_snapshot() RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $source_acl$
 SELECT jsonb_build_object('owner',c.relowner::regrole::text,'grants',(SELECT jsonb_agg(jsonb_build_object('grantor',a.grantor::regrole::text,'grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END,'privilege',a.privilege_type,'grantable',a.is_grantable) ORDER BY a.grantor::regrole::text,CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END,a.privilege_type,a.is_grantable) FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a),'columns',(SELECT jsonb_agg(jsonb_build_object('number',column_row.attnum,'name',column_row.attname,'grants',CASE WHEN column_row.attacl IS NULL THEN 'null'::jsonb ELSE COALESCE((SELECT jsonb_agg(jsonb_build_object('grantor',a.grantor::regrole::text,'grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END,'privilege',a.privilege_type,'grantable',a.is_grantable) ORDER BY a.grantor::regrole::text,CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END,a.privilege_type,a.is_grantable) FROM aclexplode(column_row.attacl) a),'[]'::jsonb) END) ORDER BY column_row.attnum) FROM pg_attribute column_row WHERE column_row.attrelid=c.oid AND column_row.attnum>0 AND NOT column_row.attisdropped)) FROM pg_class c WHERE c.oid='public.zasp_workflow_audit'::regclass
$source_acl$;
CREATE FUNCTION public.zasp_audit_export_source_acl_expected(before_value jsonb) RETURNS jsonb LANGUAGE sql IMMUTABLE STRICT SET search_path TO pg_catalog,public AS $expected_acl$
 SELECT jsonb_build_object('owner',before_value->'owner','columns',before_value->'columns','grants',(SELECT jsonb_agg(value ORDER BY value->>'grantor',value->>'grantee',value->>'privilege',(value->>'grantable')::boolean) FROM (
 SELECT value FROM jsonb_array_elements(before_value->'grants')
 UNION ALL SELECT jsonb_build_object('grantor',before_value->>'owner','grantee','zasp_discovery_authority','privilege','SELECT','grantable',false) WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(before_value->'grants') g WHERE g->>'grantor'=before_value->>'owner' AND g->>'grantee'='zasp_discovery_authority' AND g->>'privilege'='SELECT')
 ) grants))
$expected_acl$;
DO $source_read_grant$
DECLARE prior jsonb;current_value jsonb;
BEGIN
 prior:=public.zasp_audit_export_source_acl_snapshot();
 GRANT SELECT ON public.zasp_admin_audit TO zasp_discovery_authority;
 current_value:=public.zasp_audit_export_source_acl_snapshot();
 IF current_value IS DISTINCT FROM public.zasp_audit_export_source_acl_expected(prior) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export source privilege delta rejected';END IF;
 INSERT INTO public.zasp_audit_export_source_acl VALUES(true,prior,current_value,public.zasp_audit_export_workflow_acl_snapshot());
END $source_read_grant$;
CREATE FUNCTION public.zasp_audit_export_source_acl_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $source_ready$
 SELECT (SELECT count(*)=1 FROM public.zasp_audit_export_source_acl)
 AND EXISTS(SELECT 1 FROM public.zasp_audit_export_source_acl s WHERE s.after_state=public.zasp_audit_export_source_acl_expected(s.before_state) AND s.after_state=public.zasp_audit_export_source_acl_snapshot())
 AND EXISTS(SELECT 1 FROM pg_class WHERE oid='public.zasp_admin_audit'::regclass AND relkind='r' AND NOT relrowsecurity AND NOT relforcerowsecurity)
 AND has_table_privilege('zasp_discovery_authority','public.zasp_admin_audit','SELECT,INSERT')
 AND NOT has_table_privilege('zasp_discovery_authority','public.zasp_admin_audit','UPDATE,DELETE')
$source_ready$;
CREATE FUNCTION public.zasp_audit_export_immutable_source_acl() RETURNS trigger LANGUAGE plpgsql SET search_path TO pg_catalog,public AS $immutable_acl$
BEGIN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export source privilege state is immutable';END
$immutable_acl$;
CREATE TRIGGER zasp_audit_export_immutable_source_acl BEFORE UPDATE OR DELETE ON public.zasp_audit_export_source_acl FOR EACH ROW EXECUTE FUNCTION public.zasp_audit_export_immutable_source_acl();

CREATE FUNCTION public.zasp_audit_export_workflow_acl_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $workflow_acl$
 SELECT (SELECT count(*)=1 FROM public.zasp_audit_export_source_acl)
 AND EXISTS(SELECT 1 FROM public.zasp_audit_export_source_acl s JOIN public.zasp_discovery_principal_bindings b ON b.principal_name=s.workflow_state->>'owner' JOIN pg_roles r ON r.rolname=b.principal_name WHERE b.authority_role='zasp_discovery_authority' AND r.rolcanlogin AND s.workflow_state=public.zasp_audit_export_workflow_acl_snapshot())
 AND has_table_privilege('zasp_discovery_authority','public.zasp_workflow_audit','SELECT')
$workflow_acl$;
CREATE FUNCTION public.zasp_audit_export_source_catalog_role(role_value oid,owner_value oid) RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $source_role$
 SELECT CASE WHEN role_value=0 THEN 'PUBLIC'
 WHEN role_value=owner_value AND public.zasp_audit_export_source_acl_ready() AND public.zasp_audit_export_workflow_acl_ready() AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings b JOIN pg_roles r ON r.rolname=b.principal_name WHERE r.oid=owner_value AND b.authority_role='zasp_discovery_authority' AND r.rolcanlogin) THEN 'registered-migration-owner'
 ELSE role_value::regrole::text END
$source_role$;
CREATE FUNCTION public.zasp_audit_export_source_catalog_acl(acl_value aclitem[],owner_value oid) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $catalog_acl$
 SELECT CASE WHEN acl_value IS NULL THEN 'null'::jsonb ELSE COALESCE(jsonb_agg(value ORDER BY value::text),'[]'::jsonb) END FROM (SELECT jsonb_build_object('grantor',public.zasp_audit_export_source_catalog_role(a.grantor,owner_value),'grantee',public.zasp_audit_export_source_catalog_role(a.grantee,owner_value),'privilege',a.privilege_type,'grantable',a.is_grantable) AS value FROM aclexplode(acl_value) a) grants
$catalog_acl$;

CREATE TABLE public.zasp_audit_export_policies (
 policy_id text PRIMARY KEY CHECK(zasp_valid_product_id(policy_id)),
 expected_current_policy_id text REFERENCES public.zasp_audit_export_policies(policy_id),
 bucket text NOT NULL CHECK(bucket ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'),
 expected_bucket_owner text NOT NULL CHECK(expected_bucket_owner ~ '^[0-9]{12}$'),
 kms_key_arn text NOT NULL CHECK(kms_key_arn ~ '^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
 maximum_export_bytes bigint NOT NULL CHECK(maximum_export_bytes BETWEEN 1 AND 9007199254740991),
 maximum_retained_bytes bigint NOT NULL CHECK(maximum_retained_bytes BETWEEN 1 AND 9007199254740991),
 maximum_inflight integer NOT NULL CHECK(maximum_inflight>0),
 capture_timeout_seconds integer NOT NULL CHECK(capture_timeout_seconds BETWEEN 1 AND 120),
 policy_digest bytea NOT NULL CHECK(octet_length(policy_digest)=32),
 CHECK(expected_current_policy_id IS DISTINCT FROM policy_id)
);
CREATE TABLE public.zasp_audit_export_current_policy (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 policy_id text REFERENCES public.zasp_audit_export_policies(policy_id)
);
INSERT INTO public.zasp_audit_export_current_policy(singleton) VALUES(true);

-- These validated scalar strings are ASCII. Explicit field order and separators
-- match the trusted Go configuration codec, rather than jsonb's presentation.
CREATE FUNCTION public.zasp_audit_export_policy_digest(policy_value text,bucket_value text,owner_value text,kms_value text,export_limit bigint,retained_limit bigint,inflight_limit integer,timeout_value integer) RETURNS bytea LANGUAGE sql IMMUTABLE STRICT SET search_path TO pg_catalog,public AS $digest$
 SELECT digest(convert_to('{"schema":"audit-export-policy-v1","policy_id":'||to_json(policy_value)::text||',"bucket":'||to_json(bucket_value)::text||',"expected_bucket_owner":'||to_json(owner_value)::text||',"kms_key_arn":'||to_json(kms_value)::text||',"maximum_export_bytes":'||export_limit::text||',"maximum_retained_bytes":'||retained_limit::text||',"maximum_inflight":'||inflight_limit::text||',"capture_timeout_seconds":'||timeout_value::text||'}','UTF8'),'sha256')
$digest$;
CREATE FUNCTION public.zasp_audit_export_policy_json(policy_value public.zasp_audit_export_policies) RETURNS jsonb LANGUAGE sql IMMUTABLE STRICT SET search_path TO pg_catalog,public AS $policy$
 SELECT jsonb_build_object('schema','audit-export-policy-v1','policy_id',policy_value.policy_id,'policy_digest',encode(policy_value.policy_digest,'hex'),'bucket',policy_value.bucket,'expected_bucket_owner',policy_value.expected_bucket_owner,'kms_key_arn',policy_value.kms_key_arn,'maximum_export_bytes',policy_value.maximum_export_bytes,'maximum_retained_bytes',policy_value.maximum_retained_bytes,'maximum_inflight',policy_value.maximum_inflight,'capture_timeout_seconds',policy_value.capture_timeout_seconds)
$policy$;
CREATE FUNCTION public.zasp_audit_export_policy_state_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $policy_ready$
 SELECT (SELECT count(*)=1 FROM public.zasp_audit_export_current_policy)
 AND NOT EXISTS(SELECT 1 FROM public.zasp_audit_export_current_policy c WHERE c.policy_id IS NULL AND EXISTS(SELECT 1 FROM public.zasp_audit_export_policies))
 AND NOT EXISTS(SELECT 1 FROM public.zasp_audit_export_policies p WHERE p.policy_digest IS DISTINCT FROM public.zasp_audit_export_policy_digest(p.policy_id,p.bucket,p.expected_bucket_owner,p.kms_key_arn,p.maximum_export_bytes,p.maximum_retained_bytes,p.maximum_inflight,p.capture_timeout_seconds))
$policy_ready$;
CREATE FUNCTION public.zasp_audit_export_immutable_policy() RETURNS trigger LANGUAGE plpgsql SET search_path TO pg_catalog,public AS $immutable$
BEGIN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export policy revision is immutable';END
$immutable$;
CREATE TRIGGER zasp_audit_export_immutable_policy BEFORE UPDATE OR DELETE ON public.zasp_audit_export_policies FOR EACH ROW EXECUTE FUNCTION public.zasp_audit_export_immutable_policy();

CREATE INDEX zasp_audit_export_source_scan_idx ON public.zasp_admin_audit(organization_id,occurred_at DESC,id COLLATE "C" DESC);

-- Include the actual changed predecessor graph. Catalog reads do not execute
-- any readiness function, so the public51 ->52 bridge cannot recurse here.
-- The fingerprint literal is metadata, not a literal inside these function
-- bodies. Every function body, including this one, remains in the hash.
CREATE FUNCTION public.zasp_production_audit_exports_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','prior',zasp_production_runtime_precision_live_fingerprint())
 UNION ALL SELECT concat_ws('|','export-role',rolname,rolcanlogin,rolinherit,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls,rolconnlimit,COALESCE(rolvaliduntil::text,''),COALESCE(rolconfig::text,'')) FROM pg_roles WHERE rolname IN('zasp_audit_export_worker','zasp_audit_export_outbox')
 -- Inherited wrappers sometimes obtain their expected51 pins from metadata.
 -- Hash all predecessor metadata too, so those callers cannot accept a changed
 -- stored51 identity. Exclude only52's own roots to avoid self-reference.
 -- Only the two validated saved migration-owner names vary by installation.
 -- Normalize them only while they still name the registered live authority.
 -- All other metadata values and every52-owned owner, ACL and body stay exact.
 UNION ALL SELECT concat_ws('|','metadata',key,CASE WHEN key IN('production_discovery_execution_prior_owner','red_team_execution_prior_permissions_owner') AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings b JOIN pg_roles r ON r.rolname=b.principal_name WHERE b.principal_name=value AND b.authority_role='zasp_discovery_authority' AND r.rolcanlogin) THEN 'registered-migration-owner' ELSE value END) FROM public.zasp_schema_metadata WHERE key NOT IN('production_audit_exports_checksum','production_audit_exports_fingerprint')
 UNION ALL SELECT concat_ws('|','schema',nspname,nspowner::regrole::text,COALESCE(nspacl::text,'')) FROM pg_namespace WHERE nspname='zasp_audit_exports_predecessor'
 UNION ALL SELECT concat_ws('|','function',n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),r.rolname,p.prosecdef,p.provolatile,p.proparallel,p.proisstrict,p.proleakproof,COALESCE(p.proconfig::text,''),COALESCE(p.proacl::text,''),pg_get_functiondef(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='zasp_audit_exports_predecessor' OR n.nspname='public' AND (starts_with(p.proname,'zasp_audit_export') OR starts_with(p.proname,'zasp_production_audit_exports'))
 UNION ALL SELECT concat_ws('|','table',n.nspname,c.relname,c.relkind,c.relpersistence,c.relrowsecurity,c.relforcerowsecurity,r.rolname,COALESCE(c.relacl::text,'')) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND starts_with(c.relname,'zasp_audit_export') AND c.relkind IN('r','p','v','S')
 UNION ALL SELECT concat_ws('|','view',c.relname,pg_get_viewdef(c.oid,true),COALESCE(c.reloptions::text,'')) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND starts_with(c.relname,'zasp_audit_export') AND c.relkind='v'
 UNION ALL SELECT concat_ws('|','source-table',c.relname,c.relkind,c.relpersistence,c.relrowsecurity,c.relforcerowsecurity,public.zasp_audit_export_source_catalog_role(c.relowner,c.relowner),CASE WHEN c.relname='zasp_admin_audit' AND public.zasp_audit_export_source_acl_ready() THEN 'validated-saved-admin-acl' ELSE public.zasp_audit_export_source_catalog_acl(c.relacl,c.relowner)::text END,COALESCE(c.reloptions::text,'')) FROM pg_class c WHERE c.oid IN('public.zasp_admin_audit'::regclass,'public.zasp_workflow_audit'::regclass,'public.zasp_red_team_audit'::regclass)
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated,a.attcollation::regcollation::text,COALESCE(pg_get_expr(d.adbin,d.adrelid),''),CASE WHEN c.relname='zasp_admin_audit' AND public.zasp_audit_export_source_acl_ready() THEN 'validated-saved-admin-column-acl' WHEN c.relname IN('zasp_admin_audit','zasp_workflow_audit','zasp_red_team_audit') THEN public.zasp_audit_export_source_catalog_acl(a.attacl,c.relowner)::text ELSE COALESCE(a.attacl::text,'') END) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum WHERE n.nspname='public' AND (starts_with(c.relname,'zasp_audit_export') OR c.relname IN('zasp_admin_audit','zasp_workflow_audit','zasp_red_team_audit')) AND c.relkind IN('r','p','v','S') AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,k.convalidated,pg_get_constraintdef(k.oid,true)) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND (starts_with(c.relname,'zasp_audit_export') OR c.relname IN('zasp_admin_audit','zasp_workflow_audit','zasp_red_team_audit'))
 UNION ALL SELECT concat_ws('|','index',c.relname,i.indexrelid::regclass::text,i.indisvalid,i.indisready,i.indislive,pg_get_indexdef(i.indexrelid)) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND (starts_with(c.relname,'zasp_audit_export') OR c.relname IN('zasp_admin_audit','zasp_workflow_audit','zasp_red_team_audit'))
 UNION ALL SELECT concat_ws('|','policy',c.relname,p.polname,p.polpermissive,p.polcmd,(SELECT string_agg(r::regrole::text,',' ORDER BY r::regrole::text) FROM unnest(p.polroles) r),pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND (starts_with(c.relname,'zasp_audit_export') OR c.relname IN('zasp_admin_audit','zasp_workflow_audit','zasp_red_team_audit'))
 UNION ALL SELECT concat_ws('|','trigger',c.relname,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid,true),t.tgfoid::regprocedure::text) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND (starts_with(c.relname,'zasp_audit_export') OR c.relname IN('zasp_admin_audit','zasp_workflow_audit','zasp_red_team_audit')) AND NOT t.tgisinternal
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
ALTER FUNCTION public.zasp_production_audit_exports_live_fingerprint() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_audit_exports_live_fingerprint() FROM PUBLIC;

CREATE FUNCTION public.zasp_production_audit_exports_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT COALESCE(expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$'
 AND (SELECT count(*)=52 FROM public.zasp_schema_versions)
 AND NOT EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version<1 OR version>52)
 AND NOT EXISTS(SELECT 1 FROM public.zasp_audit_exports_predecessor_releases() p LEFT JOIN public.zasp_schema_versions r USING(version) WHERE r.name IS DISTINCT FROM p.name OR r.checksum IS DISTINCT FROM p.checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=52 AND name='production_audit_exports' AND checksum=expected_checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_audit_exports_checksum' AND value=expected_checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_audit_exports_fingerprint' AND value=expected_fingerprint)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_core_schema' AND value='production-recovery-v1')
 AND public.zasp_production_runtime_sandbox_binding_security_ready()
 AND public.zasp_audit_export_policy_state_ready()
 AND public.zasp_audit_export_worker_security_ready()
 AND public.zasp_audit_export_source_acl_ready()
 AND public.zasp_audit_export_workflow_acl_ready()
 AND public.zasp_production_audit_exports_live_fingerprint()=expected_fingerprint,false)
$readiness$;
ALTER FUNCTION public.zasp_production_audit_exports_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_audit_exports_readiness(text,text) FROM PUBLIC;

CREATE FUNCTION public.zasp_audit_exports_require_ready() RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog, public AS $guard$
BEGIN
 IF NOT COALESCE(public.zasp_production_audit_exports_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=52),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_audit_exports_fingerprint')),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='audit exports authority unavailable';END IF;
END $guard$;
ALTER FUNCTION public.zasp_audit_exports_require_ready() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_audit_exports_require_ready() FROM PUBLIC;
-- Existing workflow/risk functions are invoker-security API entry points.
-- The helper only checks readiness; it exposes no export mutation authority.
GRANT EXECUTE ON FUNCTION public.zasp_audit_exports_require_ready() TO zasp_discovery_api;

CREATE FUNCTION public.zasp_audit_export_configure(policy_value text,prior_value text,bucket_value text,owner_value text,kms_value text,export_limit bigint,retained_limit bigint,inflight_limit integer,timeout_value integer) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $configure$
DECLARE current_value text;prior_row public.zasp_audit_export_policies%ROWTYPE;digest_value bytea;result jsonb;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority') OR NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export configuration authority rejected';END IF;
 PERFORM public.zasp_audit_exports_require_ready();
 IF NOT COALESCE(public.zasp_valid_product_id(policy_value) AND (prior_value IS NULL OR public.zasp_valid_product_id(prior_value) AND prior_value<>policy_value) AND bucket_value ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$' AND owner_value ~ '^[0-9]{12}$' AND kms_value ~ '^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' AND export_limit BETWEEN 1 AND 9007199254740991 AND retained_limit BETWEEN 1 AND 9007199254740991 AND inflight_limit>0 AND timeout_value BETWEEN 1 AND 120,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export configuration rejected';END IF;
 digest_value:=public.zasp_audit_export_policy_digest(policy_value,bucket_value,owner_value,kms_value,export_limit,retained_limit,inflight_limit,timeout_value);
 SELECT policy_id INTO STRICT current_value FROM public.zasp_audit_export_current_policy WHERE singleton FOR UPDATE;
 PERFORM public.zasp_audit_exports_require_ready();
 SELECT * INTO prior_row FROM public.zasp_audit_export_policies WHERE policy_id=policy_value;
 IF FOUND THEN
  IF current_value IS DISTINCT FROM policy_value OR prior_row.expected_current_policy_id IS DISTINCT FROM prior_value OR prior_row.policy_digest IS DISTINCT FROM digest_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='export configuration conflict';END IF;
 ELSE
  IF current_value IS DISTINCT FROM prior_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='export configuration conflict';END IF;
  INSERT INTO public.zasp_audit_export_policies VALUES(policy_value,prior_value,bucket_value,owner_value,kms_value,export_limit,retained_limit,inflight_limit,timeout_value,digest_value) RETURNING * INTO prior_row;
  UPDATE public.zasp_audit_export_current_policy SET policy_id=policy_value WHERE singleton;
 END IF;
 result:=public.zasp_audit_export_policy_json(prior_row);
 PERFORM public.zasp_audit_exports_require_ready();
 RETURN result;
END $configure$;

-- Capability registration is separate from the release graph. Existing51 API
-- connections keep working without gaining this explicit export authority.
CREATE TABLE public.zasp_audit_export_api_bindings (
 principal_name text PRIMARY KEY,
 capability text NOT NULL DEFAULT 'audit-export-api-v1' CHECK(capability='audit-export-api-v1')
);
CREATE TABLE public.zasp_audit_export_jobs (
 organization_id text NOT NULL CHECK(zasp_valid_product_id(organization_id)),
 workspace_id text NOT NULL CHECK(zasp_valid_product_id(workspace_id)),
 environment_id text NOT NULL CHECK(zasp_valid_product_id(environment_id)),
 id text NOT NULL CHECK(zasp_valid_product_id(id)),
 principal_id text NOT NULL CHECK(zasp_valid_product_id(principal_id)),
 audit_id text NOT NULL CHECK(zasp_valid_product_id(audit_id)),
 policy_id text NOT NULL REFERENCES public.zasp_audit_export_policies(policy_id),
 storage_policy jsonb NOT NULL,
 requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 status text NOT NULL DEFAULT 'queued' CHECK(status IN('queued','processing','ready','failed')),
 failure_code text CHECK(failure_code IN('capacity_exceeded','invalid_source','execution_failed')),
 capture_id text CHECK(zasp_valid_product_id(capture_id)),
 captured boolean NOT NULL DEFAULT false,
 captured_at timestamptz,
 event_count bigint CHECK(event_count BETWEEN 0 AND 9007199254740991),
 chunk_count bigint CHECK(chunk_count BETWEEN 0 AND 9007199254740991),
 chunk_bytes bigint CHECK(chunk_bytes BETWEEN 0 AND 9007199254740991),
 chain_root bytea CHECK(octet_length(chain_root)=32),
 manifest_bytes bytea CHECK(octet_length(manifest_bytes) BETWEEN 1 AND 2048),
 reserved_bytes bigint NOT NULL DEFAULT 0 CHECK(reserved_bytes BETWEEN 0 AND 9007199254740991),
 generation bigint NOT NULL DEFAULT 0 CHECK(generation BETWEEN 0 AND 9007199254740991),
 attempt integer NOT NULL DEFAULT 0 CHECK(attempt BETWEEN 0 AND 5),
 lease_worker text,
 lease_token_digest bytea CHECK(octet_length(lease_token_digest)=32),
 lease_expires_at timestamptz,
 available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 completion_audit_id text CHECK(zasp_valid_product_id(completion_audit_id)),
 completed_at timestamptz,
 completion_worker text,
 completion_token_digest bytea CHECK(octet_length(completion_token_digest)=32),
 PRIMARY KEY(organization_id,id),
 UNIQUE(organization_id,workspace_id,environment_id,id),
 UNIQUE(organization_id,audit_id),
 CHECK((status='failed')=(failure_code IS NOT NULL)),
 CHECK(captured=(captured_at IS NOT NULL) AND captured=(event_count IS NOT NULL) AND captured=(chunk_count IS NOT NULL) AND captured=(chunk_bytes IS NOT NULL) AND captured=(chain_root IS NOT NULL) AND captured=(manifest_bytes IS NOT NULL)),
 CHECK(NOT captured OR status='failed' OR reserved_bytes=chunk_bytes+octet_length(manifest_bytes)),
 CHECK((completion_audit_id IS NULL)=(completed_at IS NULL)),
 CHECK((completion_worker IS NULL)=(completion_token_digest IS NULL)),
 CHECK((status='ready')=(completion_worker IS NOT NULL)),
 CHECK(completion_worker IS NULL OR completion_worker ~ '^[a-z][a-z0-9.-]{2,127}$' AND captured AND generation>0 AND attempt>0 AND completion_audit_id IS NOT NULL AND lease_worker IS NULL),
 CHECK((lease_worker IS NULL)=(lease_token_digest IS NULL) AND (lease_worker IS NULL)=(lease_expires_at IS NULL)),
 CHECK(lease_worker IS NULL OR status='processing' AND capture_id IS NOT NULL AND attempt>0)
);
CREATE TABLE public.zasp_audit_export_idempotency (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,
 principal_id text NOT NULL CHECK(zasp_valid_product_id(principal_id)),
 idempotency_key text NOT NULL CHECK(octet_length(idempotency_key) BETWEEN 16 AND 128 AND idempotency_key ~ '^[A-Za-z0-9._:-]+$'),
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 export_id text NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,principal_id,idempotency_key),
 FOREIGN KEY(organization_id,workspace_id,environment_id,export_id) REFERENCES public.zasp_audit_export_jobs(organization_id,workspace_id,environment_id,id)
);
CREATE TABLE public.zasp_audit_export_outbox (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,
 id text NOT NULL CHECK(zasp_valid_product_id(id)),export_id text NOT NULL,
 topic text NOT NULL DEFAULT 'audit-exports' CHECK(topic='audit-exports'),
 state text NOT NULL DEFAULT 'pending' CHECK(state IN('pending','leased','published')),
 available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 generation bigint NOT NULL DEFAULT 0 CHECK(generation BETWEEN 0 AND 9007199254740991),
 attempt integer NOT NULL DEFAULT 0 CHECK(attempt BETWEEN 0 AND 100),
 lease_worker text CHECK(lease_worker ~ '^[a-z][a-z0-9.-]{2,127}$'),
 lease_token_digest bytea CHECK(octet_length(lease_token_digest)=32),
 lease_expires_at timestamptz,
 lease_seconds integer CHECK(lease_seconds BETWEEN 60 AND 300),
 retry_seconds integer CHECK(retry_seconds BETWEEN 1 AND 300),
 provider_message_id text CHECK(provider_message_id ~ '^sha256:[0-9a-f]{64}$'),
 CHECK((generation=0)=(attempt=0) AND generation>=attempt),
 CHECK((generation=0)=(lease_worker IS NULL)),
 CHECK((lease_worker IS NULL)=(lease_token_digest IS NULL) AND (lease_worker IS NULL)=(lease_expires_at IS NULL) AND (lease_worker IS NULL)=(lease_seconds IS NULL)),
 CHECK(state<>'leased' OR lease_worker IS NOT NULL),
 CHECK((retry_seconds IS NOT NULL)=(state='pending' AND generation>0)),
 CHECK((state='published')=(provider_message_id IS NOT NULL)),
 PRIMARY KEY(organization_id,id),UNIQUE(organization_id,export_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,export_id) REFERENCES public.zasp_audit_export_jobs(organization_id,workspace_id,environment_id,id)
);
CREATE TABLE public.zasp_audit_export_events (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,export_id text NOT NULL,
 capture_id text NOT NULL CHECK(zasp_valid_product_id(capture_id)),
 ordinal bigint NOT NULL CHECK(ordinal BETWEEN 1 AND 9007199254740991),
 event_id text NOT NULL CHECK(zasp_valid_product_id(event_id)),
 occurred_at timestamptz NOT NULL,
 canonical_event bytea NOT NULL CHECK(octet_length(canonical_event) BETWEEN 1 AND 131072),
 PRIMARY KEY(organization_id,export_id,ordinal),UNIQUE(organization_id,export_id,event_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,export_id) REFERENCES public.zasp_audit_export_jobs(organization_id,workspace_id,environment_id,id)
);
CREATE TABLE public.zasp_audit_export_chunks (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,export_id text NOT NULL,
 capture_id text NOT NULL CHECK(zasp_valid_product_id(capture_id)),
 ordinal bigint NOT NULL CHECK(ordinal BETWEEN 1 AND 9007199254740991),
 first_event bigint NOT NULL CHECK(first_event BETWEEN 1 AND 9007199254740991),
 event_count integer NOT NULL CHECK(event_count BETWEEN 1 AND 1000),
 previous_digest bytea NOT NULL CHECK(octet_length(previous_digest)=32),
 sha256 bytea NOT NULL CHECK(octet_length(sha256)=32),
 size_bytes bigint NOT NULL CHECK(size_bytes BETWEEN 1 AND 1048576),
 PRIMARY KEY(organization_id,export_id,ordinal),UNIQUE(organization_id,export_id,first_event),
 FOREIGN KEY(organization_id,workspace_id,environment_id,export_id) REFERENCES public.zasp_audit_export_jobs(organization_id,workspace_id,environment_id,id)
);
CREATE FUNCTION public.zasp_audit_export_immutable_capture() RETURNS trigger LANGUAGE plpgsql SET search_path TO pg_catalog,public AS $immutable_capture$
BEGIN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export frozen authority is immutable';END
$immutable_capture$;
CREATE TRIGGER zasp_audit_export_immutable_capture BEFORE UPDATE OR DELETE ON public.zasp_audit_export_events FOR EACH ROW EXECUTE FUNCTION public.zasp_audit_export_immutable_capture();
CREATE TRIGGER zasp_audit_export_immutable_capture BEFORE UPDATE OR DELETE ON public.zasp_audit_export_chunks FOR EACH ROW EXECUTE FUNCTION public.zasp_audit_export_immutable_capture();
CREATE TABLE public.zasp_audit_export_intents (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,export_id text NOT NULL,
 capture_id text NOT NULL CHECK(zasp_valid_product_id(capture_id)),
 kind text NOT NULL CHECK(kind IN('chunk','manifest')),
 ordinal bigint NOT NULL CHECK(ordinal BETWEEN 0 AND 9007199254740991),
 artifact_id text NOT NULL CHECK(zasp_valid_product_id(artifact_id)),
 object_reference text NOT NULL CHECK(octet_length(object_reference) BETWEEN 1 AND 1024),
 sha256 bytea NOT NULL CHECK(octet_length(sha256)=32 AND sha256<>decode(repeat('0',64),'hex')),
 size_bytes bigint NOT NULL CHECK(size_bytes BETWEEN 1 AND 1048576),
 PRIMARY KEY(organization_id,export_id,kind,ordinal),UNIQUE(organization_id,artifact_id),UNIQUE(object_reference),
 CHECK(kind='chunk' AND ordinal>0 OR kind='manifest' AND ordinal=0 AND size_bytes<=2048),
 CHECK(artifact_id<>ALL(ARRAY[organization_id,workspace_id,environment_id,export_id,capture_id])),
 FOREIGN KEY(organization_id,workspace_id,environment_id,export_id) REFERENCES public.zasp_audit_export_jobs(organization_id,workspace_id,environment_id,id)
);
CREATE TRIGGER zasp_audit_export_immutable_intent BEFORE UPDATE OR DELETE ON public.zasp_audit_export_intents FOR EACH ROW EXECUTE FUNCTION public.zasp_audit_export_immutable_capture();
CREATE TABLE public.zasp_audit_export_receipts (
 organization_id text NOT NULL,export_id text NOT NULL,
 kind text NOT NULL CHECK(kind IN('chunk','manifest')),
 ordinal bigint NOT NULL CHECK(ordinal BETWEEN 0 AND 9007199254740991),
 version_id text NOT NULL CHECK(octet_length(version_id) BETWEEN 1 AND 1024 AND version_id<>'null' AND version_id COLLATE "C" ~ '^[!-~]+$'),
 sha256 bytea NOT NULL CHECK(octet_length(sha256)=32 AND sha256<>decode(repeat('0',64),'hex')),
 size_bytes bigint NOT NULL CHECK(size_bytes BETWEEN 1 AND 1048576),
 PRIMARY KEY(organization_id,export_id,kind,ordinal),
 CHECK(kind='chunk' AND ordinal>0 OR kind='manifest' AND ordinal=0 AND size_bytes<=2048),
 FOREIGN KEY(organization_id,export_id,kind,ordinal) REFERENCES public.zasp_audit_export_intents(organization_id,export_id,kind,ordinal)
);
CREATE TRIGGER zasp_audit_export_immutable_receipt BEFORE UPDATE OR DELETE ON public.zasp_audit_export_receipts FOR EACH ROW EXECUTE FUNCTION public.zasp_audit_export_immutable_capture();
CREATE TABLE public.zasp_audit_export_retries (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,export_id text NOT NULL,
 capture_id text NOT NULL CHECK(zasp_valid_product_id(capture_id)),
 generation bigint NOT NULL CHECK(generation BETWEEN 1 AND 9007199254740991),
 attempt integer NOT NULL CHECK(attempt BETWEEN 1 AND 5),
 worker_name text NOT NULL CHECK(worker_name ~ '^[a-z][a-z0-9.-]{2,127}$'),
 token_digest bytea NOT NULL CHECK(octet_length(token_digest)=32),
 retry_seconds integer NOT NULL CHECK(retry_seconds BETWEEN 0 AND 300),
 state text NOT NULL CHECK(state IN('retry','failed')),
 available_at timestamptz,
 completion_audit_id text CHECK(zasp_valid_product_id(completion_audit_id)),
 PRIMARY KEY(organization_id,export_id,generation),UNIQUE(organization_id,export_id,attempt),
 CHECK((state='retry')=(available_at IS NOT NULL)),
 CHECK((state='failed')=(completion_audit_id IS NOT NULL)),
 CHECK(state='failed' OR retry_seconds>0 AND attempt<5),
 FOREIGN KEY(organization_id,workspace_id,environment_id,export_id) REFERENCES public.zasp_audit_export_jobs(organization_id,workspace_id,environment_id,id)
);
CREATE TRIGGER zasp_audit_export_immutable_retry BEFORE UPDATE OR DELETE ON public.zasp_audit_export_retries FOR EACH ROW EXECUTE FUNCTION public.zasp_audit_export_immutable_capture();
DO $export_rls$
DECLARE relation text;
BEGIN
 FOREACH relation IN ARRAY ARRAY['zasp_audit_export_source_acl','zasp_audit_export_worker_bindings','zasp_audit_export_policies','zasp_audit_export_current_policy','zasp_audit_export_api_bindings','zasp_audit_export_jobs','zasp_audit_export_idempotency','zasp_audit_export_outbox','zasp_audit_export_events','zasp_audit_export_chunks','zasp_audit_export_intents','zasp_audit_export_receipts','zasp_audit_export_retries'] LOOP
  EXECUTE format('ALTER TABLE public.%I OWNER TO zasp_discovery_authority',relation);
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',relation);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',relation);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC',relation);
  EXECUTE format('CREATE POLICY %I ON public.%I TO zasp_discovery_authority USING (true) WITH CHECK (true)',relation||'_authority',relation);
 END LOOP;
END $export_rls$;

CREATE FUNCTION public.zasp_audit_export_register_workers(executor_value text,outbox_value text) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $register_workers$
DECLARE names text[]:=ARRAY[executor_value,outbox_value];authorities text[]:=ARRAY['zasp_audit_export_worker','zasp_audit_export_outbox'];index_value integer;role_row record;prior_value text;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority') OR NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export worker registration authority rejected';END IF;
 IF NOT COALESCE(executor_value ~ '^[a-z][a-z0-9_]{2,62}$' AND outbox_value ~ '^[a-z][a-z0-9_]{2,62}$' AND executor_value<>outbox_value AND executor_value<>session_user AND outbox_value<>session_user,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export worker identities rejected';END IF;
 PERFORM public.zasp_audit_exports_require_ready();
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-audit-export-registration',0));
 LOCK TABLE public.zasp_audit_export_worker_bindings IN ROW EXCLUSIVE MODE;
 PERFORM public.zasp_audit_exports_require_ready();
 FOR index_value IN 1..2 LOOP
  SELECT * INTO role_row FROM pg_roles WHERE rolname=names[index_value];
  IF NOT FOUND OR NOT role_row.rolcanlogin OR NOT role_row.rolinherit OR role_row.rolsuper OR role_row.rolcreatedb OR role_row.rolcreaterole OR role_row.rolreplication OR role_row.rolbypassrls OR EXISTS(SELECT 1 FROM pg_roles r WHERE starts_with(r.rolname,'zasp_') AND r.oid<>role_row.oid AND r.rolname<>authorities[index_value] AND pg_has_role(role_row.oid,r.oid,'MEMBER')) OR EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid WHERE m.member=role_row.oid AND starts_with(r.rolname,'zasp_') AND (r.rolname<>authorities[index_value] OR m.admin_option OR NOT m.inherit_option OR m.set_option)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export worker principal rejected';END IF;
  SELECT principal_name INTO prior_value FROM public.zasp_audit_export_worker_bindings WHERE authority_role=authorities[index_value];
  IF FOUND AND prior_value<>names[index_value] OR EXISTS(SELECT 1 FROM public.zasp_audit_export_worker_bindings WHERE principal_name=names[index_value] AND authority_role<>authorities[index_value]) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='export worker registration conflict';END IF;
  EXECUTE format('GRANT %I TO %I WITH INHERIT TRUE, SET FALSE',authorities[index_value],names[index_value]);
  INSERT INTO public.zasp_audit_export_worker_bindings VALUES(names[index_value],authorities[index_value]) ON CONFLICT(principal_name) DO NOTHING;
 END LOOP;
 PERFORM public.zasp_audit_exports_require_ready();
 RETURN true;
END $register_workers$;
CREATE FUNCTION public.zasp_audit_export_worker_readiness(expected_checksum text,expected_fingerprint text,authority_value text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $worker_ready$
 SELECT COALESCE(public.zasp_production_audit_exports_readiness(expected_checksum,expected_fingerprint) AND authority_value IN('zasp_audit_export_worker','zasp_audit_export_outbox') AND EXISTS(SELECT 1 FROM public.zasp_audit_export_worker_bindings WHERE principal_name=session_user AND authority_role=authority_value),false)
$worker_ready$;

CREATE FUNCTION public.zasp_audit_export_job_policy_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $job_policy$
DECLARE policy_row public.zasp_audit_export_policies%ROWTYPE;current_value text;
BEGIN
 PERFORM public.zasp_audit_exports_require_ready();
 IF TG_OP='UPDATE' AND (NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.id,NEW.principal_id,NEW.audit_id,NEW.requested_at,NEW.policy_id,NEW.storage_policy) IS DISTINCT FROM (OLD.organization_id,OLD.workspace_id,OLD.environment_id,OLD.id,OLD.principal_id,OLD.audit_id,OLD.requested_at,OLD.policy_id,OLD.storage_policy) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export job authority is immutable';END IF;
 IF TG_OP='UPDATE' AND (OLD.capture_id IS NOT NULL AND NEW.capture_id IS DISTINCT FROM OLD.capture_id OR OLD.completion_audit_id IS NOT NULL AND NEW IS DISTINCT FROM OLD) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export retained authority is immutable';END IF;
 IF TG_OP='UPDATE' AND OLD.captured AND (NEW.captured,NEW.captured_at,NEW.event_count,NEW.chunk_count,NEW.chunk_bytes,NEW.chain_root,NEW.manifest_bytes) IS DISTINCT FROM (OLD.captured,OLD.captured_at,OLD.event_count,OLD.chunk_count,OLD.chunk_bytes,OLD.chain_root,OLD.manifest_bytes) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export frozen header is immutable';END IF;
 IF TG_OP='INSERT' THEN
  SELECT policy_id INTO STRICT current_value FROM public.zasp_audit_export_current_policy WHERE singleton FOR SHARE;
  IF NEW.policy_id IS DISTINCT FROM current_value THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export policy selection rejected';END IF;
 END IF;
 SELECT * INTO policy_row FROM public.zasp_audit_export_policies WHERE policy_id=NEW.policy_id;
 IF NOT FOUND OR NEW.storage_policy IS DISTINCT FROM public.zasp_audit_export_policy_json(policy_row) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export job storage authority rejected';END IF;
 PERFORM public.zasp_audit_exports_require_ready();
 RETURN NEW;
END $job_policy$;
CREATE TRIGGER zasp_audit_export_job_policy_guard BEFORE INSERT OR UPDATE ON public.zasp_audit_export_jobs FOR EACH ROW EXECUTE FUNCTION public.zasp_audit_export_job_policy_guard();

-- Only retained export completion rows are fenced. Legacy audit mutations on
-- unrelated rows retain their released behavior and privileges.
CREATE FUNCTION public.zasp_audit_export_completion_audit_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $audit_guard$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_audit_export_jobs WHERE organization_id=OLD.organization_id AND completion_audit_id=OLD.id) OR (TG_OP='UPDATE' AND EXISTS(SELECT 1 FROM public.zasp_audit_export_jobs WHERE organization_id=NEW.organization_id AND completion_audit_id=NEW.id)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export completion audit is immutable';END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
END $audit_guard$;
CREATE TRIGGER zasp_audit_export_completion_audit_guard BEFORE UPDATE OR DELETE ON public.zasp_admin_audit FOR EACH ROW EXECUTE FUNCTION public.zasp_audit_export_completion_audit_guard();

CREATE FUNCTION public.zasp_audit_export_require_failure(job_value public.zasp_audit_export_jobs) RETURNS void LANGUAGE plpgsql STABLE SET search_path TO pg_catalog,public AS $failure_proof$
BEGIN
 IF job_value.reserved_bytes IS DISTINCT FROM (SELECT COALESCE(sum(size_bytes),0) FROM public.zasp_audit_export_intents WHERE organization_id=job_value.organization_id AND export_id=job_value.id AND capture_id=job_value.capture_id) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export retained intent bytes rejected';END IF;
 IF job_value.status<>'failed' OR job_value.completion_audit_id IS NULL OR job_value.completed_at IS NULL OR NOT EXISTS(SELECT 1 FROM public.zasp_admin_audit a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.id,a.actor_id,a.action,a.target_id,a.outcome,a.occurred_at)=(job_value.organization_id,job_value.workspace_id,job_value.environment_id,job_value.completion_audit_id,job_value.principal_id,'audit_export.complete',job_value.id,'rejected',job_value.completed_at) AND a.metadata=jsonb_build_object('failure_code',job_value.failure_code)) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export failure authority unavailable';END IF;
END $failure_proof$;
CREATE FUNCTION public.zasp_audit_export_fail(job_value public.zasp_audit_export_jobs,code_value text) RETURNS public.zasp_audit_export_jobs LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $fail$
DECLARE result public.zasp_audit_export_jobs%ROWTYPE;audit_value text:='pid_'||gen_random_uuid()::text;stamp timestamptz:=clock_timestamp();
BEGIN
 IF job_value.status NOT IN('queued','processing') OR code_value NOT IN('capacity_exceeded','invalid_source','execution_failed') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export failure transition rejected';END IF;
 -- The caller holds organization then job fences. Every issued intent may
 -- already have saved provider bytes, even when its receipt is still absent.
 UPDATE public.zasp_audit_export_jobs SET status='failed',failure_code=code_value,completion_audit_id=audit_value,completed_at=stamp,lease_worker=NULL,lease_token_digest=NULL,lease_expires_at=NULL,reserved_bytes=(SELECT COALESCE(sum(size_bytes),0) FROM public.zasp_audit_export_intents WHERE organization_id=job_value.organization_id AND export_id=job_value.id AND capture_id=job_value.capture_id) WHERE organization_id=job_value.organization_id AND id=job_value.id RETURNING * INTO STRICT result;
 INSERT INTO public.zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) VALUES(result.organization_id,result.workspace_id,result.environment_id,audit_value,result.principal_id,'audit_export.complete',result.id,'rejected',jsonb_build_object('failure_code',code_value),stamp);
 PERFORM public.zasp_audit_export_require_failure(result);
 RETURN result;
END $fail$;

CREATE FUNCTION public.zasp_audit_export_register_api(principal_value text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $register$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority') OR NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export registration authority rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-audit-export-registration',0));
 PERFORM public.zasp_audit_exports_require_ready();
 IF NOT EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings b JOIN pg_roles r ON r.rolname=b.principal_name WHERE b.principal_name=principal_value AND b.authority_role='zasp_discovery_api' AND r.rolcanlogin AND r.rolinherit AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolreplication AND NOT r.rolbypassrls) OR NOT pg_has_role(principal_value,'zasp_discovery_api','MEMBER') OR pg_has_role(principal_value,'zasp_discovery_authority','MEMBER') OR EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid JOIN pg_roles p ON p.oid=m.member WHERE p.rolname=principal_value AND r.rolname LIKE 'zasp_%' AND (r.rolname<>'zasp_discovery_api' OR m.admin_option)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export API principal rejected';END IF;
 INSERT INTO public.zasp_audit_export_api_bindings(principal_name) VALUES(principal_value) ON CONFLICT(principal_name) DO NOTHING;
 PERFORM public.zasp_audit_exports_require_ready();
 RETURN true;
END $register$;

CREATE FUNCTION public.zasp_audit_export_api_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $api_ready$
 SELECT COALESCE(public.zasp_production_audit_exports_readiness(expected_checksum,expected_fingerprint) AND public.zasp_discovery_principal_ready('zasp_discovery_api') AND EXISTS(SELECT 1 FROM public.zasp_audit_export_api_bindings WHERE principal_name=session_user AND capability='audit-export-api-v1') AND EXISTS(SELECT 1 FROM public.zasp_audit_export_current_policy WHERE policy_id IS NOT NULL),false)
$api_ready$;

CREATE FUNCTION public.zasp_audit_export_require_api(expected_checksum text,expected_fingerprint text) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $api_guard$
BEGIN
 IF NOT COALESCE(public.zasp_production_audit_exports_readiness(expected_checksum,expected_fingerprint),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export release unavailable';END IF;
 IF NOT COALESCE(public.zasp_audit_export_api_readiness(expected_checksum,expected_fingerprint),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export API authority rejected';END IF;
END $api_guard$;

-- Hold session and membership rows through the operation. Re-read effective
-- scopes and the wall clock after later waits, including verified group grants.
-- A stale Go freshness flag grants nothing here. No new legacy write grants.
CREATE FUNCTION public.zasp_audit_export_require_browser(org_value text,workspace_value text,environment_value text,principal_value text,session_value bytea,csrf_value text,fresh_value boolean) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $browser$
DECLARE session_row public.zasp_product_sessions%ROWTYPE;membership_row public.zasp_identity_memberships%ROWTYPE;
BEGIN
 SELECT * INTO session_row FROM public.zasp_product_sessions WHERE token_digest=session_value AND principal_id=principal_value AND organization_id=org_value AND workspace_id=workspace_value AND environment_id=environment_value FOR SHARE;
 IF NOT FOUND OR session_row.revoked_at IS NOT NULL OR session_row.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='export browser session rejected';END IF;
 IF csrf_value IS NULL OR octet_length(csrf_value)<32 OR session_row.csrf_token IS DISTINCT FROM csrf_value OR (fresh_value AND (session_row.authenticated_at<clock_timestamp()-interval '5 minutes' OR session_row.authenticated_at>clock_timestamp())) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export browser authorization rejected';END IF;
 SELECT * INTO membership_row FROM public.zasp_identity_memberships WHERE organization_id=org_value AND principal_id=principal_value FOR SHARE;
 IF NOT FOUND OR NOT membership_row.active THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export membership rejected';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.zasp_identity_admin_effective_scopes(principal_value,org_value) scope WHERE (scope.organization_id,scope.workspace_id,scope.environment_id)=(org_value,workspace_value,environment_value) AND scope.permissions ? 'view_audit') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export scope rejected';END IF;
END $browser$;

CREATE FUNCTION public.zasp_audit_export_descriptor(job_value public.zasp_audit_export_jobs) RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path TO pg_catalog,public AS $descriptor$
DECLARE result jsonb;
BEGIN
 result:=jsonb_build_object('id',job_value.id,'organization_id',job_value.organization_id,'workspace_id',job_value.workspace_id,'environment_id',job_value.environment_id,'created_at',to_char(job_value.requested_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'audit_correlation_id',job_value.audit_id,'status',job_value.status,'event_count',NULL);
 IF job_value.status='ready' THEN
  PERFORM public.zasp_audit_export_require_ready_receipt(job_value);
  result:=result||jsonb_build_object('event_count',job_value.event_count,'captured_at',to_char(job_value.captured_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'chunk_count',job_value.chunk_count,'chunk_bytes',job_value.chunk_bytes,'manifest_sha256',encode(digest(job_value.manifest_bytes,'sha256'),'hex'));
 END IF;
 IF job_value.status='failed' THEN PERFORM public.zasp_audit_export_require_failure(job_value);result:=result||jsonb_build_object('failure_code',job_value.failure_code);END IF;
 RETURN result;
END $descriptor$;

CREATE FUNCTION public.zasp_audit_export_create(org_value text,workspace_value text,environment_value text,principal_value text,session_value bytea,csrf_value text,idempotency_value text,export_value text,audit_value text,outbox_value text,request_value bytea,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $create$
DECLARE prior public.zasp_audit_export_idempotency%ROWTYPE;job_row public.zasp_audit_export_jobs%ROWTYPE;policy_row public.zasp_audit_export_policies%ROWTYPE;current_value text;result jsonb;
BEGIN
 PERFORM public.zasp_audit_export_require_api(expected_checksum,expected_fingerprint);
 IF EXISTS(SELECT 1 FROM unnest(ARRAY[org_value,workspace_value,environment_value,principal_value,export_value,audit_value,outbox_value]) value WHERE NOT COALESCE(public.zasp_valid_product_id(value),false)) OR (SELECT count(DISTINCT value) FROM unnest(ARRAY[org_value,workspace_value,environment_value,principal_value,export_value,audit_value,outbox_value]) value)<>7 OR session_value IS NULL OR octet_length(session_value)<>32 OR session_value=decode(repeat('00',32),'hex') OR idempotency_value IS NULL OR octet_length(idempotency_value) NOT BETWEEN 16 AND 128 OR idempotency_value !~ '^[A-Za-z0-9._:-]+$' OR request_value IS DISTINCT FROM digest(convert_to('{}','UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export request rejected';END IF;
 PERFORM public.zasp_audit_export_require_browser(org_value,workspace_value,environment_value,principal_value,session_value,csrf_value,true);
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws('|','zasp-audit-export-create',org_value,workspace_value,environment_value,principal_value,idempotency_value),0));
 PERFORM public.zasp_audit_export_require_api(expected_checksum,expected_fingerprint);
 PERFORM public.zasp_audit_export_require_browser(org_value,workspace_value,environment_value,principal_value,session_value,csrf_value,true);
 SELECT * INTO prior FROM public.zasp_audit_export_idempotency WHERE (organization_id,workspace_id,environment_id,principal_id,idempotency_key)=(org_value,workspace_value,environment_value,principal_value,idempotency_value) FOR UPDATE;
 IF FOUND THEN
  IF prior.request_digest IS DISTINCT FROM request_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='export idempotency conflict';END IF;
  SELECT * INTO STRICT job_row FROM public.zasp_audit_export_jobs WHERE organization_id=org_value AND id=prior.export_id FOR SHARE;
 ELSE
  PERFORM pg_advisory_xact_lock(hashtextextended('zasp-audit-export-admission|'||org_value,0));
  SELECT policy_id INTO STRICT current_value FROM public.zasp_audit_export_current_policy WHERE singleton FOR SHARE;
  SELECT * INTO STRICT policy_row FROM public.zasp_audit_export_policies WHERE policy_id=current_value;
  PERFORM public.zasp_audit_export_require_api(expected_checksum,expected_fingerprint);
  PERFORM public.zasp_audit_export_require_browser(org_value,workspace_value,environment_value,principal_value,session_value,csrf_value,true);
  INSERT INTO public.zasp_audit_export_jobs(organization_id,workspace_id,environment_id,id,principal_id,audit_id,policy_id,storage_policy) VALUES(org_value,workspace_value,environment_value,export_value,principal_value,audit_value,current_value,public.zasp_audit_export_policy_json(policy_row)) RETURNING * INTO job_row;
  INSERT INTO public.zasp_audit_export_idempotency(organization_id,workspace_id,environment_id,principal_id,idempotency_key,request_digest,export_id) VALUES(org_value,workspace_value,environment_value,principal_value,idempotency_value,request_value,export_value);
  INSERT INTO public.zasp_audit_export_outbox(organization_id,workspace_id,environment_id,id,export_id) VALUES(org_value,workspace_value,environment_value,outbox_value,export_value);
  INSERT INTO public.zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) VALUES(org_value,workspace_value,environment_value,audit_value,principal_value,'audit_export.request',export_value,'succeeded','{}');
  IF (SELECT count(*) FROM public.zasp_audit_export_jobs WHERE organization_id=org_value AND status IN('queued','processing'))>policy_row.maximum_inflight OR (SELECT COALESCE(sum(reserved_bytes),0) FROM public.zasp_audit_export_jobs WHERE organization_id=org_value)>=policy_row.maximum_retained_bytes THEN job_row:=public.zasp_audit_export_fail(job_row,'capacity_exceeded');END IF;
 END IF;
 result:=public.zasp_audit_export_descriptor(job_row);
 PERFORM public.zasp_audit_export_require_api(expected_checksum,expected_fingerprint);
 PERFORM public.zasp_audit_export_require_browser(org_value,workspace_value,environment_value,principal_value,session_value,csrf_value,true);
 RETURN result;
END $create$;

CREATE FUNCTION public.zasp_audit_export_require_worker(expected_checksum text,expected_fingerprint text) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $worker_guard$
BEGIN
 IF NOT COALESCE(public.zasp_production_audit_exports_readiness(expected_checksum,expected_fingerprint),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export release unavailable';END IF;
 IF NOT COALESCE(public.zasp_audit_export_worker_readiness(expected_checksum,expected_fingerprint,'zasp_audit_export_worker'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export worker authority rejected';END IF;
END $worker_guard$;
CREATE FUNCTION public.zasp_audit_export_check_job(job_value public.zasp_audit_export_jobs,policy_value text,digest_value bytea) RETURNS void LANGUAGE plpgsql STABLE SET search_path TO pg_catalog,public AS $job_check$
BEGIN
 IF job_value.policy_id IS DISTINCT FROM policy_value OR decode(job_value.storage_policy->>'policy_digest','hex') IS DISTINCT FROM digest_value OR NOT EXISTS(SELECT 1 FROM public.zasp_audit_export_policies p WHERE p.policy_id=policy_value AND p.policy_digest=digest_value AND job_value.storage_policy=public.zasp_audit_export_policy_json(p)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export retained policy rejected';END IF;
END $job_check$;
CREATE FUNCTION public.zasp_audit_export_lock_job(org_value text,workspace_value text,environment_value text,export_value text,policy_value text,digest_value bytea,expected_checksum text,expected_fingerprint text) RETURNS public.zasp_audit_export_jobs LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $job_lock$
DECLARE result public.zasp_audit_export_jobs%ROWTYPE;
BEGIN
 PERFORM public.zasp_audit_export_require_worker(expected_checksum,expected_fingerprint);
 IF EXISTS(SELECT 1 FROM unnest(ARRAY[org_value,workspace_value,environment_value,export_value,policy_value]) value WHERE NOT COALESCE(public.zasp_valid_product_id(value),false)) OR digest_value IS NULL OR octet_length(digest_value)<>32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export worker scope rejected';END IF;
 -- All lifecycle mutations acquire this organization fence before job rows.
 -- It also serializes quota admission across retained policy revisions.
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-audit-export-admission|'||org_value,0));
 SELECT * INTO result FROM public.zasp_audit_export_jobs WHERE (organization_id,workspace_id,environment_id,id)=(org_value,workspace_value,environment_value,export_value) FOR UPDATE;
 PERFORM public.zasp_audit_export_require_worker(expected_checksum,expected_fingerprint);
 IF result.id IS NULL THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='export not found';END IF;
 PERFORM public.zasp_audit_export_check_job(result,policy_value,digest_value);
 RETURN result;
END $job_lock$;
CREATE FUNCTION public.zasp_audit_export_lease_json(job_value public.zasp_audit_export_jobs) RETURNS jsonb LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $lease_json$
 SELECT jsonb_build_object('organization_id',job_value.organization_id,'workspace_id',job_value.workspace_id,'environment_id',job_value.environment_id,'export_id',job_value.id,'capture_id',job_value.capture_id,'policy_id',job_value.policy_id,'policy_digest',job_value.storage_policy->>'policy_digest','generation',job_value.generation,'attempt',job_value.attempt,'lease_expires_at',to_char(job_value.lease_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'captured',job_value.captured,'storage_policy',job_value.storage_policy)
$lease_json$;
CREATE FUNCTION public.zasp_audit_export_claim(org_value text,workspace_value text,environment_value text,export_value text,worker_value text,token_value text,seconds_value integer,policy_value text,digest_value bytea,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $claim$
DECLARE job_row public.zasp_audit_export_jobs%ROWTYPE;result jsonb:='null'::jsonb;token_digest bytea;
BEGIN
 PERFORM public.zasp_audit_export_require_worker(expected_checksum,expected_fingerprint);
 IF NOT COALESCE(worker_value ~ '^[a-z][a-z0-9.-]{2,127}$' AND token_value ~ '^[0-9a-f]{64}$' AND token_value<>repeat('0',64) AND seconds_value BETWEEN 60 AND 300,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export claim rejected';END IF;
 token_digest:=digest(convert_to(token_value,'UTF8'),'sha256');
 job_row:=public.zasp_audit_export_lock_job(org_value,workspace_value,environment_value,export_value,policy_value,digest_value,expected_checksum,expected_fingerprint);
 IF job_row.status='failed' THEN PERFORM public.zasp_audit_export_require_failure(job_row);
 ELSIF job_row.status='ready' THEN PERFORM public.zasp_audit_export_descriptor(job_row);
 ELSIF job_row.lease_expires_at>clock_timestamp() THEN
  IF job_row.lease_worker=worker_value AND job_row.lease_token_digest=token_digest THEN result:=public.zasp_audit_export_lease_json(job_row);END IF;
 ELSIF job_row.available_at<=clock_timestamp() THEN
  IF job_row.attempt>=5 THEN job_row:=public.zasp_audit_export_fail(job_row,'execution_failed');
  ELSE
   UPDATE public.zasp_audit_export_jobs SET status='processing',capture_id=COALESCE(capture_id,'pid_'||gen_random_uuid()::text),generation=generation+1,attempt=attempt+1,lease_worker=worker_value,lease_token_digest=token_digest,lease_expires_at=clock_timestamp()+make_interval(secs=>seconds_value) WHERE organization_id=org_value AND id=export_value RETURNING * INTO job_row;
   result:=public.zasp_audit_export_lease_json(job_row);
  END IF;
 END IF;
 PERFORM public.zasp_audit_export_require_worker(expected_checksum,expected_fingerprint);
 IF result<>'null'::jsonb AND job_row.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export lease expired';END IF;
 RETURN result;
END $claim$;
CREATE FUNCTION public.zasp_audit_export_require_lease(org_value text,workspace_value text,environment_value text,export_value text,capture_value text,generation_value bigint,attempt_value integer,worker_value text,token_value text,policy_value text,digest_value bytea,expected_checksum text,expected_fingerprint text) RETURNS public.zasp_audit_export_jobs LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $lease_guard$
DECLARE job_row public.zasp_audit_export_jobs%ROWTYPE;
BEGIN
 job_row:=public.zasp_audit_export_lock_job(org_value,workspace_value,environment_value,export_value,policy_value,digest_value,expected_checksum,expected_fingerprint);
 IF NOT COALESCE(job_row.status='processing' AND job_row.capture_id=capture_value AND job_row.generation=generation_value AND job_row.attempt=attempt_value AND job_row.lease_worker=worker_value AND token_value ~ '^[0-9a-f]{64}$' AND token_value<>repeat('0',64) AND job_row.lease_token_digest=digest(convert_to(token_value,'UTF8'),'sha256') AND job_row.lease_expires_at>clock_timestamp(),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export lease rejected';END IF;
 RETURN job_row;
END $lease_guard$;
CREATE FUNCTION public.zasp_audit_export_heartbeat(org_value text,workspace_value text,environment_value text,export_value text,capture_value text,generation_value bigint,attempt_value integer,worker_value text,token_value text,policy_value text,digest_value bytea,expected_checksum text,expected_fingerprint text,seconds_value integer) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $heartbeat$
DECLARE job_row public.zasp_audit_export_jobs%ROWTYPE;prior_expiry timestamptz;result jsonb;
BEGIN
 IF seconds_value IS NULL OR seconds_value NOT BETWEEN 60 AND 300 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export heartbeat rejected';END IF;
 job_row:=public.zasp_audit_export_require_lease(org_value,workspace_value,environment_value,export_value,capture_value,generation_value,attempt_value,worker_value,token_value,policy_value,digest_value,expected_checksum,expected_fingerprint);
 prior_expiry:=job_row.lease_expires_at;
 UPDATE public.zasp_audit_export_jobs SET lease_expires_at=greatest(lease_expires_at,clock_timestamp()+make_interval(secs=>seconds_value)) WHERE organization_id=org_value AND id=export_value RETURNING * INTO job_row;
 result:=public.zasp_audit_export_lease_json(job_row);
 PERFORM public.zasp_audit_export_require_worker(expected_checksum,expected_fingerprint);
 IF prior_expiry<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export lease expired';END IF;
 RETURN result;
END $heartbeat$;
CREATE FUNCTION public.zasp_audit_export_terminal(org_value text,workspace_value text,environment_value text,export_value text,policy_value text,digest_value bytea,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $terminal$
DECLARE job_row public.zasp_audit_export_jobs%ROWTYPE;result jsonb;
BEGIN
 PERFORM public.zasp_audit_export_require_worker(expected_checksum,expected_fingerprint);
 IF EXISTS(SELECT 1 FROM unnest(ARRAY[org_value,workspace_value,environment_value,export_value,policy_value]) value WHERE NOT COALESCE(public.zasp_valid_product_id(value),false)) OR digest_value IS NULL OR octet_length(digest_value)<>32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export worker scope rejected';END IF;
 SELECT * INTO job_row FROM public.zasp_audit_export_jobs WHERE (organization_id,workspace_id,environment_id,id)=(org_value,workspace_value,environment_value,export_value) FOR SHARE;
 PERFORM public.zasp_audit_export_require_worker(expected_checksum,expected_fingerprint);
 IF job_row.id IS NULL THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='export not found';END IF;
 PERFORM public.zasp_audit_export_check_job(job_row,policy_value,digest_value);
 IF job_row.status IN('ready','failed') THEN result:=jsonb_build_object('state',job_row.status,'export',public.zasp_audit_export_descriptor(job_row));ELSE result:=jsonb_build_object('state','nonterminal');END IF;
 PERFORM public.zasp_audit_export_require_worker(expected_checksum,expected_fingerprint);
 RETURN result;
END $terminal$;

CREATE FUNCTION public.zasp_audit_export_get(org_value text,workspace_value text,environment_value text,principal_value text,session_value bytea,csrf_value text,export_value text,ordinal_value bigint,manifest_value bytea,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $get$
DECLARE job_row public.zasp_audit_export_jobs%ROWTYPE;result jsonb;
BEGIN
 PERFORM public.zasp_audit_export_require_api(expected_checksum,expected_fingerprint);
 IF EXISTS(SELECT 1 FROM unnest(ARRAY[org_value,workspace_value,environment_value,principal_value,export_value]) value WHERE NOT COALESCE(public.zasp_valid_product_id(value),false)) OR session_value IS NULL OR octet_length(session_value)<>32 OR ordinal_value IS NULL OR ordinal_value<1 OR ordinal_value>9007199254740991 OR (manifest_value IS NOT NULL AND octet_length(manifest_value)<>32) OR (ordinal_value>1 AND manifest_value IS NULL) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export read rejected';END IF;
 PERFORM public.zasp_audit_export_require_browser(org_value,workspace_value,environment_value,principal_value,session_value,csrf_value,false);
 SELECT * INTO job_row FROM public.zasp_audit_export_jobs WHERE organization_id=org_value AND id=export_value FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='export not found';END IF;
 IF job_row.status='ready' THEN
  result:=jsonb_build_object('export',public.zasp_audit_export_descriptor(job_row),'authority',public.zasp_audit_export_read_authority(job_row,ordinal_value,manifest_value));
 ELSE
  IF ordinal_value<>1 OR manifest_value IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export cursor unavailable';END IF;
  result:=jsonb_build_object('export',public.zasp_audit_export_descriptor(job_row),'authority',NULL);
 END IF;
 PERFORM public.zasp_audit_export_require_api(expected_checksum,expected_fingerprint);
 PERFORM public.zasp_audit_export_require_browser(org_value,workspace_value,environment_value,principal_value,session_value,csrf_value,false);
 RETURN result;
END $get$;

-- Frozen bytes use the public audit projection, not jsonb presentation. Validate
-- original metadata before redaction so invalid source is never hidden or lost.
CREATE FUNCTION public.zasp_audit_export_json_string(value text) RETURNS text LANGUAGE sql IMMUTABLE STRICT SET search_path TO pg_catalog,public AS $quote$
 SELECT replace(replace(replace(replace(replace(to_json(value)::text,'<',E'\\u003c'),'>',E'\\u003e'),'&',E'\\u0026'),chr(8232),E'\\u2028'),chr(8233),E'\\u2029')
$quote$;
CREATE FUNCTION public.zasp_audit_export_event_bytes(ordinal_value bigint,event_value public.zasp_admin_audit) RETURNS bytea LANGUAGE plpgsql IMMUTABLE SET search_path TO pg_catalog,public AS $event$
DECLARE entry record;metadata_value text:='';lower_key text;stamp text;result bytea;control_pattern text:='['||chr(1)||'-'||chr(31)||chr(127)||']';
BEGIN
 IF NOT COALESCE(ordinal_value BETWEEN 1 AND 9007199254740991 AND public.zasp_valid_product_id(event_value.id) AND public.zasp_valid_product_id(event_value.actor_id) AND public.zasp_valid_product_id(event_value.organization_id) AND public.zasp_valid_product_id(event_value.workspace_id) AND public.zasp_valid_product_id(event_value.environment_id) AND event_value.organization_id<>event_value.workspace_id AND event_value.organization_id<>event_value.environment_id AND event_value.workspace_id<>event_value.environment_id AND octet_length(event_value.action) BETWEEN 1 AND 127 AND (event_value.action COLLATE "C" ~ '^[a-z]([a-z0-9]|[._-][a-z0-9])*$' OR event_value.action COLLATE "C" IN('identity_provider.createSSOConnection','identity_provider.deleteSSOConnection','identity_provider.testSSOConnection','identity_provider.createSCIMConnection','identity_provider.deleteSCIMConnection')) AND octet_length(event_value.target_id) BETWEEN 1 AND 128 AND event_value.target_id !~ control_pattern AND event_value.outcome IN('succeeded','rejected','failed','denied') AND jsonb_typeof(event_value.metadata)='object' AND isfinite(event_value.occurred_at) AND event_value.occurred_at>='0001-01-01T00:00:00Z'::timestamptz AND event_value.occurred_at<'10000-01-01T00:00:00Z'::timestamptz AND event_value.occurred_at<>'0001-01-01T00:00:00Z'::timestamptz,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export source rejected';END IF;
 IF (SELECT count(*) FROM jsonb_object_keys(event_value.metadata))>32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export source metadata rejected';END IF;
 FOR entry IN SELECT key,value FROM jsonb_each_text(event_value.metadata) ORDER BY key COLLATE "C" LOOP
  IF entry.value IS NULL OR octet_length(entry.key) NOT BETWEEN 1 AND 64 OR octet_length(entry.value) NOT BETWEEN 1 AND 512 OR entry.key ~ control_pattern OR entry.value ~ control_pattern THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export source metadata rejected';END IF;
  -- These are the Unicode simple-lower mappings into ASCII used by Go for
  -- matching the six existing ASCII secret-key substrings, independent of DB locale.
  lower_key:=translate(entry.key,'ABCDEFGHIJKLMNOPQRSTUVWXYZ'||chr(304)||chr(8490),'abcdefghijklmnopqrstuvwxyzik');
  IF lower_key LIKE '%secret%' OR lower_key LIKE '%token%' OR lower_key LIKE '%password%' OR lower_key LIKE '%authorization%' OR lower_key LIKE '%credential%' OR position('api_key' IN lower_key)>0 THEN entry.value:='[REDACTED]';END IF;
  IF metadata_value<>'' THEN metadata_value:=metadata_value||',';END IF;
  metadata_value:=metadata_value||public.zasp_audit_export_json_string(entry.key)||':'||public.zasp_audit_export_json_string(entry.value);
 END LOOP;
 stamp:=to_char(event_value.occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
 result:=convert_to('{"ordinal":'||ordinal_value::text||',"id":'||public.zasp_audit_export_json_string(event_value.id)||',"organization_id":'||public.zasp_audit_export_json_string(event_value.organization_id)||',"workspace_id":'||public.zasp_audit_export_json_string(event_value.workspace_id)||',"environment_id":'||public.zasp_audit_export_json_string(event_value.environment_id)||',"actor_id":'||public.zasp_audit_export_json_string(event_value.actor_id)||',"action":'||public.zasp_audit_export_json_string(event_value.action)||',"target_id":'||public.zasp_audit_export_json_string(event_value.target_id)||',"outcome":'||public.zasp_audit_export_json_string(CASE WHEN event_value.outcome='rejected' THEN 'denied' ELSE event_value.outcome END)||',"metadata":{'||metadata_value||'},"occurred_at":'||public.zasp_audit_export_json_string(stamp)||'}','UTF8');
 IF octet_length(result)>131072 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export source bytes rejected';END IF;
 RETURN result;
END $event$;

CREATE FUNCTION public.zasp_audit_export_binding_bytes(job_value public.zasp_audit_export_jobs) RETURNS text LANGUAGE sql IMMUTABLE STRICT SET search_path TO pg_catalog,public AS $binding$
 SELECT '{"organization_id":'||to_json(job_value.organization_id)::text||',"workspace_id":'||to_json(job_value.workspace_id)::text||',"environment_id":'||to_json(job_value.environment_id)::text||',"export_id":'||to_json(job_value.id)::text||',"capture_id":'||to_json(job_value.capture_id)::text||'}'
$binding$;
CREATE FUNCTION public.zasp_audit_export_chunk_prefix(job_value public.zasp_audit_export_jobs,ordinal_value bigint,first_value bigint,count_value integer,previous_value bytea) RETURNS text LANGUAGE sql IMMUTABLE STRICT SET search_path TO pg_catalog,public AS $chunk_prefix$
 SELECT '{"schema":"audit-export-chunk-v1","binding":'||public.zasp_audit_export_binding_bytes(job_value)||',"ordinal":'||ordinal_value::text||',"first_event":'||first_value::text||',"event_count":'||count_value::text||',"previous_digest":"'||encode(previous_value,'hex')||'","events":['
$chunk_prefix$;
CREATE FUNCTION public.zasp_audit_export_planned_chunk_bytes(job_value public.zasp_audit_export_jobs,ordinal_value bigint,first_value bigint,count_value integer,previous_value bytea) RETURNS bytea LANGUAGE plpgsql STABLE SET search_path TO pg_catalog,public AS $chunk_bytes$
DECLARE prefix text;actual_count bigint;event_bytes bigint;payload text;
BEGIN
 IF NOT COALESCE(count_value BETWEEN 1 AND 1000 AND first_value BETWEEN 1 AND 9007199254740991-count_value+1 AND ordinal_value BETWEEN 1 AND first_value AND octet_length(previous_value)=32,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export chunk range rejected';END IF;
 prefix:=public.zasp_audit_export_chunk_prefix(job_value,ordinal_value,first_value,count_value,previous_value);
 SELECT count(*),COALESCE(sum(octet_length(canonical_event)),0) INTO actual_count,event_bytes FROM public.zasp_audit_export_events WHERE organization_id=job_value.organization_id AND export_id=job_value.id AND capture_id=job_value.capture_id AND ordinal BETWEEN first_value AND first_value+count_value-1;
 IF actual_count<>count_value OR octet_length(prefix)+event_bytes+count_value-1+2>1048576 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export frozen chunk authority rejected';END IF;
 -- Aggregate only after both complete wire bytes and row count are bounded.
 SELECT string_agg(convert_from(canonical_event,'UTF8'),',' ORDER BY ordinal) INTO payload FROM public.zasp_audit_export_events WHERE organization_id=job_value.organization_id AND export_id=job_value.id AND capture_id=job_value.capture_id AND ordinal BETWEEN first_value AND first_value+count_value-1;
 RETURN convert_to(prefix||payload||']}','UTF8');
END $chunk_bytes$;
CREATE FUNCTION public.zasp_audit_export_manifest_bytes(job_value public.zasp_audit_export_jobs) RETURNS bytea LANGUAGE sql IMMUTABLE STRICT SET search_path TO pg_catalog,public AS $manifest$
 SELECT convert_to('{"schema":"audit-export-manifest-v1","binding":'||public.zasp_audit_export_binding_bytes(job_value)||',"event_count":'||job_value.event_count::text||',"chunk_count":'||job_value.chunk_count::text||',"chunk_bytes":'||job_value.chunk_bytes::text||',"chain_root":"'||encode(job_value.chain_root,'hex')||'"}','UTF8')
$manifest$;
CREATE FUNCTION public.zasp_audit_export_recorded_prefix(job_value public.zasp_audit_export_jobs) RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path TO pg_catalog,public AS $prefix$
DECLARE count_value bigint;bytes_value bigint;last_value bigint;events_value bigint;previous_value bytea:=decode(repeat('0',64),'hex');
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_audit_export_receipts r LEFT JOIN public.zasp_audit_export_intents i USING(organization_id,export_id,kind,ordinal) LEFT JOIN public.zasp_audit_export_chunks c ON (c.organization_id,c.export_id,c.ordinal)=(r.organization_id,r.export_id,r.ordinal) WHERE r.organization_id=job_value.organization_id AND r.export_id=job_value.id AND r.kind='chunk' AND NOT COALESCE((i.workspace_id,i.environment_id,i.capture_id,c.capture_id,i.sha256,i.size_bytes,r.sha256,r.size_bytes)=(job_value.workspace_id,job_value.environment_id,job_value.capture_id,job_value.capture_id,c.sha256,c.size_bytes,c.sha256,c.size_bytes),false)) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export receipt authority rejected';END IF;
 SELECT count(*),COALESCE(sum(r.size_bytes),0),COALESCE(max(r.ordinal),0),COALESCE(sum(c.event_count),0) INTO count_value,bytes_value,last_value,events_value FROM public.zasp_audit_export_receipts r JOIN public.zasp_audit_export_chunks c ON (c.organization_id,c.export_id,c.ordinal)=(r.organization_id,r.export_id,r.ordinal) WHERE r.organization_id=job_value.organization_id AND r.export_id=job_value.id AND r.kind='chunk';
 IF count_value<>last_value OR count_value>job_value.chunk_count OR events_value>job_value.event_count OR bytes_value>job_value.chunk_bytes THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export receipt prefix rejected';END IF;
 IF count_value>0 THEN SELECT sha256 INTO STRICT previous_value FROM public.zasp_audit_export_chunks WHERE organization_id=job_value.organization_id AND export_id=job_value.id AND ordinal=last_value;END IF;
 RETURN jsonb_build_object('next_chunk',count_value+1,'next_event',events_value+1,'recorded_chunk_count',count_value,'recorded_chunk_bytes',bytes_value,'previous_digest',encode(previous_value,'hex'));
END $prefix$;
CREATE FUNCTION public.zasp_audit_export_capture_progress(job_value public.zasp_audit_export_jobs) RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path TO pg_catalog,public AS $progress$
BEGIN
 IF NOT job_value.captured OR (SELECT count(*) FROM public.zasp_audit_export_events WHERE organization_id=job_value.organization_id AND export_id=job_value.id)<>job_value.event_count OR NOT (SELECT count(*)=job_value.chunk_count AND COALESCE(sum(event_count),0)=job_value.event_count AND COALESCE(sum(size_bytes),0)=job_value.chunk_bytes FROM public.zasp_audit_export_chunks WHERE organization_id=job_value.organization_id AND export_id=job_value.id) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export frozen totals rejected';END IF;
 RETURN jsonb_build_object('state','processing','captured',true,'binding',public.zasp_audit_export_binding_bytes(job_value)::jsonb,'storage_policy',job_value.storage_policy,'event_count',job_value.event_count,'chunk_count',job_value.chunk_count,'chunk_bytes',job_value.chunk_bytes,'chain_root',encode(job_value.chain_root,'hex'))||public.zasp_audit_export_recorded_prefix(job_value);
END $progress$;
CREATE FUNCTION public.zasp_audit_export_capture_event(ordinal_value bigint,event_value public.zasp_admin_audit,deadline_value timestamptz) RETURNS bytea LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $capture_event$
BEGIN
 IF clock_timestamp()>=deadline_value THEN RAISE EXCEPTION USING ERRCODE='57014',MESSAGE='export capture deadline elapsed';END IF;
 RETURN public.zasp_audit_export_event_bytes(ordinal_value,event_value);
END $capture_event$;

-- Shared private source for full public audit listing and frozen exports.
-- Retain invalid eligible records so consumers refuse rather than omit them.
CREATE VIEW public.zasp_audit_export_public_source_v1 WITH (security_barrier=true) AS
 SELECT organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at,'administration'::text AS source_kind,true AS source_valid FROM public.zasp_admin_audit
 UNION ALL
 SELECT organization_id,workspace_id,environment_id,audit_id,principal_id,
 CASE operation WHEN 'createPolicy' THEN 'policy.create' WHEN 'updatePolicy' THEN 'policy.update' WHEN 'deletePolicy' THEN 'policy.delete' WHEN 'rolloutPolicy' THEN 'policy.rollout' WHEN 'disablePolicy' THEN 'policy.disable' END,
 resource_id,'succeeded',
 CASE WHEN resource_kind='policy' AND resource_id ~ '^policy-[a-z0-9][a-z0-9-]{0,120}$' AND resource_version>0 AND public.zasp_valid_product_id(correlation_id) THEN jsonb_build_object('source','workflow_policy','source_operation',operation,'correlation_id',correlation_id,'resource_version',resource_version::text) ELSE '{}'::jsonb END,
 created_at,'workflow_policy',COALESCE(resource_kind='policy' AND resource_id ~ '^policy-[a-z0-9][a-z0-9-]{0,120}$' AND resource_version>0 AND public.zasp_valid_product_id(correlation_id),false)
 FROM public.zasp_workflow_audit WHERE operation IN('createPolicy','updatePolicy','deletePolicy','rolloutPolicy','disablePolicy')
 UNION ALL
 SELECT organization_id,workspace_id,environment_id,audit_id,actor_id,
 CASE event_kind WHEN 'red_team_definition_created' THEN 'test.create' WHEN 'red_team_definition_updated' THEN 'test.update' WHEN 'red_team_run_queued' THEN 'test.run.queued' WHEN 'red_team_run_cancelled' THEN 'test.run.cancel_requested' END,
 resource_id,'succeeded',
 CASE WHEN public.zasp_valid_product_id(resource_id) AND public.zasp_valid_product_id(correlation_id) AND public.zasp_valid_product_id(receipt_id) AND octet_length(event_digest)=32 THEN jsonb_build_object('source','red_team_mutation','source_event_kind',event_kind,'correlation_id',correlation_id,'receipt_id',receipt_id,'event_sha256',encode(event_digest,'hex')) ELSE '{}'::jsonb END,
 created_at,'red_team_mutation',COALESCE(public.zasp_valid_product_id(resource_id) AND public.zasp_valid_product_id(correlation_id) AND public.zasp_valid_product_id(receipt_id) AND octet_length(event_digest)=32,false)
 FROM public.zasp_red_team_audit WHERE event_kind IN('red_team_definition_created','red_team_definition_updated','red_team_run_queued','red_team_run_cancelled');
ALTER VIEW public.zasp_audit_export_public_source_v1 OWNER TO zasp_discovery_authority;
REVOKE ALL ON public.zasp_audit_export_public_source_v1 FROM PUBLIC,zasp_discovery_api,zasp_audit_export_worker,zasp_audit_export_outbox;
-- Public listing deliberately preserves the older UTF-16 string contract,
-- including empty metadata values and unrestricted keys. Export byte validation
-- is a different consumer and must not be reused here.
CREATE FUNCTION public.zasp_audit_export_public_page_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $public_page_ready$
 SELECT COALESCE(public.zasp_production_audit_exports_readiness(expected_checksum,expected_fingerprint) AND public.zasp_discovery_principal_ready('zasp_discovery_api'),false)
$public_page_ready$;

CREATE FUNCTION public.zasp_audit_export_public_action(value text) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $action$
 SELECT COALESCE(octet_length(value) BETWEEN 1 AND 127 AND (value ~ '^[a-z][a-z0-9]*([._-][a-z0-9]+)*$' OR value IN('identity_provider.createSSOConnection','identity_provider.deleteSSOConnection','identity_provider.testSSOConnection','identity_provider.createSCIMConnection','identity_provider.deleteSCIMConnection')),false)
$action$;
CREATE FUNCTION public.zasp_audit_export_public_utf16(value text,maximum integer) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path TO pg_catalog,public AS $utf16$
DECLARE units integer:=0;position integer;
BEGIN
 IF value IS NULL OR octet_length(value)>maximum*4 THEN RETURN false;END IF;
 FOR position IN 1..char_length(value) LOOP
  units:=units+CASE WHEN ascii(substr(value,position,1))>65535 THEN 2 ELSE 1 END;
  IF units>maximum THEN RETURN false;END IF;
 END LOOP;
 RETURN true;
END $utf16$;
CREATE FUNCTION public.zasp_audit_export_public_item(event_value public.zasp_audit_export_public_source_v1,identity_count bigint) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $page_item$
DECLARE pair record;properties integer:=0;projected jsonb:='{}';
BEGIN
 IF event_value.source_valid IS DISTINCT FROM true OR identity_count IS DISTINCT FROM 1::bigint
 OR NOT COALESCE(public.zasp_valid_product_id(event_value.organization_id) AND public.zasp_valid_product_id(event_value.workspace_id) AND public.zasp_valid_product_id(event_value.environment_id) AND public.zasp_valid_product_id(event_value.id) AND public.zasp_valid_product_id(event_value.actor_id),false)
 OR NOT public.zasp_audit_export_public_action(event_value.action)
 OR NOT public.zasp_audit_export_public_utf16(event_value.target_id,128) OR event_value.target_id=''
 OR event_value.outcome IS NULL OR event_value.outcome NOT IN('succeeded','rejected')
 OR event_value.occurred_at IS NULL OR NOT isfinite(event_value.occurred_at) OR extract(year FROM event_value.occurred_at AT TIME ZONE 'UTC') NOT BETWEEN 1 AND 9999
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='public audit source unavailable';END IF;
 -- These procedural gates precede every enumeration. Logical sizing can detoast
 -- the original datum; it is not a first-allocation or total-memory guarantee.
 IF jsonb_typeof(event_value.metadata) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='public audit metadata unavailable';END IF;
 IF octet_length(event_value.metadata::text)>1048832 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='public audit metadata unavailable';END IF;
 FOR pair IN SELECT key FROM jsonb_object_keys(event_value.metadata) key LOOP
  properties:=properties+1;
  IF properties>32 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='public audit metadata unavailable';END IF;
 END LOOP;
 FOR pair IN SELECT key,value FROM jsonb_each_text(event_value.metadata) LOOP
  IF NOT public.zasp_audit_export_public_utf16(pair.value,512) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='public audit metadata unavailable';END IF;
 END LOOP;
 -- Every projected value is validated before constructing the final object.
 SELECT COALESCE(jsonb_object_agg(key,value),'{}'::jsonb) INTO projected FROM jsonb_each_text(event_value.metadata);
 RETURN jsonb_build_object('id',event_value.id,'workspace_id',event_value.workspace_id,'environment_id',event_value.environment_id,'actor_id',event_value.actor_id,'action',event_value.action,'target_id',event_value.target_id,'outcome',CASE event_value.outcome WHEN 'rejected' THEN 'denied' ELSE event_value.outcome END,'metadata',projected,'occurred_at',to_char(event_value.occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
EXCEPTION WHEN data_exception THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='public audit source unavailable';
END $page_item$;
CREATE FUNCTION public.zasp_audit_export_public_page(org_value text,workspace_value text,environment_value text,principal_value text,session_value bytea,csrf_value text,filters_value jsonb,after_time_value timestamptz,after_id_value text,limit_value integer,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $public_page$
DECLARE started timestamptz:=clock_timestamp();entry record;filter record;from_value timestamptz;to_value timestamptz;parsed timestamptz;item jsonb;item_text text;estimated bigint;budget bigint:=2050;retained integer:=0;seen integer:=0;stopped boolean:=false;items jsonb:='[]';result jsonb;
BEGIN
 IF NOT COALESCE(public.zasp_valid_product_id(org_value) AND public.zasp_valid_product_id(workspace_value) AND public.zasp_valid_product_id(environment_value) AND public.zasp_valid_product_id(principal_value),false)
 OR session_value IS NULL OR octet_length(session_value)<>32 OR session_value=decode(repeat('00',32),'hex') OR csrf_value IS NULL
 OR limit_value IS NULL OR limit_value NOT BETWEEN 1 AND 100
 OR jsonb_typeof(filters_value) IS DISTINCT FROM 'object' OR octet_length(filters_value::text)>1024
 OR (after_time_value IS NULL)<>(after_id_value IS NULL)
 OR (after_id_value IS NOT NULL AND (NOT public.zasp_valid_product_id(after_id_value) OR NOT isfinite(after_time_value) OR extract(year FROM after_time_value AT TIME ZONE 'UTC') NOT BETWEEN 1 AND 9999))
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public audit query rejected';END IF;
 FOR filter IN SELECT key,value FROM jsonb_each(filters_value) LOOP
  IF filter.key NOT IN('actor_id','action','outcome','from','to') OR jsonb_typeof(filter.value)<>'string' OR filter.value#>>'{}'='' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public audit query rejected';END IF;
  IF filter.key='actor_id' AND NOT public.zasp_valid_product_id(filter.value#>>'{}') OR filter.key='action' AND NOT public.zasp_audit_export_public_action(filter.value#>>'{}') OR filter.key='outcome' AND filter.value#>>'{}' NOT IN('succeeded','denied','failed') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public audit query rejected';END IF;
  IF filter.key IN('from','to') THEN
   BEGIN
    IF filter.value#>>'{}' !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$' THEN RAISE EXCEPTION USING ERRCODE='22023';END IF;
    parsed:=(filter.value#>>'{}')::timestamptz;
    IF NOT isfinite(parsed) OR to_char(parsed AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')<>filter.value#>>'{}' THEN RAISE EXCEPTION USING ERRCODE='22023';END IF;
   EXCEPTION WHEN data_exception THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public audit query rejected';END;
   IF filter.key='from' THEN from_value:=parsed;ELSE to_value:=parsed;END IF;
  END IF;
 END LOOP;
 IF from_value>=to_value THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public audit query rejected';END IF;
 IF NOT COALESCE(public.zasp_production_audit_exports_readiness(expected_checksum,expected_fingerprint),false) OR NOT COALESCE(public.zasp_discovery_principal_ready('zasp_discovery_api'),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='public audit authority unavailable';END IF;
 PERFORM public.zasp_audit_export_require_browser(org_value,workspace_value,environment_value,principal_value,session_value,csrf_value,false);
 -- The materialized stage contains identities only. Collision probes ignore
 -- every caller filter and keyset, and the bounded fetch shares this snapshot.
 FOR entry IN
  WITH candidates AS MATERIALIZED (
   SELECT s.id,s.occurred_at,s.source_kind FROM public.zasp_audit_export_public_source_v1 s
   WHERE s.organization_id=org_value
   AND (NOT filters_value ? 'actor_id' OR s.actor_id=filters_value->>'actor_id')
   AND (NOT filters_value ? 'action' OR s.action=filters_value->>'action')
   AND (NOT filters_value ? 'outcome' OR CASE s.outcome WHEN 'rejected' THEN 'denied' ELSE s.outcome END=filters_value->>'outcome')
   AND (from_value IS NULL OR s.occurred_at>=from_value) AND (to_value IS NULL OR s.occurred_at<to_value)
   AND (after_time_value IS NULL OR (s.occurred_at,s.id COLLATE "C")<(after_time_value,after_id_value COLLATE "C"))
   ORDER BY s.occurred_at DESC,s.id COLLATE "C" DESC LIMIT limit_value+1
  )
  SELECT fetched.source,(SELECT count(*) FROM public.zasp_audit_export_public_source_v1 collision WHERE collision.organization_id=org_value AND collision.id=c.id) AS identity_count
  FROM candidates c CROSS JOIN LATERAL (
   SELECT s AS source FROM public.zasp_audit_export_public_source_v1 s
   WHERE s.organization_id=org_value AND s.id=c.id AND s.source_kind=c.source_kind
   -- Retain the correlated fetch boundary: flattening this into a hash join
   -- constructs unselected whole-source composites before the identity match.
   OFFSET 0
  ) fetched
  ORDER BY c.occurred_at DESC,c.id COLLATE "C" DESC
 LOOP
  item:=public.zasp_audit_export_public_item(entry.source,entry.identity_count);
  seen:=seen+1;
  IF NOT stopped AND retained<limit_value THEN
   item_text:=item::text;
   estimated:=octet_length(item_text)::bigint+5::bigint*(char_length(item_text)-char_length(translate(item_text,'<>&','')))+3::bigint*(char_length(item_text)-char_length(translate(item_text,U&'\2028\2029','')));
   IF retained=0 OR budget+estimated+1<=786432 THEN items:=items||jsonb_build_array(item);retained:=retained+1;budget:=budget+estimated+1;ELSE stopped:=true;END IF;
  END IF;
  IF clock_timestamp()>started+interval '5 seconds' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='public audit page deadline exceeded';END IF;
 END LOOP;
 result:=jsonb_build_object('items',items,'has_more',seen>retained);
 IF octet_length(result::text)>1052672 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='public audit page unavailable';END IF;
 IF NOT COALESCE(public.zasp_production_audit_exports_readiness(expected_checksum,expected_fingerprint),false) OR NOT COALESCE(public.zasp_discovery_principal_ready('zasp_discovery_api'),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='public audit authority unavailable';END IF;
 PERFORM public.zasp_audit_export_require_browser(org_value,workspace_value,environment_value,principal_value,session_value,csrf_value,false);
 IF clock_timestamp()>started+interval '5 seconds' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='public audit page deadline exceeded';END IF;
 RETURN result;
END $public_page$;
CREATE FUNCTION public.zasp_audit_export_public_capture_event(ordinal_value bigint,event_value public.zasp_audit_export_public_source_v1,identity_count bigint,deadline_value timestamptz) RETURNS bytea LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $public_event$
BEGIN
 IF event_value.source_valid IS DISTINCT FROM true OR identity_count IS DISTINCT FROM 1::bigint THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public audit source rejected';END IF;
 RETURN public.zasp_audit_export_capture_event(ordinal_value,ROW(event_value.organization_id,event_value.workspace_id,event_value.environment_id,event_value.id,event_value.actor_id,event_value.action,event_value.target_id,event_value.outcome,event_value.metadata,event_value.occurred_at)::public.zasp_admin_audit,deadline_value);
END $public_event$;
CREATE FUNCTION public.zasp_audit_export_capture(org_value text,workspace_value text,environment_value text,export_value text,capture_value text,generation_value bigint,attempt_value integer,worker_value text,token_value text,policy_value text,digest_value bytea,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $capture$
DECLARE job_row public.zasp_audit_export_jobs%ROWTYPE;current_policy public.zasp_audit_export_policies%ROWTYPE;current_id text;deadline_value timestamptz;entry record;result jsonb;failure_value text;body bytea;previous_value bytea:=decode(repeat('0',64),'hex');chunk_value bigint:=1;first_value bigint:=1;count_value integer:=0;event_bytes bigint:=0;total_bytes bigint:=0;total_events bigint;planned_bytes bigint;stamp timestamptz;
BEGIN
 job_row:=public.zasp_audit_export_require_lease(org_value,workspace_value,environment_value,export_value,capture_value,generation_value,attempt_value,worker_value,token_value,policy_value,digest_value,expected_checksum,expected_fingerprint);
 IF job_row.captured THEN
  result:=public.zasp_audit_export_capture_progress(job_row);
 ELSE
  SELECT policy_id INTO STRICT current_id FROM public.zasp_audit_export_current_policy WHERE singleton FOR SHARE;
  SELECT * INTO STRICT current_policy FROM public.zasp_audit_export_policies WHERE policy_id=current_id;
  PERFORM public.zasp_audit_export_require_worker(expected_checksum,expected_fingerprint);
  deadline_value:=least(clock_timestamp()+make_interval(secs=>(job_row.storage_policy->>'capture_timeout_seconds')::integer),job_row.lease_expires_at-interval '5 seconds');
  IF deadline_value<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export capture lease margin unavailable';END IF;
  stamp:=clock_timestamp();
  BEGIN
   -- One statement snapshot, including every visible organization row. The
   -- timestamp records capture time; it is never a later source predicate.
   INSERT INTO public.zasp_audit_export_events(organization_id,workspace_id,environment_id,export_id,capture_id,ordinal,event_id,occurred_at,canonical_event)
   SELECT org_value,workspace_value,environment_value,export_value,capture_value,c.ordinal,(c.source).id,(c.source).occurred_at,public.zasp_audit_export_public_capture_event(c.ordinal,c.source,c.identity_count,deadline_value)
   FROM (SELECT a AS source,row_number() OVER(ORDER BY a.occurred_at DESC,a.id COLLATE "C" DESC) AS ordinal,count(*) OVER(PARTITION BY a.id) AS identity_count FROM public.zasp_audit_export_public_source_v1 a WHERE a.organization_id=org_value) c;
   GET DIAGNOSTICS total_events=ROW_COUNT;
   PERFORM public.zasp_audit_export_require_worker(expected_checksum,expected_fingerprint);
   IF job_row.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export capture lease expired';END IF;
   IF clock_timestamp()>=deadline_value THEN RAISE EXCEPTION USING ERRCODE='57014',MESSAGE='export capture deadline elapsed';END IF;
   FOR entry IN SELECT ordinal,octet_length(canonical_event) size_bytes FROM public.zasp_audit_export_events WHERE organization_id=org_value AND export_id=export_value ORDER BY ordinal LOOP
    IF clock_timestamp()>=deadline_value THEN RAISE EXCEPTION USING ERRCODE='57014',MESSAGE='export capture deadline elapsed';END IF;
    IF count_value>0 AND (count_value=1000 OR octet_length(public.zasp_audit_export_chunk_prefix(job_row,chunk_value,first_value,count_value+1,previous_value))+event_bytes+entry.size_bytes+count_value+2>1048576) THEN
     body:=public.zasp_audit_export_planned_chunk_bytes(job_row,chunk_value,first_value,count_value,previous_value);
     INSERT INTO public.zasp_audit_export_chunks VALUES(org_value,workspace_value,environment_value,export_value,capture_value,chunk_value,first_value,count_value,previous_value,digest(body,'sha256'),octet_length(body));
     previous_value:=digest(body,'sha256');total_bytes:=total_bytes+octet_length(body);chunk_value:=chunk_value+1;first_value:=entry.ordinal;count_value:=0;event_bytes:=0;
    END IF;
    count_value:=count_value+1;event_bytes:=event_bytes+entry.size_bytes;
   END LOOP;
   IF count_value>0 THEN
    body:=public.zasp_audit_export_planned_chunk_bytes(job_row,chunk_value,first_value,count_value,previous_value);
    INSERT INTO public.zasp_audit_export_chunks VALUES(org_value,workspace_value,environment_value,export_value,capture_value,chunk_value,first_value,count_value,previous_value,digest(body,'sha256'),octet_length(body));
    previous_value:=digest(body,'sha256');total_bytes:=total_bytes+octet_length(body);
   ELSE chunk_value:=0;END IF;
   job_row.event_count:=total_events;job_row.chunk_count:=chunk_value;job_row.chunk_bytes:=total_bytes;job_row.chain_root:=previous_value;job_row.manifest_bytes:=public.zasp_audit_export_manifest_bytes(job_row);
   planned_bytes:=total_bytes+octet_length(job_row.manifest_bytes);
   IF planned_bytes>(job_row.storage_policy->>'maximum_export_bytes')::bigint OR (SELECT COALESCE(sum(reserved_bytes),0) FROM public.zasp_audit_export_jobs WHERE organization_id=org_value)+planned_bytes>current_policy.maximum_retained_bytes OR (SELECT count(*) FROM public.zasp_audit_export_jobs WHERE organization_id=org_value AND status IN('queued','processing'))>current_policy.maximum_inflight THEN RAISE EXCEPTION USING ERRCODE='P5201',MESSAGE='export capacity exceeded';END IF;
   UPDATE public.zasp_audit_export_jobs SET captured=true,captured_at=stamp,event_count=job_row.event_count,chunk_count=job_row.chunk_count,chunk_bytes=job_row.chunk_bytes,chain_root=job_row.chain_root,manifest_bytes=job_row.manifest_bytes,reserved_bytes=planned_bytes WHERE organization_id=org_value AND id=export_value RETURNING * INTO job_row;
   PERFORM public.zasp_audit_export_require_worker(expected_checksum,expected_fingerprint);
   IF job_row.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export capture lease expired';END IF;
   IF clock_timestamp()>=deadline_value THEN RAISE EXCEPTION USING ERRCODE='57014',MESSAGE='export capture deadline elapsed';END IF;
  EXCEPTION WHEN SQLSTATE 'P5201' THEN failure_value:='capacity_exceeded';WHEN invalid_parameter_value THEN failure_value:='invalid_source';
  END;
  IF failure_value IS NOT NULL THEN
   SELECT * INTO STRICT job_row FROM public.zasp_audit_export_jobs WHERE organization_id=org_value AND id=export_value;
   PERFORM public.zasp_audit_export_require_worker(expected_checksum,expected_fingerprint);
   IF job_row.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export capture lease expired';END IF;
   IF clock_timestamp()>=deadline_value THEN RAISE EXCEPTION USING ERRCODE='57014',MESSAGE='export capture deadline elapsed';END IF;
   job_row:=public.zasp_audit_export_fail(job_row,failure_value);result:=jsonb_build_object('state','failed','failure_code',failure_value);
  ELSE result:=public.zasp_audit_export_capture_progress(job_row);END IF;
 END IF;
 PERFORM public.zasp_audit_export_require_worker(expected_checksum,expected_fingerprint);
 IF job_row.status='processing' AND job_row.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export capture lease expired';END IF;
 IF deadline_value IS NOT NULL AND clock_timestamp()>=deadline_value THEN RAISE EXCEPTION USING ERRCODE='57014',MESSAGE='export capture deadline elapsed';END IF;
 RETURN result;
END $capture$;
CREATE FUNCTION public.zasp_audit_export_frozen_page(org_value text,workspace_value text,environment_value text,export_value text,capture_value text,generation_value bigint,attempt_value integer,worker_value text,token_value text,policy_value text,digest_value bytea,expected_checksum text,expected_fingerprint text,next_value bigint) RETURNS json LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $page$
DECLARE job_row public.zasp_audit_export_jobs%ROWTYPE;plan public.zasp_audit_export_chunks%ROWTYPE;body bytea;payload text;following text;
BEGIN
 job_row:=public.zasp_audit_export_require_lease(org_value,workspace_value,environment_value,export_value,capture_value,generation_value,attempt_value,worker_value,token_value,policy_value,digest_value,expected_checksum,expected_fingerprint);
 IF NOT job_row.captured OR next_value IS NULL OR next_value NOT BETWEEN 1 AND job_row.event_count THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export frozen cursor rejected';END IF;
 SELECT * INTO plan FROM public.zasp_audit_export_chunks WHERE organization_id=org_value AND export_id=export_value AND capture_id=capture_value AND first_event=next_value;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export frozen cursor rejected';END IF;
 body:=public.zasp_audit_export_planned_chunk_bytes(job_row,plan.ordinal,plan.first_event,plan.event_count,plan.previous_digest);
 IF digest(body,'sha256')<>plan.sha256 OR octet_length(body)<>plan.size_bytes THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export frozen bytes rejected';END IF;
 following:=CASE WHEN plan.first_event+plan.event_count>job_row.event_count THEN 'null' ELSE (plan.first_event+plan.event_count)::text END;
 payload:=substring(convert_from(body,'UTF8') FROM length('{"schema":"audit-export-chunk-v1",')+1);
 payload:='{'||left(payload,length(payload)-1)||',"next_event":'||following||'}';
 IF octet_length(payload)>1048576 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export frozen page bound rejected';END IF;
 PERFORM public.zasp_audit_export_require_worker(expected_checksum,expected_fingerprint);
 IF job_row.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export frozen lease expired';END IF;
 RETURN payload::json;
END $page$;

CREATE FUNCTION public.zasp_audit_export_artifact_id(job_value public.zasp_audit_export_jobs,kind_value text,ordinal_value bigint) RETURNS text LANGUAGE sql IMMUTABLE STRICT SET search_path TO pg_catalog,public AS $artifact_id$
 SELECT 'pid_'||substr(value,1,8)||'-'||substr(value,9,4)||'-4'||substr(value,14,3)||'-8'||substr(value,18,3)||'-'||substr(value,21,12)
 FROM (SELECT encode(digest(convert_to(job_value.id,'UTF8')||decode('00','hex')||convert_to(job_value.capture_id,'UTF8')||decode('00','hex')||convert_to('audit-export-'||kind_value||':'||ordinal_value::text,'UTF8'),'sha256'),'hex') value) identity
$artifact_id$;
CREATE FUNCTION public.zasp_audit_export_prepare_chunk(org_value text,workspace_value text,environment_value text,export_value text,capture_value text,generation_value bigint,attempt_value integer,worker_value text,token_value text,policy_value text,digest_value bytea,expected_checksum text,expected_fingerprint text,bytes_value bytea) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $prepare_chunk$
DECLARE job_row public.zasp_audit_export_jobs%ROWTYPE;plan public.zasp_audit_export_chunks%ROWTYPE;intent public.zasp_audit_export_intents%ROWTYPE;ordinal_value bigint;artifact_value text;reference_value text;result jsonb;
BEGIN
 job_row:=public.zasp_audit_export_require_lease(org_value,workspace_value,environment_value,export_value,capture_value,generation_value,attempt_value,worker_value,token_value,policy_value,digest_value,expected_checksum,expected_fingerprint);
 IF NOT job_row.captured OR bytes_value IS NULL OR octet_length(bytes_value) NOT BETWEEN 1 AND 1048576 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export chunk bytes rejected';END IF;
 BEGIN ordinal_value:=(convert_from(bytes_value,'UTF8')::jsonb->>'ordinal')::bigint;
 EXCEPTION WHEN data_exception THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export chunk encoding rejected';END;
 SELECT * INTO plan FROM public.zasp_audit_export_chunks WHERE organization_id=org_value AND export_id=export_value AND capture_id=capture_value AND ordinal=ordinal_value;
 IF NOT FOUND OR octet_length(bytes_value)<>plan.size_bytes OR digest(bytes_value,'sha256')<>plan.sha256 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export chunk plan rejected';END IF;
 IF bytes_value IS DISTINCT FROM public.zasp_audit_export_planned_chunk_bytes(job_row,plan.ordinal,plan.first_event,plan.event_count,plan.previous_digest) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export chunk source rejected';END IF;
 artifact_value:=public.zasp_audit_export_artifact_id(job_row,'chunk',ordinal_value);
 reference_value:='s3://'||(job_row.storage_policy->>'bucket')||'/organizations/'||org_value||'/workspaces/'||workspace_value||'/environments/'||environment_value||'/exports/'||artifact_value;
 INSERT INTO public.zasp_audit_export_intents VALUES(org_value,workspace_value,environment_value,export_value,capture_value,'chunk',ordinal_value,artifact_value,reference_value,plan.sha256,plan.size_bytes) ON CONFLICT(organization_id,export_id,kind,ordinal) DO NOTHING;
 SELECT * INTO STRICT intent FROM public.zasp_audit_export_intents WHERE organization_id=org_value AND export_id=export_value AND kind='chunk' AND ordinal=ordinal_value;
 IF (intent.workspace_id,intent.environment_id,intent.capture_id,intent.artifact_id,intent.object_reference,intent.sha256,intent.size_bytes) IS DISTINCT FROM (workspace_value,environment_value,capture_value,artifact_value,reference_value,plan.sha256,plan.size_bytes) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export intent authority rejected';END IF;
 result:=jsonb_build_object('binding',public.zasp_audit_export_binding_bytes(job_row)::jsonb,'storage_policy',job_row.storage_policy,'kind','chunk','ordinal',ordinal_value,'first_event',plan.first_event,'event_count',plan.event_count,'previous_digest',encode(plan.previous_digest,'hex'),'artifact_id',intent.artifact_id,'object_reference',intent.object_reference,'sha256',encode(intent.sha256,'hex'),'size_bytes',intent.size_bytes);
 PERFORM public.zasp_audit_export_require_worker(expected_checksum,expected_fingerprint);
 IF job_row.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export prepare lease expired';END IF;
 RETURN result;
END $prepare_chunk$;

CREATE FUNCTION public.zasp_audit_export_record_chunk(org_value text,workspace_value text,environment_value text,export_value text,capture_value text,generation_value bigint,attempt_value integer,worker_value text,token_value text,policy_value text,digest_value bytea,expected_checksum text,expected_fingerprint text,ordinal_value bigint,version_value text,sha_value bytea,size_value bigint) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $record_chunk$
DECLARE job_row public.zasp_audit_export_jobs%ROWTYPE;intent public.zasp_audit_export_intents%ROWTYPE;receipt public.zasp_audit_export_receipts%ROWTYPE;prefix jsonb;
BEGIN
 job_row:=public.zasp_audit_export_require_lease(org_value,workspace_value,environment_value,export_value,capture_value,generation_value,attempt_value,worker_value,token_value,policy_value,digest_value,expected_checksum,expected_fingerprint);
 IF NOT COALESCE(job_row.captured AND ordinal_value BETWEEN 1 AND 9007199254740991 AND octet_length(version_value) BETWEEN 1 AND 1024 AND version_value<>'null' AND version_value COLLATE "C" ~ '^[!-~]+$' AND octet_length(sha_value)=32 AND size_value BETWEEN 1 AND 1048576,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export receipt rejected';END IF;
 SELECT * INTO intent FROM public.zasp_audit_export_intents WHERE organization_id=org_value AND export_id=export_value AND kind='chunk' AND ordinal=ordinal_value;
 IF NOT FOUND OR (intent.workspace_id,intent.environment_id,intent.capture_id) IS DISTINCT FROM (workspace_value,environment_value,capture_value) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export intent missing';END IF;
 IF (intent.sha256,intent.size_bytes) IS DISTINCT FROM (sha_value,size_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export receipt does not match intent';END IF;
 prefix:=public.zasp_audit_export_recorded_prefix(job_row);
 IF ordinal_value>(prefix->>'next_chunk')::bigint THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export receipt gap rejected';END IF;
 INSERT INTO public.zasp_audit_export_receipts VALUES(org_value,export_value,'chunk',ordinal_value,version_value,sha_value,size_value) ON CONFLICT(organization_id,export_id,kind,ordinal) DO NOTHING;
 SELECT * INTO STRICT receipt FROM public.zasp_audit_export_receipts WHERE organization_id=org_value AND export_id=export_value AND kind='chunk' AND ordinal=ordinal_value;
 IF (receipt.version_id,receipt.sha256,receipt.size_bytes) IS DISTINCT FROM (version_value,sha_value,size_value) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='export receipt replay changed';END IF;
 PERFORM public.zasp_audit_export_recorded_prefix(job_row);
 PERFORM public.zasp_audit_export_require_worker(expected_checksum,expected_fingerprint);
 IF job_row.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export record lease expired';END IF;
 RETURN jsonb_build_object('recorded',true);
END $record_chunk$;

CREATE FUNCTION public.zasp_audit_export_require_complete_chunks(job_value public.zasp_audit_export_jobs) RETURNS void LANGUAGE plpgsql STABLE SET search_path TO pg_catalog,public AS $complete_chunks$
DECLARE progress jsonb;
BEGIN
 progress:=public.zasp_audit_export_capture_progress(job_value);
 IF (progress->>'recorded_chunk_count')::bigint<>job_value.chunk_count OR (progress->>'recorded_chunk_bytes')::bigint<>job_value.chunk_bytes OR (progress->>'next_event')::bigint<>job_value.event_count+1 OR progress->>'previous_digest'<>encode(job_value.chain_root,'hex') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export complete receipt coverage required';END IF;
 IF job_value.manifest_bytes IS DISTINCT FROM public.zasp_audit_export_manifest_bytes(job_value) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export manifest authority rejected';END IF;
END $complete_chunks$;

CREATE FUNCTION public.zasp_audit_export_prepare_manifest(org_value text,workspace_value text,environment_value text,export_value text,capture_value text,generation_value bigint,attempt_value integer,worker_value text,token_value text,policy_value text,digest_value bytea,expected_checksum text,expected_fingerprint text,bytes_value bytea) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $prepare_manifest$
DECLARE job_row public.zasp_audit_export_jobs%ROWTYPE;intent public.zasp_audit_export_intents%ROWTYPE;artifact_value text;reference_value text;sha_value bytea;size_value bigint;result jsonb;
BEGIN
 job_row:=public.zasp_audit_export_require_lease(org_value,workspace_value,environment_value,export_value,capture_value,generation_value,attempt_value,worker_value,token_value,policy_value,digest_value,expected_checksum,expected_fingerprint);
 IF NOT job_row.captured OR bytes_value IS NULL OR octet_length(bytes_value) NOT BETWEEN 1 AND 2048 OR bytes_value IS DISTINCT FROM job_row.manifest_bytes THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export manifest bytes rejected';END IF;
 PERFORM public.zasp_audit_export_require_complete_chunks(job_row);
 artifact_value:=public.zasp_audit_export_artifact_id(job_row,'manifest',0);
 reference_value:='s3://'||(job_row.storage_policy->>'bucket')||'/organizations/'||org_value||'/workspaces/'||workspace_value||'/environments/'||environment_value||'/exports/'||artifact_value;
 sha_value:=digest(bytes_value,'sha256');size_value:=octet_length(bytes_value);
 INSERT INTO public.zasp_audit_export_intents VALUES(org_value,workspace_value,environment_value,export_value,capture_value,'manifest',0,artifact_value,reference_value,sha_value,size_value) ON CONFLICT(organization_id,export_id,kind,ordinal) DO NOTHING;
 SELECT * INTO STRICT intent FROM public.zasp_audit_export_intents WHERE organization_id=org_value AND export_id=export_value AND kind='manifest' AND ordinal=0;
 IF (intent.workspace_id,intent.environment_id,intent.capture_id,intent.artifact_id,intent.object_reference,intent.sha256,intent.size_bytes) IS DISTINCT FROM (workspace_value,environment_value,capture_value,artifact_value,reference_value,sha_value,size_value) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export manifest intent authority rejected';END IF;
 result:=jsonb_build_object('binding',public.zasp_audit_export_binding_bytes(job_row)::jsonb,'storage_policy',job_row.storage_policy,'kind','manifest','artifact_id',intent.artifact_id,'object_reference',intent.object_reference,'sha256',encode(intent.sha256,'hex'),'size_bytes',intent.size_bytes);
 PERFORM public.zasp_audit_export_require_worker(expected_checksum,expected_fingerprint);
 IF job_row.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export manifest lease expired';END IF;
 RETURN result;
END $prepare_manifest$;

CREATE FUNCTION public.zasp_audit_export_require_ready_receipt(job_value public.zasp_audit_export_jobs) RETURNS void LANGUAGE plpgsql STABLE SET search_path TO pg_catalog,public AS $ready_receipt$
DECLARE intent public.zasp_audit_export_intents%ROWTYPE;receipt public.zasp_audit_export_receipts%ROWTYPE;artifact_value text;reference_value text;
BEGIN
 IF NOT COALESCE(job_value.status='ready' AND job_value.captured AND job_value.completion_audit_id IS NOT NULL AND job_value.completed_at>=job_value.captured_at AND job_value.completion_worker IS NOT NULL AND octet_length(job_value.completion_token_digest)=32 AND job_value.lease_worker IS NULL,false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export ready authority unavailable';END IF;
 PERFORM public.zasp_audit_export_check_job(job_value,job_value.policy_id,decode(job_value.storage_policy->>'policy_digest','hex'));
 PERFORM public.zasp_audit_export_require_complete_chunks(job_value);
 SELECT * INTO intent FROM public.zasp_audit_export_intents WHERE organization_id=job_value.organization_id AND export_id=job_value.id AND kind='manifest' AND ordinal=0;
 SELECT * INTO receipt FROM public.zasp_audit_export_receipts WHERE organization_id=job_value.organization_id AND export_id=job_value.id AND kind='manifest' AND ordinal=0;
 artifact_value:=public.zasp_audit_export_artifact_id(job_value,'manifest',0);
 reference_value:='s3://'||(job_value.storage_policy->>'bucket')||'/organizations/'||job_value.organization_id||'/workspaces/'||job_value.workspace_id||'/environments/'||job_value.environment_id||'/exports/'||artifact_value;
 IF NOT COALESCE((intent.workspace_id,intent.environment_id,intent.capture_id,intent.artifact_id,intent.object_reference,intent.sha256,intent.size_bytes,receipt.sha256,receipt.size_bytes)=(job_value.workspace_id,job_value.environment_id,job_value.capture_id,artifact_value,reference_value,digest(job_value.manifest_bytes,'sha256'),octet_length(job_value.manifest_bytes),digest(job_value.manifest_bytes,'sha256'),octet_length(job_value.manifest_bytes)) AND receipt.version_id IS NOT NULL,false) OR job_value.reserved_bytes IS DISTINCT FROM (SELECT COALESCE(sum(size_bytes),0) FROM public.zasp_audit_export_intents WHERE organization_id=job_value.organization_id AND export_id=job_value.id AND capture_id=job_value.capture_id) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export final receipt rejected';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.zasp_admin_audit a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.id,a.actor_id,a.action,a.target_id,a.outcome,a.occurred_at)=(job_value.organization_id,job_value.workspace_id,job_value.environment_id,job_value.completion_audit_id,job_value.principal_id,'audit_export.complete',job_value.id,'succeeded',job_value.completed_at) AND a.metadata=jsonb_build_object('event_count',job_value.event_count,'chunk_count',job_value.chunk_count,'chunk_bytes',job_value.chunk_bytes,'manifest_sha256',encode(receipt.sha256,'hex'))) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export completion audit unavailable';END IF;
END $ready_receipt$;

CREATE FUNCTION public.zasp_audit_export_read_authority(job_value public.zasp_audit_export_jobs,ordinal_value bigint,manifest_value bytea) RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path TO pg_catalog,public AS $read_authority$
DECLARE manifest jsonb;chunk jsonb:='null'::jsonb;
BEGIN
 PERFORM public.zasp_audit_export_require_ready_receipt(job_value);
 IF NOT COALESCE(ordinal_value BETWEEN 1 AND greatest(job_value.chunk_count,1),false) OR (manifest_value IS NOT NULL AND manifest_value IS DISTINCT FROM digest(job_value.manifest_bytes,'sha256')) OR (ordinal_value>1 AND manifest_value IS NULL) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export ready cursor rejected';END IF;
 SELECT jsonb_build_object('artifact_id',i.artifact_id,'object_reference',i.object_reference,'version_id',r.version_id,'sha256',encode(r.sha256,'hex'),'size_bytes',r.size_bytes) INTO STRICT manifest FROM public.zasp_audit_export_intents i JOIN public.zasp_audit_export_receipts r USING(organization_id,export_id,kind,ordinal) WHERE i.organization_id=job_value.organization_id AND i.export_id=job_value.id AND i.kind='manifest' AND i.ordinal=0;
 IF job_value.chunk_count>0 THEN
  SELECT jsonb_build_object('artifact_id',i.artifact_id,'object_reference',i.object_reference,'version_id',r.version_id,'sha256',encode(r.sha256,'hex'),'size_bytes',r.size_bytes,'ordinal',c.ordinal,'first_event',c.first_event,'event_count',c.event_count,'previous_digest',encode(c.previous_digest,'hex')) INTO STRICT chunk FROM public.zasp_audit_export_intents i JOIN public.zasp_audit_export_receipts r USING(organization_id,export_id,kind,ordinal) JOIN public.zasp_audit_export_chunks c ON (c.organization_id,c.export_id,c.ordinal)=(r.organization_id,r.export_id,r.ordinal) WHERE i.organization_id=job_value.organization_id AND i.export_id=job_value.id AND i.kind='chunk' AND i.ordinal=ordinal_value;
 END IF;
 RETURN jsonb_build_object('binding',public.zasp_audit_export_binding_bytes(job_value)::jsonb,'storage_policy',job_value.storage_policy,'manifest',manifest,'chunk',chunk);
END $read_authority$;

CREATE FUNCTION public.zasp_audit_export_finish(org_value text,workspace_value text,environment_value text,export_value text,capture_value text,generation_value bigint,attempt_value integer,worker_value text,token_value text,policy_value text,digest_value bytea,expected_checksum text,expected_fingerprint text,version_value text,sha_value bytea,size_value bigint,audit_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $finish$
DECLARE job_row public.zasp_audit_export_jobs%ROWTYPE;intent public.zasp_audit_export_intents%ROWTYPE;receipt public.zasp_audit_export_receipts%ROWTYPE;result jsonb;prior_expiry timestamptz;stamp timestamptz;
BEGIN
 job_row:=public.zasp_audit_export_lock_job(org_value,workspace_value,environment_value,export_value,policy_value,digest_value,expected_checksum,expected_fingerprint);
 IF NOT COALESCE(octet_length(version_value) BETWEEN 1 AND 1024 AND version_value<>'null' AND version_value COLLATE "C" ~ '^[!-~]+$' AND octet_length(sha_value)=32 AND size_value BETWEEN 1 AND 2048 AND public.zasp_valid_product_id(audit_value) AND audit_value NOT IN(org_value,workspace_value,environment_value,export_value,capture_value,job_row.principal_id,job_row.audit_id),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export final receipt rejected';END IF;
 IF job_row.status='ready' THEN
  IF NOT COALESCE((job_row.capture_id,job_row.generation,job_row.attempt,job_row.completion_worker)=(capture_value,generation_value,attempt_value,worker_value) AND token_value ~ '^[0-9a-f]{64}$' AND token_value<>repeat('0',64) AND job_row.completion_token_digest=digest(convert_to(token_value,'UTF8'),'sha256'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export completion lease rejected';END IF;
  SELECT * INTO receipt FROM public.zasp_audit_export_receipts WHERE organization_id=org_value AND export_id=export_value AND kind='manifest' AND ordinal=0;
  IF (receipt.version_id,receipt.sha256,receipt.size_bytes,job_row.completion_audit_id) IS DISTINCT FROM (version_value,sha_value,size_value,audit_value) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='export completion replay changed';END IF;
 ELSE
  job_row:=public.zasp_audit_export_require_lease(org_value,workspace_value,environment_value,export_value,capture_value,generation_value,attempt_value,worker_value,token_value,policy_value,digest_value,expected_checksum,expected_fingerprint);
  prior_expiry:=job_row.lease_expires_at;
  PERFORM public.zasp_audit_export_require_complete_chunks(job_row);
  SELECT * INTO intent FROM public.zasp_audit_export_intents WHERE organization_id=org_value AND export_id=export_value AND kind='manifest' AND ordinal=0;
  IF NOT FOUND OR (intent.workspace_id,intent.environment_id,intent.capture_id) IS DISTINCT FROM (workspace_value,environment_value,capture_value) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export manifest intent missing';END IF;
  IF (intent.sha256,intent.size_bytes) IS DISTINCT FROM (sha_value,size_value) OR intent.sha256<>digest(job_row.manifest_bytes,'sha256') OR intent.size_bytes<>octet_length(job_row.manifest_bytes) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export final receipt does not match intent';END IF;
  INSERT INTO public.zasp_audit_export_receipts VALUES(org_value,export_value,'manifest',0,version_value,sha_value,size_value);
  stamp:=clock_timestamp();
  UPDATE public.zasp_audit_export_jobs SET status='ready',completion_audit_id=audit_value,completed_at=stamp,completion_worker=worker_value,completion_token_digest=lease_token_digest,lease_worker=NULL,lease_token_digest=NULL,lease_expires_at=NULL WHERE organization_id=org_value AND id=export_value RETURNING * INTO STRICT job_row;
  INSERT INTO public.zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) VALUES(org_value,workspace_value,environment_value,audit_value,job_row.principal_id,'audit_export.complete',export_value,'succeeded',jsonb_build_object('event_count',job_row.event_count,'chunk_count',job_row.chunk_count,'chunk_bytes',job_row.chunk_bytes,'manifest_sha256',encode(sha_value,'hex')),stamp);
 END IF;
 result:=public.zasp_audit_export_descriptor(job_row);
 PERFORM public.zasp_audit_export_require_worker(expected_checksum,expected_fingerprint);
 IF prior_expiry IS NOT NULL AND prior_expiry<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export finish lease expired';END IF;
 RETURN result;
END $finish$;

CREATE FUNCTION public.zasp_audit_export_retry(org_value text,workspace_value text,environment_value text,export_value text,capture_value text,generation_value bigint,attempt_value integer,worker_value text,token_value text,policy_value text,digest_value bytea,expected_checksum text,expected_fingerprint text,seconds_value integer,code_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $retry$
DECLARE job_row public.zasp_audit_export_jobs%ROWTYPE;receipt public.zasp_audit_export_retries%ROWTYPE;prior_expiry timestamptz;result jsonb;
BEGIN
 job_row:=public.zasp_audit_export_lock_job(org_value,workspace_value,environment_value,export_value,policy_value,digest_value,expected_checksum,expected_fingerprint);
 IF NOT COALESCE(seconds_value BETWEEN 0 AND 300 AND code_value='execution_failed',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export retry rejected';END IF;
 IF NOT COALESCE((job_row.capture_id,job_row.generation,job_row.attempt)=(capture_value,generation_value,attempt_value) AND token_value ~ '^[0-9a-f]{64}$' AND token_value<>repeat('0',64),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export retry lease rejected';END IF;
 SELECT * INTO receipt FROM public.zasp_audit_export_retries WHERE organization_id=org_value AND export_id=export_value AND generation=generation_value;
 IF FOUND THEN
  IF (receipt.workspace_id,receipt.environment_id,receipt.capture_id,receipt.attempt,receipt.worker_name,receipt.token_digest) IS DISTINCT FROM (workspace_value,environment_value,capture_value,attempt_value,worker_value,digest(convert_to(token_value,'UTF8'),'sha256')) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export retry replay lease rejected';END IF;
  IF receipt.retry_seconds<>seconds_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='export retry replay changed';END IF;
 ELSE
  job_row:=public.zasp_audit_export_require_lease(org_value,workspace_value,environment_value,export_value,capture_value,generation_value,attempt_value,worker_value,token_value,policy_value,digest_value,expected_checksum,expected_fingerprint);
  prior_expiry:=job_row.lease_expires_at;
  IF seconds_value=0 OR job_row.attempt>=5 THEN
   job_row:=public.zasp_audit_export_fail(job_row,'execution_failed');
  ELSE
   UPDATE public.zasp_audit_export_jobs SET available_at=clock_timestamp()+make_interval(secs=>seconds_value),lease_worker=NULL,lease_token_digest=NULL,lease_expires_at=NULL WHERE organization_id=org_value AND id=export_value RETURNING * INTO STRICT job_row;
  END IF;
  INSERT INTO public.zasp_audit_export_retries VALUES(org_value,workspace_value,environment_value,export_value,capture_value,generation_value,attempt_value,worker_value,digest(convert_to(token_value,'UTF8'),'sha256'),seconds_value,CASE WHEN job_row.status='failed' THEN 'failed' ELSE 'retry' END,CASE WHEN job_row.status='failed' THEN NULL ELSE job_row.available_at END,job_row.completion_audit_id) RETURNING * INTO receipt;
 END IF;
 IF receipt.state='failed' THEN
  IF job_row.completion_audit_id IS DISTINCT FROM receipt.completion_audit_id OR job_row.failure_code IS DISTINCT FROM 'execution_failed' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export retry failure authority rejected';END IF;
  PERFORM public.zasp_audit_export_require_failure(job_row);
 ELSE
  IF job_row.status<>'processing' OR job_row.lease_worker IS NOT NULL OR job_row.available_at IS DISTINCT FROM receipt.available_at THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export retry availability authority rejected';END IF;
 END IF;
 result:=jsonb_build_object('state',receipt.state,'failure_code',CASE WHEN receipt.state='failed' THEN 'execution_failed' ELSE NULL END,'available_at',CASE WHEN receipt.available_at IS NULL THEN NULL ELSE to_char(receipt.available_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END);
 PERFORM public.zasp_audit_export_require_worker(expected_checksum,expected_fingerprint);
 IF prior_expiry IS NOT NULL AND prior_expiry<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export retry lease expired';END IF;
 RETURN result;
END $retry$;

CREATE FUNCTION public.zasp_audit_export_outbox_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $outbox_guard$
BEGIN
 PERFORM public.zasp_audit_exports_require_ready();
 IF TG_OP='DELETE' OR (TG_OP='UPDATE' AND ((NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.id,NEW.export_id,NEW.topic) IS DISTINCT FROM (OLD.organization_id,OLD.workspace_id,OLD.environment_id,OLD.id,OLD.export_id,OLD.topic) OR OLD.state='published' AND NEW IS DISTINCT FROM OLD)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export outbox authority is immutable';END IF;
 RETURN NEW;
END $outbox_guard$;
CREATE TRIGGER zasp_audit_export_outbox_guard BEFORE INSERT OR UPDATE OR DELETE ON public.zasp_audit_export_outbox FOR EACH ROW EXECUTE FUNCTION public.zasp_audit_export_outbox_guard();

CREATE FUNCTION public.zasp_audit_export_require_outbox(expected_checksum text,expected_fingerprint text) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $outbox_ready$
BEGIN
 IF NOT COALESCE(public.zasp_production_audit_exports_readiness(expected_checksum,expected_fingerprint),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export release unavailable';END IF;
 IF NOT COALESCE(public.zasp_audit_export_worker_readiness(expected_checksum,expected_fingerprint,'zasp_audit_export_outbox'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export outbox authority rejected';END IF;
END $outbox_ready$;
CREATE FUNCTION public.zasp_audit_export_claim_outbox(worker_value text,token_value text,seconds_value integer,limit_value integer,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $outbox_claim$
DECLARE item public.zasp_audit_export_outbox%ROWTYPE;policy_value text;result jsonb:='[]'::jsonb;token_digest bytea;
BEGIN
 PERFORM public.zasp_audit_export_require_outbox(expected_checksum,expected_fingerprint);
 IF NOT COALESCE(worker_value ~ '^[a-z][a-z0-9.-]{2,127}$' AND token_value ~ '^[0-9a-f]{64}$' AND token_value<>repeat('0',64) AND seconds_value BETWEEN 60 AND 300 AND limit_value BETWEEN 1 AND 10,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export outbox claim rejected';END IF;
 token_digest:=digest(convert_to(token_value,'UTF8'),'sha256');
 FOR item IN SELECT o.* FROM public.zasp_audit_export_outbox o WHERE (o.state='leased' AND o.lease_expires_at>clock_timestamp() AND o.lease_worker=worker_value AND o.lease_token_digest=token_digest) OR (o.state='pending' AND o.available_at<=clock_timestamp()) OR (o.state='leased' AND o.lease_expires_at<=clock_timestamp()) ORDER BY CASE WHEN o.state='leased' AND o.lease_expires_at>clock_timestamp() AND o.lease_worker=worker_value AND o.lease_token_digest=token_digest THEN 0 ELSE 1 END,o.available_at,o.id COLLATE "C" LIMIT limit_value FOR UPDATE SKIP LOCKED LOOP
  PERFORM public.zasp_audit_export_require_outbox(expected_checksum,expected_fingerprint);
  IF item.state='leased' AND item.lease_expires_at>clock_timestamp() THEN
   IF item.lease_seconds<>seconds_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='export outbox claim replay changed';END IF;
  ELSE
   IF item.generation>=9007199254740991 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export outbox generation unavailable';END IF;
   -- Publication has no lifetime exhaustion. Attempts are diagnostic; only
   -- monotonically advancing generation grants fresh mutation authority.
   UPDATE public.zasp_audit_export_outbox SET state='leased',generation=generation+1,attempt=least(attempt+1,100),lease_worker=worker_value,lease_token_digest=token_digest,lease_expires_at=clock_timestamp()+make_interval(secs=>seconds_value),lease_seconds=seconds_value,retry_seconds=NULL WHERE organization_id=item.organization_id AND id=item.id RETURNING * INTO item;
  END IF;
  SELECT policy_id INTO STRICT policy_value FROM public.zasp_audit_export_jobs WHERE organization_id=item.organization_id AND id=item.export_id;
  result:=result||jsonb_build_array(jsonb_build_object('organization_id',item.organization_id,'workspace_id',item.workspace_id,'environment_id',item.environment_id,'outbox_id',item.id,'export_id',item.export_id,'policy_id',policy_value,'generation',item.generation,'attempt',item.attempt,'lease_expires_at',to_char(item.lease_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')));
 END LOOP;
 PERFORM public.zasp_audit_export_require_outbox(expected_checksum,expected_fingerprint);
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(result) lease WHERE (lease->>'lease_expires_at')::timestamptz<=clock_timestamp()) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export outbox claim expired';END IF;
 RETURN result;
END $outbox_claim$;

CREATE FUNCTION public.zasp_audit_export_lock_outbox(org_value text,workspace_value text,environment_value text,outbox_value text,worker_value text,token_value text,generation_value bigint,attempt_value integer,expected_checksum text,expected_fingerprint text) RETURNS public.zasp_audit_export_outbox LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $outbox_lock$
DECLARE result public.zasp_audit_export_outbox%ROWTYPE;
BEGIN
 PERFORM public.zasp_audit_export_require_outbox(expected_checksum,expected_fingerprint);
 IF EXISTS(SELECT 1 FROM unnest(ARRAY[org_value,workspace_value,environment_value,outbox_value]) value WHERE NOT COALESCE(public.zasp_valid_product_id(value),false)) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export outbox scope rejected';END IF;
 SELECT * INTO result FROM public.zasp_audit_export_outbox WHERE (organization_id,workspace_id,environment_id,id)=(org_value,workspace_value,environment_value,outbox_value) FOR UPDATE;
 PERFORM public.zasp_audit_export_require_outbox(expected_checksum,expected_fingerprint);
 IF result.id IS NULL THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='export outbox not found';END IF;
 IF NOT COALESCE((result.generation,result.attempt,result.lease_worker)=(generation_value,attempt_value,worker_value) AND token_value ~ '^[0-9a-f]{64}$' AND token_value<>repeat('0',64) AND result.lease_token_digest=digest(convert_to(token_value,'UTF8'),'sha256'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export outbox lease rejected';END IF;
 RETURN result;
END $outbox_lock$;

CREATE FUNCTION public.zasp_audit_export_finish_outbox(org_value text,workspace_value text,environment_value text,outbox_value text,worker_value text,token_value text,generation_value bigint,attempt_value integer,ack_value text,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $outbox_finish$
DECLARE item public.zasp_audit_export_outbox%ROWTYPE;prior_expiry timestamptz;
BEGIN
 item:=public.zasp_audit_export_lock_outbox(org_value,workspace_value,environment_value,outbox_value,worker_value,token_value,generation_value,attempt_value,expected_checksum,expected_fingerprint);
 IF NOT COALESCE(ack_value ~ '^sha256:[0-9a-f]{64}$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export publish acknowledgement rejected';END IF;
 IF item.state='published' THEN
  IF item.provider_message_id IS DISTINCT FROM ack_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='export publish replay changed';END IF;
 ELSE
  IF item.state<>'leased' OR item.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export publish lease expired';END IF;
  prior_expiry:=item.lease_expires_at;
  UPDATE public.zasp_audit_export_outbox SET state='published',provider_message_id=ack_value WHERE organization_id=org_value AND id=outbox_value;
 END IF;
 PERFORM public.zasp_audit_export_require_outbox(expected_checksum,expected_fingerprint);
 IF prior_expiry IS NOT NULL AND prior_expiry<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export publish lease expired';END IF;
 RETURN jsonb_build_object('finished',true);
END $outbox_finish$;

CREATE FUNCTION public.zasp_audit_export_retry_outbox(org_value text,workspace_value text,environment_value text,outbox_value text,worker_value text,token_value text,generation_value bigint,attempt_value integer,seconds_value integer,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $outbox_retry$
DECLARE item public.zasp_audit_export_outbox%ROWTYPE;prior_expiry timestamptz;
BEGIN
 item:=public.zasp_audit_export_lock_outbox(org_value,workspace_value,environment_value,outbox_value,worker_value,token_value,generation_value,attempt_value,expected_checksum,expected_fingerprint);
 IF NOT COALESCE(seconds_value BETWEEN 1 AND 300,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export publish retry rejected';END IF;
 IF item.state='pending' AND item.retry_seconds IS NOT NULL THEN
  IF item.retry_seconds<>seconds_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='export publish retry replay changed';END IF;
 ELSE
  IF item.state<>'leased' OR item.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export publish retry lease expired';END IF;
  prior_expiry:=item.lease_expires_at;
  UPDATE public.zasp_audit_export_outbox SET state='pending',retry_seconds=seconds_value,available_at=clock_timestamp()+make_interval(secs=>seconds_value) WHERE organization_id=org_value AND id=outbox_value;
 END IF;
 PERFORM public.zasp_audit_export_require_outbox(expected_checksum,expected_fingerprint);
 IF prior_expiry IS NOT NULL AND prior_expiry<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export publish retry lease expired';END IF;
 RETURN jsonb_build_object('retried',true);
END $outbox_retry$;

DO $export_functions$
DECLARE item record;
BEGIN
 FOR item IN SELECT p.oid::regprocedure::text signature FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND starts_with(p.proname,'zasp_audit_export_') LOOP
  EXECUTE 'ALTER FUNCTION '||item.signature||' OWNER TO zasp_discovery_authority';
  EXECUTE 'REVOKE ALL ON FUNCTION '||item.signature||' FROM PUBLIC';
 END LOOP;
END $export_functions$;
GRANT EXECUTE ON FUNCTION public.zasp_audit_export_api_readiness(text,text),public.zasp_audit_export_create(text,text,text,text,bytea,text,text,text,text,text,bytea,text,text),public.zasp_audit_export_get(text,text,text,text,bytea,text,text,bigint,bytea,text,text) TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION public.zasp_audit_export_public_page(text,text,text,text,bytea,text,jsonb,timestamptz,text,integer,text,text) TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION public.zasp_audit_export_public_page_readiness(text,text) TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION public.zasp_audit_export_worker_readiness(text,text,text) TO zasp_audit_export_worker,zasp_audit_export_outbox;
GRANT EXECUTE ON FUNCTION public.zasp_audit_export_claim(text,text,text,text,text,text,integer,text,bytea,text,text),public.zasp_audit_export_heartbeat(text,text,text,text,text,bigint,integer,text,text,text,bytea,text,text,integer),public.zasp_audit_export_terminal(text,text,text,text,text,bytea,text,text) TO zasp_audit_export_worker;
GRANT EXECUTE ON FUNCTION public.zasp_audit_export_capture(text,text,text,text,text,bigint,integer,text,text,text,bytea,text,text),public.zasp_audit_export_frozen_page(text,text,text,text,text,bigint,integer,text,text,text,bytea,text,text,bigint) TO zasp_audit_export_worker;
GRANT EXECUTE ON FUNCTION public.zasp_audit_export_prepare_chunk(text,text,text,text,text,bigint,integer,text,text,text,bytea,text,text,bytea) TO zasp_audit_export_worker;
GRANT EXECUTE ON FUNCTION public.zasp_audit_export_record_chunk(text,text,text,text,text,bigint,integer,text,text,text,bytea,text,text,bigint,text,bytea,bigint) TO zasp_audit_export_worker;
GRANT EXECUTE ON FUNCTION public.zasp_audit_export_prepare_manifest(text,text,text,text,text,bigint,integer,text,text,text,bytea,text,text,bytea) TO zasp_audit_export_worker;
GRANT EXECUTE ON FUNCTION public.zasp_audit_export_finish(text,text,text,text,text,bigint,integer,text,text,text,bytea,text,text,text,bytea,bigint,text) TO zasp_audit_export_worker;
GRANT EXECUTE ON FUNCTION public.zasp_audit_export_retry(text,text,text,text,text,bigint,integer,text,text,text,bytea,text,text,integer,text) TO zasp_audit_export_worker;
GRANT EXECUTE ON FUNCTION public.zasp_audit_export_claim_outbox(text,text,integer,integer,text,text),public.zasp_audit_export_finish_outbox(text,text,text,text,text,text,bigint,integer,text,text,text),public.zasp_audit_export_retry_outbox(text,text,text,text,text,text,bigint,integer,integer,text,text) TO zasp_audit_export_outbox;

DO $compatibility$
DECLARE definition text;prior text;signature text;needle text;expected integer;occurrences integer;
BEGIN
 FOREACH signature IN ARRAY ARRAY['zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','zasp_production_security_agent_attack_path_security_ready()','zasp_production_workflow_compatibility_security_ready()'] LOOP
  definition:=pg_get_functiondef(('public.'||signature)::regprocedure);prior:=definition;
  occurrences:=0;
  expected:=CASE WHEN split_part(signature,'(',1) IN('zasp_workflow_mutate','zasp_risk_mutate') THEN 1 ELSE 3 END;
  FOR needle IN SELECT unnest(ARRAY['later_release."version" > 51','later."version">51','later."version" > 51']) LOOP
   -- The two security inspectors contain one workflow needle and both risk
   -- spelling alternatives; each individual occurrence is unique.
   IF (length(definition)-length(replace(definition,needle,'')))/length(needle)>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='audit exports compatibility occurrence rejected';END IF;
   occurrences:=occurrences+(length(definition)-length(replace(definition,needle,'')))/length(needle);
   definition:=replace(definition,needle,replace(needle,'51','52'));
  END LOOP;
  IF definition=prior OR occurrences<>expected THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='audit exports compatibility rejected';END IF;
  IF split_part(signature,'(',1) IN('zasp_workflow_mutate','zasp_risk_mutate') THEN
   needle:=CASE WHEN split_part(signature,'(',1)='zasp_workflow_mutate' THEN 'LOCK TABLE "public"."zasp_workflow_idempotency" IN ROW EXCLUSIVE MODE;' ELSE 'LOCK TABLE "public"."zasp_risk_findings", "public"."zasp_workflow_idempotency", "public"."zasp_workflow_audit", "public"."zasp_workflow_receipts" IN ROW EXCLUSIVE MODE;' END;
   IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='audit exports mutation fence rejected';END IF;
   definition:=replace(definition,needle,needle||E'\n    PERFORM public.zasp_audit_exports_require_ready();');
   -- The body can wait again on idempotency, receipt and finding locks. A
   -- final fresh check rolls back every write and refuses replay success.
   needle:=CASE WHEN split_part(signature,'(',1)='zasp_workflow_mutate' THEN 'RETURN mutation_response' ELSE 'RETURN prior_response' END;
   expected:=CASE WHEN split_part(signature,'(',1)='zasp_workflow_mutate' THEN 3 ELSE 2 END;
   IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>expected THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='audit exports final mutation fence rejected';END IF;
   definition:=replace(definition,needle,'PERFORM public.zasp_audit_exports_require_ready(); '||needle);
  END IF;
  EXECUTE definition;
 END LOOP;
END $compatibility$;

CREATE OR REPLACE FUNCTION public.zasp_production_runtime_precision_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $compatibility$
 SELECT COALESCE(expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$'
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=51 AND name='production_runtime_precision' AND checksum=expected_checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_runtime_precision_checksum' AND value=expected_checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_runtime_precision_fingerprint' AND value=expected_fingerprint)
 AND public.zasp_production_audit_exports_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=52),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_audit_exports_fingerprint')),false)
$compatibility$;
INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_audit_exports_fingerprint', 'cd508434fb91a1d36330afa42657414f131e9af8d1cafb22acf6c0fd7ce8e635');
