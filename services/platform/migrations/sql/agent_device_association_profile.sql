CREATE SCHEMA zasp_agent_device_association_v1 AUTHORIZATION zasp_discovery_authority;
-- agent device association authority definitions
REVOKE ALL ON SCHEMA zasp_agent_device_association_v1 FROM PUBLIC;
CREATE TABLE zasp_agent_device_association_v1.registration(singleton boolean NOT NULL DEFAULT true,checksum text NOT NULL,rawseal text NOT NULL,CONSTRAINT registration_pkey PRIMARY KEY(singleton),CONSTRAINT registration_singleton_ck CHECK(singleton),CONSTRAINT registration_checksum_ck CHECK(checksum ~ '^[a-f0-9]{64}$'),CONSTRAINT registration_rawseal_ck CHECK(rawseal ~ '^[a-f0-9]{64}$'));
ALTER TABLE zasp_agent_device_association_v1.registration OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_agent_device_association_v1.registration ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_agent_device_association_v1.registration FORCE ROW LEVEL SECURITY;
REVOKE ALL ON zasp_agent_device_association_v1.registration FROM PUBLIC,zasp_discovery_api,zasp_gateway_control;
CREATE POLICY authority ON zasp_agent_device_association_v1.registration TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE TABLE zasp_agent_device_association_v1.pairs(organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,agent_id text NOT NULL,device_id text NOT NULL,association_id text NOT NULL,version bigint NOT NULL,state text NOT NULL,active jsonb,created_by text NOT NULL,created_at timestamp with time zone NOT NULL,activated_by text,activated_at timestamp with time zone,revoked_at timestamp with time zone,CONSTRAINT pairs_pkey PRIMARY KEY(organization_id,workspace_id,environment_id,agent_id,device_id),CONSTRAINT pairs_version_ck CHECK(version>=0),CONSTRAINT pairs_state_ck CHECK(state ~ '^(none|admitted|revoked)$'),CONSTRAINT pairs_active_ck CHECK(jsonb_typeof(active)='object'),CONSTRAINT pairs_association_key UNIQUE(organization_id,workspace_id,environment_id,association_id));
ALTER TABLE zasp_agent_device_association_v1.pairs OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_agent_device_association_v1.pairs ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_agent_device_association_v1.pairs FORCE ROW LEVEL SECURITY;
REVOKE ALL ON zasp_agent_device_association_v1.pairs FROM PUBLIC,zasp_discovery_api,zasp_gateway_control;
CREATE POLICY authority ON zasp_agent_device_association_v1.pairs TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE TABLE zasp_agent_device_association_v1.challenges(organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,challenge_id text NOT NULL,association_id text NOT NULL,actor text NOT NULL,expected_version bigint NOT NULL,source_identity jsonb NOT NULL,source_digest bytea NOT NULL,snapshot jsonb NOT NULL,wire bytea NOT NULL,nonce_digest bytea NOT NULL,expires_at timestamp with time zone NOT NULL,created_at timestamp with time zone NOT NULL,state text NOT NULL,CONSTRAINT challenges_pkey PRIMARY KEY(organization_id,workspace_id,environment_id,challenge_id),CONSTRAINT challenges_version_ck CHECK(expected_version>=0),CONSTRAINT challenges_source_ck CHECK(jsonb_typeof(source_identity)='object'),CONSTRAINT challenges_snapshot_ck CHECK(jsonb_typeof(snapshot)='object'),CONSTRAINT challenges_digest_ck CHECK(octet_length(source_digest)=32),CONSTRAINT challenges_nonce_ck CHECK(octet_length(nonce_digest)=32),CONSTRAINT challenges_wire_min_ck CHECK(octet_length(wire)>0),CONSTRAINT challenges_wire_max_ck CHECK(octet_length(wire)<=4096),CONSTRAINT challenges_time_ck CHECK(expires_at>created_at),CONSTRAINT challenges_state_ck CHECK(state ~ '^(pending_device|pending_human|expired|superseded|activated|revoked)$'),CONSTRAINT challenges_pair_fk FOREIGN KEY(organization_id,workspace_id,environment_id,association_id) REFERENCES zasp_agent_device_association_v1.pairs(organization_id,workspace_id,environment_id,association_id));
ALTER TABLE zasp_agent_device_association_v1.challenges OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_agent_device_association_v1.challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_agent_device_association_v1.challenges FORCE ROW LEVEL SECURITY;
REVOKE ALL ON zasp_agent_device_association_v1.challenges FROM PUBLIC,zasp_discovery_api,zasp_gateway_control;
CREATE POLICY authority ON zasp_agent_device_association_v1.challenges TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE TABLE zasp_agent_device_association_v1.acceptances(organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,challenge_id text NOT NULL,credential_id text NOT NULL,credential_generation bigint NOT NULL,request_digest bytea NOT NULL,response jsonb NOT NULL,accepted_at timestamp with time zone NOT NULL,expires_at timestamp with time zone NOT NULL,accepted_tx xid8 NOT NULL DEFAULT pg_current_xact_id(),CONSTRAINT acceptances_pkey PRIMARY KEY(organization_id,workspace_id,environment_id,challenge_id),CONSTRAINT acceptances_generation_ck CHECK(credential_generation>0),CONSTRAINT acceptances_digest_ck CHECK(octet_length(request_digest)=32),CONSTRAINT acceptances_response_ck CHECK(jsonb_typeof(response)='object'),CONSTRAINT acceptances_time_ck CHECK(expires_at>accepted_at),CONSTRAINT acceptances_challenge_fk FOREIGN KEY(organization_id,workspace_id,environment_id,challenge_id) REFERENCES zasp_agent_device_association_v1.challenges(organization_id,workspace_id,environment_id,challenge_id));
ALTER TABLE zasp_agent_device_association_v1.acceptances OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_agent_device_association_v1.acceptances ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_agent_device_association_v1.acceptances FORCE ROW LEVEL SECURITY;
REVOKE ALL ON zasp_agent_device_association_v1.acceptances FROM PUBLIC,zasp_discovery_api,zasp_gateway_control;
CREATE POLICY authority ON zasp_agent_device_association_v1.acceptances TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE TABLE zasp_agent_device_association_v1.human_receipts(organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,actor text NOT NULL,operation text NOT NULL,idempotency_key text NOT NULL,request_digest bytea NOT NULL,association_id text NOT NULL,challenge_id text,result jsonb NOT NULL,material jsonb NOT NULL,recorded_at timestamp with time zone NOT NULL,created_tx xid8 NOT NULL DEFAULT pg_current_xact_id(),CONSTRAINT human_receipts_pkey PRIMARY KEY(organization_id,workspace_id,environment_id,actor,operation,idempotency_key),CONSTRAINT human_receipts_digest_ck CHECK(octet_length(request_digest)=32),CONSTRAINT human_receipts_result_ck CHECK(jsonb_typeof(result)='object'),CONSTRAINT human_receipts_material_ck CHECK(jsonb_typeof(material)='object'),CONSTRAINT human_receipts_operation_ck CHECK(operation ~ '^(createAgentDeviceIntent|activateAgentDeviceAssociation|revokeAgentDeviceAssociation)$'));
ALTER TABLE zasp_agent_device_association_v1.human_receipts OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_agent_device_association_v1.human_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_agent_device_association_v1.human_receipts FORCE ROW LEVEL SECURITY;
REVOKE ALL ON zasp_agent_device_association_v1.human_receipts FROM PUBLIC,zasp_discovery_api,zasp_gateway_control;
CREATE POLICY authority ON zasp_agent_device_association_v1.human_receipts TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE INDEX pairs_page ON zasp_agent_device_association_v1.pairs(organization_id,workspace_id,environment_id,agent_id,association_id COLLATE "C");
CREATE UNIQUE INDEX challenges_one_pending ON zasp_agent_device_association_v1.challenges(organization_id,workspace_id,environment_id,association_id) WHERE state ~ '^pending_(device|human)$';
CREATE INDEX challenges_pair ON zasp_agent_device_association_v1.challenges(organization_id,workspace_id,environment_id,association_id,created_at,challenge_id);
CREATE FUNCTION zasp_agent_device_association_v1.fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 WITH facts(v) AS (
 SELECT concat_ws('|','schema',nspowner,nspacl::text) FROM pg_namespace WHERE nspname='zasp_agent_device_association_v1'
 UNION ALL SELECT concat_ws('|','type',t.oid,t.typname,t.typowner,t.typacl::text,t.typtype,t.typcategory,t.typrelid,t.typelem,t.typarray,t.typbasetype,t.typisdefined,t.typnotnull,t.typndims,t.typcollation,t.typinput,t.typoutput,t.typreceive,t.typsend,t.typmodin,t.typmodout,t.typanalyze,t.typsubscript,t.typlen,t.typbyval,t.typalign,t.typstorage,t.typdelim,t.typdefaultbin::text,t.typdefault) FROM pg_type t WHERE t.typnamespace='zasp_agent_device_association_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','function',p.oid::regprocedure::text,p.proowner,p.proacl::text,pg_get_functiondef(p.oid)) FROM pg_proc p WHERE p.pronamespace='zasp_agent_device_association_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','relation',c.relname,c.relkind,c.relowner,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity) FROM pg_class c WHERE c.relnamespace='zasp_agent_device_association_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attacl::text,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid)) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_agent_device_association_v1'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_class c JOIN pg_constraint k ON k.conrelid=c.oid WHERE c.relnamespace='zasp_agent_device_association_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','index',i.indexrelid::regclass::text,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_agent_device_association_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','trigger',t.tgrelid,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='zasp_agent_device_association_v1'::regnamespace AND NOT t.tgisinternal
 UNION ALL SELECT concat_ws('|','policy',p.polrelid,p.polname,p.polcmd,p.polpermissive,p.polroles::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_agent_device_association_v1'::regnamespace
 ) SELECT encode(public.digest(convert_to(string_agg(v,E'\n' ORDER BY v),'UTF8'),'sha256'),'hex') FROM facts
$$;
CREATE FUNCTION zasp_agent_device_association_v1.immutable_registration() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='agent device association registration is immutable';END
$$;
CREATE TRIGGER immutable_registration BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_agent_device_association_v1.registration FOR EACH STATEMENT EXECUTE FUNCTION zasp_agent_device_association_v1.immutable_registration();
CREATE TRIGGER immutable_registration BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_agent_device_association_v1.acceptances FOR EACH STATEMENT EXECUTE FUNCTION zasp_agent_device_association_v1.immutable_registration();
CREATE TRIGGER immutable_registration BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_agent_device_association_v1.human_receipts FOR EACH STATEMENT EXECUTE FUNCTION zasp_agent_device_association_v1.immutable_registration();
CREATE FUNCTION zasp_agent_device_association_v1.raw_seal_ready() RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE manifest constant text:=$coverage_manifest$-- agent device association manifest$coverage_manifest$;part jsonb;field jsonb;f record;t record;expected integer;expr text;BEGIN
 IF(SELECT count(*) FROM zasp_agent_device_association_v1.registration)<>1 OR NOT EXISTS(SELECT 1 FROM zasp_agent_device_association_v1.registration WHERE singleton AND checksum='-- agent device association checksum' AND rawseal=zasp_agent_device_association_v1.fingerprint()) THEN RETURN false;END IF;
 IF(SELECT count(*) FROM pg_proc WHERE pronamespace='zasp_agent_device_association_v1'::regnamespace)<>23 OR(SELECT count(*) FROM pg_class WHERE relnamespace='zasp_agent_device_association_v1'::regnamespace AND relkind='r')<>5 OR(SELECT count(*) FROM pg_class WHERE relnamespace='zasp_agent_device_association_v1'::regnamespace AND relkind='i')<>9 OR EXISTS(SELECT 1 FROM pg_class WHERE relnamespace='zasp_agent_device_association_v1'::regnamespace AND relkind NOT IN('r','i')) THEN RETURN false;END IF;
 FOR part IN SELECT value FROM jsonb_array_elements(manifest::jsonb->'own') LOOP
  SELECT p.*,l.lanname INTO STRICT f FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=(part->>'signature')::regprocedure;
  IF f.proowner<>'zasp_discovery_authority'::regrole OR NOT f.prosecdef OR f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, public'] OR f.prokind<>'f' OR f.proretset OR f.proisstrict OR f.proleakproof OR f.proparallel<>'u' OR f.provariadic<>0 OR f.pronargdefaults<>0 OR f.proallargtypes IS NOT NULL OR f.proargmodes IS NOT NULL OR f.proargnames IS DISTINCT FROM ARRAY(SELECT jsonb_array_elements_text(part->'argnames')) AND NOT(part->'argnames'='[]'::jsonb AND f.proargnames IS NULL) OR f.lanname<>part->>'language' OR f.provolatile::text<>part->>'volatility' OR f.prorettype<>(part->>'returns')::regtype THEN RETURN false;END IF;
  IF encode(public.digest(convert_to(replace(replace(f.prosrc,'-- agent device association checksum','-- agent device association '||'checksum'),manifest,'-- agent device association '||'manifest'),'UTF8'),'sha256'),'hex')<>part->>'source' THEN RETURN false;END IF;
  IF EXISTS(SELECT 1 FROM aclexplode(COALESCE(f.proacl,acldefault('f',f.proowner))) a WHERE a.grantor<>f.proowner OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR a.grantee<>f.proowner AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(part->'roles') role_name WHERE a.grantee=role_name::regrole)) OR NOT has_function_privilege(f.proowner,f.oid,'EXECUTE') OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(part->'roles') role_name WHERE NOT has_function_privilege(role_name,f.oid,'EXECUTE')) THEN RETURN false;END IF;
 END LOOP;
 FOR part IN SELECT value FROM jsonb_array_elements(manifest::jsonb->'tables') LOOP
  SELECT * INTO STRICT t FROM pg_class WHERE oid=('zasp_agent_device_association_v1.'||(part->>'name'))::regclass;
  IF t.relowner<>'zasp_discovery_authority'::regrole OR NOT t.relrowsecurity OR NOT t.relforcerowsecurity OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(t.relacl,acldefault('r',t.relowner))) a WHERE a.grantee<>t.relowner OR a.grantor<>t.relowner OR a.is_grantable) OR(SELECT count(*) FROM pg_policy WHERE polrelid=t.oid)<>1 OR NOT EXISTS(SELECT 1 FROM pg_policy WHERE polrelid=t.oid AND polname='authority' AND polpermissive AND polcmd='*' AND polroles=ARRAY['zasp_discovery_authority'::regrole::oid] AND pg_get_expr(polqual,polrelid)='true' AND pg_get_expr(polwithcheck,polrelid)='true') THEN RETURN false;END IF;
  IF(SELECT count(*) FROM pg_attribute WHERE attrelid=t.oid AND attnum>0 AND NOT attisdropped)<>jsonb_array_length(part->'columns') THEN RETURN false;END IF;
  expected:=0;FOR field IN SELECT value FROM jsonb_array_elements(part->'columns') LOOP
   expected:=expected+1;
   IF NOT EXISTS(SELECT 1 FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid=t.oid AND a.attnum=expected AND a.attname=field->>'name' AND format_type(a.atttypid,a.atttypmod)=field->>'type' AND a.attnotnull IS NOT DISTINCT FROM NOT COALESCE((field->>'nullable')::boolean,false) AND NOT a.attisdropped AND a.attacl IS NULL AND a.attidentity='' AND a.attgenerated='' AND CASE WHEN field ? 'default_expression' THEN pg_get_expr(d.adbin,d.adrelid)=field->>'default_expression' WHEN(field->>'default')::boolean THEN pg_get_expr(d.adbin,d.adrelid)='true' ELSE d.oid IS NULL END) THEN RETURN false;END IF;
  END LOOP;
  IF(SELECT count(*) FROM pg_constraint WHERE conrelid=t.oid AND contype<>'n')<>1+jsonb_array_length(part->'checks')+jsonb_array_length(part->'uniques')+jsonb_array_length(part->'foreign') OR NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=t.oid AND contype='p' AND convalidated AND array_to_string(conkey,',')=part->>'pk') OR EXISTS(SELECT 1 FROM pg_constraint k WHERE k.conrelid=t.oid AND k.contype='n' AND(cardinality(k.conkey) IS DISTINCT FROM 1 OR NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=t.oid AND a.attnum=k.conkey[1] AND a.attnum>0 AND NOT a.attisdropped AND a.attnotnull))) THEN RETURN false;END IF;
  FOR field IN SELECT value FROM jsonb_array_elements(part->'checks') LOOP
   SELECT pg_get_expr(conbin,conrelid) INTO STRICT expr FROM pg_constraint WHERE conrelid=t.oid AND conname=field->>'name' AND contype='c' AND convalidated;
   -- Each fixed CHECK is a single atomic comparison; no boolean regrouping is
   -- normalized. IN's catalog ANY-array spelling is handled separately.
   IF translate(regexp_replace(expr,'::text','','g'),E' \n\t()','') IS DISTINCT FROM translate(field->>'expression',E' \n\t()','') THEN RETURN false;END IF;
  END LOOP;
  FOR field IN SELECT value FROM jsonb_array_elements(part->'uniques') LOOP
   IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=t.oid AND conname=field->>'name' AND contype='u' AND convalidated AND NOT condeferrable AND array_to_string(conkey,',')=field->>'key') THEN RETURN false;END IF;
  END LOOP;
  FOR field IN SELECT value FROM jsonb_array_elements(part->'foreign') LOOP
   IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=t.oid AND conname=field->>'name' AND contype='f' AND convalidated AND NOT condeferrable AND confdeltype='a' AND confupdtype='a' AND confmatchtype='s' AND array_to_string(conkey,',')=field->>'key' AND confrelid=('zasp_agent_device_association_v1.'||(field->>'ref'))::regclass AND array_to_string(confkey,',')=field->>'refkey') THEN RETURN false;END IF;
  END LOOP;
  IF(SELECT count(*) FROM pg_index WHERE indrelid=t.oid)<>jsonb_array_length(part->'indexes') THEN RETURN false;END IF;
  FOR field IN SELECT value FROM jsonb_array_elements(part->'indexes') LOOP
   IF NOT EXISTS(SELECT 1 FROM pg_index x JOIN pg_class ic ON ic.oid=x.indexrelid JOIN pg_am am ON am.oid=ic.relam WHERE x.indrelid=t.oid AND ic.relname=field->>'name' AND ic.relowner=t.relowner AND am.amname='btree' AND x.indisvalid AND x.indisready AND x.indislive AND NOT x.indisexclusion AND x.indexprs IS NULL AND x.indnkeyatts=x.indnatts AND x.indisprimary=(field->>'primary')::boolean AND x.indisunique=(field->>'unique')::boolean AND replace(x.indkey::text,' ',',')=field->>'key' AND pg_get_expr(x.indpred,x.indrelid) IS NOT DISTINCT FROM field->>'predicate') THEN RETURN false;END IF;
  END LOOP;
  IF NOT EXISTS(SELECT 1 FROM pg_type c JOIN pg_type a ON a.oid=c.typarray WHERE c.oid=t.reltype AND c.typnamespace=t.relnamespace AND c.typrelid=t.oid AND c.typtype='c' AND c.typcategory='C' AND c.typname=part->>'name' AND c.typowner=t.relowner AND c.typacl IS NULL AND c.typelem=0 AND c.typbasetype=0 AND c.typisdefined AND NOT c.typnotnull AND c.typndims=0 AND c.typdefault IS NULL AND c.typdefaultbin IS NULL AND a.typnamespace=t.relnamespace AND a.typname='_'||(part->>'name') AND a.typowner=t.relowner AND a.typacl IS NULL AND a.typtype='b' AND a.typcategory='A' AND a.typelem=c.oid AND a.typrelid=0 AND a.typarray=0 AND a.typbasetype=0 AND a.typisdefined AND NOT a.typnotnull AND a.typndims=0 AND a.typdefault IS NULL AND a.typdefaultbin IS NULL) THEN RETURN false;END IF;
 END LOOP;
 IF(SELECT count(*) FROM pg_type WHERE typnamespace='zasp_agent_device_association_v1'::regnamespace)<>10 OR(SELECT count(*) FROM pg_trigger x JOIN pg_class t ON t.oid=x.tgrelid WHERE t.relnamespace='zasp_agent_device_association_v1'::regnamespace AND NOT x.tgisinternal)<>3 OR (SELECT count(*) FROM pg_trigger WHERE tgrelid IN('zasp_agent_device_association_v1.registration'::regclass,'zasp_agent_device_association_v1.acceptances'::regclass,'zasp_agent_device_association_v1.human_receipts'::regclass) AND tgname='immutable_registration' AND tgenabled='O' AND tgtype=58 AND tgnargs=0 AND tgfoid='zasp_agent_device_association_v1.immutable_registration()'::regprocedure)<>3 THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='zasp_agent_device_association_v1' AND(n.nspowner<>'zasp_discovery_authority'::regrole OR a.grantor<>n.nspowner OR a.is_grantable OR NOT(a.grantee=n.nspowner AND a.privilege_type IN('USAGE','CREATE') OR a.grantee IN('zasp_discovery_api'::regrole,'zasp_gateway_control'::regrole) AND a.privilege_type='USAGE'))) OR NOT has_schema_privilege('zasp_gateway_control','zasp_agent_device_association_v1','USAGE') OR NOT has_schema_privilege('zasp_discovery_api','zasp_agent_device_association_v1','USAGE') THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM pg_operator WHERE oprnamespace='zasp_agent_device_association_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_collation WHERE collnamespace='zasp_agent_device_association_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_conversion WHERE connamespace='zasp_agent_device_association_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_opclass WHERE opcnamespace='zasp_agent_device_association_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_opfamily WHERE opfnamespace='zasp_agent_device_association_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_ts_config WHERE cfgnamespace='zasp_agent_device_association_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_ts_dict WHERE dictnamespace='zasp_agent_device_association_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_ts_parser WHERE prsnamespace='zasp_agent_device_association_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_ts_template WHERE tmplnamespace='zasp_agent_device_association_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_statistic_ext WHERE stxnamespace='zasp_agent_device_association_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_extension WHERE extnamespace='zasp_agent_device_association_v1'::regnamespace) THEN RETURN false;END IF;
 RETURN true;EXCEPTION WHEN OTHERS THEN RETURN false;END
$$;
CREATE FUNCTION zasp_agent_device_association_v1.effective_ready() RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE manifest constant text:=$coverage_manifest$-- agent device association manifest$coverage_manifest$;part jsonb;f record;BEGIN
 -- Trusted compiled parent bodies and exact owner/ACL frames are independent of
 -- registration's captured live seal. No parent or dynamic data is cached.
 FOR part IN SELECT value FROM jsonb_array_elements(manifest::jsonb->'parents') LOOP
  SELECT p.* INTO STRICT f FROM pg_proc p WHERE p.oid=(part->>'signature')::regprocedure;
  IF f.proowner<>'zasp_discovery_authority'::regrole OR f.prosecdef IS DISTINCT FROM(part->>'secdef')::boolean OR f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, public'] OR encode(public.digest(convert_to(f.prosrc,'UTF8'),'sha256'),'hex')<>part->>'source' OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(f.proacl,acldefault('f',f.proowner))) a WHERE a.grantor<>f.proowner OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR a.grantee<>f.proowner AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(part->'roles') role_name WHERE a.grantee=role_name::regrole)) OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(part->'roles') role_name WHERE NOT has_function_privilege(role_name,f.oid,'EXECUTE')) THEN RETURN false;END IF;
 END LOOP;
 RETURN COALESCE(zasp_agent_device_association_v1.raw_seal_ready()
 AND public.zasp_inventory_security_ready() AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=14 AND checksum='-- association typed14') AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='typed_inventory_cutover_fingerprint' AND value='-- association typed14 fingerprint')
 AND zasp_authorization79.ready('-- agent device association parent79') AND zasp_authorization80.ready('-- agent device association parent80') AND zasp_authorization80_temporal.ready()
 AND zasp_authorization80_worker.catalog_ready() AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE singleton AND checksum='-- agent device association worker')
 AND zasp_authorization80_runtime.catalog_ready() AND zasp_authorization80_runtime.current_ready() AND EXISTS(SELECT 1 FROM zasp_authorization80_runtime.registration WHERE singleton AND checksum='-- agent device association runtime')
 AND(SELECT count(*)=1 AND bool_and(singleton AND name='canonical61-temporal78-authorization79-80-v1' AND audit_mode='-- agent device association audit mode' AND identity_mode='-- agent device association identity mode') FROM zasp_authorization80.runtime_profile)
 -- agent device association selected parent predicate
 ,false);EXCEPTION WHEN OTHERS THEN RETURN false;END
$$;
CREATE FUNCTION zasp_agent_device_association_v1.caller_ready(purpose text,pin text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT COALESCE(pin='-- agent device association checksum' AND zasp_agent_device_association_v1.effective_ready() AND CASE purpose WHEN 'gateway-control' THEN public.zasp_runtime_principal_ready('zasp_gateway_control') WHEN 'public-api' THEN public.zasp_discovery_principal_ready('zasp_discovery_api') ELSE false END,false)
$$;
CREATE FUNCTION zasp_agent_device_association_v1.stamp(t timestamp with time zone) RETURNS text LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT rtrim(rtrim(to_char($1 AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),'0'),'.')||'Z'
$$;
CREATE FUNCTION zasp_agent_device_association_v1.require_human(o text,w text,e text,actor text,agent_id text,operation text,pin text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE p jsonb;r jsonb;BEGIN
 IF $6 NOT IN('createAgentDeviceIntent','activateAgentDeviceAssociation','revokeAgentDeviceAssociation','listAgentDeviceAssociations') OR NOT zasp_agent_device_association_v1.caller_ready('public-api',$7) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='association authority unavailable';END IF;
 p:=zasp_authorization80.context();
 PERFORM zasp_authorization80.require_read($1,$2,$3,ARRAY[$6],CASE WHEN $6='listAgentDeviceAssociations' THEN 'view' ELSE 'manage_identity' END,false,$4);
 IF COALESCE((p->>'collection')::boolean,true) OR jsonb_array_length(p->'targets')<>1 OR p->'targets' IS DISTINCT FROM p->'allowed' OR NOT zasp_authorization80.allowed($1,$2,$3,'agent',$5) OR p#>>'{path_parameters,id}' IS DISTINCT FROM $5 OR ($6<>'listAgentDeviceAssociations' AND (p->>'credential_kind'<>'1' OR NOT COALESCE((p->>'fresh_auth')::boolean,false))) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='association Agent purpose rejected';END IF;
 PERFORM zasp_authorization80_worker.gateway_api_organization_lock($1);
 r:=p->'revision';PERFORM zasp_authorization79.revalidate($1,(r->>'desired')::bigint,(r->>'generation')::bigint,r->>'store_id',r->>'model_id');
 PERFORM zasp_authorization80.identity_fence(p);
 PERFORM v FROM zasp_authorization80.source_rows($1,$2,$3,'agent',$5,true) v;
 IF NOT FOUND OR p IS DISTINCT FROM zasp_authorization80.context() OR NOT zasp_agent_device_association_v1.caller_ready('public-api',$7) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='association current authority changed';END IF;
 RETURN p;
END $$;
CREATE FUNCTION zasp_agent_device_association_v1.source_digest(facts jsonb) RETURNS text LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT encode(public.digest(convert_to('zasp-agent-device-source-v1','UTF8')||decode('00','hex')||decode(string_agg(encode(int4send(octet_length(convert_to(v,'UTF8')))||convert_to(v,'UTF8'),'hex'),'' ORDER BY n),'hex'),'sha256'),'hex') FROM jsonb_array_elements_text(jsonb_build_array($1->>'organization_id',$1->>'workspace_id',$1->>'environment_id',$1->>'agent_id',$1->>'integration_id',$1->>'provider',$1->>'source',$1->>'identity_namespace',$1->>'source_native_id',$1->>'rule_version')) WITH ORDINALITY f(v,n)
$$;
CREATE FUNCTION zasp_agent_device_association_v1.source_facts(o text,w text,e text,agent_id text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE a public.zasp_inventory_entities%ROWTYPE;s public.zasp_inventory_source_observations%ROWTYPE;b public.zasp_inventory_identity_bindings%ROWTYPE;ev public.zasp_inventory_evidence%ROWTYPE;ident jsonb;snap jsonb;BEGIN
 SELECT * INTO a FROM public.zasp_inventory_entities x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.id)=($1,$2,$3,$4) FOR SHARE;
 IF NOT FOUND OR a.state<>'active' OR a.product_kind<>'agent' THEN RETURN jsonb_build_object('status','source_removed');END IF;
 SELECT * INTO s FROM public.zasp_inventory_source_observations x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.integration_id,x.provider,x.source,x.entity_id,x.source_native_id,x.snapshot_id,x.generation,x.evidence_id,x.identity_rule_version,x.product_kind,x.source_state)=($1,$2,$3,a.winning_integration_id,a.winning_provider,a.winning_source,$4,a.winning_source_native_id,a.winning_snapshot_id,a.winning_generation,a.winning_evidence_id,a.winning_identity_rule,'agent','present') FOR SHARE;
 IF NOT FOUND THEN RETURN jsonb_build_object('status','source_identity_changed');END IF;
 IF NOT EXISTS(SELECT 1 FROM public.zasp_integrations x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.id)=($1,$2,$3,s.integration_id) AND x.state IN('active','degraded')) OR NOT EXISTS(SELECT 1 FROM public.zasp_discovery_snapshots x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.integration_id,x.source,x.id,x.state,x.complete,x.is_last_good)=($1,$2,$3,s.integration_id,s.source,s.snapshot_id,'complete',true,true)) THEN RETURN jsonb_build_object('status','source_removed');END IF;
 IF (SELECT count(*) FROM public.zasp_inventory_identity_bindings x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.provider,x.source,x.source_native_id,x.entity_id,x.product_kind,x.rule_version)=($1,$2,$3,s.provider,s.source,s.source_native_id,$4,'agent',s.identity_rule_version))<>1 THEN RETURN jsonb_build_object('status','source_identity_changed');END IF;
 SELECT * INTO STRICT b FROM public.zasp_inventory_identity_bindings x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.provider,x.source,x.identity_namespace,x.source_native_id,x.entity_id,x.product_kind,x.rule_version)=($1,$2,$3,s.provider,s.source,s.identity_namespace,s.source_native_id,$4,'agent',s.identity_rule_version) FOR SHARE;
 SELECT * INTO ev FROM public.zasp_inventory_evidence x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.id,x.integration_id,x.snapshot_id,x.entity_id,x.source,x.generation)=($1,$2,$3,s.evidence_id,s.integration_id,s.snapshot_id,$4,s.source,s.generation) FOR SHARE;
 IF NOT FOUND THEN RETURN jsonb_build_object('status','source_removed');END IF;
 IF s.fresh_until<=clock_timestamp() OR a.fresh_until<=clock_timestamp() OR s.observed_at>clock_timestamp() THEN RETURN jsonb_build_object('status','source_stale');END IF;
 ident:=jsonb_build_object('integration_id',s.integration_id,'provider',s.provider,'source',s.source,'identity_namespace',b.identity_namespace,'source_native_id',s.source_native_id,'rule_version',s.identity_rule_version,'agent_id',$4);
 snap:=jsonb_build_object('snapshot_id',s.snapshot_id,'evidence_id',s.evidence_id,'generation',s.generation,'content_sha256',encode(s.content_digest,'hex'),'observed_at',zasp_agent_device_association_v1.stamp(s.observed_at),'fresh_until',zasp_agent_device_association_v1.stamp(s.fresh_until));
 RETURN jsonb_build_object('status','current','entity_fresh_until',zasp_agent_device_association_v1.stamp(a.fresh_until),'identity',ident,'snapshot',snap,'digest',zasp_agent_device_association_v1.source_digest(ident||jsonb_build_object('organization_id',$1,'workspace_id',$2,'environment_id',$3)));
END $$;
CREATE FUNCTION zasp_agent_device_association_v1.device_facts(o text,w text,e text,device_id text,credential_id text,credential_generation bigint) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE d public.zasp_gateway_devices%ROWTYPE;c public.zasp_gateway_credentials%ROWTYPE;reason text;BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1,$2,$3,$4),0));
 SELECT * INTO d FROM public.zasp_gateway_devices x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.id)=($1,$2,$3,$4) FOR SHARE;
 IF NOT FOUND OR d.state<>'active' OR d.version<1 THEN RETURN jsonb_build_object('reason','device_unavailable','credential',NULL);END IF;
 SELECT * INTO c FROM public.zasp_gateway_credentials x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.device_id)=($1,$2,$3,$4) AND x.format_version=1 AND($5 IS NULL OR x.id=$5) ORDER BY x.credential_generation DESC LIMIT 1 FOR SHARE;
 IF NOT FOUND THEN RETURN jsonb_build_object('reason','credential_revoked','credential',NULL);END IF;
 reason:=CASE WHEN EXISTS(SELECT 1 FROM public.zasp_gateway_credentials x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.device_id)=($1,$2,$3,$4) AND x.credential_generation>c.credential_generation) OR($6 IS NOT NULL AND $6<>c.credential_generation) THEN 'credential_rotated' WHEN c.revoked_at IS NOT NULL THEN 'credential_revoked' WHEN c.expires_at<=clock_timestamp() THEN 'credential_expired' WHEN c.audience<>'runtime-gateway' OR c.algorithm<>'Ed25519' OR octet_length(c.public_key)<>32 OR c.key_id IS NULL OR c.credential_generation<1 THEN 'device_unavailable' END;
 RETURN jsonb_build_object('reason',reason,'credential',jsonb_build_object('credential_id',c.id,'credential_generation',c.credential_generation,'expires_at',zasp_agent_device_association_v1.stamp(c.expires_at)));
END $$;
CREATE FUNCTION zasp_agent_device_association_v1.pair_id(o text,w text,e text,agent_id text,device_id text) RETURNS text LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT public.zasp_discovery_canonical_id($1,$2,$3,'agent_device_association',$4||chr(31)||$5)
$$;
CREATE FUNCTION zasp_agent_device_association_v1.build_challenge(o text,w text,e text,agent_id text,device_id text,association_id text,challenge_id text,source_digest text,expected_version bigint,nonce bytea,expires_at timestamp with time zone) RETURNS bytea LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT convert_to('{"schema":"agent-device-intent-v1","challenge_id":"'||$7||'","association_id":"'||$6||'","organization_id":"'||$1||'","workspace_id":"'||$2||'","environment_id":"'||$3||'","agent_id":"'||$4||'","agent_source_digest":"'||$8||'","device_id":"'||$5||'","expected_association_version":'||$9::text||',"nonce":"'||translate(rtrim(replace(encode($10,'base64'),chr(10),''),'='),'+/','-_')||'","expires_at":"'||to_char($11 AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')||'"}','UTF8')
$$;
CREATE FUNCTION zasp_agent_device_association_v1.human_replay(o text,w text,e text,actor text,operation text,idempotency_key text,request_digest bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE r zasp_agent_device_association_v1.human_receipts%ROWTYPE;BEGIN
 SELECT * INTO r FROM zasp_agent_device_association_v1.human_receipts x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.actor,x.operation,x.idempotency_key)=($1,$2,$3,$4,$5,$6) FOR SHARE;
 IF NOT FOUND THEN RETURN NULL;END IF;
 IF r.request_digest IS DISTINCT FROM $7 THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='association idempotency conflict';END IF;
 RETURN r.result||jsonb_build_object('replayed',r.created_tx<>pg_current_xact_id(),'new_mutation',r.created_tx=pg_current_xact_id());
END $$;
CREATE FUNCTION zasp_agent_device_association_v1.store_human_receipt(o text,w text,e text,actor text,agent_id text,operation text,idempotency_key text,request_digest bytea,association_id text,challenge_id text,result jsonb,material jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF $7 IS NULL OR length($7) NOT BETWEEN 16 AND 128 OR $7!~'^[A-Za-z0-9._:-]+$' OR octet_length($8) IS DISTINCT FROM 32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='association receipt rejected';END IF;
 INSERT INTO zasp_agent_device_association_v1.human_receipts(organization_id,workspace_id,environment_id,actor,operation,idempotency_key,request_digest,association_id,challenge_id,result,material,recorded_at) VALUES($1,$2,$3,$4,$6,$7,$8,$9,$10,$11,$12,($11#>>'{receipt,recorded_at}')::timestamptz);
 INSERT INTO public.zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) VALUES($1,$2,$3,public.zasp_discovery_canonical_id($1,$2,$3,'agent_device_association_audit',$4||chr(31)||$6||chr(31)||$7),$4,CASE $6 WHEN 'createAgentDeviceIntent' THEN 'agent.device.intent.create' WHEN 'activateAgentDeviceAssociation' THEN 'agent.device.activate' ELSE 'agent.device.revoke' END,$5,'succeeded',jsonb_build_object('association_id',$9,'challenge_id',$10,'version',$11#>'{receipt,version}'),clock_timestamp());
 RETURN $11||jsonb_build_object('replayed',false,'new_mutation',true);
END $$;
CREATE FUNCTION zasp_agent_device_association_v1.create_intent(o text,w text,e text,actor text,agent_id text,device_id text,idempotency_key text,request_digest bytea,expected_version bigint,challenge_id text,nonce bytea,ttl_seconds integer,pin text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE p zasp_agent_device_association_v1.pairs%ROWTYPE;f jsonb;d jsonb;r jsonb;wire bytea;now_value timestamptz;expiry timestamptz;pair text;envelope jsonb;BEGIN
 PERFORM zasp_agent_device_association_v1.require_human($1,$2,$3,$4,$5,'createAgentDeviceIntent',$13);
 IF NOT public.zasp_valid_product_id($6) OR NOT public.zasp_valid_product_id($10) OR octet_length($11) IS DISTINCT FROM 32 OR $12 NOT BETWEEN 60 AND 300 OR $9<0 OR $9 IS NULL THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='association intent rejected';END IF;
 f:=zasp_agent_device_association_v1.source_facts($1,$2,$3,$5);d:=zasp_agent_device_association_v1.device_facts($1,$2,$3,$6,NULL,NULL);
 pair:=zasp_agent_device_association_v1.pair_id($1,$2,$3,$5,$6);
 SELECT * INTO p FROM zasp_agent_device_association_v1.pairs x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.association_id)=($1,$2,$3,pair) FOR UPDATE;
 r:=zasp_agent_device_association_v1.human_replay($1,$2,$3,$4,'createAgentDeviceIntent',$7,$8);IF r IS NOT NULL THEN RETURN r;END IF;
 IF f->>'status'<>'current' OR d->>'reason' IS NOT NULL OR COALESCE(p.version,0)<>$9 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='association intent authority unavailable';END IF;
 now_value:=clock_timestamp();expiry:=date_trunc('second',now_value)+make_interval(secs=>$12);
 IF p.association_id IS NULL THEN INSERT INTO zasp_agent_device_association_v1.pairs VALUES($1,$2,$3,$5,$6,pair,0,'none',NULL,$4,now_value,NULL,NULL,NULL);END IF;
 UPDATE zasp_agent_device_association_v1.challenges x SET state=CASE WHEN x.expires_at<=now_value THEN 'expired' ELSE 'superseded' END WHERE(x.organization_id,x.workspace_id,x.environment_id,x.association_id)=($1,$2,$3,pair) AND x.state IN('pending_device','pending_human');
 wire:=zasp_agent_device_association_v1.build_challenge($1,$2,$3,$5,$6,pair,$10,f->>'digest',$9,$11,expiry);
 INSERT INTO zasp_agent_device_association_v1.challenges VALUES($1,$2,$3,$10,pair,$4,$9,f->'identity',decode(f->>'digest','hex'),f->'snapshot',wire,public.digest($11,'sha256'),expiry,now_value,'pending_device');
 envelope:=jsonb_build_object('schema','agent-device-challenge-envelope-v1','challenge_wire',translate(rtrim(replace(encode(wire,'base64'),chr(10),''),'='),'+/','-_'),'challenge_sha256',encode(public.digest(wire,'sha256'),'hex'));
 r:=jsonb_build_object('receipt',jsonb_build_object('operation','createAgentDeviceIntent','association_id',pair,'challenge_id',$10,'version',$9,'recorded_state','intent_created','recorded_at',zasp_agent_device_association_v1.stamp(now_value)),'challenge',envelope);
 RETURN zasp_agent_device_association_v1.store_human_receipt($1,$2,$3,$4,$5,'createAgentDeviceIntent',$7,$8,pair,$10,r,jsonb_build_object('agent_id',$5,'device_id',$6,'source_digest',f->>'digest','wire_sha256',encode(public.digest(wire,'sha256'),'hex')));
END $$;
CREATE FUNCTION zasp_agent_device_association_v1.activate(o text,w text,e text,actor text,agent_id text,association_id text,challenge_id text,challenge_sha256 bytea,expected_version bigint,idempotency_key text,request_digest bytea,pin text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE p zasp_agent_device_association_v1.pairs%ROWTYPE;c zasp_agent_device_association_v1.challenges%ROWTYPE;a zasp_agent_device_association_v1.acceptances%ROWTYPE;f jsonb;d jsonb;r jsonb;now_value timestamptz;proof jsonb;BEGIN
 proof:=zasp_agent_device_association_v1.require_human($1,$2,$3,$4,$5,'activateAgentDeviceAssociation',$12);
 IF proof#>>'{path_parameters,associationId}' IS DISTINCT FROM $6 OR octet_length($8) IS DISTINCT FROM 32 OR $9 IS NULL OR $9<0 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='association activation rejected';END IF;
 SELECT * INTO p FROM zasp_agent_device_association_v1.pairs x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.agent_id,x.association_id)=($1,$2,$3,$5,$6);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='association missing';END IF;
 f:=zasp_agent_device_association_v1.source_facts($1,$2,$3,$5);
 SELECT * INTO a FROM zasp_agent_device_association_v1.acceptances x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.challenge_id)=($1,$2,$3,$7);
 d:=zasp_agent_device_association_v1.device_facts($1,$2,$3,p.device_id,a.credential_id,a.credential_generation);
 PERFORM 1 FROM zasp_agent_device_association_v1.pairs x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.association_id)=($1,$2,$3,$6) FOR UPDATE;
 r:=zasp_agent_device_association_v1.human_replay($1,$2,$3,$4,'activateAgentDeviceAssociation',$10,$11);IF r IS NOT NULL THEN RETURN r;END IF;
 SELECT * INTO c FROM zasp_agent_device_association_v1.challenges x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.association_id,x.challenge_id)=($1,$2,$3,$6,$7) FOR UPDATE;
 now_value:=clock_timestamp();
 IF NOT FOUND OR c.actor<>$4 OR c.state<>'pending_human' OR c.expires_at<=now_value OR c.expected_version<>$9 OR p.version<>$9 OR public.digest(c.wire,'sha256') IS DISTINCT FROM $8 OR a.challenge_id IS NULL OR f->>'status'<>'current' OR decode(f->>'digest','hex') IS DISTINCT FROM c.source_digest OR d->>'reason' IS NOT NULL OR a.expires_at<=now_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='association activation authority changed';END IF;
 UPDATE zasp_agent_device_association_v1.pairs x SET version=version+1,state='admitted',active=jsonb_build_object('source_identity',f->'identity','source_digest',f->>'digest','admission_snapshot',f->'snapshot','device_credential',d->'credential','challenge_id',$7),activated_by=$4,activated_at=now_value,revoked_at=NULL WHERE(x.organization_id,x.workspace_id,x.environment_id,x.association_id,x.version)=($1,$2,$3,$6,$9);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='association version changed';END IF;
 UPDATE zasp_agent_device_association_v1.challenges x SET state='activated' WHERE(x.organization_id,x.workspace_id,x.environment_id,x.challenge_id)=($1,$2,$3,$7);
 r:=jsonb_build_object('receipt',jsonb_build_object('operation','activateAgentDeviceAssociation','association_id',$6,'challenge_id',$7,'version',$9+1,'recorded_state','activated','recorded_at',zasp_agent_device_association_v1.stamp(now_value)),'challenge',NULL);
 RETURN zasp_agent_device_association_v1.store_human_receipt($1,$2,$3,$4,$5,'activateAgentDeviceAssociation',$10,$11,$6,$7,r,jsonb_build_object('agent_id',$5,'device_id',p.device_id,'source_digest',f->>'digest','credential_id',a.credential_id,'credential_generation',a.credential_generation));
END $$;
CREATE FUNCTION zasp_agent_device_association_v1.revoke(o text,w text,e text,actor text,agent_id text,association_id text,expected_version bigint,idempotency_key text,request_digest bytea,pin text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE p zasp_agent_device_association_v1.pairs%ROWTYPE;r jsonb;now_value timestamptz;proof jsonb;BEGIN
 proof:=zasp_agent_device_association_v1.require_human($1,$2,$3,$4,$5,'revokeAgentDeviceAssociation',$10);
 IF proof#>>'{path_parameters,associationId}' IS DISTINCT FROM $6 OR $7 IS NULL OR $7<0 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='association revoke rejected';END IF;
 SELECT * INTO p FROM zasp_agent_device_association_v1.pairs x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.agent_id,x.association_id)=($1,$2,$3,$5,$6);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='association missing';END IF;
 PERFORM zasp_agent_device_association_v1.device_facts($1,$2,$3,p.device_id,NULL,NULL);
 SELECT * INTO p FROM zasp_agent_device_association_v1.pairs x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.agent_id,x.association_id)=($1,$2,$3,$5,$6) FOR UPDATE;
 r:=zasp_agent_device_association_v1.human_replay($1,$2,$3,$4,'revokeAgentDeviceAssociation',$8,$9);IF r IS NOT NULL THEN RETURN r;END IF;
 IF p.version<>$7 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='association version changed';END IF;
 now_value:=clock_timestamp();
 UPDATE zasp_agent_device_association_v1.pairs x SET version=version+1,state='revoked',revoked_at=now_value WHERE(x.organization_id,x.workspace_id,x.environment_id,x.association_id)=($1,$2,$3,$6);
 UPDATE zasp_agent_device_association_v1.challenges x SET state='revoked' WHERE(x.organization_id,x.workspace_id,x.environment_id,x.association_id)=($1,$2,$3,$6) AND x.state IN('pending_device','pending_human');
 r:=jsonb_build_object('receipt',jsonb_build_object('operation','revokeAgentDeviceAssociation','association_id',$6,'challenge_id',NULL,'version',$7+1,'recorded_state','revoked','recorded_at',zasp_agent_device_association_v1.stamp(now_value)),'challenge',NULL);
 RETURN zasp_agent_device_association_v1.store_human_receipt($1,$2,$3,$4,$5,'revokeAgentDeviceAssociation',$8,$9,$6,NULL,r,jsonb_build_object('agent_id',$5,'device_id',p.device_id));
END $$;
CREATE FUNCTION zasp_agent_device_association_v1.pair_value(o text,w text,e text,association_id text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE p zasp_agent_device_association_v1.pairs%ROWTYPE;c zasp_agent_device_association_v1.challenges%ROWTYPE;a zasp_agent_device_association_v1.acceptances%ROWTYPE;f jsonb;d jsonb;reason text;pending jsonb;BEGIN
 SELECT * INTO STRICT p FROM zasp_agent_device_association_v1.pairs x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.association_id)=($1,$2,$3,$4);
 f:=zasp_agent_device_association_v1.source_facts($1,$2,$3,p.agent_id);
 d:=zasp_agent_device_association_v1.device_facts($1,$2,$3,p.device_id,p.active#>>'{device_credential,credential_id}',(p.active#>>'{device_credential,credential_generation}')::bigint);
 IF p.state='admitted' THEN reason:=CASE WHEN f->>'status'<>'current' THEN f->>'status' WHEN p.active->>'source_digest' IS DISTINCT FROM f->>'digest' THEN 'source_identity_changed' ELSE d->>'reason' END;END IF;
 SELECT * INTO c FROM zasp_agent_device_association_v1.challenges x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.association_id)=($1,$2,$3,$4) AND x.state IN('pending_device','pending_human') ORDER BY x.created_at DESC,x.challenge_id LIMIT 1;
 IF FOUND THEN
  SELECT * INTO a FROM zasp_agent_device_association_v1.acceptances x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.challenge_id)=($1,$2,$3,c.challenge_id);
  pending:=jsonb_build_object('challenge_id',c.challenge_id,'challenge_wire',translate(rtrim(replace(encode(c.wire,'base64'),chr(10),''),'='),'+/','-_'),'challenge_sha256',encode(public.digest(c.wire,'sha256'),'hex'),'created_by',c.actor,'created_at',zasp_agent_device_association_v1.stamp(c.created_at),'expires_at',zasp_agent_device_association_v1.stamp(c.expires_at),'state',CASE WHEN c.expires_at<=clock_timestamp() THEN 'expired' ELSE c.state END,'acceptance',a.response->'acceptance');
 END IF;
 RETURN jsonb_build_object('association_id',p.association_id,'agent_id',p.agent_id,'device_id',p.device_id,'version',p.version,'state',CASE WHEN reason IS NOT NULL THEN 'unavailable' ELSE p.state END,'unavailable_reason',COALESCE(reason,'none'),'source_identity',p.active->'source_identity','admission_snapshot',p.active->'admission_snapshot','device_credential',p.active->'device_credential','created_by',p.created_by,'activated_by',p.activated_by,'created_at',zasp_agent_device_association_v1.stamp(p.created_at),'activated_at',zasp_agent_device_association_v1.stamp(p.activated_at),'revoked_at',zasp_agent_device_association_v1.stamp(p.revoked_at),'pending_intent',pending);
END $$;
CREATE FUNCTION zasp_agent_device_association_v1.page(o text,w text,e text,agent_id text,after_association_id text,page_limit integer,pin text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE x record;items jsonb:='[]';next_id text;count_value integer:=0;BEGIN
 PERFORM zasp_agent_device_association_v1.require_human($1,$2,$3,zasp_authorization80.context()->>'principal_id',$4,'listAgentDeviceAssociations',$7);
 IF $6 IS NULL OR $6 NOT BETWEEN 1 AND 100 OR($5 IS NOT NULL AND NOT public.zasp_valid_product_id($5)) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='association page rejected';END IF;
 FOR x IN SELECT association_id FROM zasp_agent_device_association_v1.pairs p WHERE(p.organization_id,p.workspace_id,p.environment_id,p.agent_id)=($1,$2,$3,$4) AND($5 IS NULL OR p.association_id COLLATE "C">$5 COLLATE "C") ORDER BY p.association_id COLLATE "C" LIMIT $6+1 LOOP
  count_value:=count_value+1;IF count_value>$6 THEN EXIT;END IF;
  items:=items||jsonb_build_array(zasp_agent_device_association_v1.pair_value($1,$2,$3,x.association_id));next_id:=x.association_id;
 END LOOP;
 RETURN jsonb_build_object('items',items,'next_association_id',CASE WHEN count_value>$6 THEN next_id END);
END $$;
CREATE FUNCTION zasp_agent_device_association_v1.confirm_human(o text,w text,e text,actor text,agent_id text,operation text,idempotency_key text,request_digest bytea,expected_receipt jsonb,pin text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE r zasp_agent_device_association_v1.human_receipts%ROWTYPE;c zasp_agent_device_association_v1.challenges%ROWTYPE;p zasp_agent_device_association_v1.pairs%ROWTYPE;f jsonb;d jsonb;actual jsonb;new_value boolean;BEGIN
 PERFORM zasp_agent_device_association_v1.require_human($1,$2,$3,$4,$5,$6,$10);
 SELECT * INTO r FROM zasp_agent_device_association_v1.human_receipts x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.actor,x.operation,x.idempotency_key)=($1,$2,$3,$4,$6,$7);
 IF NOT FOUND OR r.request_digest IS DISTINCT FROM $8 OR r.material->>'agent_id' IS DISTINCT FROM $5 THEN RETURN false;END IF;
 f:=zasp_agent_device_association_v1.source_facts($1,$2,$3,$5);
 d:=zasp_agent_device_association_v1.device_facts($1,$2,$3,r.material->>'device_id',r.material->>'credential_id',(r.material->>'credential_generation')::bigint);
 SELECT * INTO p FROM zasp_agent_device_association_v1.pairs x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.association_id,x.agent_id)=($1,$2,$3,r.association_id,$5) FOR UPDATE;
 SELECT * INTO c FROM zasp_agent_device_association_v1.challenges x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.challenge_id)=($1,$2,$3,r.challenge_id) FOR SHARE;
 new_value:=r.created_tx=pg_current_xact_id();actual:=r.result||jsonb_build_object('replayed',NOT new_value,'new_mutation',new_value);
 IF actual IS DISTINCT FROM $9 OR p.association_id IS NULL OR p.version<(r.result#>>'{receipt,version}')::bigint THEN RETURN false;END IF;
 -- Historical receipts remain metadata only. They never renew a challenge,
 -- change an old TX marker, or assert the current admission state.
 IF new_value AND $6='createAgentDeviceIntent' AND(c.state<>'pending_device' OR c.expires_at<=clock_timestamp() OR c.expected_version<>p.version OR f->>'status'<>'current' OR f->>'digest' IS DISTINCT FROM r.material->>'source_digest' OR d->>'reason' IS NOT NULL OR public.digest(c.wire,'sha256') IS DISTINCT FROM decode(r.material->>'wire_sha256','hex')) THEN RETURN false;END IF;
 IF new_value AND $6='activateAgentDeviceAssociation' AND(p.state<>'admitted' OR c.state<>'activated' OR c.actor<>$4 OR c.expires_at<=clock_timestamp() OR f->>'status'<>'current' OR f->>'digest' IS DISTINCT FROM r.material->>'source_digest' OR d->>'reason' IS NOT NULL OR p.version<>(r.result#>>'{receipt,version}')::bigint) THEN RETURN false;END IF;
 IF new_value AND $6='revokeAgentDeviceAssociation' AND(p.state<>'revoked' OR p.version<>(r.result#>>'{receipt,version}')::bigint OR EXISTS(SELECT 1 FROM zasp_agent_device_association_v1.challenges x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.association_id)=($1,$2,$3,r.association_id) AND x.state IN('pending_device','pending_human'))) THEN RETURN false;END IF;
 PERFORM zasp_agent_device_association_v1.require_human($1,$2,$3,$4,$5,$6,$10);
 RETURN NOT new_value OR $6='revokeAgentDeviceAssociation' OR(c.expires_at>clock_timestamp() AND(f#>>'{snapshot,fresh_until}')::timestamptz>clock_timestamp() AND(f->>'entity_fresh_until')::timestamptz>clock_timestamp() AND(d#>>'{credential,expires_at}')::timestamptz>clock_timestamp());
END $$;
CREATE FUNCTION zasp_agent_device_association_v1.parse_accept(body bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE original json;value jsonb;inner_json json;inner_value jsonb;raw bytea;canonical text;name text;BEGIN
 IF $1 IS NULL OR octet_length($1) NOT BETWEEN 1 AND 16384 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='association acceptance rejected';END IF;
 original:=convert_from($1,'UTF8')::json;value:=original::jsonb;
 IF NOT zasp_authorization80.unique_json(original,0) OR jsonb_typeof(value)<>'object' OR(SELECT count(*) FROM jsonb_object_keys(value))<>3 OR jsonb_typeof(value->'schema') IS DISTINCT FROM 'string' OR value->>'schema' IS DISTINCT FROM 'agent-device-accept-v1' OR jsonb_typeof(value->'challenge_wire') IS DISTINCT FROM 'string' OR value->>'challenge_wire'!~'^[A-Za-z0-9_-]+$' OR length(value->>'challenge_wire')%4=1 OR jsonb_typeof(value->'challenge_sha256') IS DISTINCT FROM 'string' OR value->>'challenge_sha256'!~'^[a-f0-9]{64}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='association acceptance envelope rejected';END IF;
 raw:=decode(translate(value->>'challenge_wire','-_','+/')||repeat('=',(4-length(value->>'challenge_wire')%4)%4),'base64');
 IF octet_length(raw) NOT BETWEEN 1 AND 4096 OR translate(rtrim(replace(encode(raw,'base64'),chr(10),''),'='),'+/','-_') IS DISTINCT FROM value->>'challenge_wire' OR encode(public.digest(raw,'sha256'),'hex') IS DISTINCT FROM value->>'challenge_sha256' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='association challenge digest rejected';END IF;
 inner_json:=convert_from(raw,'UTF8')::json;inner_value:=inner_json::jsonb;
 IF NOT zasp_authorization80.unique_json(inner_json,0) OR jsonb_typeof(inner_value)<>'object' OR(SELECT count(*) FROM jsonb_object_keys(inner_value))<>12 OR inner_value->>'schema'<>'agent-device-intent-v1' OR inner_value->>'agent_source_digest'!~'^[a-f0-9]{64}$' OR inner_value->>'nonce'!~'^[A-Za-z0-9_-]{43}$' OR inner_value->>'expires_at'!~'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' OR(inner_json->'expected_association_version')::text!~'^(0|[1-9][0-9]*)$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='association challenge rejected';END IF;
 FOREACH name IN ARRAY ARRAY['challenge_id','association_id','organization_id','workspace_id','environment_id','agent_id','device_id'] LOOP IF jsonb_typeof(inner_value->name)<>'string' OR NOT public.zasp_valid_product_id(inner_value->>name) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='association challenge identity rejected';END IF;END LOOP;
 IF decode(translate(inner_value->>'nonce','-_','+/')||'=','base64') IS NULL OR octet_length(decode(translate(inner_value->>'nonce','-_','+/')||'=','base64'))<>32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='association nonce rejected';END IF;
 canonical:=convert_from(zasp_agent_device_association_v1.build_challenge(inner_value->>'organization_id',inner_value->>'workspace_id',inner_value->>'environment_id',inner_value->>'agent_id',inner_value->>'device_id',inner_value->>'association_id',inner_value->>'challenge_id',inner_value->>'agent_source_digest',(inner_value->>'expected_association_version')::bigint,decode(translate(inner_value->>'nonce','-_','+/')||'=','base64'),(inner_value->>'expires_at')::timestamptz),'UTF8');
 IF convert_to(canonical,'UTF8') IS DISTINCT FROM raw THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='association canonical wire rejected';END IF;
 RETURN inner_value||jsonb_build_object('wire',value->>'challenge_wire','wire_sha256',value->>'challenge_sha256');
END $$;
CREATE FUNCTION zasp_agent_device_association_v1.accept_intent(credential_id text,body bytea,pin text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v jsonb;authority_value jsonb;f jsonb;d jsonb;c zasp_agent_device_association_v1.challenges%ROWTYPE;p zasp_agent_device_association_v1.pairs%ROWTYPE;a zasp_agent_device_association_v1.acceptances%ROWTYPE;r jsonb;accepted timestamptz;expiry timestamptz;BEGIN
 IF NOT zasp_agent_device_association_v1.caller_ready('gateway-control',$3) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='association control unavailable';END IF;
 v:=zasp_agent_device_association_v1.parse_accept($2);
 authority_value:=public.zasp_runtime_gateway_credential_authority($1,'runtime-gateway');
 IF(authority_value->>'organization_id',authority_value->>'workspace_id',authority_value->>'environment_id',authority_value->>'device_id') IS DISTINCT FROM(v->>'organization_id',v->>'workspace_id',v->>'environment_id',v->>'device_id') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='association Device binding rejected';END IF;
 PERFORM zasp_authorization80_worker.gateway_organization_lock(v->>'organization_id');
 f:=zasp_agent_device_association_v1.source_facts(v->>'organization_id',v->>'workspace_id',v->>'environment_id',v->>'agent_id');
 d:=zasp_agent_device_association_v1.device_facts(v->>'organization_id',v->>'workspace_id',v->>'environment_id',v->>'device_id',$1,(authority_value->>'credential_generation')::bigint);
 SELECT * INTO p FROM zasp_agent_device_association_v1.pairs x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.association_id,x.agent_id,x.device_id)=(v->>'organization_id',v->>'workspace_id',v->>'environment_id',v->>'association_id',v->>'agent_id',v->>'device_id') FOR UPDATE;
 SELECT * INTO c FROM zasp_agent_device_association_v1.challenges x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.challenge_id,x.association_id)=(v->>'organization_id',v->>'workspace_id',v->>'environment_id',v->>'challenge_id',v->>'association_id') FOR UPDATE;
 IF NOT FOUND OR p.association_id IS NULL OR c.wire IS DISTINCT FROM decode(translate(v->>'wire','-_','+/')||repeat('=',(4-length(v->>'wire')%4)%4),'base64') OR c.state NOT IN('pending_device','pending_human') OR c.expected_version<>p.version OR p.version<>(v->>'expected_association_version')::bigint OR f->>'status'<>'current' OR f->>'digest' IS DISTINCT FROM v->>'agent_source_digest' OR d->>'reason' IS NOT NULL OR c.nonce_digest IS DISTINCT FROM public.digest(decode(translate(v->>'nonce','-_','+/')||'=','base64'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='association live challenge authority rejected';END IF;
 SELECT * INTO a FROM zasp_agent_device_association_v1.acceptances x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.challenge_id)=(c.organization_id,c.workspace_id,c.environment_id,c.challenge_id) FOR SHARE;
 IF FOUND THEN
  IF a.credential_id<>$1 OR a.credential_generation<>(authority_value->>'credential_generation')::bigint OR a.request_digest IS DISTINCT FROM public.digest($2,'sha256') OR c.expires_at<=clock_timestamp() OR a.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='association acceptance replay rejected';END IF;
  RETURN jsonb_build_object('receipt',a.response||jsonb_build_object('replayed',a.accepted_tx<>pg_current_xact_id()),'new_mutation',a.accepted_tx=pg_current_xact_id());
 END IF;
 accepted:=clock_timestamp();expiry:=LEAST(c.expires_at,(d#>>'{credential,expires_at}')::timestamptz);
 IF expiry<=accepted OR(f#>>'{snapshot,fresh_until}')::timestamptz<=accepted THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='association challenge expired';END IF;
 r:=jsonb_build_object('challenge_id',c.challenge_id,'challenge_sha256',encode(public.digest(c.wire,'sha256'),'hex'),'association_id',c.association_id,'acceptance',jsonb_build_object('request_sha256',encode(public.digest($2,'sha256'),'hex'),'credential',d->'credential','accepted_at',zasp_agent_device_association_v1.stamp(accepted),'expires_at',zasp_agent_device_association_v1.stamp(expiry)),'replayed',false);
 INSERT INTO zasp_agent_device_association_v1.acceptances(organization_id,workspace_id,environment_id,challenge_id,credential_id,credential_generation,request_digest,response,accepted_at,expires_at) VALUES(c.organization_id,c.workspace_id,c.environment_id,c.challenge_id,$1,(authority_value->>'credential_generation')::bigint,public.digest($2,'sha256'),r,accepted,expiry);
 UPDATE zasp_agent_device_association_v1.challenges x SET state='pending_human' WHERE(x.organization_id,x.workspace_id,x.environment_id,x.challenge_id)=(c.organization_id,c.workspace_id,c.environment_id,c.challenge_id);
 INSERT INTO public.zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) VALUES(c.organization_id,c.workspace_id,c.environment_id,public.zasp_discovery_canonical_id(c.organization_id,c.workspace_id,c.environment_id,'agent_device_acceptance_audit',c.challenge_id),$1,'agent.device.intent.accept',p.agent_id,'succeeded',jsonb_build_object('association_id',c.association_id,'challenge_id',c.challenge_id,'credential_generation',(authority_value->>'credential_generation')::bigint),accepted);
 RETURN jsonb_build_object('receipt',r,'new_mutation',true);
END $$;
CREATE FUNCTION zasp_agent_device_association_v1.confirm_device(credential_id text,body bytea,expected_receipt jsonb,pin text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE actual jsonb;v jsonb;a zasp_agent_device_association_v1.acceptances%ROWTYPE;c zasp_agent_device_association_v1.challenges%ROWTYPE;d jsonb;f jsonb;BEGIN
 -- Re-executing the closed operation is an exact replay fence under the same
 -- organization/Agent/Device/own-row locks. Immutable accepted_tx distinguishes
 -- an old receipt from an effect newly committed by this transaction.
 actual:=zasp_agent_device_association_v1.accept_intent($1,$2,$4);
 IF actual IS DISTINCT FROM $3 THEN RETURN false;END IF;
 v:=zasp_agent_device_association_v1.parse_accept($2);
 SELECT * INTO STRICT a FROM zasp_agent_device_association_v1.acceptances x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.challenge_id)=(v->>'organization_id',v->>'workspace_id',v->>'environment_id',v->>'challenge_id') FOR SHARE;
 SELECT * INTO STRICT c FROM zasp_agent_device_association_v1.challenges x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.challenge_id)=(a.organization_id,a.workspace_id,a.environment_id,a.challenge_id) FOR SHARE;
 f:=zasp_agent_device_association_v1.source_facts(a.organization_id,a.workspace_id,a.environment_id,v->>'agent_id');
 d:=zasp_agent_device_association_v1.device_facts(a.organization_id,a.workspace_id,a.environment_id,v->>'device_id',$1,a.credential_generation);
 RETURN zasp_agent_device_association_v1.caller_ready('gateway-control',$4) AND f->>'status'='current' AND f->>'digest'=v->>'agent_source_digest' AND d->>'reason' IS NULL AND c.state='pending_human' AND a.request_digest=public.digest($2,'sha256') AND a.expires_at>clock_timestamp() AND c.expires_at>clock_timestamp() AND(f#>>'{snapshot,fresh_until}')::timestamptz>clock_timestamp() AND(f->>'entity_fresh_until')::timestamptz>clock_timestamp() AND(d#>>'{credential,expires_at}')::timestamptz>clock_timestamp();
END $$;
DO $association_owners$ DECLARE p record;BEGIN
 FOR p IN SELECT oid::regprocedure signature FROM pg_proc WHERE pronamespace='zasp_agent_device_association_v1'::regnamespace LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p.signature);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zasp_discovery_api,zasp_gateway_control',p.signature);
 END LOOP;
END $association_owners$;
GRANT USAGE ON SCHEMA zasp_agent_device_association_v1 TO zasp_discovery_api,zasp_gateway_control;
GRANT EXECUTE ON FUNCTION zasp_agent_device_association_v1.caller_ready(text,text),zasp_agent_device_association_v1.create_intent(text,text,text,text,text,text,text,bytea,bigint,text,bytea,integer,text),zasp_agent_device_association_v1.activate(text,text,text,text,text,text,text,bytea,bigint,text,bytea,text),zasp_agent_device_association_v1.revoke(text,text,text,text,text,text,bigint,text,bytea,text),zasp_agent_device_association_v1.page(text,text,text,text,text,integer,text),zasp_agent_device_association_v1.confirm_human(text,text,text,text,text,text,text,bytea,jsonb,text) TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION zasp_agent_device_association_v1.caller_ready(text,text),zasp_agent_device_association_v1.accept_intent(text,bytea,text),zasp_agent_device_association_v1.confirm_device(text,bytea,jsonb,text) TO zasp_gateway_control;
