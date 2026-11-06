CREATE SCHEMA zasp_gateway_installation_v1 AUTHORIZATION zasp_discovery_authority;
-- gateway installation authority definitions
REVOKE ALL ON SCHEMA zasp_gateway_installation_v1 FROM PUBLIC;
CREATE TABLE zasp_gateway_installation_v1.registration(singleton boolean NOT NULL DEFAULT true,checksum text NOT NULL,rawseal text NOT NULL,CONSTRAINT registration_pkey PRIMARY KEY(singleton),CONSTRAINT registration_singleton_ck CHECK(singleton),CONSTRAINT registration_checksum_ck CHECK(checksum ~ '^[a-f0-9]{64}$'),CONSTRAINT registration_rawseal_ck CHECK(rawseal ~ '^[a-f0-9]{64}$'));
ALTER TABLE zasp_gateway_installation_v1.registration OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_gateway_installation_v1.registration ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_gateway_installation_v1.registration FORCE ROW LEVEL SECURITY;
REVOKE ALL ON zasp_gateway_installation_v1.registration FROM PUBLIC,zasp_gateway_control;
CREATE POLICY authority ON zasp_gateway_installation_v1.registration TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE TABLE zasp_gateway_installation_v1.latest(organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,device_id text NOT NULL,credential_id text NOT NULL,credential_generation bigint NOT NULL,sequence bigint NOT NULL,installed_observed_at timestamp with time zone NOT NULL,request_digest bytea NOT NULL,wire bytea NOT NULL,recorded_at timestamp with time zone NOT NULL,recorded_tx xid8 NOT NULL DEFAULT pg_current_xact_id(),CONSTRAINT latest_pkey PRIMARY KEY(organization_id,workspace_id,environment_id,device_id,credential_id,credential_generation),CONSTRAINT latest_generation_ck CHECK(credential_generation>0),CONSTRAINT latest_sequence_ck CHECK(sequence>0),CONSTRAINT latest_digest_ck CHECK(octet_length(request_digest)=32),CONSTRAINT latest_wire_min_ck CHECK(octet_length(wire)>0),CONSTRAINT latest_wire_max_ck CHECK(octet_length(wire)<=4096));
ALTER TABLE zasp_gateway_installation_v1.latest OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_gateway_installation_v1.latest ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_gateway_installation_v1.latest FORCE ROW LEVEL SECURITY;
REVOKE ALL ON zasp_gateway_installation_v1.latest FROM PUBLIC,zasp_gateway_control;
CREATE POLICY authority ON zasp_gateway_installation_v1.latest TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE FUNCTION zasp_gateway_installation_v1.fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 WITH facts(v) AS (
 SELECT concat_ws('|','schema',nspowner,nspacl::text) FROM pg_namespace WHERE nspname='zasp_gateway_installation_v1'
 UNION ALL SELECT concat_ws('|','type',t.oid,t.typname,t.typowner,t.typacl::text,t.typtype,t.typcategory,t.typrelid,t.typelem,t.typarray,t.typbasetype,t.typisdefined,t.typnotnull,t.typndims,t.typcollation,t.typinput,t.typoutput,t.typreceive,t.typsend,t.typmodin,t.typmodout,t.typanalyze,t.typsubscript,t.typlen,t.typbyval,t.typalign,t.typstorage,t.typdelim,t.typdefaultbin::text,t.typdefault) FROM pg_type t WHERE t.typnamespace='zasp_gateway_installation_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','function',p.oid::regprocedure::text,p.proowner,p.proacl::text,pg_get_functiondef(p.oid)) FROM pg_proc p WHERE p.pronamespace='zasp_gateway_installation_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','relation',c.relname,c.relkind,c.relowner,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity) FROM pg_class c WHERE c.relnamespace='zasp_gateway_installation_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attacl::text,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid)) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_gateway_installation_v1'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_class c JOIN pg_constraint k ON k.conrelid=c.oid WHERE c.relnamespace='zasp_gateway_installation_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','index',i.indexrelid::regclass::text,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_gateway_installation_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','trigger',t.tgrelid,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='zasp_gateway_installation_v1'::regnamespace AND NOT t.tgisinternal
 UNION ALL SELECT concat_ws('|','policy',p.polrelid,p.polname,p.polcmd,p.polpermissive,p.polroles::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_gateway_installation_v1'::regnamespace
 ) SELECT encode(public.digest(convert_to(string_agg(v,E'\n' ORDER BY v),'UTF8'),'sha256'),'hex') FROM facts
$$;
CREATE FUNCTION zasp_gateway_installation_v1.immutable_registration() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='gateway installation registration is immutable';END
$$;
CREATE TRIGGER immutable_registration BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_gateway_installation_v1.registration FOR EACH STATEMENT EXECUTE FUNCTION zasp_gateway_installation_v1.immutable_registration();
CREATE FUNCTION zasp_gateway_installation_v1.raw_seal_ready() RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE manifest constant text:=$coverage_manifest$-- gateway installation manifest$coverage_manifest$;part jsonb;field jsonb;f record;t record;expected integer;expr text;BEGIN
 IF(SELECT count(*) FROM zasp_gateway_installation_v1.registration)<>1 OR NOT EXISTS(SELECT 1 FROM zasp_gateway_installation_v1.registration WHERE singleton AND checksum='-- gateway installation checksum' AND rawseal=zasp_gateway_installation_v1.fingerprint()) THEN RETURN false;END IF;
 IF(SELECT count(*) FROM pg_proc WHERE pronamespace='zasp_gateway_installation_v1'::regnamespace)<>9 OR(SELECT count(*) FROM pg_class WHERE relnamespace='zasp_gateway_installation_v1'::regnamespace AND relkind='r')<>2 OR(SELECT count(*) FROM pg_class WHERE relnamespace='zasp_gateway_installation_v1'::regnamespace AND relkind='i')<>2 OR EXISTS(SELECT 1 FROM pg_class WHERE relnamespace='zasp_gateway_installation_v1'::regnamespace AND relkind NOT IN('r','i')) THEN RETURN false;END IF;
 FOR part IN SELECT value FROM jsonb_array_elements(manifest::jsonb->'own') LOOP
  SELECT p.*,l.lanname INTO STRICT f FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=(part->>'signature')::regprocedure;
  IF f.proowner<>'zasp_discovery_authority'::regrole OR NOT f.prosecdef OR f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, public'] OR f.prokind<>'f' OR f.proretset OR f.proisstrict OR f.proleakproof OR f.proparallel<>'u' OR f.provariadic<>0 OR f.pronargdefaults<>0 OR f.proallargtypes IS NOT NULL OR f.proargmodes IS NOT NULL OR f.proargnames IS DISTINCT FROM ARRAY(SELECT jsonb_array_elements_text(part->'argnames')) AND NOT(part->'argnames'='[]'::jsonb AND f.proargnames IS NULL) OR f.lanname<>part->>'language' OR f.provolatile::text<>part->>'volatility' OR f.prorettype<>(part->>'returns')::regtype THEN RETURN false;END IF;
  IF encode(public.digest(convert_to(replace(replace(f.prosrc,'-- gateway installation checksum','-- gateway installation '||'checksum'),manifest,'-- gateway installation '||'manifest'),'UTF8'),'sha256'),'hex')<>part->>'source' THEN RETURN false;END IF;
  IF EXISTS(SELECT 1 FROM aclexplode(COALESCE(f.proacl,acldefault('f',f.proowner))) a WHERE a.grantor<>f.proowner OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR a.grantee<>f.proowner AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(part->'roles') role_name WHERE a.grantee=role_name::regrole)) OR NOT has_function_privilege(f.proowner,f.oid,'EXECUTE') OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(part->'roles') role_name WHERE NOT has_function_privilege(role_name,f.oid,'EXECUTE')) THEN RETURN false;END IF;
 END LOOP;
 FOR part IN SELECT value FROM jsonb_array_elements(manifest::jsonb->'tables') LOOP
  SELECT * INTO STRICT t FROM pg_class WHERE oid=('zasp_gateway_installation_v1.'||(part->>'name'))::regclass;
  IF t.relowner<>'zasp_discovery_authority'::regrole OR NOT t.relrowsecurity OR NOT t.relforcerowsecurity OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(t.relacl,acldefault('r',t.relowner))) a WHERE a.grantee<>t.relowner OR a.grantor<>t.relowner OR a.is_grantable) OR(SELECT count(*) FROM pg_policy WHERE polrelid=t.oid)<>1 OR NOT EXISTS(SELECT 1 FROM pg_policy WHERE polrelid=t.oid AND polname='authority' AND polpermissive AND polcmd='*' AND polroles=ARRAY['zasp_discovery_authority'::regrole::oid] AND pg_get_expr(polqual,polrelid)='true' AND pg_get_expr(polwithcheck,polrelid)='true') THEN RETURN false;END IF;
  IF(SELECT count(*) FROM pg_attribute WHERE attrelid=t.oid AND attnum>0 AND NOT attisdropped)<>jsonb_array_length(part->'columns') THEN RETURN false;END IF;
  expected:=0;FOR field IN SELECT value FROM jsonb_array_elements(part->'columns') LOOP
   expected:=expected+1;
   IF NOT EXISTS(SELECT 1 FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid=t.oid AND a.attnum=expected AND a.attname=field->>'name' AND format_type(a.atttypid,a.atttypmod)=field->>'type' AND a.attnotnull AND NOT a.attisdropped AND a.attacl IS NULL AND a.attidentity='' AND a.attgenerated='' AND CASE WHEN field ? 'default_expression' THEN pg_get_expr(d.adbin,d.adrelid)=field->>'default_expression' WHEN(field->>'default')::boolean THEN pg_get_expr(d.adbin,d.adrelid)='true' ELSE d.oid IS NULL END) THEN RETURN false;END IF;
  END LOOP;
  IF(SELECT count(*) FROM pg_constraint WHERE conrelid=t.oid AND contype<>'n')<>1+jsonb_array_length(part->'checks') OR NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=t.oid AND contype='p' AND convalidated AND array_to_string(conkey,',')=part->>'pk') OR EXISTS(SELECT 1 FROM pg_constraint k WHERE k.conrelid=t.oid AND k.contype='n' AND(cardinality(k.conkey) IS DISTINCT FROM 1 OR NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=t.oid AND a.attnum=k.conkey[1] AND a.attnum>0 AND NOT a.attisdropped AND a.attnotnull))) THEN RETURN false;END IF;
  FOR field IN SELECT value FROM jsonb_array_elements(part->'checks') LOOP
   SELECT pg_get_expr(conbin,conrelid) INTO STRICT expr FROM pg_constraint WHERE conrelid=t.oid AND conname=field->>'name' AND contype='c' AND convalidated;
   -- Each fixed CHECK is a single atomic comparison; no boolean regrouping is
   -- normalized. IN's catalog ANY-array spelling is handled separately.
   IF translate(regexp_replace(expr,'::text','','g'),E' \n\t()','') IS DISTINCT FROM translate(field->>'expression',E' \n\t()','') THEN RETURN false;END IF;
  END LOOP;
  IF(SELECT count(*) FROM pg_index WHERE indrelid=t.oid)<>1 OR NOT EXISTS(SELECT 1 FROM pg_index WHERE indrelid=t.oid AND indisprimary AND indisunique AND indisvalid AND indisready AND indislive AND replace(indkey::text,' ',',')=part->>'pk') THEN RETURN false;END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_type c JOIN pg_type a ON a.oid=c.typarray WHERE c.oid=t.reltype AND c.typnamespace=t.relnamespace AND c.typrelid=t.oid AND c.typtype='c' AND c.typcategory='C' AND c.typname=part->>'name' AND c.typowner=t.relowner AND c.typacl IS NULL AND c.typelem=0 AND c.typbasetype=0 AND c.typisdefined AND NOT c.typnotnull AND c.typndims=0 AND c.typdefault IS NULL AND c.typdefaultbin IS NULL AND a.typnamespace=t.relnamespace AND a.typname='_'||(part->>'name') AND a.typowner=t.relowner AND a.typacl IS NULL AND a.typtype='b' AND a.typcategory='A' AND a.typelem=c.oid AND a.typrelid=0 AND a.typarray=0 AND a.typbasetype=0 AND a.typisdefined AND NOT a.typnotnull AND a.typndims=0 AND a.typdefault IS NULL AND a.typdefaultbin IS NULL) THEN RETURN false;END IF;
 END LOOP;
 IF(SELECT count(*) FROM pg_type WHERE typnamespace='zasp_gateway_installation_v1'::regnamespace)<>4 OR(SELECT count(*) FROM pg_trigger x JOIN pg_class t ON t.oid=x.tgrelid WHERE t.relnamespace='zasp_gateway_installation_v1'::regnamespace AND NOT x.tgisinternal)<>1 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='zasp_gateway_installation_v1.registration'::regclass AND tgname='immutable_registration' AND tgenabled='O' AND tgtype=58 AND tgnargs=0 AND tgfoid='zasp_gateway_installation_v1.immutable_registration()'::regprocedure) THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='zasp_gateway_installation_v1' AND(n.nspowner<>'zasp_discovery_authority'::regrole OR a.grantor<>n.nspowner OR a.is_grantable OR NOT(a.grantee=n.nspowner AND a.privilege_type IN('USAGE','CREATE') OR a.grantee='zasp_gateway_control'::regrole AND a.privilege_type='USAGE'))) OR NOT has_schema_privilege('zasp_gateway_control','zasp_gateway_installation_v1','USAGE') THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM pg_operator WHERE oprnamespace='zasp_gateway_installation_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_collation WHERE collnamespace='zasp_gateway_installation_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_conversion WHERE connamespace='zasp_gateway_installation_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_opclass WHERE opcnamespace='zasp_gateway_installation_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_opfamily WHERE opfnamespace='zasp_gateway_installation_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_ts_config WHERE cfgnamespace='zasp_gateway_installation_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_ts_dict WHERE dictnamespace='zasp_gateway_installation_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_ts_parser WHERE prsnamespace='zasp_gateway_installation_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_ts_template WHERE tmplnamespace='zasp_gateway_installation_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_statistic_ext WHERE stxnamespace='zasp_gateway_installation_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_extension WHERE extnamespace='zasp_gateway_installation_v1'::regnamespace) THEN RETURN false;END IF;
 RETURN true;EXCEPTION WHEN OTHERS THEN RETURN false;END
$$;
CREATE FUNCTION zasp_gateway_installation_v1.effective_ready() RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE manifest constant text:=$coverage_manifest$-- gateway installation manifest$coverage_manifest$;part jsonb;f record;BEGIN
 -- Trusted compiled parent bodies and exact owner/ACL frames are independent of
 -- registration's captured live seal. No parent or dynamic data is cached.
 FOR part IN SELECT value FROM jsonb_array_elements(manifest::jsonb->'parents') LOOP
  SELECT p.* INTO STRICT f FROM pg_proc p WHERE p.oid=(part->>'signature')::regprocedure;
  IF f.proowner<>'zasp_discovery_authority'::regrole OR f.prosecdef IS DISTINCT FROM(part->>'secdef')::boolean OR f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, public'] OR encode(public.digest(convert_to(f.prosrc,'UTF8'),'sha256'),'hex')<>part->>'source' OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(f.proacl,acldefault('f',f.proowner))) a WHERE a.grantor<>f.proowner OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR a.grantee<>f.proowner AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(part->'roles') role_name WHERE a.grantee=role_name::regrole)) OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(part->'roles') role_name WHERE NOT has_function_privilege(role_name,f.oid,'EXECUTE')) THEN RETURN false;END IF;
 END LOOP;
 RETURN COALESCE(zasp_gateway_installation_v1.raw_seal_ready()
 AND zasp_authorization79.ready('-- gateway installation parent79') AND zasp_authorization80.ready('-- gateway installation parent80') AND zasp_authorization80_temporal.ready()
 AND zasp_authorization80_worker.catalog_ready() AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE singleton AND checksum='-- gateway installation worker')
 AND zasp_authorization80_runtime.catalog_ready() AND zasp_authorization80_runtime.current_ready() AND EXISTS(SELECT 1 FROM zasp_authorization80_runtime.registration WHERE singleton AND checksum='-- gateway installation runtime')
 AND(SELECT count(*)=1 AND bool_and(singleton AND name='canonical61-temporal78-authorization79-80-v1' AND audit_mode='-- gateway installation audit mode' AND identity_mode='-- gateway installation identity mode') FROM zasp_authorization80.runtime_profile)
 -- gateway installation selected parent predicate
 ,false);EXCEPTION WHEN OTHERS THEN RETURN false;END
$$;
CREATE FUNCTION zasp_gateway_installation_v1.caller_ready(purpose text,pin text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT COALESCE(purpose='gateway-control' AND pin='-- gateway installation checksum' AND zasp_gateway_installation_v1.effective_ready() AND public.zasp_runtime_principal_ready('zasp_gateway_control'),false)
$$;
CREATE FUNCTION zasp_gateway_installation_v1.require_live_credential(credential_id text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE a jsonb;b jsonb;BEGIN
 IF NOT zasp_gateway_installation_v1.caller_ready('gateway-control','-- gateway installation checksum') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='gateway installation unavailable';END IF;
 a:=public.zasp_runtime_gateway_credential_authority($1,'runtime-gateway');
 PERFORM zasp_authorization80_worker.gateway_credential_lock(a->>'organization_id',a->>'workspace_id',a->>'environment_id',a->>'device_id',$1);
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),a->>'organization_id',a->>'workspace_id',a->>'environment_id',a->>'device_id'),0));
 PERFORM 1 FROM public.zasp_gateway_devices d WHERE(d.organization_id,d.workspace_id,d.environment_id,d.id)=(a->>'organization_id',a->>'workspace_id',a->>'environment_id',a->>'device_id') FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='gateway installation device unavailable';END IF;
 PERFORM 1 FROM public.zasp_gateway_credentials c WHERE(c.organization_id,c.workspace_id,c.environment_id,c.device_id,c.id,c.credential_generation)=(a->>'organization_id',a->>'workspace_id',a->>'environment_id',a->>'device_id',$1,(a->>'credential_generation')::bigint) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='gateway installation credential unavailable';END IF;
 b:=public.zasp_runtime_gateway_credential_authority($1,'runtime-gateway');
 IF(a->>'organization_id',a->>'workspace_id',a->>'environment_id',a->>'device_id',a->>'credential_id',a->>'credential_generation') IS DISTINCT FROM(b->>'organization_id',b->>'workspace_id',b->>'environment_id',b->>'device_id',b->>'credential_id',b->>'credential_generation') OR NOT COALESCE((b->>'expires_at')::timestamptz>clock_timestamp(),false) OR NOT zasp_gateway_installation_v1.caller_ready('gateway-control','-- gateway installation checksum') THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='gateway installation authority changed';END IF;
 RETURN b;
END $$;
CREATE FUNCTION zasp_gateway_installation_v1.validate_wire(body bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE original json;v jsonb;k text;stamp text;BEGIN
 IF $1 IS NULL OR octet_length($1) NOT BETWEEN 1 AND 4096 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid gateway installation';END IF;
 original:=convert_from($1,'UTF8')::json;
 IF NOT zasp_authorization80.unique_json(original,0) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='duplicate gateway installation member';END IF;
 v:=original::jsonb;
 IF jsonb_typeof(v)<>'object' OR NOT v ?& ARRAY['schema','credential_generation','contract_version','key_id','algorithm','audience','sequence','policy_version','issued_at','expires_at','failure_mode','payload_digest','signature','installed_observed_at'] OR v-ARRAY['schema','credential_generation','contract_version','key_id','algorithm','audience','sequence','policy_version','issued_at','expires_at','failure_mode','payload_digest','signature','installed_observed_at']<>'{}'::jsonb THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid gateway installation members';END IF;
 FOREACH k IN ARRAY ARRAY['credential_generation','contract_version','sequence','policy_version'] LOOP
  IF jsonb_typeof(v->k) IS DISTINCT FROM 'number' OR original->>k!~'^[1-9][0-9]*$' OR(v->>k)::numeric>9223372036854775807 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid gateway installation integer';END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['schema','key_id','algorithm','audience','issued_at','expires_at','failure_mode','payload_digest','signature','installed_observed_at'] LOOP
  IF jsonb_typeof(v->k) IS DISTINCT FROM 'string' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid gateway installation scalar';END IF;
 END LOOP;
 IF v->>'schema'<>'gateway-policy-installation-v1' OR v->>'contract_version'<>'1' OR v->>'key_id'!~'^[a-z][a-z0-9_-]{7,63}$' OR v->>'algorithm'<>'Ed25519' OR v->>'audience'<>'runtime-gateway-policy' OR v->>'failure_mode' NOT IN('open','closed') OR v->>'payload_digest'!~'^[0-9a-f]{64}$' OR v->>'signature'!~'^[A-Za-z0-9_-]{86}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid gateway installation signed scalars';END IF;
 IF octet_length(decode(translate(v->>'signature','-_','+/')||'==','base64'))<>64 OR translate(rtrim(replace(encode(decode(translate(v->>'signature','-_','+/')||'==','base64'),'base64'),chr(10),''),'='),'+/','-_')<>v->>'signature' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid gateway installation signature encoding';END IF;
 FOREACH k IN ARRAY ARRAY['issued_at','expires_at','installed_observed_at'] LOOP
  stamp:=v->>k;
  IF stamp!~'^[0-9]{4}-[0-9]{2}-[0-9]{2}T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$' OR stamp LIKE '0000-%' OR to_char(stamp::timestamptz AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')<>stamp THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid gateway installation time';END IF;
 END LOOP;
 IF(v->>'expires_at')::timestamptz<=(v->>'issued_at')::timestamptz OR(v->>'expires_at')::timestamptz>(v->>'issued_at')::timestamptz+interval '24 hours' OR(v->>'installed_observed_at')::timestamptz<(v->>'issued_at')::timestamptz-interval '30 seconds' OR(v->>'installed_observed_at')::timestamptz>=(v->>'expires_at')::timestamptz THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid gateway installation interval';END IF;
 RETURN v;
END $$;
CREATE FUNCTION zasp_gateway_installation_v1.record_installation(credential_id text,body bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE a jsonb;v jsonb;p public.zasp_runtime_gateway_policy_bundles%ROWTYPE;r zasp_gateway_installation_v1.latest%ROWTYPE;h bytea;had boolean;exact boolean;disposition text;stamp text;BEGIN
 a:=zasp_gateway_installation_v1.require_live_credential($1);v:=zasp_gateway_installation_v1.validate_wire($2);h:=public.digest($2,'sha256');
 IF(v->>'credential_generation')::bigint IS DISTINCT FROM(a->>'credential_generation')::bigint THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='gateway installation generation changed';END IF;
 SELECT * INTO p FROM public.zasp_runtime_gateway_policy_bundles b WHERE(b.organization_id,b.workspace_id,b.environment_id,b.device_id,b.sequence)=(a->>'organization_id',a->>'workspace_id',a->>'environment_id',a->>'device_id',(v->>'sequence')::bigint) FOR SHARE;
 IF NOT FOUND OR(p.credential_id,p.contract_version,p.key_id,p.algorithm,p.audience,p.policy_version,p.issued_at,p.expires_at,p.failure_mode,p.payload_digest,p.signature) IS DISTINCT FROM($1,(v->>'contract_version')::integer,v->>'key_id',v->>'algorithm',v->>'audience',(v->>'policy_version')::bigint,(v->>'issued_at')::timestamptz,(v->>'expires_at')::timestamptz,v->>'failure_mode',decode(v->>'payload_digest','hex'),decode(translate(v->>'signature','-_','+/')||'==','base64')) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='gateway installation published policy mismatch';END IF;
 SELECT * INTO r FROM zasp_gateway_installation_v1.latest x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.device_id,x.credential_id,x.credential_generation)=(a->>'organization_id',a->>'workspace_id',a->>'environment_id',a->>'device_id',$1,(a->>'credential_generation')::bigint) FOR UPDATE;
 had:=FOUND;exact:=had AND r.request_digest=h AND r.wire=$2;
 IF NOT exact AND(p.expires_at<=clock_timestamp() OR(v->>'installed_observed_at')::timestamptz>clock_timestamp()+interval '30 seconds') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='gateway installation policy expired';END IF;
 IF NOT had OR((v->>'sequence')::bigint,(v->>'installed_observed_at')::timestamptz,encode(h,'hex') COLLATE "C")>(r.sequence,r.installed_observed_at,encode(r.request_digest,'hex') COLLATE "C") THEN
  INSERT INTO zasp_gateway_installation_v1.latest(organization_id,workspace_id,environment_id,device_id,credential_id,credential_generation,sequence,installed_observed_at,request_digest,wire,recorded_at,recorded_tx)
  VALUES(a->>'organization_id',a->>'workspace_id',a->>'environment_id',a->>'device_id',$1,(a->>'credential_generation')::bigint,(v->>'sequence')::bigint,(v->>'installed_observed_at')::timestamptz,h,$2,clock_timestamp(),pg_current_xact_id())
  ON CONFLICT ON CONSTRAINT latest_pkey DO UPDATE SET sequence=EXCLUDED.sequence,installed_observed_at=EXCLUDED.installed_observed_at,request_digest=EXCLUDED.request_digest,wire=EXCLUDED.wire,recorded_at=EXCLUDED.recorded_at,recorded_tx=EXCLUDED.recorded_tx RETURNING * INTO r;
 END IF;
 PERFORM zasp_gateway_installation_v1.require_live_credential($1);
 IF(r.recorded_tx=pg_current_xact_id() OR r.request_digest<>h OR r.wire<>$2) AND(p.expires_at<=clock_timestamp() OR(v->>'installed_observed_at')::timestamptz>clock_timestamp()+interval '30 seconds') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='gateway installation expired during record';END IF;
 disposition:=CASE WHEN r.request_digest=h AND r.wire=$2 THEN 'recorded' ELSE 'coalesced' END;
 stamp:=to_char(r.recorded_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS')||CASE WHEN extract(microseconds FROM r.recorded_at)::bigint%1000000=0 THEN '' ELSE '.'||rtrim(to_char(r.recorded_at AT TIME ZONE 'UTC','US'),'0') END||'Z';
 RETURN jsonb_build_object('schema','gateway-policy-installation-receipt-v1','request_sha256',encode(h,'hex'),'organization_id',r.organization_id,'workspace_id',r.workspace_id,'environment_id',r.environment_id,'device_id',r.device_id,'credential_id',r.credential_id,'credential_generation',r.credential_generation,'disposition',disposition,'representative_sha256',encode(r.request_digest,'hex'),'representative_sequence',r.sequence,'representative_installed_observed_at',to_char(r.installed_observed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),'representative_recorded_at',stamp);
END $$;
CREATE FUNCTION zasp_gateway_installation_v1.confirm_receipt(credential_id text,body bytea,expected_receipt jsonb) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE a jsonb;v jsonb;p public.zasp_runtime_gateway_policy_bundles%ROWTYPE;r zasp_gateway_installation_v1.latest%ROWTYPE;h bytea;receipt jsonb;stamp text;exact boolean;BEGIN
 a:=zasp_gateway_installation_v1.require_live_credential($1);v:=zasp_gateway_installation_v1.validate_wire($2);h:=public.digest($2,'sha256');
 IF(v->>'credential_generation')::bigint IS DISTINCT FROM(a->>'credential_generation')::bigint THEN RETURN false;END IF;
 SELECT * INTO p FROM public.zasp_runtime_gateway_policy_bundles b WHERE(b.organization_id,b.workspace_id,b.environment_id,b.device_id,b.sequence)=(a->>'organization_id',a->>'workspace_id',a->>'environment_id',a->>'device_id',(v->>'sequence')::bigint) FOR SHARE;
 IF NOT FOUND OR(p.credential_id,p.contract_version,p.key_id,p.algorithm,p.audience,p.policy_version,p.issued_at,p.expires_at,p.failure_mode,p.payload_digest,p.signature) IS DISTINCT FROM($1,(v->>'contract_version')::integer,v->>'key_id',v->>'algorithm',v->>'audience',(v->>'policy_version')::bigint,(v->>'issued_at')::timestamptz,(v->>'expires_at')::timestamptz,v->>'failure_mode',decode(v->>'payload_digest','hex'),decode(translate(v->>'signature','-_','+/')||'==','base64')) THEN RETURN false;END IF;
 SELECT * INTO r FROM zasp_gateway_installation_v1.latest x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.device_id,x.credential_id,x.credential_generation)=(a->>'organization_id',a->>'workspace_id',a->>'environment_id',a->>'device_id',$1,(a->>'credential_generation')::bigint) FOR UPDATE;
 IF NOT FOUND THEN RETURN false;END IF;
 exact:=r.request_digest=h AND r.wire=$2;
 IF NOT exact AND NOT(r.sequence,r.installed_observed_at,encode(r.request_digest,'hex') COLLATE "C")>((v->>'sequence')::bigint,(v->>'installed_observed_at')::timestamptz,encode(h,'hex') COLLATE "C") THEN RETURN false;END IF;
 -- Reauthenticate after every possible own-row wait. Parent writers share the
 -- organization/device lock, so the published row matched by record is stable.
 PERFORM zasp_gateway_installation_v1.require_live_credential($1);
 IF(r.recorded_tx=pg_current_xact_id() OR NOT exact) AND((v->>'expires_at')::timestamptz<=clock_timestamp() OR(v->>'installed_observed_at')::timestamptz>clock_timestamp()+interval '30 seconds') THEN RETURN false;END IF;
 stamp:=to_char(r.recorded_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS')||CASE WHEN extract(microseconds FROM r.recorded_at)::bigint%1000000=0 THEN '' ELSE '.'||rtrim(to_char(r.recorded_at AT TIME ZONE 'UTC','US'),'0') END||'Z';
 receipt:=jsonb_build_object('schema','gateway-policy-installation-receipt-v1','request_sha256',encode(h,'hex'),'organization_id',r.organization_id,'workspace_id',r.workspace_id,'environment_id',r.environment_id,'device_id',r.device_id,'credential_id',r.credential_id,'credential_generation',r.credential_generation,'disposition',CASE WHEN exact THEN 'recorded' ELSE 'coalesced' END,'representative_sha256',encode(r.request_digest,'hex'),'representative_sequence',r.sequence,'representative_installed_observed_at',to_char(r.installed_observed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),'representative_recorded_at',stamp);
 RETURN COALESCE(receipt=$3,false);
END $$;
DO $installation_owners$
DECLARE p record;BEGIN
 FOR p IN SELECT p.oid::regprocedure identity FROM pg_proc p WHERE p.pronamespace='zasp_gateway_installation_v1'::regnamespace LOOP
  EXECUTE 'ALTER FUNCTION '||p.identity||' OWNER TO zasp_discovery_authority';
  EXECUTE 'REVOKE ALL ON FUNCTION '||p.identity||' FROM PUBLIC,zasp_gateway_control';
 END LOOP;
END $installation_owners$;
GRANT USAGE ON SCHEMA zasp_gateway_installation_v1 TO zasp_gateway_control;
GRANT EXECUTE ON FUNCTION zasp_gateway_installation_v1.caller_ready(text,text),zasp_gateway_installation_v1.record_installation(text,bytea),zasp_gateway_installation_v1.confirm_receipt(text,bytea,jsonb) TO zasp_gateway_control;
