CREATE SCHEMA zasp_gateway_bootstrap_v1 AUTHORIZATION zasp_discovery_authority;
-- gateway bootstrap authority definitions
REVOKE ALL ON SCHEMA zasp_gateway_bootstrap_v1 FROM PUBLIC;
CREATE TABLE zasp_gateway_bootstrap_v1.registration(singleton boolean NOT NULL DEFAULT true,checksum text NOT NULL,rawseal text NOT NULL,CONSTRAINT registration_pkey PRIMARY KEY(singleton),CONSTRAINT registration_singleton_ck CHECK(singleton),CONSTRAINT registration_checksum_ck CHECK(checksum ~ '^[a-f0-9]{64}$'),CONSTRAINT registration_rawseal_ck CHECK(rawseal ~ '^[a-f0-9]{64}$'));
ALTER TABLE zasp_gateway_bootstrap_v1.registration OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_gateway_bootstrap_v1.registration ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_gateway_bootstrap_v1.registration FORCE ROW LEVEL SECURITY;
REVOKE ALL ON zasp_gateway_bootstrap_v1.registration FROM PUBLIC,zasp_gateway_control,zasp_discovery_api;
CREATE POLICY authority ON zasp_gateway_bootstrap_v1.registration TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE TABLE zasp_gateway_bootstrap_v1.mutations(organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,actor text NOT NULL,operation text NOT NULL,idempotency_key text NOT NULL,request_digest bytea NOT NULL,result jsonb NOT NULL,material jsonb NOT NULL,recorded_at timestamp with time zone NOT NULL,created_tx xid8 NOT NULL DEFAULT pg_current_xact_id(),CONSTRAINT mutations_pkey PRIMARY KEY(organization_id,workspace_id,environment_id,actor,operation,idempotency_key),CONSTRAINT mutations_digest_ck CHECK(octet_length(request_digest)=32),CONSTRAINT mutations_result_ck CHECK(jsonb_typeof(result)='object'),CONSTRAINT mutations_material_ck CHECK(jsonb_typeof(material)='object'));
ALTER TABLE zasp_gateway_bootstrap_v1.mutations OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_gateway_bootstrap_v1.mutations ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_gateway_bootstrap_v1.mutations FORCE ROW LEVEL SECURITY;
REVOKE ALL ON zasp_gateway_bootstrap_v1.mutations FROM PUBLIC,zasp_discovery_api,zasp_gateway_control;
CREATE POLICY authority ON zasp_gateway_bootstrap_v1.mutations TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE FUNCTION zasp_gateway_bootstrap_v1.fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 WITH facts(v) AS (
 SELECT concat_ws('|','schema',nspowner,nspacl::text) FROM pg_namespace WHERE nspname='zasp_gateway_bootstrap_v1'
 UNION ALL SELECT concat_ws('|','type',t.oid,t.typname,t.typowner,t.typacl::text,t.typtype,t.typcategory,t.typrelid,t.typelem,t.typarray,t.typbasetype,t.typisdefined,t.typnotnull,t.typndims,t.typcollation,t.typinput,t.typoutput,t.typreceive,t.typsend,t.typmodin,t.typmodout,t.typanalyze,t.typsubscript,t.typlen,t.typbyval,t.typalign,t.typstorage,t.typdelim,t.typdefaultbin::text,t.typdefault) FROM pg_type t WHERE t.typnamespace='zasp_gateway_bootstrap_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','function',p.oid::regprocedure::text,p.proowner,p.proacl::text,pg_get_functiondef(p.oid)) FROM pg_proc p WHERE p.pronamespace='zasp_gateway_bootstrap_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','relation',c.relname,c.relkind,c.relowner,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity) FROM pg_class c WHERE c.relnamespace='zasp_gateway_bootstrap_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attacl::text,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid)) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_gateway_bootstrap_v1'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_class c JOIN pg_constraint k ON k.conrelid=c.oid WHERE c.relnamespace='zasp_gateway_bootstrap_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','index',i.indexrelid::regclass::text,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_gateway_bootstrap_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','trigger',t.tgrelid,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='zasp_gateway_bootstrap_v1'::regnamespace AND NOT t.tgisinternal
 UNION ALL SELECT concat_ws('|','policy',p.polrelid,p.polname,p.polcmd,p.polpermissive,p.polroles::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_gateway_bootstrap_v1'::regnamespace
 ) SELECT encode(public.digest(convert_to(string_agg(v,E'\n' ORDER BY v),'UTF8'),'sha256'),'hex') FROM facts
$$;
CREATE FUNCTION zasp_gateway_bootstrap_v1.immutable_registration() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='gateway bootstrap registration is immutable';END
$$;
CREATE TRIGGER immutable_registration BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_gateway_bootstrap_v1.registration FOR EACH STATEMENT EXECUTE FUNCTION zasp_gateway_bootstrap_v1.immutable_registration();
CREATE FUNCTION zasp_gateway_bootstrap_v1.raw_seal_ready() RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE manifest constant text:=$coverage_manifest$-- gateway bootstrap manifest$coverage_manifest$;part jsonb;field jsonb;f record;t record;expected integer;expr text;BEGIN
 IF(SELECT count(*) FROM zasp_gateway_bootstrap_v1.registration)<>1 OR NOT EXISTS(SELECT 1 FROM zasp_gateway_bootstrap_v1.registration WHERE singleton AND checksum='-- gateway bootstrap checksum' AND rawseal=zasp_gateway_bootstrap_v1.fingerprint()) THEN RETURN false;END IF;
 IF(SELECT count(*) FROM pg_proc WHERE pronamespace='zasp_gateway_bootstrap_v1'::regnamespace)<>17 OR(SELECT count(*) FROM pg_class WHERE relnamespace='zasp_gateway_bootstrap_v1'::regnamespace AND relkind='r')<>2 OR(SELECT count(*) FROM pg_class WHERE relnamespace='zasp_gateway_bootstrap_v1'::regnamespace AND relkind='i')<>2 OR EXISTS(SELECT 1 FROM pg_class WHERE relnamespace='zasp_gateway_bootstrap_v1'::regnamespace AND relkind NOT IN('r','i')) THEN RETURN false;END IF;
 FOR part IN SELECT value FROM jsonb_array_elements(manifest::jsonb->'own') LOOP
  SELECT p.*,l.lanname INTO STRICT f FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=(part->>'signature')::regprocedure;
  IF f.proowner<>'zasp_discovery_authority'::regrole OR NOT f.prosecdef OR f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, public'] OR f.prokind<>'f' OR f.proretset OR f.proisstrict OR f.proleakproof OR f.proparallel<>'u' OR f.provariadic<>0 OR f.pronargdefaults<>0 OR f.proallargtypes IS NOT NULL OR f.proargmodes IS NOT NULL OR f.proargnames IS DISTINCT FROM ARRAY(SELECT jsonb_array_elements_text(part->'argnames')) AND NOT(part->'argnames'='[]'::jsonb AND f.proargnames IS NULL) OR f.lanname<>part->>'language' OR f.provolatile::text<>part->>'volatility' OR f.prorettype<>(part->>'returns')::regtype THEN RETURN false;END IF;
  IF encode(public.digest(convert_to(replace(replace(f.prosrc,'-- gateway bootstrap checksum','-- gateway bootstrap '||'checksum'),manifest,'-- gateway bootstrap '||'manifest'),'UTF8'),'sha256'),'hex')<>part->>'source' THEN RETURN false;END IF;
  IF EXISTS(SELECT 1 FROM aclexplode(COALESCE(f.proacl,acldefault('f',f.proowner))) a WHERE a.grantor<>f.proowner OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR a.grantee<>f.proowner AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(part->'roles') role_name WHERE a.grantee=role_name::regrole)) OR NOT has_function_privilege(f.proowner,f.oid,'EXECUTE') OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(part->'roles') role_name WHERE NOT has_function_privilege(role_name,f.oid,'EXECUTE')) THEN RETURN false;END IF;
 END LOOP;
 FOR part IN SELECT value FROM jsonb_array_elements(manifest::jsonb->'tables') LOOP
  SELECT * INTO STRICT t FROM pg_class WHERE oid=('zasp_gateway_bootstrap_v1.'||(part->>'name'))::regclass;
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
 IF(SELECT count(*) FROM pg_type WHERE typnamespace='zasp_gateway_bootstrap_v1'::regnamespace)<>4 OR(SELECT count(*) FROM pg_trigger x JOIN pg_class t ON t.oid=x.tgrelid WHERE t.relnamespace='zasp_gateway_bootstrap_v1'::regnamespace AND NOT x.tgisinternal)<>1 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='zasp_gateway_bootstrap_v1.registration'::regclass AND tgname='immutable_registration' AND tgenabled='O' AND tgtype=58 AND tgnargs=0 AND tgfoid='zasp_gateway_bootstrap_v1.immutable_registration()'::regprocedure) THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='zasp_gateway_bootstrap_v1' AND(n.nspowner<>'zasp_discovery_authority'::regrole OR a.grantor<>n.nspowner OR a.is_grantable OR NOT(a.grantee=n.nspowner AND a.privilege_type IN('USAGE','CREATE') OR a.grantee IN('zasp_discovery_api'::regrole,'zasp_gateway_control'::regrole) AND a.privilege_type='USAGE'))) OR NOT has_schema_privilege('zasp_gateway_control','zasp_gateway_bootstrap_v1','USAGE') OR NOT has_schema_privilege('zasp_discovery_api','zasp_gateway_bootstrap_v1','USAGE') THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM pg_operator WHERE oprnamespace='zasp_gateway_bootstrap_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_collation WHERE collnamespace='zasp_gateway_bootstrap_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_conversion WHERE connamespace='zasp_gateway_bootstrap_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_opclass WHERE opcnamespace='zasp_gateway_bootstrap_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_opfamily WHERE opfnamespace='zasp_gateway_bootstrap_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_ts_config WHERE cfgnamespace='zasp_gateway_bootstrap_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_ts_dict WHERE dictnamespace='zasp_gateway_bootstrap_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_ts_parser WHERE prsnamespace='zasp_gateway_bootstrap_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_ts_template WHERE tmplnamespace='zasp_gateway_bootstrap_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_statistic_ext WHERE stxnamespace='zasp_gateway_bootstrap_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_extension WHERE extnamespace='zasp_gateway_bootstrap_v1'::regnamespace) THEN RETURN false;END IF;
 RETURN true;EXCEPTION WHEN OTHERS THEN RETURN false;END
$$;
CREATE FUNCTION zasp_gateway_bootstrap_v1.effective_ready() RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE manifest constant text:=$coverage_manifest$-- gateway bootstrap manifest$coverage_manifest$;part jsonb;f record;BEGIN
 -- Trusted compiled parent bodies and exact owner/ACL frames are independent of
 -- registration's captured live seal. No parent or dynamic data is cached.
 FOR part IN SELECT value FROM jsonb_array_elements(manifest::jsonb->'parents') LOOP
  SELECT p.* INTO STRICT f FROM pg_proc p WHERE p.oid=(part->>'signature')::regprocedure;
  IF f.proowner<>'zasp_discovery_authority'::regrole OR f.prosecdef IS DISTINCT FROM(part->>'secdef')::boolean OR f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, public'] OR encode(public.digest(convert_to(f.prosrc,'UTF8'),'sha256'),'hex')<>part->>'source' OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(f.proacl,acldefault('f',f.proowner))) a WHERE a.grantor<>f.proowner OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR a.grantee<>f.proowner AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(part->'roles') role_name WHERE a.grantee=role_name::regrole)) OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(part->'roles') role_name WHERE NOT has_function_privilege(role_name,f.oid,'EXECUTE')) THEN RETURN false;END IF;
 END LOOP;
 RETURN COALESCE(zasp_gateway_bootstrap_v1.raw_seal_ready()
 AND zasp_authorization79.ready('-- gateway bootstrap parent79') AND zasp_authorization80.ready('-- gateway bootstrap parent80') AND zasp_authorization80_temporal.ready()
 AND zasp_authorization80_worker.catalog_ready() AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE singleton AND checksum='-- gateway bootstrap worker')
 AND zasp_authorization80_runtime.catalog_ready() AND zasp_authorization80_runtime.current_ready() AND EXISTS(SELECT 1 FROM zasp_authorization80_runtime.registration WHERE singleton AND checksum='-- gateway bootstrap runtime')
 AND(SELECT count(*)=1 AND bool_and(singleton AND name='canonical61-temporal78-authorization79-80-v1' AND audit_mode='-- gateway bootstrap audit mode' AND identity_mode='-- gateway bootstrap identity mode') FROM zasp_authorization80.runtime_profile)
 -- gateway bootstrap selected parent predicate
 ,false);EXCEPTION WHEN OTHERS THEN RETURN false;END
$$;
CREATE FUNCTION zasp_gateway_bootstrap_v1.caller_ready(purpose text,pin text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT COALESCE(pin='-- gateway bootstrap checksum' AND zasp_gateway_bootstrap_v1.effective_ready() AND CASE purpose WHEN 'gateway-control' THEN public.zasp_runtime_principal_ready('zasp_gateway_control') WHEN 'public-api' THEN public.zasp_discovery_principal_ready('zasp_discovery_api') ELSE false END,false)
$$;
CREATE FUNCTION zasp_gateway_bootstrap_v1.stamp(t timestamp with time zone) RETURNS text LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT regexp_replace(to_char($1 AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),'\.?0+$','')||'Z'
$$;
CREATE FUNCTION zasp_gateway_bootstrap_v1.require_public(o text,w text,e text,actor text,operation text,pin text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE proof jsonb;revision jsonb;permission_value text;BEGIN
 IF $5 NOT IN('createGatewayDevice','issueGatewayEnrollment','revokeGatewayEnrollment','getGatewayDevice') OR NOT zasp_gateway_bootstrap_v1.caller_ready('public-api',$6) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='gateway bootstrap unavailable';END IF;
 permission_value:=CASE WHEN $5='getGatewayDevice' THEN 'view' ELSE 'manage_identity' END;
 proof:=zasp_authorization80.context();
 PERFORM zasp_authorization80.require_read($1,$2,$3,ARRAY[$5],permission_value,false,$4);
 IF COALESCE((proof->>'collection')::boolean,true) OR NOT zasp_authorization80.allowed($1,$2,$3,'environment',$3) OR($5<>'getGatewayDevice' AND proof->>'credential_kind'='1' AND NOT COALESCE((proof->>'fresh_auth')::boolean,false)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='gateway environment purpose rejected';END IF;
 PERFORM zasp_authorization80_worker.gateway_api_organization_lock($1);
 revision:=proof->'revision';
 PERFORM zasp_authorization79.revalidate($1,(revision->>'desired')::bigint,(revision->>'generation')::bigint,revision->>'store_id',revision->>'model_id');
 PERFORM zasp_authorization80.identity_fence(proof);
 IF proof IS DISTINCT FROM zasp_authorization80.context() OR NOT zasp_gateway_bootstrap_v1.caller_ready('public-api',$6) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='gateway authority changed';END IF;
 RETURN proof;
END $$;
CREATE FUNCTION zasp_gateway_bootstrap_v1.device_value(o text,w text,e text,device_id text) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT jsonb_build_object('id',d.id,'name',d.name,'state',d.state,'version',d.version,'replay_floor',d.replay_floor,'created_at',zasp_gateway_bootstrap_v1.stamp(d.created_at)) FROM public.zasp_gateway_devices d WHERE(d.organization_id,d.workspace_id,d.environment_id,d.id)=($1,$2,$3,$4)
$$;
CREATE FUNCTION zasp_gateway_bootstrap_v1.enrollment_value(o text,w text,e text,device_id text,enrollment_id text) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT jsonb_build_object('id',t.id,'device_id',t.device_id,'token_generation',t.token_generation,'device_version',t.device_version_at_issue,'audience',t.audience,'issued_at',zasp_gateway_bootstrap_v1.stamp(t.issued_at),'expires_at',zasp_gateway_bootstrap_v1.stamp(t.expires_at),'consumed_at',zasp_gateway_bootstrap_v1.stamp(t.consumed_at),'revoked_at',zasp_gateway_bootstrap_v1.stamp(t.revoked_at)) FROM public.zasp_gateway_enrollment_tokens t WHERE(t.organization_id,t.workspace_id,t.environment_id,t.device_id,t.id)=($1,$2,$3,$4,$5) AND t.format_version=1
$$;
CREATE FUNCTION zasp_gateway_bootstrap_v1.mutate(o text,w text,e text,actor text,operation text,idempotency_key text,request_digest bytea,device_id text,device_name text,expected_version bigint,enrollment_id text,locator_digest bytea,salt bytea,token_hash bytea,expires_at timestamp with time zone,pin text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE proof jsonb;prior zasp_gateway_bootstrap_v1.mutations%ROWTYPE;d public.zasp_gateway_devices%ROWTYPE;native jsonb;result_value jsonb;material_value jsonb:='{}';generation_value bigint;next_credential bigint;recorded timestamp with time zone;BEGIN
 proof:=zasp_gateway_bootstrap_v1.require_public($1,$2,$3,$4,$5,$16);
 IF $5 NOT IN('createGatewayDevice','issueGatewayEnrollment','revokeGatewayEnrollment') OR NOT public.zasp_valid_product_id($4) OR NOT public.zasp_valid_product_id($8) OR $6 IS NULL OR length($6) NOT BETWEEN 16 AND 128 OR $6!~'^[A-Za-z0-9._:-]+$' OR $7 IS NULL OR octet_length($7)<>32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='gateway mutation rejected';END IF;
 IF $5<>'createGatewayDevice' AND proof#>>'{path_parameters,id}' IS DISTINCT FROM $8 OR $5='revokeGatewayEnrollment' AND proof#>>'{path_parameters,enrollmentId}' IS DISTINCT FROM $11 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='gateway path target rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1,$2,$3,$8),0));
 PERFORM zasp_gateway_bootstrap_v1.require_public($1,$2,$3,$4,$5,$16);
 SELECT * INTO prior FROM zasp_gateway_bootstrap_v1.mutations m WHERE(m.organization_id,m.workspace_id,m.environment_id,m.actor,m.operation,m.idempotency_key)=($1,$2,$3,$4,$5,$6) FOR UPDATE;
 IF FOUND THEN
  IF prior.request_digest<>$7 THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='gateway idempotency conflict';END IF;
  PERFORM zasp_gateway_bootstrap_v1.require_public($1,$2,$3,$4,$5,$16);
  RETURN prior.result||jsonb_build_object('replayed',true,'new_mutation',false);
 END IF;
 SELECT * INTO d FROM public.zasp_gateway_devices x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.id)=($1,$2,$3,$8) FOR UPDATE;
 IF $5='createGatewayDevice' THEN
  IF FOUND OR $9 IS NULL OR octet_length($9) NOT BETWEEN 1 AND 128 OR $9<>btrim($9) OR $9~'[[:cntrl:]]' THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='gateway create conflict';END IF;
  native:=public.zasp_discovery_create_gateway_device($1,$2,$3,$8,$9);
 ELSE
  IF NOT FOUND OR d.version IS DISTINCT FROM $10 OR d.state NOT IN('pending','active') OR NOT public.zasp_valid_product_id($11) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='gateway device version changed';END IF;
  IF $5='issueGatewayEnrollment' THEN
   IF $12 IS NULL OR octet_length($12)<>32 OR $13 IS NULL OR octet_length($13)<>32 OR $14 IS NULL OR octet_length($14)<>32 OR $15 IS NULL OR $15<=clock_timestamp() OR $15>clock_timestamp()+interval '24 hours' OR date_trunc('second',$15)<>$15 OR $11=$8 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='gateway enrollment material rejected';END IF;
   IF EXISTS(SELECT 1 FROM public.zasp_gateway_credentials c WHERE(c.organization_id,c.workspace_id,c.environment_id,c.device_id)=($1,$2,$3,$8) AND c.format_version=1 AND c.revoked_at IS NULL) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='gateway current credential exists';END IF;
   SELECT COALESCE(max(t.token_generation),0)+1 INTO generation_value FROM public.zasp_gateway_enrollment_tokens t WHERE(t.organization_id,t.workspace_id,t.environment_id,t.device_id)=($1,$2,$3,$8) AND t.token_generation IS NOT NULL;
   SELECT COALESCE(max(c.credential_generation),0)+1 INTO next_credential FROM public.zasp_gateway_credentials c WHERE(c.organization_id,c.workspace_id,c.environment_id,c.device_id)=($1,$2,$3,$8) AND c.credential_generation IS NOT NULL;
   native:=public.zasp_runtime_issue_gateway_enrollment($1,$2,$3,$11,$8,generation_value,$10,$12,$13,$14,$15);
   IF native->>'replayed' IS DISTINCT FROM 'false' THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='gateway native token already exists';END IF;
   material_value:=jsonb_build_object('device_id',$8,'enrollment_id',$11,'token_generation',generation_value,'device_version',$10,'locator_digest',encode($12,'hex'),'salt',encode($13,'hex'),'token_hash',encode($14,'hex'),'expires_at',zasp_gateway_bootstrap_v1.stamp($15),'credential_generation',next_credential);
  ELSE
   native:=public.zasp_runtime_revoke_gateway_enrollment($1,$2,$3,$8,$11);
  END IF;
 END IF;
 recorded:=clock_timestamp();
 result_value:=jsonb_build_object('operation',$5,'device',zasp_gateway_bootstrap_v1.device_value($1,$2,$3,$8),'enrollment',CASE WHEN $5='createGatewayDevice' THEN NULL ELSE zasp_gateway_bootstrap_v1.enrollment_value($1,$2,$3,$8,$11) END,'credential_generation',CASE WHEN $5='issueGatewayEnrollment' THEN next_credential ELSE NULL END);
 INSERT INTO zasp_gateway_bootstrap_v1.mutations(organization_id,workspace_id,environment_id,actor,operation,idempotency_key,request_digest,result,material,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,result_value,material_value,recorded);
 INSERT INTO public.zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) VALUES($1,$2,$3,public.zasp_discovery_canonical_id($1,$2,$3,'gateway_bootstrap_audit',jsonb_build_array($4,$5,$6)::text),$4,CASE $5 WHEN 'createGatewayDevice' THEN 'gateway.device.create' WHEN 'issueGatewayEnrollment' THEN 'gateway.enrollment.issue' ELSE 'gateway.enrollment.revoke' END,$8,'succeeded',jsonb_build_object('device_version',(result_value#>>'{device,version}')::bigint),recorded);
 PERFORM zasp_gateway_bootstrap_v1.require_public($1,$2,$3,$4,$5,$16);
 IF $5='issueGatewayEnrollment' AND $15<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='gateway token expired during issue';END IF;
 RETURN result_value||jsonb_build_object('replayed',false,'new_mutation',true);
END $$;
CREATE FUNCTION zasp_gateway_bootstrap_v1.create_device(o text,w text,e text,actor text,idempotency_key text,request_digest bytea,device_id text,device_name text,pin text) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT zasp_gateway_bootstrap_v1.mutate($1,$2,$3,$4,'createGatewayDevice',$5,$6,$7,$8,NULL,NULL,NULL,NULL,NULL,NULL,$9)
$$;
CREATE FUNCTION zasp_gateway_bootstrap_v1.issue_enrollment(o text,w text,e text,actor text,idempotency_key text,request_digest bytea,device_id text,expected_version bigint,enrollment_id text,locator_digest bytea,salt bytea,token_hash bytea,expires_at timestamp with time zone,pin text) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT zasp_gateway_bootstrap_v1.mutate($1,$2,$3,$4,'issueGatewayEnrollment',$5,$6,$7,NULL,$8,$9,$10,$11,$12,$13,$14)
$$;
CREATE FUNCTION zasp_gateway_bootstrap_v1.revoke_enrollment(o text,w text,e text,actor text,idempotency_key text,request_digest bytea,device_id text,expected_version bigint,enrollment_id text,pin text) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT zasp_gateway_bootstrap_v1.mutate($1,$2,$3,$4,'revokeGatewayEnrollment',$5,$6,$7,NULL,$8,$9,NULL,NULL,NULL,NULL,$10)
$$;
CREATE FUNCTION zasp_gateway_bootstrap_v1.get_device(o text,w text,e text,device_id text,pin text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE proof jsonb;device jsonb;enrollment jsonb;next_generation bigint;state_value text;BEGIN
 proof:=zasp_gateway_bootstrap_v1.require_public($1,$2,$3,NULL,'getGatewayDevice',$5);
 IF NOT public.zasp_valid_product_id($4) OR proof#>>'{path_parameters,id}' IS DISTINCT FROM $4 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='gateway request target rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1,$2,$3,$4),0));
 device:=zasp_gateway_bootstrap_v1.device_value($1,$2,$3,$4);
 IF device IS NULL THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='gateway unavailable';END IF;
 SELECT zasp_gateway_bootstrap_v1.enrollment_value($1,$2,$3,$4,t.id) INTO enrollment FROM public.zasp_gateway_enrollment_tokens t WHERE(t.organization_id,t.workspace_id,t.environment_id,t.device_id)=($1,$2,$3,$4) AND t.format_version=1 ORDER BY t.token_generation DESC LIMIT 1;
 SELECT COALESCE(max(c.credential_generation),0)+1 INTO next_generation FROM public.zasp_gateway_credentials c WHERE(c.organization_id,c.workspace_id,c.environment_id,c.device_id)=($1,$2,$3,$4) AND c.credential_generation IS NOT NULL;
 state_value:=CASE WHEN device->>'state' NOT IN('pending','active') THEN 'device_unavailable' WHEN EXISTS(SELECT 1 FROM public.zasp_gateway_credentials c WHERE(c.organization_id,c.workspace_id,c.environment_id,c.device_id)=($1,$2,$3,$4) AND c.format_version=1 AND c.revoked_at IS NULL) THEN 'existing_credential' WHEN EXISTS(SELECT 1 FROM public.zasp_gateway_enrollment_tokens t WHERE(t.organization_id,t.workspace_id,t.environment_id,t.device_id)=($1,$2,$3,$4) AND t.format_version=1 AND t.consumed_at IS NULL AND t.revoked_at IS NULL) THEN 'existing_enrollment' ELSE 'available' END;
 PERFORM zasp_gateway_bootstrap_v1.require_public($1,$2,$3,NULL,'getGatewayDevice',$5);
 RETURN jsonb_build_object('device',device,'latest_enrollment',enrollment,'next_credential_generation',next_generation,'issuance_state',state_value);
END $$;
CREATE FUNCTION zasp_gateway_bootstrap_v1.confirm_public(o text,w text,e text,actor text,operation text,idempotency_key text,request_digest bytea,expected_receipt jsonb,pin text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE r zasp_gateway_bootstrap_v1.mutations%ROWTYPE;expected jsonb;fresh boolean;BEGIN
 PERFORM zasp_gateway_bootstrap_v1.require_public($1,$2,$3,$4,$5,$9);
 SELECT * INTO r FROM zasp_gateway_bootstrap_v1.mutations m WHERE(m.organization_id,m.workspace_id,m.environment_id,m.actor,m.operation,m.idempotency_key)=($1,$2,$3,$4,$5,$6) FOR UPDATE;
 IF NOT FOUND OR r.request_digest IS DISTINCT FROM $7 OR jsonb_typeof($8)<>'object' OR jsonb_typeof($8->'new_mutation') IS DISTINCT FROM 'boolean' THEN RETURN false;END IF;
 fresh:=($8->>'new_mutation')::boolean;
 IF fresh AND r.created_tx<>pg_current_xact_id() THEN RETURN false;END IF;
 expected:=r.result||jsonb_build_object('new_mutation',fresh,'replayed',NOT fresh);
 IF expected IS DISTINCT FROM $8 THEN RETURN false;END IF;
 IF fresh AND $5='issueGatewayEnrollment' THEN
  IF NOT EXISTS(SELECT 1 FROM public.zasp_gateway_enrollment_tokens t WHERE(t.organization_id,t.workspace_id,t.environment_id,t.device_id,t.id)=($1,$2,$3,r.material->>'device_id',r.material->>'enrollment_id') AND t.format_version=1 AND t.token_generation=(r.material->>'token_generation')::bigint AND t.device_version_at_issue=(r.material->>'device_version')::bigint AND t.locator_digest=decode(r.material->>'locator_digest','hex') AND t.salt=decode(r.material->>'salt','hex') AND t.token_hash=decode(r.material->>'token_hash','hex') AND t.expires_at=(r.material->>'expires_at')::timestamptz AND t.consumed_at IS NULL AND t.revoked_at IS NULL)
  OR EXISTS(SELECT 1 FROM public.zasp_gateway_credentials c WHERE(c.organization_id,c.workspace_id,c.environment_id,c.device_id)=($1,$2,$3,r.material->>'device_id') AND c.format_version=1 AND c.revoked_at IS NULL)
  OR(SELECT COALESCE(max(c.credential_generation),0)+1 FROM public.zasp_gateway_credentials c WHERE(c.organization_id,c.workspace_id,c.environment_id,c.device_id)=($1,$2,$3,r.material->>'device_id') AND c.credential_generation IS NOT NULL) IS DISTINCT FROM(r.material->>'credential_generation')::bigint THEN RETURN false;END IF;
 END IF;
 PERFORM zasp_gateway_bootstrap_v1.require_public($1,$2,$3,$4,$5,$9);
 -- Last check after all potentially blocking queries; original own marker and
 -- exact native tuple above distinguish a new token from historical metadata.
 IF fresh AND $5='issueGatewayEnrollment' AND(r.material->>'expires_at')::timestamptz<=clock_timestamp() THEN RETURN false;END IF;
 RETURN true;
END $$;
CREATE FUNCTION zasp_gateway_bootstrap_v1.prepare_issue(o text,w text,e text,actor text,idempotency_key text,request_digest bytea,device_id text,expected_version bigint,pin text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE proof jsonb;r zasp_gateway_bootstrap_v1.mutations%ROWTYPE;d public.zasp_gateway_devices%ROWTYPE;token_generation bigint;credential_generation bigint;BEGIN
 proof:=zasp_gateway_bootstrap_v1.require_public($1,$2,$3,$4,'issueGatewayEnrollment',$9);
 IF proof#>>'{path_parameters,id}' IS DISTINCT FROM $7 OR NOT public.zasp_valid_product_id($7) OR $8<1 OR $6 IS NULL OR octet_length($6)<>32 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='gateway issue prepare rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1,$2,$3,$7),0));
 SELECT * INTO r FROM zasp_gateway_bootstrap_v1.mutations m WHERE(m.organization_id,m.workspace_id,m.environment_id,m.actor,m.operation,m.idempotency_key)=($1,$2,$3,$4,'issueGatewayEnrollment',$5) FOR UPDATE;
 IF FOUND THEN
  IF r.request_digest<>$6 THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='gateway idempotency conflict';END IF;
  RETURN jsonb_build_object('device_version',(r.result#>>'{enrollment,device_version}')::bigint,'token_generation',(r.result#>>'{enrollment,token_generation}')::bigint,'credential_generation',(r.result->>'credential_generation')::bigint,'replayed',true);
 END IF;
 SELECT * INTO d FROM public.zasp_gateway_devices x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.id)=($1,$2,$3,$7) FOR UPDATE;
 IF NOT FOUND OR d.version IS DISTINCT FROM $8 OR d.state NOT IN('pending','active') OR EXISTS(SELECT 1 FROM public.zasp_gateway_credentials c WHERE(c.organization_id,c.workspace_id,c.environment_id,c.device_id)=($1,$2,$3,$7) AND c.format_version=1 AND c.revoked_at IS NULL) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='gateway issue prepare unavailable';END IF;
 SELECT COALESCE(max(t.token_generation),0)+1 INTO token_generation FROM public.zasp_gateway_enrollment_tokens t WHERE(t.organization_id,t.workspace_id,t.environment_id,t.device_id)=($1,$2,$3,$7) AND t.token_generation IS NOT NULL;
 SELECT COALESCE(max(c.credential_generation),0)+1 INTO credential_generation FROM public.zasp_gateway_credentials c WHERE(c.organization_id,c.workspace_id,c.environment_id,c.device_id)=($1,$2,$3,$7) AND c.credential_generation IS NOT NULL;
 PERFORM zasp_gateway_bootstrap_v1.require_public($1,$2,$3,$4,'issueGatewayEnrollment',$9);
 RETURN jsonb_build_object('device_version',d.version,'token_generation',token_generation,'credential_generation',credential_generation,'replayed',false);
END $$;
CREATE FUNCTION zasp_gateway_bootstrap_v1.enrollment_final_fence(locator bytea,secret bytea,credential_id text,expected_receipt jsonb,pin text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE a jsonb;c jsonb;t public.zasp_gateway_enrollment_tokens%ROWTYPE;v jsonb;BEGIN
 IF NOT zasp_gateway_bootstrap_v1.caller_ready('gateway-control',$5) OR jsonb_typeof($4) IS DISTINCT FROM 'object' THEN RETURN false;END IF;
 a:=public.zasp_runtime_authenticate_gateway_enrollment($1,$2,'runtime-gateway-enroll');
 c:=public.zasp_runtime_gateway_credential_authority($3,'runtime-gateway');v:=$4;
 IF NOT v ?& ARRAY['schema','request_sha256','organization_id','workspace_id','environment_id','device_id','enrollment_id','token_generation','credential_id','credential_generation','key_id','algorithm','public_key','audience','issued_at','expires_at','replayed'] OR v-ARRAY['schema','request_sha256','organization_id','workspace_id','environment_id','device_id','enrollment_id','token_generation','credential_id','credential_generation','key_id','algorithm','public_key','audience','issued_at','expires_at','replayed']<>'{}'::jsonb OR v->>'schema'<>'gateway-enrollment-receipt-v1' OR v->>'request_sha256'!~'^[0-9a-f]{64}$' OR jsonb_typeof(v->'replayed') IS DISTINCT FROM 'boolean' THEN RETURN false;END IF;
 IF(c->>'organization_id',c->>'workspace_id',c->>'environment_id',c->>'device_id',c->>'credential_id',c->>'credential_generation',c->>'key_id',c->>'algorithm',c->>'public_key',c->>'audience') IS DISTINCT FROM(v->>'organization_id',v->>'workspace_id',v->>'environment_id',v->>'device_id',v->>'credential_id',v->>'credential_generation',v->>'key_id',v->>'algorithm',v->>'public_key',v->>'audience') OR $3 IS DISTINCT FROM v->>'credential_id'
 OR(a->>'organization_id',a->>'workspace_id',a->>'environment_id',a->>'device_id',a->>'enrollment_id',a->>'token_generation') IS DISTINCT FROM(v->>'organization_id',v->>'workspace_id',v->>'environment_id',v->>'device_id',v->>'enrollment_id',v->>'token_generation') THEN RETURN false;END IF;
 SELECT * INTO t FROM public.zasp_gateway_enrollment_tokens x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.device_id,x.id)=(a->>'organization_id',a->>'workspace_id',a->>'environment_id',a->>'device_id',a->>'enrollment_id');
 IF NOT FOUND OR t.revoked_at IS NOT NULL OR t.consumed_at IS NULL OR t.format_version<>1 THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM public.zasp_gateway_credentials x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.device_id,x.id,x.enrollment_token_id)=(a->>'organization_id',a->>'workspace_id',a->>'environment_id',a->>'device_id',$3,t.id) AND x.issued_at=(v->>'issued_at')::timestamptz AND x.expires_at=(v->>'expires_at')::timestamptz AND x.credential_generation=(v->>'credential_generation')::bigint) THEN RETURN false;END IF;
 IF NOT zasp_gateway_bootstrap_v1.caller_ready('gateway-control',$5) THEN RETURN false;END IF;
 -- No blocking query after this final token AND credential wall-clock fence.
 RETURN COALESCE(t.expires_at>clock_timestamp() AND(c->>'expires_at')::timestamptz>clock_timestamp(),false);
EXCEPTION WHEN data_exception THEN RETURN false;END $$;
DO $bootstrap_owners$ DECLARE p record;BEGIN
 FOR p IN SELECT p.oid::regprocedure identity FROM pg_proc p WHERE p.pronamespace='zasp_gateway_bootstrap_v1'::regnamespace LOOP
  EXECUTE 'ALTER FUNCTION '||p.identity||' OWNER TO zasp_discovery_authority';EXECUTE 'REVOKE ALL ON FUNCTION '||p.identity||' FROM PUBLIC,zasp_gateway_control,zasp_discovery_api';
 END LOOP;
END $bootstrap_owners$;
GRANT USAGE ON SCHEMA zasp_gateway_bootstrap_v1 TO zasp_discovery_api,zasp_gateway_control;
GRANT EXECUTE ON FUNCTION zasp_gateway_bootstrap_v1.caller_ready(text,text) TO zasp_discovery_api,zasp_gateway_control;
GRANT EXECUTE ON FUNCTION zasp_gateway_bootstrap_v1.create_device(text,text,text,text,text,bytea,text,text,text),zasp_gateway_bootstrap_v1.issue_enrollment(text,text,text,text,text,bytea,text,bigint,text,bytea,bytea,bytea,timestamp with time zone,text),zasp_gateway_bootstrap_v1.revoke_enrollment(text,text,text,text,text,bytea,text,bigint,text,text),zasp_gateway_bootstrap_v1.get_device(text,text,text,text,text),zasp_gateway_bootstrap_v1.confirm_public(text,text,text,text,text,text,bytea,jsonb,text) TO zasp_discovery_api;

GRANT EXECUTE ON FUNCTION zasp_gateway_bootstrap_v1.prepare_issue(text,text,text,text,text,bytea,text,bigint,text) TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION zasp_gateway_bootstrap_v1.enrollment_final_fence(bytea,bytea,text,jsonb,text) TO zasp_gateway_control;
