-- Legacy linked-test boundary only. Original child/journal/evidence authority is retained.
SET LOCAL lock_timeout='3s';
CREATE SCHEMA zasp_temporal71 AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_temporal71 FROM PUBLIC;
CREATE TABLE zasp_temporal71.registration(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),checksum text NOT NULL,fingerprint text NOT NULL);
CREATE TABLE zasp_temporal71.predecessor_functions(signature text PRIMARY KEY,definition text NOT NULL,owner_name text NOT NULL,acl text NOT NULL);
DO $tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['registration','predecessor_functions'] LOOP
  EXECUTE format('ALTER TABLE zasp_temporal71.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_temporal71.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_temporal71.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_temporal71.%I USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',n);
  EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal71.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n);
 END LOOP;
END $tables$;
CREATE FUNCTION zasp_temporal71.ready(c text,f text) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
BEGIN RETURN COALESCE(c='-- legacy71 checksum' AND f='-- legacy71 fingerprint' AND zasp_temporal70.ready('-- compatibility70 checksum','-- compatibility70 fingerprint')
 AND (SELECT count(*)=1 FROM zasp_temporal71.registration) AND EXISTS(SELECT 1 FROM zasp_temporal71.registration WHERE checksum=c AND fingerprint=f) AND zasp_temporal71.fingerprint()=f,false);END $ready$;
CREATE FUNCTION zasp_temporal71.current_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$ SELECT zasp_temporal71.ready('-- legacy71 checksum','-- legacy71 fingerprint') $ready$;
CREATE FUNCTION zasp_temporal71.client_ready(c text,f text,a text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $client$
 SELECT zasp_temporal71.ready(c,f) AND CASE WHEN a='zasp_security_agent_worker' THEN public.zasp_sa_export_principal_ready(a) WHEN a IN('zasp_red_team_worker','zasp_red_team_adapter') THEN public.zasp_red_team_principal_ready(a) ELSE false END
$client$;
CREATE FUNCTION zasp_temporal71.require_principal(a text) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $principal$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='legacy test requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal71.client_ready('-- legacy71 checksum','-- legacy71 fingerprint',a) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='legacy test principal unavailable';END IF;
END $principal$;
CREATE FUNCTION zasp_temporal71.legacy_parent(o text,w text,e text,r text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $parent$
 SELECT NOT zasp_temporal66.is_temporal(o,w,e,r) AND EXISTS(SELECT 1 FROM public.zasp_security_agent_runs rr JOIN public.zasp_security_agent_definition_versions d ON (d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.version)=(rr.organization_id,rr.workspace_id,rr.environment_id,rr.definition_id,rr.definition_version) WHERE (rr.organization_id,rr.workspace_id,rr.environment_id,rr.run_id)=(o,w,e,r) AND d.definition->'allowed_actions' IN('["run_test"]'::jsonb,'["rerun_test"]'::jsonb) AND d.definition_digest=digest(convert_to(d.definition::text,'UTF8'),'sha256'))
$parent$;
CREATE FUNCTION zasp_temporal71.require_parent(o text,w text,e text,r text,child boolean) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $parent$
DECLARE parent_id text:=r;BEGIN
 IF child THEN SELECT run_id INTO parent_id FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,r);END IF;
 IF parent_id IS NULL OR NOT zasp_temporal71.legacy_parent(o,w,e,parent_id) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='legacy test parent rejected';END IF;
END $parent$;
DO $sources$ DECLARE x record;p record;BEGIN
 FOR x IN SELECT * FROM (VALUES
 ('zasp_production_security_agent_existing_tests_cancel_core(text,text,text,text,bigint,text,bytea,bytea)','b78010cee2aa6a33d5d7b2a4f027cb4ad53d79b3bd6d1aff41e705a3684cee12','{zasp_discovery_authority=X/zasp_discovery_authority}'),
 ('zasp_production_security_agent_existing_tests_invocation_comple(text,text,text,text,integer,bytea,text,bytea,integer,bytea,boolean,bytea,text,text)','982290c03285393a189e5c1562631bfb3f76f847594e27bda1c260951c3fde85','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_red_team_adapter=X/zasp_discovery_authority}'),
 ('zasp_production_security_agent_existing_tests_invocation_parent(text,text,text,text)','5f85b40773b479d6597f241cccbd3f15980e8ed59abee2706e03fc206b2c895b','{zasp_discovery_authority=X/zasp_discovery_authority}'),
 ('zasp_production_security_agent_existing_tests_invocation_resolv(text,text,text,text,text,text,bytea,text,text,text)','a1d8220fd3d4fd514eea413faae2c76485095bacf11d5bc240cf6c0840868245','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_red_team_adapter=X/zasp_discovery_authority}'),
 ('zasp_production_security_agent_existing_tests_invocation_start(text,text,text,text,bytea,text,bytea,text,text)','90fee306c54ec571506e526d4c86b66853e365841f92d23cc82ee2873ab8aeec','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_red_team_adapter=X/zasp_discovery_authority}'),
 ('zasp_production_security_agent_existing_tests_invocation_start_(text,text,text,text,bytea,text,bytea)','1bf3dbf36be6c3100cbeca20fe0b34b5dc654bd6c150ce3ae2aaa73bc3c19fd6','{zasp_discovery_authority=X/zasp_discovery_authority}'),
 ('zasp_production_security_agent_existing_tests_reconcile_authori(text,text,text,text,bytea,text,text)','833d50af674750cd1ff33be9719d83c4fbd8d75b952a2af41c84149369b7a045','{zasp_discovery_authority=X/zasp_discovery_authority}'),
 ('zasp_production_security_agent_existing_tests_reconcile_cancel_(text,text,text,text,text,text,bytea,bigint,uuid,text,text)','9ead53f012f60bf13cf142d9bdbd9311db2ba9ca53bd1e171dd489f30ed0c178','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
 ('zasp_production_security_agent_existing_tests_reconcile_claim(text,text,text,text,bytea,integer,integer,text,text)','43543a21a52e396bdf85c42007d1c39f901ad90c368c7184b01a7279c81cc9eb','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
 ('zasp_production_security_agent_existing_tests_reconcile_evidenc(text,text,text,text,text,text,bytea,bigint,uuid,text,text)','d76991d9530136b8a0eda9d91a99cd0d309807f89cace532cd200544f9cc919e','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
 ('zasp_production_security_agent_existing_tests_reconcile_heartbe(text,text,text,text,text,text,bytea,bigint,uuid,integer,text,text)','135dab9423e3492be424926d759e1538fc23c26da5e7706d48f9ad9163f060d3','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
 ('zasp_production_security_agent_existing_tests_reconcile_lock(text,text,text,text,text,text,bytea,bigint,uuid,text,text)','f6a266ad6aef8f2693fd73bada0ff7da955ddba70269a515e0fd1638ef88543e','{zasp_discovery_authority=X/zasp_discovery_authority}'),
 ('zasp_production_security_agent_existing_tests_reconcile_release(text,text,text,text,text,text,bytea,bigint,uuid,integer,text,text)','62baafe7e0e862df3580da1467a2041b8eac22b893d52de5dedd368bd6d233e4','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
 ('zasp_production_security_agent_existing_tests_reconcile_scopes(text,text,text,text,text,text)','35e274086b9712381f7e7c1cd889385e4864e0848ae806600e2cf53387cb518d','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
 ('zasp_production_security_agent_existing_tests_reconcile_settle(text,text,text,text,text,text,bytea,bigint,uuid,jsonb,bytea,text,text)','10acd9367ffe2cc9975f26e6d979bd948b223aa03f5dd5f1103edfa5f04fd589','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
 ('zasp_production_security_agent_existing_tests_worker_cancel(text,text,text,text,text,bytea,bytea,text,text)','61db10c95534ee9c348eec454ce3b99228019fa1f7c9c6379057185e5ec74bc5','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_red_team_worker=X/zasp_discovery_authority}'),
 ('zasp_production_security_agent_existing_tests_worker_claim(text,text,text,text,text,bytea,integer,text,text)','9649a88ba281eeb1d03398256bba30ee04be3c6bc364ba4c993636f54c9dfee7','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_red_team_worker=X/zasp_discovery_authority}'),
 ('zasp_production_security_agent_existing_tests_worker_finish(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint,jsonb,text,text,bytea)','62c1cc9c06069713609f1b7e64892fdc600e75cabcf2b774f17f3e5e01e5ea40','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_red_team_worker=X/zasp_discovery_authority}'),
 ('zasp_production_security_agent_existing_tests_worker_heartbeat(text,text,text,text,text,bytea,integer,text,text)','f9a22de4e9753f90f8661535d3d537432c0d224d486c5d391753135369ee2721','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_red_team_worker=X/zasp_discovery_authority}'),
 ('zasp_production_security_agent_existing_tests_worker_protocol(text,text,text,text,text,text)','2ced9a8de8e074feb6454f4c1778d47f264a1280b9ba301dcb4817d6d241275a','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_red_team_worker=X/zasp_discovery_authority}'),
 ('zasp_production_security_agent_run_context_test_binding(text,text,text,text,bigint)','cf7b7975b47d9b2b4c1a88d5cad945ed9cc68039fc3b6f3820c700c323b2e481','{zasp_discovery_authority=X/zasp_discovery_authority}'),
 ('zasp_production_security_agent_existing_tests_invocation_comple(text,text,text,text,integer,bytea,text,bytea,integer,bytea,boolean,bytea)','fed106259e43aa861db24ced8ee9388e98ad2587771ad37751674b0fd1c703c0','{zasp_discovery_authority=X/zasp_discovery_authority}'),
 ('zasp_production_security_agent_existing_tests_readiness(text,text)','a5b6a22bb3aaf96dcc24f62453459efa0c41d377f5e038e86cecd20f383493a0','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_global_operator=X/zasp_discovery_authority}'),
 ('zasp_sa_attack_lab_guard()','e704927623a7d6a7185a943e81407ec7cf06abc390ffc88982609ffc37492ad0','{zasp_discovery_authority=X/zasp_discovery_authority}')
 ) AS inventory(signature,source_hash,source_acl) LOOP
  SELECT pg_get_functiondef(oid) AS definition,proowner::regrole::text AS owner_name,COALESCE(proacl::text,'') AS acl INTO STRICT p FROM pg_proc WHERE oid=to_regprocedure(x.signature);
  IF p.owner_name<>'zasp_discovery_authority' OR p.acl IS DISTINCT FROM x.source_acl OR encode(digest(convert_to(p.definition,'UTF8'),'sha256'),'hex')<>x.source_hash THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='legacy test predecessor changed';END IF;
  INSERT INTO zasp_temporal71.predecessor_functions VALUES(x.signature,p.definition,p.owner_name,p.acl);
 END LOOP;
END $sources$;
CREATE FUNCTION zasp_temporal71.guard1(expected_checksum text, expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $guard$ SELECT COALESCE(expected_checksum='01920b296d2ebbc4b84c6e714edaf50d6265d630e577bd26297755a15289fa00' AND expected_fingerprint='2c324e78917f97feee14f915b397efbb92a183d47afd7473139dd0691cf0bb04' AND zasp_temporal71.current_ready(),false) $guard$;
CREATE FUNCTION zasp_temporal71.guard2() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $guard$ SELECT COALESCE(zasp_temporal71.current_ready(),false) $guard$;
DO $copies$ DECLARE x record;y record;d text;pattern text;before_count integer;original_count integer;needle text;BEGIN
 PERFORM set_config('check_function_bodies','off',true);
 FOR x IN SELECT * FROM (VALUES
 ('zasp_production_security_agent_existing_tests_cancel_core(text,text,text,text,bigint,text,bytea,bytea)','body01'),
 ('zasp_production_security_agent_existing_tests_invocation_comple(text,text,text,text,integer,bytea,text,bytea,integer,bytea,boolean,bytea,text,text)','body02'),
 ('zasp_production_security_agent_existing_tests_invocation_parent(text,text,text,text)','body03'),
 ('zasp_production_security_agent_existing_tests_invocation_resolv(text,text,text,text,text,text,bytea,text,text,text)','body04'),
 ('zasp_production_security_agent_existing_tests_invocation_start(text,text,text,text,bytea,text,bytea,text,text)','body05'),
 ('zasp_production_security_agent_existing_tests_invocation_start_(text,text,text,text,bytea,text,bytea)','body06'),
 ('zasp_production_security_agent_existing_tests_reconcile_authori(text,text,text,text,bytea,text,text)','body07'),
 ('zasp_production_security_agent_existing_tests_reconcile_cancel_(text,text,text,text,text,text,bytea,bigint,uuid,text,text)','body08'),
 ('zasp_production_security_agent_existing_tests_reconcile_claim(text,text,text,text,bytea,integer,integer,text,text)','body09'),
 ('zasp_production_security_agent_existing_tests_reconcile_evidenc(text,text,text,text,text,text,bytea,bigint,uuid,text,text)','body10'),
 ('zasp_production_security_agent_existing_tests_reconcile_heartbe(text,text,text,text,text,text,bytea,bigint,uuid,integer,text,text)','body11'),
 ('zasp_production_security_agent_existing_tests_reconcile_lock(text,text,text,text,text,text,bytea,bigint,uuid,text,text)','body12'),
 ('zasp_production_security_agent_existing_tests_reconcile_release(text,text,text,text,text,text,bytea,bigint,uuid,integer,text,text)','body13'),
 ('zasp_production_security_agent_existing_tests_reconcile_scopes(text,text,text,text,text,text)','body14'),
 ('zasp_production_security_agent_existing_tests_reconcile_settle(text,text,text,text,text,text,bytea,bigint,uuid,jsonb,bytea,text,text)','body15'),
 ('zasp_production_security_agent_existing_tests_worker_cancel(text,text,text,text,text,bytea,bytea,text,text)','body16'),
 ('zasp_production_security_agent_existing_tests_worker_claim(text,text,text,text,text,bytea,integer,text,text)','body17'),
 ('zasp_production_security_agent_existing_tests_worker_finish(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint,jsonb,text,text,bytea)','body18'),
 ('zasp_production_security_agent_existing_tests_worker_heartbeat(text,text,text,text,text,bytea,integer,text,text)','body19'),
 ('zasp_production_security_agent_existing_tests_worker_protocol(text,text,text,text,text,text)','body20'),
 ('zasp_production_security_agent_run_context_test_binding(text,text,text,text,bigint)','body21'),
 ('zasp_production_security_agent_existing_tests_invocation_comple(text,text,text,text,integer,bytea,text,bytea,integer,bytea,boolean,bytea)','body02')
 ) AS inventory(signature,alias) LOOP
  SELECT definition INTO STRICT d FROM zasp_temporal71.predecessor_functions WHERE signature=x.signature;
  FOR y IN SELECT * FROM (VALUES
 ('public.zasp_production_security_agent_existing_tests_cancel_core','body01'),
 ('public.zasp_production_security_agent_existing_tests_invocation_comple','body02'),
 ('public.zasp_production_security_agent_existing_tests_invocation_parent','body03'),
 ('public.zasp_production_security_agent_existing_tests_invocation_resolv','body04'),
 ('public.zasp_production_security_agent_existing_tests_invocation_start','body05'),
 ('public.zasp_production_security_agent_existing_tests_invocation_start_','body06'),
 ('public.zasp_production_security_agent_existing_tests_reconcile_authori','body07'),
 ('public.zasp_production_security_agent_existing_tests_reconcile_cancel_','body08'),
 ('public.zasp_production_security_agent_existing_tests_reconcile_claim','body09'),
 ('public.zasp_production_security_agent_existing_tests_reconcile_evidenc','body10'),
 ('public.zasp_production_security_agent_existing_tests_reconcile_heartbe','body11'),
 ('public.zasp_production_security_agent_existing_tests_reconcile_lock','body12'),
 ('public.zasp_production_security_agent_existing_tests_reconcile_release','body13'),
 ('public.zasp_production_security_agent_existing_tests_reconcile_scopes','body14'),
 ('public.zasp_production_security_agent_existing_tests_reconcile_settle','body15'),
 ('public.zasp_production_security_agent_existing_tests_worker_cancel','body16'),
 ('public.zasp_production_security_agent_existing_tests_worker_claim','body17'),
 ('public.zasp_production_security_agent_existing_tests_worker_finish','body18'),
 ('public.zasp_production_security_agent_existing_tests_worker_heartbeat','body19'),
 ('public.zasp_production_security_agent_existing_tests_worker_protocol','body20'),
 ('public.zasp_production_security_agent_run_context_test_binding','body21'),
 ('public.zasp_production_security_agent_existing_tests_readiness','guard1'),
 ('public.zasp_sa_attack_lab_guard','guard2')
  ) AS mapping(source_name,alias) LOOP
   -- PostgreSQL truncates identifiers to63 bytes. The exact-signature source
   -- allowlist above includes both completion overloads. Mapping preserves
   -- their arity under one overloaded private name; it never selects an OID by
   -- bare name or changes argument expressions/order.
   pattern:='\m'||CASE WHEN starts_with(y.source_name,'public.') THEN '(public\.)?'||substr(y.source_name,8) ELSE replace(y.source_name,'.','\.') END||CASE WHEN length(split_part(y.source_name,'.',2))=63 THEN '[a-z0-9_]*' ELSE '' END||'\(';
   SELECT count(*) INTO before_count FROM regexp_matches(d,pattern,'g');
   SELECT count(*) INTO original_count FROM zasp_temporal71.predecessor_functions p CROSS JOIN LATERAL regexp_matches(p.definition,pattern,'g') WHERE p.signature=x.signature;
   IF before_count<>original_count THEN RAISE EXCEPTION 'legacy test call replacement changed';END IF;
   d:=regexp_replace(d,pattern,'zasp_temporal71.'||y.alias||'(','g');
  END LOOP;
  IF x.signature='zasp_production_security_agent_existing_tests_reconcile_scopes(text,text,text,text,text,text)' THEN
   needle:='WHERE (l.organization_id COLLATE';
   IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'legacy scope scan changed';END IF;
   d:=replace(d,needle,'WHERE zasp_temporal71.legacy_parent(l.organization_id,l.workspace_id,l.environment_id,l.run_id) AND (l.organization_id COLLATE');
  ELSIF x.signature='zasp_production_security_agent_existing_tests_reconcile_claim(text,text,text,text,bytea,integer,integer,text,text)' THEN
   needle:='WHERE (l.organization_id,l.workspace_id,l.environment_id)=(o,w,e)';
   IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'legacy claim scan changed';END IF;
   d:=replace(d,needle,needle||' AND zasp_temporal71.legacy_parent(l.organization_id,l.workspace_id,l.environment_id,l.run_id)');
  END IF;
  EXECUTE d;
 END LOOP;
 PERFORM set_config('check_function_bodies','on',true);
END $copies$;
-- zasp_production_security_agent_existing_tests_worker_protocol(text,text,text,text,text,text)
CREATE FUNCTION zasp_temporal71.op01(o text, w text, e text, r text, expected_checksum text, expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal71.require_principal('zasp_red_team_worker');
 PERFORM zasp_temporal71.require_parent(o,w,e,r,true);
 RETURN zasp_temporal71.body20(o,w,e,r,expected_checksum,expected_fingerprint);
END $operation$;
-- zasp_production_security_agent_existing_tests_worker_claim(text,text,text,text,text,bytea,integer,text,text)
CREATE FUNCTION zasp_temporal71.op02(o text, w text, e text, r text, worker_value text, lease_value bytea, lease_seconds integer, expected_checksum text, expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal71.require_principal('zasp_red_team_worker');
 PERFORM zasp_temporal71.require_parent(o,w,e,r,true);
 RETURN zasp_temporal71.body17(o,w,e,r,worker_value,lease_value,lease_seconds,expected_checksum,expected_fingerprint);
END $operation$;
-- zasp_production_security_agent_existing_tests_worker_heartbeat(text,text,text,text,text,bytea,integer,text,text)
CREATE FUNCTION zasp_temporal71.op03(o text, w text, e text, r text, worker_value text, lease_value bytea, lease_seconds integer, expected_checksum text, expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal71.require_principal('zasp_red_team_worker');
 PERFORM zasp_temporal71.require_parent(o,w,e,r,true);
 RETURN zasp_temporal71.body19(o,w,e,r,worker_value,lease_value,lease_seconds,expected_checksum,expected_fingerprint);
END $operation$;
-- zasp_production_security_agent_existing_tests_worker_cancel(text,text,text,text,text,bytea,bytea,text,text)
CREATE FUNCTION zasp_temporal71.op04(o text, w text, e text, r text, worker_value text, lease_value bytea, input_value bytea, expected_checksum text, expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal71.require_principal('zasp_red_team_worker');
 PERFORM zasp_temporal71.require_parent(o,w,e,r,true);
 RETURN zasp_temporal71.body16(o,w,e,r,worker_value,lease_value,input_value,expected_checksum,expected_fingerprint);
END $operation$;
-- zasp_production_security_agent_existing_tests_worker_finish(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint,jsonb,text,text,bytea)
CREATE FUNCTION zasp_temporal71.op05(o text, w text, e text, r text, worker_value text, lease_value bytea, input_digest_value bytea, verdict_value text, objective_value text, behavior_value text, error_value text, evidence_value jsonb, reference_value text, key_value text, version_value text, checksum_value bytea, size_value bigint, input_value jsonb, expected_checksum text, expected_fingerprint text, artifact_value bytea) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal71.require_principal('zasp_red_team_worker');
 PERFORM zasp_temporal71.require_parent(o,w,e,r,true);
 RETURN zasp_temporal71.body18(o,w,e,r,worker_value,lease_value,input_digest_value,verdict_value,objective_value,behavior_value,error_value,evidence_value,reference_value,key_value,version_value,checksum_value,size_value,input_value,expected_checksum,expected_fingerprint,artifact_value);
END $operation$;
-- zasp_production_security_agent_existing_tests_invocation_start(text,text,text,text,bytea,text,bytea,text,text)
CREATE FUNCTION zasp_temporal71.op06(o text, w text, e text, r text, lease_value bytea, category_value text, request_digest_value bytea, expected_checksum text, expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal71.require_principal('zasp_red_team_adapter');
 PERFORM zasp_temporal71.require_parent(o,w,e,r,true);
 RETURN zasp_temporal71.body05(o,w,e,r,lease_value,category_value,request_digest_value,expected_checksum,expected_fingerprint);
END $operation$;
-- zasp_production_security_agent_existing_tests_invocation_comple(text,text,text,text,integer,bytea,text,bytea,integer,bytea,boolean,bytea,text,text)
CREATE FUNCTION zasp_temporal71.op07(o text, w text, e text, r text, attempt_value integer, lease_value bytea, category_value text, request_digest_value bytea, status_value integer, response_digest_value bytea, protected_value boolean, credential_version_value bytea, expected_checksum text, expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal71.require_principal('zasp_red_team_adapter');
 PERFORM zasp_temporal71.require_parent(o,w,e,r,true);
 RETURN zasp_temporal71.body02(o,w,e,r,attempt_value,lease_value,category_value,request_digest_value,status_value,response_digest_value,protected_value,credential_version_value,expected_checksum,expected_fingerprint);
END $operation$;
-- zasp_production_security_agent_existing_tests_invocation_resolv(text,text,text,text,text,text,bytea,text,text,text)
CREATE FUNCTION zasp_temporal71.op08(o text, w text, e text, target_value text, target_kind_value text, r text, lease_value bytea, category_value text, expected_checksum text, expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal71.require_principal('zasp_red_team_adapter');
 PERFORM zasp_temporal71.require_parent(o,w,e,r,true);
 RETURN zasp_temporal71.body04(o,w,e,target_value,target_kind_value,r,lease_value,category_value,expected_checksum,expected_fingerprint);
END $operation$;
-- zasp_production_security_agent_existing_tests_reconcile_scopes(text,text,text,text,text,text)
CREATE FUNCTION zasp_temporal71.op09(after_o text, after_w text, after_e text, worker_value text, expected_checksum text, expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal71.require_principal('zasp_security_agent_worker');
 RETURN zasp_temporal71.body14(after_o,after_w,after_e,worker_value,expected_checksum,expected_fingerprint);
END $operation$;
-- zasp_production_security_agent_existing_tests_reconcile_claim(text,text,text,text,bytea,integer,integer,text,text)
CREATE FUNCTION zasp_temporal71.op10(o text, w text, e text, worker_value text, lease_value bytea, seconds_value integer, limit_value integer, expected_checksum text, expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal71.require_principal('zasp_security_agent_worker');
 RETURN zasp_temporal71.body09(o,w,e,worker_value,lease_value,seconds_value,limit_value,expected_checksum,expected_fingerprint);
END $operation$;
-- zasp_production_security_agent_existing_tests_reconcile_evidenc(text,text,text,text,text,text,bytea,bigint,uuid,text,text)
CREATE FUNCTION zasp_temporal71.op11(o text, w text, e text, r text, s text, worker_value text, lease_value bytea, version_value bigint, generation_value uuid, expected_checksum text, expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal71.require_principal('zasp_security_agent_worker');
 PERFORM zasp_temporal71.require_parent(o,w,e,r,false);
 RETURN zasp_temporal71.body10(o,w,e,r,s,worker_value,lease_value,version_value,generation_value,expected_checksum,expected_fingerprint);
END $operation$;
-- zasp_production_security_agent_existing_tests_reconcile_cancel_(text,text,text,text,text,text,bytea,bigint,uuid,text,text)
CREATE FUNCTION zasp_temporal71.op12(o text, w text, e text, r text, s text, worker_value text, lease_value bytea, version_value bigint, generation_value uuid, expected_checksum text, expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal71.require_principal('zasp_security_agent_worker');
 PERFORM zasp_temporal71.require_parent(o,w,e,r,false);
 RETURN zasp_temporal71.body08(o,w,e,r,s,worker_value,lease_value,version_value,generation_value,expected_checksum,expected_fingerprint);
END $operation$;
-- zasp_production_security_agent_existing_tests_reconcile_heartbe(text,text,text,text,text,text,bytea,bigint,uuid,integer,text,text)
CREATE FUNCTION zasp_temporal71.op13(o text, w text, e text, r text, s text, worker_value text, lease_value bytea, version_value bigint, generation_value uuid, seconds_value integer, expected_checksum text, expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal71.require_principal('zasp_security_agent_worker');
 PERFORM zasp_temporal71.require_parent(o,w,e,r,false);
 RETURN zasp_temporal71.body11(o,w,e,r,s,worker_value,lease_value,version_value,generation_value,seconds_value,expected_checksum,expected_fingerprint);
END $operation$;
-- zasp_production_security_agent_existing_tests_reconcile_release(text,text,text,text,text,text,bytea,bigint,uuid,integer,text,text)
CREATE FUNCTION zasp_temporal71.op14(o text, w text, e text, r text, s text, worker_value text, lease_value bytea, version_value bigint, generation_value uuid, delay_value integer, expected_checksum text, expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal71.require_principal('zasp_security_agent_worker');
 PERFORM zasp_temporal71.require_parent(o,w,e,r,false);
 RETURN zasp_temporal71.body13(o,w,e,r,s,worker_value,lease_value,version_value,generation_value,delay_value,expected_checksum,expected_fingerprint);
END $operation$;
-- zasp_production_security_agent_existing_tests_reconcile_settle(text,text,text,text,text,text,bytea,bigint,uuid,jsonb,bytea,text,text)
CREATE FUNCTION zasp_temporal71.op15(o text, w text, e text, r text, s text, worker_value text, lease_value bytea, version_value bigint, generation_value uuid, expected_snapshot jsonb, proof_bytes bytea, expected_checksum text, expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal71.require_principal('zasp_security_agent_worker');
 PERFORM zasp_temporal71.require_parent(o,w,e,r,false);
 RETURN zasp_temporal71.body15(o,w,e,r,s,worker_value,lease_value,version_value,generation_value,expected_snapshot,proof_bytes,expected_checksum,expected_fingerprint);
END $operation$;
-- Read-only routing; the selected operation still owns its independent checks.
CREATE FUNCTION zasp_temporal71.adapter_protocol(o text,w text,e text,r text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $protocol$
DECLARE parent_id text;BEGIN
 PERFORM zasp_temporal71.require_principal('zasp_red_team_adapter');
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(r),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='linked protocol unavailable';END IF;
 SELECT l.run_id INTO parent_id FROM public.zasp_security_agent_test_links l JOIN public.zasp_security_agent_runs p ON (p.organization_id,p.workspace_id,p.environment_id,p.run_id)=(l.organization_id,l.workspace_id,l.environment_id,l.run_id)
 WHERE (l.organization_id,l.workspace_id,l.environment_id,l.test_run_id)=(o,w,e,r) AND NOT zasp_temporal66.is_temporal(o,w,e,l.run_id);
 IF parent_id IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='linked protocol unavailable';END IF;
 IF zasp_temporal71.legacy_parent(o,w,e,parent_id) THEN RETURN jsonb_build_object('protocol','legacy_single_test');END IF;
 IF EXISTS(SELECT 1 FROM public.zasp_security_agent_runs p JOIN public.zasp_security_agent_plans plan USING(organization_id,workspace_id,environment_id,run_id)
 JOIN public.zasp_sa_multistep_runs m USING(organization_id,workspace_id,environment_id,run_id)
 JOIN public.zasp_security_agent_definition_versions d ON (d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.version)=(p.organization_id,p.workspace_id,p.environment_id,p.definition_id,p.definition_version)
 WHERE (p.organization_id,p.workspace_id,p.environment_id,p.run_id)=(o,w,e,parent_id) AND plan.plan->'contract_version'='61'::jsonb AND plan.plan_hash=p.plan_hash AND plan.plan_hash=digest(convert_to(plan.plan::text,'UTF8'),'sha256') AND d.definition_digest=digest(convert_to(d.definition::text,'UTF8'),'sha256')) THEN RETURN jsonb_build_object('protocol','retained_ordered');END IF;
 RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='linked protocol unavailable';
END $protocol$;

DO $fingerprint$ DECLARE d text;BEGIN
 SELECT pg_get_functiondef('zasp_temporal70.fingerprint()'::regprocedure) INTO d;
 d:=replace(d,'zasp_temporal70','zasp_temporal71');d:=replace(d,'-- compatibility70 checksum','-- legacy71 checksum');d:=replace(d,'-- compatibility70 fingerprint','-- legacy71 fingerprint');EXECUTE d;
END $fingerprint$;
DO $functions$ DECLARE p record;BEGIN
 FOR p IN SELECT oid::regprocedure AS signature FROM pg_proc WHERE pronamespace='zasp_temporal71'::regnamespace LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p.signature);EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p.signature);
 END LOOP;
END $functions$;
GRANT USAGE ON SCHEMA zasp_temporal71 TO zasp_security_agent_worker,zasp_red_team_worker,zasp_red_team_adapter;
GRANT EXECUTE ON FUNCTION zasp_temporal71.adapter_protocol(text,text,text,text) TO zasp_red_team_adapter;
GRANT EXECUTE ON FUNCTION zasp_temporal71.client_ready(text,text,text) TO zasp_security_agent_worker,zasp_red_team_worker,zasp_red_team_adapter;
GRANT EXECUTE ON FUNCTION zasp_temporal71.op01(text,text,text,text,text,text) TO zasp_red_team_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal71.op02(text,text,text,text,text,bytea,integer,text,text) TO zasp_red_team_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal71.op03(text,text,text,text,text,bytea,integer,text,text) TO zasp_red_team_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal71.op04(text,text,text,text,text,bytea,bytea,text,text) TO zasp_red_team_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal71.op05(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint,jsonb,text,text,bytea) TO zasp_red_team_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal71.op06(text,text,text,text,bytea,text,bytea,text,text) TO zasp_red_team_adapter;
GRANT EXECUTE ON FUNCTION zasp_temporal71.op07(text,text,text,text,integer,bytea,text,bytea,integer,bytea,boolean,bytea,text,text) TO zasp_red_team_adapter;
GRANT EXECUTE ON FUNCTION zasp_temporal71.op08(text,text,text,text,text,text,bytea,text,text,text) TO zasp_red_team_adapter;
GRANT EXECUTE ON FUNCTION zasp_temporal71.op09(text,text,text,text,text,text) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal71.op10(text,text,text,text,bytea,integer,integer,text,text) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal71.op11(text,text,text,text,text,text,bytea,bigint,uuid,text,text) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal71.op12(text,text,text,text,text,text,bytea,bigint,uuid,text,text) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal71.op13(text,text,text,text,text,text,bytea,bigint,uuid,integer,text,text) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal71.op14(text,text,text,text,text,text,bytea,bigint,uuid,integer,text,text) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal71.op15(text,text,text,text,text,text,bytea,bigint,uuid,jsonb,bytea,text,text) TO zasp_security_agent_worker;
