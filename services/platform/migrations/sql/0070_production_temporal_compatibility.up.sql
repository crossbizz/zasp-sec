-- Transitional legacy worker composition. P9 retires its existing claim/schedule glue.
-- No historical function, accepted68 object or Temporal owner is changed.
SET LOCAL lock_timeout='3s';
CREATE SCHEMA zasp_temporal70 AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_temporal70 FROM PUBLIC;
CREATE TABLE zasp_temporal70.registration(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),checksum text NOT NULL,fingerprint text NOT NULL);
CREATE TABLE zasp_temporal70.predecessor_functions(signature text PRIMARY KEY,definition text NOT NULL,owner_name text NOT NULL,acl text NOT NULL);
DO $tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['registration','predecessor_functions'] LOOP
  EXECUTE format('ALTER TABLE zasp_temporal70.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_temporal70.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_temporal70.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_temporal70.%I USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',n);
  EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal70.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n);
 END LOOP;
END $tables$;
CREATE FUNCTION zasp_temporal70.ready(c text,f text) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
BEGIN RETURN COALESCE(c='-- compatibility70 checksum' AND f='-- compatibility70 fingerprint'
 AND zasp_temporal69.ready('-- workflow69 checksum','-- workflow69 fingerprint')
 AND (SELECT count(*)=1 FROM zasp_temporal70.registration)
 AND EXISTS(SELECT 1 FROM zasp_temporal70.registration WHERE checksum=c AND fingerprint=f)
 AND zasp_temporal70.fingerprint()=f,false); END
$ready$;
CREATE FUNCTION zasp_temporal70.current_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT zasp_temporal70.ready('-- compatibility70 checksum','-- compatibility70 fingerprint')
$ready$;
CREATE FUNCTION zasp_temporal70.client_ready(c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $client$
 SELECT zasp_temporal70.ready(c,f) AND public.zasp_sa_export_principal_ready('zasp_security_agent_worker')
$client$;
CREATE FUNCTION zasp_temporal70.require_worker() RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $worker$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='compatibility worker requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal70.current_ready() OR NOT public.zasp_sa_export_principal_ready('zasp_security_agent_worker') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='compatibility worker unavailable';END IF;
END $worker$;
CREATE FUNCTION zasp_temporal70.require_legacy(o text,w text,e text,r text) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $legacy$
BEGIN
 -- Existing66 admits historical runs without an owner row as legacy. A row,
 -- once captured, is immutable; a claimed historical run cannot transfer.
 IF zasp_temporal66.is_temporal(o,w,e,r) OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_runs rr WHERE (rr.organization_id,rr.workspace_id,rr.environment_id,rr.run_id)=(o,w,e,r)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='compatibility owner rejected';END IF;
END $legacy$;

-- Each exact source definition and ACL is checked before extracting any body.
DO $sources$ DECLARE x record;p record;BEGIN
 FOR x IN SELECT * FROM (VALUES
  ('zasp_production_security_agent_existing_tests_accept_planner(text,text,text,text,text,text,bytea,bytea,text,text,jsonb,text,timestamp with time zone,text,text)','afe24ba13c8083a5292ac59a012556afb3d3d10a4b0d0f1843a760c098017c24','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
  ('zasp_production_security_agent_existing_tests_admit(text,text,text,text,bigint,text,text,bigint,text,text,text,text,boolean)','81460644efc8134e1aed89ec984664333b64573e288760300e773ee234bc8577','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_production_security_agent_existing_tests_authorize_step(text,text,text,text,text)','fe4bdf6acb16d1d1f41b3b98460f63b78a48ca8d421e6c2fbcbf6f97231fe1e8','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_production_security_agent_existing_tests_candidate_binding(text,text,text,jsonb,text)','166526a3beea6c3eeeeee468b92479dfc1675e90c0cb98d299e847c7931dfff4','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_production_security_agent_existing_tests_execute_run(text,text,text,text,text,text,text,text,text,text)','2f2d44e8e43111e514c20f75f593cd7222c216610232a8f2b565934dd1c4819d','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
  ('zasp_production_security_agent_existing_tests_fail_planner(text,text,text,text,text,text,bytea,bytea,text,text,text,text,text)','2b654d388815ccecc5bcce961bc89885c743b3f844767b28c54d419a35074324','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
  ('zasp_production_security_agent_existing_tests_finish_prepare(text,text,text,text,text,text,jsonb)','7666523ac19715c18be4184d0aada5486b024520e072118733d4affde49f49eb','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_production_security_agent_existing_tests_planner_context(text,text,text,text,text,text)','9f2fd5f8a61f53bc908337d4fab981c06f3df6c6c95072829a059903fc76ce9b','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
  ('zasp_production_security_agent_existing_tests_prepare_core(text,text,text,text,text,text,text,timestamp with time zone,text,text)','8562499b4e0762ddac5575cdf6fb443c0a8590a58bf07b3cc66246c44da3fbcc','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_production_security_agent_existing_tests_prepare_run(text,text,text,text,text,text,text,timestamp with time zone,text,text)','c5c028f78c6dae90066eec0f6e4f63ccf3882f5da2634c0cf19195c75c55a618','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
  ('zasp_production_security_agent_existing_tests_recheck_context(text,text,text,text,text,text)','2f13593ecdfdbf370a09ddfd175200f56faa9fd470d093823307f97488b4736f','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_production_security_agent_existing_tests_reserve_core(text,text,text,text,text,text,bigint,text,bytea,text,text,text,bigint,bigint)','edb2c9465a33a1b0aeb7ab2d46cd685e51fcf4d91b15fd14c9b42668acb2dc54','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_production_security_agent_existing_tests_reserve_planner(text,text,text,text,text,text,bigint,text,bytea,text,text,text,bigint,bigint)','d7454131dc6f0cae3957b6722f980c3e7bb7164d41816bca2adb20db76131e38','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
  ('zasp_production_security_agent_existing_tests_schedule(text,integer,text,text)','17bdf686bded80606aba4d8aecc9bab3e1b3aad100727d576566f67c8f8b226e','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
  ('zasp_production_security_agent_run_context_test_binding(text,text,text,text,bigint)','cf7b7975b47d9b2b4c1a88d5cad945ed9cc68039fc3b6f3820c700c323b2e481','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_sa_attack_lab_accept_planner(text,text,text,text,text,text,bytea,bytea,text,text,jsonb,text,timestamp with time zone,text,text)','4fb0fef19d89db43e224e60be7c569fe2321d7fff90259661e684b817ef18274','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
  ('zasp_sa_attack_lab_authorize(text,text,text,text,text)','3811bd0ffa61825f75420ed588a9ccff4b3601d8da0a5cd63dfecd935cb58f3f','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_sa_attack_lab_execute_run(text,text,text,text,text,text,text,text,text,text)','7134f1dbd6499a49ae328a023c2735fd654ec2802f7db2b85e06430c4bad1f92','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
  ('zasp_sa_attack_lab_fail_planner(text,text,text,text,text,text,bytea,bytea,text,text,text,text,text)','aca9047494078ab02b258b7e48bf2c264cc6399d5abae26ddcfb54508d6f9e3a','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
  ('zasp_sa_attack_lab_finish_prepare(text,text,text,text,text,text,jsonb)','1a5e674d29f65998a14b831f03a8c8d1c5abc09ba0e53a4848413e15f06079ca','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_sa_attack_lab_planner_context(text,text,text,text,text,text)','c2d4d11a014c0ba6ba038208ec73ee3a4e2ecfd63c1ac836e5fc5a18581c99a0','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
  ('zasp_sa_attack_lab_preflight_stop(text,text,text,text,text,text)','c5001d2e473351676abb1e06b5997ce22d668cb857aef1b9ccc42e6128d804c2','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_sa_attack_lab_prepare_core(text,text,text,text,text,text,text,timestamp with time zone,text,text)','37db7b11a42570c5169488a9c868e029f09de92d8786b1caf2916d4dfb8f7b08','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_sa_attack_lab_prepare_run(text,text,text,text,text,text,text,timestamp with time zone,text,text)','9cc3e00ec0509313d56e13110ddec70b159f787a657595bbafb03a45b2e19434','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
  ('zasp_sa_attack_lab_recheck_context(text,text,text,text,text,text)','5ca705a477ba318d3250628c621f0ba9b60eb76534197ab609d476a3bdb24450','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_sa_attack_lab_reserve_core(text,text,text,text,text,text,bigint,text,bytea,text,text,text,bigint,bigint)','ebb5a689b0deb4225b63c5dbc4b38bf626108009ffb20bdf171b56356ff8d718','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_sa_attack_lab_reserve_planner(text,text,text,text,text,text,bigint,text,bytea,text,text,text,bigint,bigint)','73e7f28869a463cdd4637eea10d32a553b0f058952ae0cbcc75856e70369e950','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
  ('zasp_sa_attack_lab_run_kind(text,text,text,text,text,text)','4e5da123e5a181d1870b9499a602f74c65eb14fec5005a12ba27f7047b6af3b8','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
  ('zasp_sa_export_accept_core(text,text,text,text,text,text,bytea,bytea,text,text,jsonb,text,timestamp with time zone,text,text)','18720af130a62b1579c07d964ce8d411193a7f0e2a14c93e51cb3c78324afa89','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_sa_export_accept_planner(text,text,text,text,text,text,bytea,bytea,text,text,jsonb,text,timestamp with time zone,text,text)','cfa4530b03de67e4ca522f90fb76e179694ed45fd974c11057bac0557068e94d','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
  ('zasp_sa_export_execute_run(text,text,text,text,text,text,text,text,text,text)','ba1ae1b7aecae2e326a85fb451626c2d2ba83f3acae038e1ffc4d9d2f09c66eb','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
  ('zasp_sa_export_fail_core(text,text,text,text,text,text,bytea,bytea,text,text,text,text,text)','68fce4ff1fce0c74dd69d62365388ee42ea90ae1735f75b506128c1b12f828fc','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_sa_export_fail_planner(text,text,text,text,text,text,bytea,bytea,text,text,text,text,text)','2edbf148ed380b74e3822a3958b0b46a8afb437187c212a5b9d306ee22a075ee','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
  ('zasp_sa_export_finish_prepare(text,text,text,text,text,text,jsonb)','ac15864c1ab79afae58dec34e915b4b0332ac6c5828bf173ff2f38517edf8921','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_sa_export_planner_accounting_gate(text,text,text,text,text,text,bytea,bytea,text,text)','4e8966d624c5dcc0aa7e083ebab14f9a3d87319a87edece1461c1bb5730e2824','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_sa_export_planner_context(text,text,text,text,text,text)','d484013203aa0c6b42f6d3e0c27f8bcf65fc3b4c27c10011b6d4d770484376c4','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
  ('zasp_sa_export_planner_context_core(text,text,text,text,text,text,boolean)','b017237325b55aed014057a2d5c6361c9f6f249bfbdb55f02a7a2d80402c90a1','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_sa_export_prepare_core(text,text,text,text,text,text,text,timestamp with time zone,text,text,jsonb)','01ff46e51bdd82864a67b68ef520cd783875834e5c2e1f102535012a6693d5a4','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_sa_export_recheck_context(text,text,text,text,text,text)','3a74edd7018c8d384a19e0cfd3ecc823541aead409eaefc25d388f8ebe302fe8','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_sa_export_reserve_core(text,text,text,text,text,text,bigint,text,bytea,text,text,text,bigint,bigint)','ea223a616c8758f597cbff08bf4bdef6b46a8dfa9bbaa01625abc37ffe7a7148','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_sa_export_reserve_planner(text,text,text,text,text,text,bigint,text,bytea,text,text,text,bigint,bigint)','0ff0ae5fabc7fe4c3c703a2bed7ba2cba476e30b02ebf7e1db72a19bd2977221','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
  ('zasp_sa_export_run_kind(text,text,text,text,text,text)','c11e3dbc4f53775ba5af29e21e539f1b7954fd666d62a00d0f3a41b92dfb3613','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
  ('zasp_sa_export_settle(text,text,text,text,text,text,text,text,text,text)','84b28069018d1cb1a495b311e0137b5f473b871eca78084732123f1ccc8fdba8','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
  ('zasp_sa_export_settlement_claim(text,text,integer,integer,text,text)','ee18469e904387b6919c1275082d5863583242c75ffb8000917eeee5f0a2df2d','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
  ('zasp_sa_manual_authority(text,text,text,text,bigint,text)','aff502a456d1774cb3e1d907d559d590844578beabed9bfc7a44f828173aff55','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_sa_manual_recheck(text,text,text,text)','16ab1763caca91893b74997dfb2fb46a670cf62d1d9141b36cb6eee6c6cc42ee','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_security_agent_accept_planner_candidate_v33(text,text,text,text,text,text,bytea,bytea,text,text,jsonb,text,timestamp with time zone,text,text)','22fc93994c0add33c5ee09a904d9a32332f7e5fa730e3ff13896d6c8c1a2e2ed','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
  ('zasp_security_agent_claim_budgeted_runs(text,text,integer,integer)','f5d2e35d22192e85ab48fd5ca1a89e2265fb310c5a004fdbc889244247eb4c70','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_security_agent_claim_runs_v22(text,text,integer,integer)','508d054e3a6096f1690064eee66d056d257402c457dd24addd56f2307b1d88a4','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
  ('zasp_security_agent_claim_runs_v23(text,text,integer,integer)','733b6a0286c8c7ff92327d0452e34ceeaa9a8a39bbbc37933afd7e4a99806d0f','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'),
  ('zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text)','38a2b3a4256f65e5ec6eed9544610c81c17017115cf6d406c7a762cf6eddfd2b','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_security_agent_test_link_enqueue(text,text,text,text,text,text)','bd7f6b19fe6e647e36dcdba059203e74c254dbc5f37166d32db16095939af876','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_sa_export_prior.accounting_10(text,text,text,text,text,text,bytea,bytea,text,text,text,text,text)','c5019b2adb0a383123fe1134d68350b590b839f9aaa388a96c66f5aad3ffb6d2','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_sa_export_prior.accounting_5(text,text,text,text,text,text,bytea,bytea,text,text,jsonb,text,timestamp with time zone,text,text)','2b7ffca56c6ad1cd6027b513821a80367e79f9a33be99aaba18a65d85a83dc2d','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_sa_export_prior.accounting_6(text,text,text,text,text,text,bytea,bytea,text,text,text,text,text)','a2def8a971a425e8b6fceba02f534c37867e115b48ba75afee0e98bca79cb663','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_sa_export_prior.accounting_7(text,text,text,text,text,text,bytea,bytea,text,text,jsonb,text,timestamp with time zone,text,text)','cc75c0b00f58124463815d90268c782f5fcaef412d17d7d655b97a9bf07ae52f','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_sa_export_prior.accounting_8(text,text,text,text,text,text,bytea,bytea,text,text,text,text,text)','1c9e3ab8e09c696e203f530bed6b7f60a6c3eb5adf1b1cea2bb6aafcb3858df3','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_sa_export_prior.accounting_9(text,text,text,text,text,text,bytea,bytea,text,text,jsonb,text,timestamp with time zone,text,text)','39c8c116afc6b5959a8a55221ed8a6e8682aa2c32aa7ffba7594bf680c491f03','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_production_security_agent_existing_tests_readiness(text,text)','a5b6a22bb3aaf96dcc24f62453459efa0c41d377f5e038e86cecd20f383493a0','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_global_operator=X/zasp_discovery_authority}'),
  ('zasp_sa_attack_lab_guard()','e704927623a7d6a7185a943e81407ec7cf06abc390ffc88982609ffc37492ad0','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_sa_export_guard()','70d7b73aaed33582143f216c7c5672eca39b192bc101d6c38e8e077cd8cc415f','{zasp_discovery_authority=X/zasp_discovery_authority}'),
  ('zasp_sa_export_readiness(text,text)','9acc9094640b3d61d51cb598f1028fc5f26ae3ed87c89d52e91206d323662b9b','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_discovery_api=X/zasp_discovery_authority,zasp_security_agent_api=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority,zasp_compliance_worker=X/zasp_discovery_authority,zasp_compliance_cleanup=X/zasp_discovery_authority}'),
  ('zasp_sa_attack_lab_readiness(text,text)','1d4031f14ec4324f2200a5b7ddef72f28f3f6ad90323a301b31193d5668688cb','{zasp_discovery_authority=X/zasp_discovery_authority,zasp_discovery_api=X/zasp_discovery_authority,zasp_security_agent_api=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority,zasp_security_agent_action_worker=X/zasp_discovery_authority,zasp_security_agent_attack_lab_reconciler=X/zasp_discovery_authority}')
 ) AS inventory(signature,source_hash,source_acl) LOOP
  SELECT pg_get_functiondef(oid) AS definition,proowner::regrole::text AS owner_name,COALESCE(proacl::text,'') AS acl INTO STRICT p FROM pg_proc WHERE oid=to_regprocedure(x.signature);
  IF p.owner_name<>'zasp_discovery_authority' OR p.acl IS DISTINCT FROM x.source_acl OR encode(digest(convert_to(p.definition,'UTF8'),'sha256'),'hex')<>x.source_hash THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='compatibility predecessor changed';END IF;
  INSERT INTO zasp_temporal70.predecessor_functions VALUES(x.signature,p.definition,p.owner_name,p.acl);
 END LOOP;
END $sources$;
CREATE FUNCTION zasp_temporal70.guard01(expected_checksum text, expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $guard$ SELECT COALESCE(expected_checksum='01920b296d2ebbc4b84c6e714edaf50d6265d630e577bd26297755a15289fa00' AND expected_fingerprint='2c324e78917f97feee14f915b397efbb92a183d47afd7473139dd0691cf0bb04' AND zasp_temporal70.current_ready(),false) $guard$;
CREATE FUNCTION zasp_temporal70.guard02() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $guard$ SELECT COALESCE(zasp_temporal70.current_ready(),false) $guard$;
CREATE FUNCTION zasp_temporal70.guard03() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $guard$ SELECT COALESCE(zasp_temporal70.current_ready(),false) $guard$;
CREATE FUNCTION zasp_temporal70.guard04(expected_checksum text, expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $guard$ SELECT COALESCE(expected_checksum='5ee183aae4e67f55c6e1ed89b2d020266b3160e0df8e3101ba51faa705f4c985' AND expected_fingerprint='8ddd2617904003772da27cdf92dd48fcc3714596d773a144f67dc8abf175ca1f' AND zasp_temporal70.current_ready(),false) $guard$;
CREATE FUNCTION zasp_temporal70.guard05(expected_checksum text, expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $guard$ SELECT COALESCE(expected_checksum='e0f037ec8948a4d574ae33f37e9554d9ff6539785b7d601d7c96685a66c01776' AND expected_fingerprint='f44bc966ef77ab523a80ace71b59defbe709c1fdbefd69ccfc40cacaf16d7ba8' AND zasp_temporal70.current_ready(),false) $guard$;
DO $copies$ DECLARE x record;y record;d text;pattern text;expected_count integer;actual_count integer;BEGIN
 PERFORM set_config('check_function_bodies','off',true);
 FOR x IN SELECT * FROM (VALUES
  ('zasp_production_security_agent_existing_tests_accept_planner(text,text,text,text,text,text,bytea,bytea,text,text,jsonb,text,timestamp with time zone,text,text)','body01'),
  ('zasp_production_security_agent_existing_tests_admit(text,text,text,text,bigint,text,text,bigint,text,text,text,text,boolean)','body02'),
  ('zasp_production_security_agent_existing_tests_authorize_step(text,text,text,text,text)','body03'),
  ('zasp_production_security_agent_existing_tests_candidate_binding(text,text,text,jsonb,text)','body04'),
  ('zasp_production_security_agent_existing_tests_execute_run(text,text,text,text,text,text,text,text,text,text)','body05'),
  ('zasp_production_security_agent_existing_tests_fail_planner(text,text,text,text,text,text,bytea,bytea,text,text,text,text,text)','body06'),
  ('zasp_production_security_agent_existing_tests_finish_prepare(text,text,text,text,text,text,jsonb)','body07'),
  ('zasp_production_security_agent_existing_tests_planner_context(text,text,text,text,text,text)','body08'),
  ('zasp_production_security_agent_existing_tests_prepare_core(text,text,text,text,text,text,text,timestamp with time zone,text,text)','body09'),
  ('zasp_production_security_agent_existing_tests_prepare_run(text,text,text,text,text,text,text,timestamp with time zone,text,text)','body10'),
  ('zasp_production_security_agent_existing_tests_recheck_context(text,text,text,text,text,text)','body11'),
  ('zasp_production_security_agent_existing_tests_reserve_core(text,text,text,text,text,text,bigint,text,bytea,text,text,text,bigint,bigint)','body12'),
  ('zasp_production_security_agent_existing_tests_reserve_planner(text,text,text,text,text,text,bigint,text,bytea,text,text,text,bigint,bigint)','body13'),
  ('zasp_production_security_agent_existing_tests_schedule(text,integer,text,text)','body14'),
  ('zasp_production_security_agent_run_context_test_binding(text,text,text,text,bigint)','body15'),
  ('zasp_sa_attack_lab_accept_planner(text,text,text,text,text,text,bytea,bytea,text,text,jsonb,text,timestamp with time zone,text,text)','body16'),
  ('zasp_sa_attack_lab_authorize(text,text,text,text,text)','body17'),
  ('zasp_sa_attack_lab_execute_run(text,text,text,text,text,text,text,text,text,text)','body18'),
  ('zasp_sa_attack_lab_fail_planner(text,text,text,text,text,text,bytea,bytea,text,text,text,text,text)','body19'),
  ('zasp_sa_attack_lab_finish_prepare(text,text,text,text,text,text,jsonb)','body20'),
  ('zasp_sa_attack_lab_planner_context(text,text,text,text,text,text)','body21'),
  ('zasp_sa_attack_lab_preflight_stop(text,text,text,text,text,text)','body22'),
  ('zasp_sa_attack_lab_prepare_core(text,text,text,text,text,text,text,timestamp with time zone,text,text)','body23'),
  ('zasp_sa_attack_lab_prepare_run(text,text,text,text,text,text,text,timestamp with time zone,text,text)','body24'),
  ('zasp_sa_attack_lab_recheck_context(text,text,text,text,text,text)','body25'),
  ('zasp_sa_attack_lab_reserve_core(text,text,text,text,text,text,bigint,text,bytea,text,text,text,bigint,bigint)','body26'),
  ('zasp_sa_attack_lab_reserve_planner(text,text,text,text,text,text,bigint,text,bytea,text,text,text,bigint,bigint)','body27'),
  ('zasp_sa_attack_lab_run_kind(text,text,text,text,text,text)','body28'),
  ('zasp_sa_export_accept_core(text,text,text,text,text,text,bytea,bytea,text,text,jsonb,text,timestamp with time zone,text,text)','body29'),
  ('zasp_sa_export_accept_planner(text,text,text,text,text,text,bytea,bytea,text,text,jsonb,text,timestamp with time zone,text,text)','body30'),
  ('zasp_sa_export_execute_run(text,text,text,text,text,text,text,text,text,text)','body31'),
  ('zasp_sa_export_fail_core(text,text,text,text,text,text,bytea,bytea,text,text,text,text,text)','body32'),
  ('zasp_sa_export_fail_planner(text,text,text,text,text,text,bytea,bytea,text,text,text,text,text)','body33'),
  ('zasp_sa_export_finish_prepare(text,text,text,text,text,text,jsonb)','body34'),
  ('zasp_sa_export_planner_accounting_gate(text,text,text,text,text,text,bytea,bytea,text,text)','body35'),
  ('zasp_sa_export_planner_context(text,text,text,text,text,text)','body36'),
  ('zasp_sa_export_planner_context_core(text,text,text,text,text,text,boolean)','body37'),
  ('zasp_sa_export_prepare_core(text,text,text,text,text,text,text,timestamp with time zone,text,text,jsonb)','body38'),
  ('zasp_sa_export_recheck_context(text,text,text,text,text,text)','body39'),
  ('zasp_sa_export_reserve_core(text,text,text,text,text,text,bigint,text,bytea,text,text,text,bigint,bigint)','body40'),
  ('zasp_sa_export_reserve_planner(text,text,text,text,text,text,bigint,text,bytea,text,text,text,bigint,bigint)','body41'),
  ('zasp_sa_export_run_kind(text,text,text,text,text,text)','body42'),
  ('zasp_sa_export_settle(text,text,text,text,text,text,text,text,text,text)','body43'),
  ('zasp_sa_export_settlement_claim(text,text,integer,integer,text,text)','body44'),
  ('zasp_sa_manual_authority(text,text,text,text,bigint,text)','body45'),
  ('zasp_sa_manual_recheck(text,text,text,text)','body46'),
  ('zasp_security_agent_accept_planner_candidate_v33(text,text,text,text,text,text,bytea,bytea,text,text,jsonb,text,timestamp with time zone,text,text)','body47'),
  ('zasp_security_agent_claim_budgeted_runs(text,text,integer,integer)','body48'),
  ('zasp_security_agent_claim_runs_v22(text,text,integer,integer)','body49'),
  ('zasp_security_agent_claim_runs_v23(text,text,integer,integer)','body50'),
  ('zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text)','body51'),
  ('zasp_security_agent_test_link_enqueue(text,text,text,text,text,text)','body52'),
  ('zasp_sa_export_prior.accounting_10(text,text,text,text,text,text,bytea,bytea,text,text,text,text,text)','body53'),
  ('zasp_sa_export_prior.accounting_5(text,text,text,text,text,text,bytea,bytea,text,text,jsonb,text,timestamp with time zone,text,text)','body54'),
  ('zasp_sa_export_prior.accounting_6(text,text,text,text,text,text,bytea,bytea,text,text,text,text,text)','body55'),
  ('zasp_sa_export_prior.accounting_7(text,text,text,text,text,text,bytea,bytea,text,text,jsonb,text,timestamp with time zone,text,text)','body56'),
  ('zasp_sa_export_prior.accounting_8(text,text,text,text,text,text,bytea,bytea,text,text,text,text,text)','body57'),
  ('zasp_sa_export_prior.accounting_9(text,text,text,text,text,text,bytea,bytea,text,text,jsonb,text,timestamp with time zone,text,text)','body58')
 ) AS inventory(signature,alias) LOOP
  SELECT definition INTO STRICT d FROM zasp_temporal70.predecessor_functions WHERE signature=x.signature;
  FOR y IN SELECT * FROM (VALUES
   ('public.zasp_production_security_agent_existing_tests_accept_planner','body01'),
   ('public.zasp_production_security_agent_existing_tests_admit','body02'),
   ('public.zasp_production_security_agent_existing_tests_authorize_step','body03'),
   ('public.zasp_production_security_agent_existing_tests_candidate_binding','body04'),
   ('public.zasp_production_security_agent_existing_tests_execute_run','body05'),
   ('public.zasp_production_security_agent_existing_tests_fail_planner','body06'),
   ('public.zasp_production_security_agent_existing_tests_finish_prepare','body07'),
   ('public.zasp_production_security_agent_existing_tests_planner_context','body08'),
   ('public.zasp_production_security_agent_existing_tests_prepare_core','body09'),
   ('public.zasp_production_security_agent_existing_tests_prepare_run','body10'),
   ('public.zasp_production_security_agent_existing_tests_recheck_context','body11'),
   ('public.zasp_production_security_agent_existing_tests_reserve_core','body12'),
   ('public.zasp_production_security_agent_existing_tests_reserve_planner','body13'),
   ('public.zasp_production_security_agent_existing_tests_schedule','body14'),
   ('public.zasp_production_security_agent_run_context_test_binding','body15'),
   ('public.zasp_sa_attack_lab_accept_planner','body16'),
   ('public.zasp_sa_attack_lab_authorize','body17'),
   ('public.zasp_sa_attack_lab_execute_run','body18'),
   ('public.zasp_sa_attack_lab_fail_planner','body19'),
   ('public.zasp_sa_attack_lab_finish_prepare','body20'),
   ('public.zasp_sa_attack_lab_planner_context','body21'),
   ('public.zasp_sa_attack_lab_preflight_stop','body22'),
   ('public.zasp_sa_attack_lab_prepare_core','body23'),
   ('public.zasp_sa_attack_lab_prepare_run','body24'),
   ('public.zasp_sa_attack_lab_recheck_context','body25'),
   ('public.zasp_sa_attack_lab_reserve_core','body26'),
   ('public.zasp_sa_attack_lab_reserve_planner','body27'),
   ('public.zasp_sa_attack_lab_run_kind','body28'),
   ('public.zasp_sa_export_accept_core','body29'),
   ('public.zasp_sa_export_accept_planner','body30'),
   ('public.zasp_sa_export_execute_run','body31'),
   ('public.zasp_sa_export_fail_core','body32'),
   ('public.zasp_sa_export_fail_planner','body33'),
   ('public.zasp_sa_export_finish_prepare','body34'),
   ('public.zasp_sa_export_planner_accounting_gate','body35'),
   ('public.zasp_sa_export_planner_context','body36'),
   ('public.zasp_sa_export_planner_context_core','body37'),
   ('public.zasp_sa_export_prepare_core','body38'),
   ('public.zasp_sa_export_recheck_context','body39'),
   ('public.zasp_sa_export_reserve_core','body40'),
   ('public.zasp_sa_export_reserve_planner','body41'),
   ('public.zasp_sa_export_run_kind','body42'),
   ('public.zasp_sa_export_settle','body43'),
   ('public.zasp_sa_export_settlement_claim','body44'),
   ('public.zasp_sa_manual_authority','body45'),
   ('public.zasp_sa_manual_recheck','body46'),
   ('public.zasp_security_agent_accept_planner_candidate_v33','body47'),
   ('public.zasp_security_agent_claim_budgeted_runs','body48'),
   ('public.zasp_security_agent_claim_runs_v22','body49'),
   ('public.zasp_security_agent_claim_runs_v23','body50'),
   ('public.zasp_security_agent_test_dispatch','body51'),
   ('public.zasp_security_agent_test_link_enqueue','body52'),
   ('zasp_sa_export_prior.accounting_10','body53'),
   ('zasp_sa_export_prior.accounting_5','body54'),
   ('zasp_sa_export_prior.accounting_6','body55'),
   ('zasp_sa_export_prior.accounting_7','body56'),
   ('zasp_sa_export_prior.accounting_8','body57'),
   ('zasp_sa_export_prior.accounting_9','body58'),
   ('public.zasp_production_security_agent_existing_tests_readiness','guard01'),
   ('public.zasp_sa_attack_lab_guard','guard02'),
   ('public.zasp_sa_export_guard','guard03'),
   ('public.zasp_sa_export_readiness','guard04'),
   ('public.zasp_sa_attack_lab_readiness','guard05')
  ) AS replacements(source_name,alias) LOOP
   -- Boundary-aware replacement covers qualified calls and public search_path
   -- calls, without rewriting literals that contain longer function names.
   pattern:='\m'||CASE WHEN starts_with(y.source_name,'public.') THEN '(public\.)?'||substr(y.source_name,8) ELSE replace(y.source_name,'.','\.') END||'\(';
   SELECT count(*) INTO actual_count FROM regexp_matches(d,pattern,'g');
   SELECT count(*) INTO expected_count FROM zasp_temporal70.predecessor_functions p CROSS JOIN LATERAL regexp_matches(p.definition,pattern,'g') WHERE p.signature=x.signature;
   IF actual_count<>expected_count THEN RAISE EXCEPTION 'compatibility call replacement count changed';END IF;
   d:=regexp_replace(d,pattern,'zasp_temporal70.'||y.alias||'(','g');
  END LOOP;
  EXECUTE d;
 END LOOP;
 PERFORM set_config('check_function_bodies','on',true);
END $copies$;
-- zasp_security_agent_expire_approvals_v28(text,integer)
CREATE FUNCTION zasp_temporal70.op01(worker_value text, limit_value integer) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal70.require_worker();
 RETURN public.zasp_security_agent_expire_approvals_v28(worker_value,limit_value);
END $operation$;
-- zasp_production_security_agent_existing_tests_schedule(text,integer,text,text)
CREATE FUNCTION zasp_temporal70.op02(worker_value text, limit_value integer, expected_checksum text, expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal70.require_worker();
 RETURN zasp_temporal70.body14(worker_value,limit_value,expected_checksum,expected_fingerprint);
END $operation$;
-- zasp_security_agent_claim_runs_v23(text,text,integer,integer)
CREATE FUNCTION zasp_temporal70.op03(worker_value text, lease_token_value text, lease_seconds integer, claim_limit integer) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal70.require_worker();
 RETURN zasp_temporal70.body50(worker_value,lease_token_value,lease_seconds,claim_limit);
END $operation$;
-- zasp_security_agent_heartbeat_run(text,text,text,text,text,text,integer)
CREATE FUNCTION zasp_temporal70.op04(organization_value text, workspace_value text, environment_value text, run_value text, worker_value text, lease_token_value text, lease_seconds integer) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal70.require_worker();
 PERFORM zasp_temporal70.require_legacy(organization_value,workspace_value,environment_value,run_value);
 RETURN public.zasp_security_agent_heartbeat_run(organization_value,workspace_value,environment_value,run_value,worker_value,lease_token_value,lease_seconds);
END $operation$;
-- zasp_sa_export_planner_context(text,text,text,text,text,text)
CREATE FUNCTION zasp_temporal70.op05(o text, w text, e text, r text, worker_value text, lease_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal70.require_worker();
 PERFORM zasp_temporal70.require_legacy(o,w,e,r);
 RETURN zasp_temporal70.body36(o,w,e,r,worker_value,lease_value);
END $operation$;
-- zasp_sa_export_accept_planner(text,text,text,text,text,text,bytea,bytea,text,text,jsonb,text,timestamp with time zone,text,text)
CREATE FUNCTION zasp_temporal70.op06(o text, w text, e text, r text, worker_value text, lease_value text, input_value bytea, output_value bytea, model_value text, policy_value text, candidate_value jsonb, approval_value text, expires_value timestamp with time zone, audit_value text, correlation_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal70.require_worker();
 PERFORM zasp_temporal70.require_legacy(o,w,e,r);
 RETURN zasp_temporal70.body30(o,w,e,r,worker_value,lease_value,input_value,output_value,model_value,policy_value,candidate_value,approval_value,expires_value,audit_value,correlation_value);
END $operation$;
-- zasp_sa_export_fail_planner(text,text,text,text,text,text,bytea,bytea,text,text,text,text,text)
CREATE FUNCTION zasp_temporal70.op07(o text, w text, e text, r text, worker_value text, lease_value text, input_value bytea, output_value bytea, model_value text, policy_value text, error_value text, audit_value text, correlation_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal70.require_worker();
 PERFORM zasp_temporal70.require_legacy(o,w,e,r);
 RETURN zasp_temporal70.body33(o,w,e,r,worker_value,lease_value,input_value,output_value,model_value,policy_value,error_value,audit_value,correlation_value);
END $operation$;
-- zasp_sa_export_reserve_planner(text,text,text,text,text,text,bigint,text,bytea,text,text,text,bigint,bigint)
CREATE FUNCTION zasp_temporal70.op08(o text, w text, e text, r text, worker_value text, lease_value text, attempt_value bigint, reservation_value text, input_digest_value bytea, model_value text, cost_policy_value text, cost_unit_value text, maximum_tokens_value bigint, maximum_cost_value bigint) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal70.require_worker();
 PERFORM zasp_temporal70.require_legacy(o,w,e,r);
 RETURN zasp_temporal70.body41(o,w,e,r,worker_value,lease_value,attempt_value,reservation_value,input_digest_value,model_value,cost_policy_value,cost_unit_value,maximum_tokens_value,maximum_cost_value);
END $operation$;
-- zasp_sa_export_run_kind(text,text,text,text,text,text)
CREATE FUNCTION zasp_temporal70.op09(o text, w text, e text, r text, worker_value text, lease_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal70.require_worker();
 PERFORM zasp_temporal70.require_legacy(o,w,e,r);
 RETURN zasp_temporal70.body42(o,w,e,r,worker_value,lease_value);
END $operation$;
-- zasp_sa_export_execute_run(text,text,text,text,text,text,text,text,text,text)
CREATE FUNCTION zasp_temporal70.op10(o text, w text, e text, r text, worker_value text, lease_value text, audit_value text, correlation_value text, expected_checksum text, expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal70.require_worker();
 PERFORM zasp_temporal70.require_legacy(o,w,e,r);
 RETURN zasp_temporal70.body31(o,w,e,r,worker_value,lease_value,audit_value,correlation_value,expected_checksum,expected_fingerprint);
END $operation$;
-- zasp_sa_export_settlement_claim(text,text,integer,integer,text,text)
CREATE FUNCTION zasp_temporal70.op11(worker_value text, lease_value text, lease_seconds integer, claim_limit integer, expected_checksum text, expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal70.require_worker();
 RETURN zasp_temporal70.body44(worker_value,lease_value,lease_seconds,claim_limit,expected_checksum,expected_fingerprint);
END $operation$;
-- zasp_sa_export_settle(text,text,text,text,text,text,text,text,text,text)
CREATE FUNCTION zasp_temporal70.op12(o text, w text, e text, r text, worker_value text, lease_value text, audit_value text, correlation_value text, expected_checksum text, expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal70.require_worker();
 PERFORM zasp_temporal70.require_legacy(o,w,e,r);
 RETURN zasp_temporal70.body43(o,w,e,r,worker_value,lease_value,audit_value,correlation_value,expected_checksum,expected_fingerprint);
END $operation$;
-- zasp_sa_attack_lab_run_kind(text,text,text,text,text,text)
CREATE FUNCTION zasp_temporal70.op13(o text, w text, e text, r text, worker_value text, lease_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal70.require_worker();
 PERFORM zasp_temporal70.require_legacy(o,w,e,r);
 RETURN zasp_temporal70.body28(o,w,e,r,worker_value,lease_value);
END $operation$;
-- zasp_production_security_agent_existing_tests_planner_context(text,text,text,text,text,text)
CREATE FUNCTION zasp_temporal70.op14(o text, w text, e text, r text, worker_value text, lease_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal70.require_worker();
 PERFORM zasp_temporal70.require_legacy(o,w,e,r);
 RETURN zasp_temporal70.body08(o,w,e,r,worker_value,lease_value);
END $operation$;
-- zasp_sa_attack_lab_planner_context(text,text,text,text,text,text)
CREATE FUNCTION zasp_temporal70.op15(o text, w text, e text, r text, worker_value text, lease_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal70.require_worker();
 PERFORM zasp_temporal70.require_legacy(o,w,e,r);
 RETURN zasp_temporal70.body21(o,w,e,r,worker_value,lease_value);
END $operation$;
-- zasp_production_security_agent_existing_tests_reserve_planner(text,text,text,text,text,text,bigint,text,bytea,text,text,text,bigint,bigint)
CREATE FUNCTION zasp_temporal70.op16(o text, w text, e text, r text, worker_value text, lease_value text, attempt_value bigint, reservation_value text, input_digest_value bytea, model_value text, cost_policy_value text, cost_unit_value text, maximum_tokens_value bigint, maximum_cost_value bigint) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal70.require_worker();
 PERFORM zasp_temporal70.require_legacy(o,w,e,r);
 RETURN zasp_temporal70.body13(o,w,e,r,worker_value,lease_value,attempt_value,reservation_value,input_digest_value,model_value,cost_policy_value,cost_unit_value,maximum_tokens_value,maximum_cost_value);
END $operation$;
-- zasp_sa_attack_lab_reserve_planner(text,text,text,text,text,text,bigint,text,bytea,text,text,text,bigint,bigint)
CREATE FUNCTION zasp_temporal70.op17(o text, w text, e text, r text, worker_value text, lease_value text, attempt_value bigint, reservation_value text, input_digest_value bytea, model_value text, cost_policy_value text, cost_unit_value text, maximum_tokens_value bigint, maximum_cost_value bigint) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal70.require_worker();
 PERFORM zasp_temporal70.require_legacy(o,w,e,r);
 RETURN zasp_temporal70.body27(o,w,e,r,worker_value,lease_value,attempt_value,reservation_value,input_digest_value,model_value,cost_policy_value,cost_unit_value,maximum_tokens_value,maximum_cost_value);
END $operation$;
-- zasp_production_security_agent_existing_tests_prepare_run(text,text,text,text,text,text,text,timestamp with time zone,text,text)
CREATE FUNCTION zasp_temporal70.op18(o text, w text, e text, r text, worker_value text, lease_value text, approval_value text, expires_value timestamp with time zone, audit_value text, correlation_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal70.require_worker();
 PERFORM zasp_temporal70.require_legacy(o,w,e,r);
 RETURN zasp_temporal70.body10(o,w,e,r,worker_value,lease_value,approval_value,expires_value,audit_value,correlation_value);
END $operation$;
-- zasp_sa_attack_lab_prepare_run(text,text,text,text,text,text,text,timestamp with time zone,text,text)
CREATE FUNCTION zasp_temporal70.op19(o text, w text, e text, r text, worker_value text, lease_value text, approval_value text, expires_value timestamp with time zone, audit_value text, correlation_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal70.require_worker();
 PERFORM zasp_temporal70.require_legacy(o,w,e,r);
 RETURN zasp_temporal70.body24(o,w,e,r,worker_value,lease_value,approval_value,expires_value,audit_value,correlation_value);
END $operation$;
-- zasp_production_security_agent_existing_tests_execute_run(text,text,text,text,text,text,text,text,text,text)
CREATE FUNCTION zasp_temporal70.op20(o text, w text, e text, r text, worker_value text, lease_value text, audit_value text, correlation_value text, expected_checksum text, expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal70.require_worker();
 PERFORM zasp_temporal70.require_legacy(o,w,e,r);
 RETURN zasp_temporal70.body05(o,w,e,r,worker_value,lease_value,audit_value,correlation_value,expected_checksum,expected_fingerprint);
END $operation$;
-- zasp_sa_attack_lab_execute_run(text,text,text,text,text,text,text,text,text,text)
CREATE FUNCTION zasp_temporal70.op21(o text, w text, e text, r text, worker_value text, lease_value text, audit_value text, correlation_value text, expected_checksum text, expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal70.require_worker();
 PERFORM zasp_temporal70.require_legacy(o,w,e,r);
 RETURN zasp_temporal70.body18(o,w,e,r,worker_value,lease_value,audit_value,correlation_value,expected_checksum,expected_fingerprint);
END $operation$;
-- zasp_security_agent_budget_settle_planner(text,text,text,text,text,text,bigint,text,bytea,bigint,bigint,bigint,bigint)
CREATE FUNCTION zasp_temporal70.op22(organization_value text, workspace_value text, environment_value text, run_value text, worker_value text, lease_token_value text, attempt_value bigint, reservation_value text, output_digest_value bytea, prompt_tokens_value bigint, completion_tokens_value bigint, total_tokens_value bigint, cost_value bigint) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $operation$
BEGIN
 PERFORM zasp_temporal70.require_worker();
 PERFORM zasp_temporal70.require_legacy(organization_value,workspace_value,environment_value,run_value);
 RETURN public.zasp_security_agent_budget_settle_planner(organization_value,workspace_value,environment_value,run_value,worker_value,lease_token_value,attempt_value,reservation_value,output_digest_value,prompt_tokens_value,completion_tokens_value,total_tokens_value,cost_value);
END $operation$;
DO $fingerprint$ DECLARE d text;BEGIN
 SELECT pg_get_functiondef('zasp_temporal69.fingerprint()'::regprocedure) INTO d;
 d:=replace(d,'zasp_temporal69','zasp_temporal70');
 d:=replace(d,'-- workflow69 checksum','-- compatibility70 checksum');
 d:=replace(d,'-- workflow69 fingerprint','-- compatibility70 fingerprint');
 EXECUTE d;
END $fingerprint$;
DO $functions$ DECLARE p record;BEGIN
 FOR p IN SELECT oid::regprocedure AS signature FROM pg_proc WHERE pronamespace='zasp_temporal70'::regnamespace LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p.signature);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p.signature);
 END LOOP;
END $functions$;
GRANT USAGE ON SCHEMA zasp_temporal70 TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal70.client_ready(text,text) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal70.op01(text,integer) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal70.op02(text,integer,text,text) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal70.op03(text,text,integer,integer) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal70.op04(text,text,text,text,text,text,integer) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal70.op05(text,text,text,text,text,text) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal70.op06(text,text,text,text,text,text,bytea,bytea,text,text,jsonb,text,timestamp with time zone,text,text) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal70.op07(text,text,text,text,text,text,bytea,bytea,text,text,text,text,text) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal70.op08(text,text,text,text,text,text,bigint,text,bytea,text,text,text,bigint,bigint) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal70.op09(text,text,text,text,text,text) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal70.op10(text,text,text,text,text,text,text,text,text,text) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal70.op11(text,text,integer,integer,text,text) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal70.op12(text,text,text,text,text,text,text,text,text,text) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal70.op13(text,text,text,text,text,text) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal70.op14(text,text,text,text,text,text) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal70.op15(text,text,text,text,text,text) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal70.op16(text,text,text,text,text,text,bigint,text,bytea,text,text,text,bigint,bigint) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal70.op17(text,text,text,text,text,text,bigint,text,bytea,text,text,text,bigint,bigint) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal70.op18(text,text,text,text,text,text,text,timestamp with time zone,text,text) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal70.op19(text,text,text,text,text,text,text,timestamp with time zone,text,text) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal70.op20(text,text,text,text,text,text,text,text,text,text) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal70.op21(text,text,text,text,text,text,text,text,text,text) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal70.op22(text,text,text,text,text,text,bigint,text,bytea,bigint,bigint,bigint,bigint) TO zasp_security_agent_worker;
