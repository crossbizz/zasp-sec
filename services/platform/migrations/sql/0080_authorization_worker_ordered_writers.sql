-- Retained action workers still run. Their target writers must take the same
-- organization lock as current worker proofs before native row/advisory locks.
-- No caller/grant retirement, NOWAIT fallback, or policy predicate substitution.
CREATE FUNCTION zasp_authorization80_worker.ordered_legacy_writer_organization(o text) RETURNS void
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $organization$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='retained policy writer requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT public.zasp_security_agent_action_principal_ready()
 OR NOT zasp_authorization80_worker.catalog_ready()
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retained policy writer rejected';END IF;
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=o FOR UPDATE;
 IF NOT FOUND OR NOT public.zasp_security_agent_action_principal_ready()
 OR NOT zasp_authorization80_worker.catalog_ready()
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retained policy writer organization rejected';END IF;
END $organization$;

-- Snapshot the original candidate organizations once, before any effect lock.
-- Every subsequent selector is restricted to this cohort. Work becoming
-- eligible in another organization during a wait is picked up on the next poll.
CREATE FUNCTION zasp_authorization80_worker.ordered_legacy_claim_organizations(session_value boolean) RETURNS text[]
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $organizations$
DECLARE cohort text[];locked_count bigint;BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='retained policy claim requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF session_value IS NULL OR NOT public.zasp_security_agent_action_principal_ready()
 OR NOT zasp_authorization80_worker.catalog_ready()
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retained policy claim rejected';END IF;
 SELECT COALESCE(array_agg(DISTINCT effect.organization_id ORDER BY effect.organization_id),ARRAY[]::text[]) INTO cohort
 FROM public.zasp_security_agent_effects effect
 WHERE (effect.action_key='create_temporary_policy' OR session_value AND effect.action_key='isolate_session')
 AND (session_value OR NOT zasp_sa_multistep_prior.ordered_action_run(effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id))
 AND (effect.state='pending' OR effect.state='leased' AND effect.lease_expires_at<=transaction_timestamp()
 OR effect.state='cleanup_pending' AND effect.updated_at<=transaction_timestamp());
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=ANY(cohort) ORDER BY organization_id FOR UPDATE;
 GET DIAGNOSTICS locked_count=ROW_COUNT;
 -- The empty cohort still rechecks caller identity; no table lock is needed.
 IF locked_count<>cardinality(cohort) OR NOT public.zasp_security_agent_action_principal_ready() OR NOT zasp_authorization80_worker.catalog_ready()
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retained policy claim authority changed';END IF;
 RETURN cohort;
END $organizations$;

-- These hashes were captured from the installed catalog, including complete
-- effective bodies rather than historical source files or the dirty git HEAD.
DO $save_ordered_writers$ DECLARE x record;p record;BEGIN
 FOR x IN SELECT * FROM(VALUES
 ('zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)','16241155ae5c203fca07c0d29460674d972a695244efa7322908612547d5f5ca',false),
 ('zasp_sa_multistep_prior.application(text,text,jsonb)','f9b7e0558b0b7f231eae380deb1fa041af29b671357fb19251341177551cca26',true),
 ('zasp_sa_multistep_prior.application_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)','e404cc03464ef4a0c58d134393f82d55e3e6617a025d7b2de9d44cd26cfba56c',false),
 ('zasp_sa_multistep_prior.cleanup(text,text,jsonb)','2d35a718e728ec53620fe87442e11575044ffb8f619ff5f94f9e7cda4a15fc65',true),
 ('zasp_security_agent_claim_session_policy_effects(text,text,integer,integer)','4a2f6573b6fe331283eabe8178d3ff0f4dce0435338ef744ae154e73312acf93',true),
 ('zasp_security_agent_claim_temporary_policy_effects(text,text,integer,integer)','b4efe2386c2d3957b147bb115e8735c32ea25519c264eb8fa437289ecc5779b8',true),
 ('zasp_security_agent_finish_session_policy_effect(text,text,text,text,text,text,text,text,bytea,text,text)','36c8e60e53106f9c6616e8e742d9df0e6e2a6dc1d708e23f49240665fb17f906',true),
 ('zasp_security_agent_finish_temporary_policy_effect(text,text,text,text,text,text,text,text,bytea,text,text)','88df19d79a8617d45465eee1b465c50689f68b50b9aae37391b617a8ca8b0e04',true),
 ('zasp_security_agent_store_session_policy_target_v27(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)','9faa12a1296152841a2685db939b2f329c0cb970e9b5d41a2c95fe1e57d74c9a',true),
 ('zasp_security_agent_store_temporary_policy_target_v27(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)','2543bc69f642ddbae68d276ab61b45dbb5fc9ae32c946d131727687f1e9ccc03',true),
 ('zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)','b3eab388aebcf4edb05a94392e04cefb2e056d5a8f6ae0537cf37b9798812357',true),
 ('zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)','11e01bbe7ad1cac1a321f045f97af4a52b387fcf3262f231d125854d05aa0e38',true)
 ) AS v(signature,body_digest,action_grant) LOOP
  SELECT oid,pg_get_functiondef(oid) definition,proowner::regrole::text owner_name,COALESCE(proacl::text,'') acl INTO STRICT p FROM pg_proc WHERE oid=to_regprocedure(x.signature);
  IF p.owner_name<>'zasp_discovery_authority' OR encode(digest(convert_to(p.definition,'UTF8'),'sha256'),'hex')<>x.body_digest
  OR p.acl IS DISTINCT FROM (CASE WHEN x.action_grant THEN '{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_action_worker=X/zasp_discovery_authority}' ELSE '{zasp_discovery_authority=X/zasp_discovery_authority}' END)
  THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='retained policy writer predecessor changed';END IF;
  INSERT INTO zasp_authorization80_worker.predecessor_functions VALUES(x.signature,p.definition,p.owner_name,p.acl);
 END LOOP;
END $save_ordered_writers$;

DO $ordered_writers$ DECLARE p record;d text;needle text;replacement text;organization_expression text;BEGIN
 FOR p IN SELECT * FROM zasp_authorization80_worker.predecessor_functions WHERE
 signature IN('zasp_sa_multistep_prior.application(text,text,jsonb)','zasp_sa_multistep_prior.cleanup(text,text,jsonb)')
 OR signature LIKE 'zasp_sa_multistep_prior.application_source(%'
 OR signature LIKE 'zasp_policy_deployment_store_temporary_source(%'
 OR signature LIKE 'zasp_security_agent_claim_temporary_policy_effects(%' OR signature LIKE 'zasp_security_agent_claim_session_policy_effects(%'
 OR signature LIKE 'zasp_security_agent_finish_temporary_policy_effect(%' OR signature LIKE 'zasp_security_agent_finish_session_policy_effect(%'
 OR signature LIKE 'zasp_security_agent_store_temporary_policy_target(%' OR signature LIKE 'zasp_security_agent_store_session_policy_target(%'
 OR signature LIKE 'zasp_security_agent_store_temporary_policy_target_v27(%' OR signature LIKE 'zasp_security_agent_store_session_policy_target_v27(%'
 LOOP
  d:=p.definition;
  IF p.signature LIKE 'zasp_security_agent_claim_%' THEN
   d:=zasp_authorization80_worker.ordered62_replace(d,'DECLARE item record;','DECLARE ordered_organizations text[];item record;');
   d:=zasp_authorization80_worker.ordered62_replace(d,E'\nBEGIN\n',E'\nBEGIN\n ordered_organizations:=zasp_authorization80_worker.ordered_legacy_claim_organizations('||CASE WHEN p.signature LIKE 'zasp_security_agent_claim_session_%' THEN 'true' ELSE 'false' END||');'||E'\n');
   needle:=CASE WHEN p.signature LIKE 'zasp_security_agent_claim_session_%' THEN $session$WHERE effect.action_key IN('create_temporary_policy','isolate_session')$session$ ELSE $temporary$WHERE effect.action_key='create_temporary_policy'$temporary$ END;
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>3 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='retained policy claim selectors changed';END IF;
   d:=replace(d,needle,needle||' AND effect.organization_id=ANY(ordered_organizations)');
  ELSE
   organization_expression:=CASE p.signature WHEN 'zasp_sa_multistep_prior.application(text,text,jsonb)' THEN $q$request_value->>'organization_id'$q$ WHEN 'zasp_sa_multistep_prior.cleanup(text,text,jsonb)' THEN $q$q->>'organization_id'$q$ ELSE 'organization_value' END;
   d:=zasp_authorization80_worker.ordered62_replace(d,E'\nBEGIN\n',E'\nBEGIN\n PERFORM zasp_authorization80_worker.ordered_legacy_writer_organization('||organization_expression||');'||E'\n');
  END IF;
  EXECUTE d;
 END LOOP;
END $ordered_writers$;
