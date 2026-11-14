-- Product completion on top of the activated baseline.
--
-- The historical chain moved about half of the product onto the current
-- authorization model (zasp_authorization80: every product statement is an
-- authorized function executed inside a fenced transaction). The read
-- surfaces and the Security Agent and identity-provider writes below were
-- never moved, so under the current model the API refused them. This file
-- adds what those surfaces need. The only existing function bodies it changes
-- are zasp_authorization80.resolve and parent_targets (section F) and
-- audit_page (section L), which keep every rule and check readiness once per
-- call or page; the only grants it removes are direct grants on historical
-- readers that an authorized function replaces (section K).
--
-- generate.sh applies this file to the superuser installation, as the
-- PostgreSQL superuser, in one transaction, after activation.sql. Every
-- object names its owner and its grantees explicitly; nothing is granted to
-- PUBLIC and no role is created. The file is re-runnable.
--
-- An existing installation applies it the same way and then re-seals the
-- catalog: SET ROLE zasp_discovery_authority; SELECT zasp_baseline.accept(...).

-- ---------------------------------------------------------------------------
-- A. Typed inventory for new Environments.
--
-- zasp_authorization80.inventory_page (and the typed inventory reads behind
-- it) serve an Environment only once its inventory scope is in phase
-- 'cutover'. The chain cut scopes over by an operator procedure
-- (zasp_inventory_backfill_scope, then zasp_inventory_cutover_scope) meant for
-- Environments that carried legacy generic inventory payloads. Nothing ran it
-- for an Environment created afterwards, so every new Environment refused its
-- inventory lists with 'authorization inventory page rejected'.
--
-- A new Environment has no legacy inventory, so the chain's own procedure
-- proves the (empty) equivalence and cuts it over at creation. The trigger
-- covers every creation path: bootstrap, zasp_authorization80.create_workspace
-- and zasp_authorization80.create_environment. Discovery writes typed
-- inventory (zasp_discovery_apply_snapshot) independently of the phase, so
-- discovered entities appear on the authorized lists.
CREATE OR REPLACE FUNCTION public.zasp_inventory_environment_cutover() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $environment_cutover$
BEGIN
 IF TG_OP<>'INSERT' OR TG_LEVEL<>'ROW' OR TG_WHEN<>'AFTER' OR TG_RELID<>'public.zasp_environments'::regclass THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='inventory environment cutover contract rejected';
 END IF;
 -- A scope that is already cut over (a state row that outlived a deleted
 -- Environment of the same ID) needs nothing and must not fail the insert.
 IF COALESCE(public.zasp_inventory_scope_state(NEW.organization_id,NEW.workspace_id,NEW.id)->>'phase','')='cutover' THEN
  RETURN NULL;
 END IF;
 PERFORM public.zasp_inventory_backfill_scope(NEW.organization_id,NEW.workspace_id,NEW.id);
 PERFORM public.zasp_inventory_cutover_scope(NEW.organization_id,NEW.workspace_id,NEW.id);
 RETURN NULL;
END $environment_cutover$;
ALTER FUNCTION public.zasp_inventory_environment_cutover() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_inventory_environment_cutover() FROM PUBLIC;

DROP TRIGGER IF EXISTS zasp_inventory_environment_cutover ON public.zasp_environments;
CREATE TRIGGER zasp_inventory_environment_cutover AFTER INSERT ON public.zasp_environments
 FOR EACH ROW EXECUTE FUNCTION public.zasp_inventory_environment_cutover();

-- Environments created before this file was applied. An Environment whose
-- legacy and typed inventory disagree stops here, as the procedure intends.
DO $existing_environments$
DECLARE scope record;
BEGIN
 FOR scope IN SELECT x.organization_id,x.workspace_id,x.id FROM public.zasp_environments x
  WHERE COALESCE(public.zasp_inventory_scope_state(x.organization_id,x.workspace_id,x.id)->>'phase','') <> 'cutover'
  ORDER BY x.organization_id,x.workspace_id,x.id LOOP
  IF COALESCE(public.zasp_inventory_scope_state(scope.organization_id,scope.workspace_id,scope.id)->>'phase','expanded')='expanded' THEN
   PERFORM public.zasp_inventory_backfill_scope(scope.organization_id,scope.workspace_id,scope.id);
  END IF;
  PERFORM public.zasp_inventory_cutover_scope(scope.organization_id,scope.workspace_id,scope.id);
 END LOOP;
END $existing_environments$;

-- ---------------------------------------------------------------------------
-- Authorized reads. Every function below follows its zasp_authorization80
-- neighbours (inventory_page, workflow_page, risk_page, receipt_page,
-- get_data_controls):
--   * it is SECURITY DEFINER, owned by zasp_discovery_authority, with a fixed
--     search_path, and executable only by the API role that serves the route;
--   * it returns data only inside a fenced transaction: require_read /
--     read_request compare the organization, workspace, environment,
--     operation and permission arguments with the attested proof that
--     zasp_authorization80.fence() verified for this transaction;
--   * every returned row passes zasp_authorization80.allowed() for its own
--     resource kind, or, for scope-level reads, the scope target itself does;
--   * page sizes are bounded.
-- Nothing here reads a caller-supplied organization outside the proof.

-- ---------------------------------------------------------------------------
-- B. Security Agent catalog, runs and approvals.
--
-- Capability readiness. The chain's zasp_sa_attack_lab_readiness and
-- zasp_sa_export_readiness require exactly 60 rows in zasp_schema_versions.
-- Release 61 (production_security_agent_multistep) did not re-pin them, so on
-- the 61-release baseline both are false for ever and the Security Agent
-- catalog reported 'provider unavailable'. These two functions state the same
-- capability for the current catalog: the release row and its recorded
-- identity, the role shape the release requires, and the current
-- authorization release, whose readiness is the catalog integrity check
-- (zasp_baseline.intact(), through zasp_authorization80.ready) plus the
-- multistep release that superseded the 60-release pins.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_attack_lab_ready(c text,f text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $attack_lab_ready$
 SELECT COALESCE(c='e0f037ec8948a4d574ae33f37e9554d9ff6539785b7d601d7c96685a66c01776' AND f='f44bc966ef77ab523a80ace71b59defbe709c1fdbefd69ccfc40cacaf16d7ba8'
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=57 AND name='production_security_agent_attack_lab' AND checksum=c)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_attack_lab_checksum' AND value=c)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_attack_lab_fingerprint' AND value=f)
 AND public.zasp_sa_attack_lab_role_ready()
 AND zasp_authorization80.ready('d7fbda32a2b3b9ea0ffbd4f7c7a7967a9d4fba2f6573f49e8386e9586a18a1fd')
 AND(public.zasp_discovery_principal_ready('zasp_discovery_api') OR public.zasp_security_agent_principal_ready('zasp_security_agent_api')),false)
$attack_lab_ready$;

CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_export_ready(c text,f text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $export_ready$
 SELECT COALESCE(c='5ee183aae4e67f55c6e1ed89b2d020266b3160e0df8e3101ba51faa705f4c985' AND f='8ddd2617904003772da27cdf92dd48fcc3714596d773a144f67dc8abf175ca1f'
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=58 AND name='production_security_agent_exports' AND checksum=c)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_exports_checksum' AND value=c)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_exports_fingerprint' AND value=f)
 AND public.zasp_sa_export_principal_ready('zasp_security_agent_api')
 AND zasp_authorization80.ready('d7fbda32a2b3b9ea0ffbd4f7c7a7967a9d4fba2f6573f49e8386e9586a18a1fd'),false)
$export_ready$;

-- Security Agent definitions (GET /security-agents). The chain's
-- workflow_page('security_agent') reads zasp_workflow_records, which holds no
-- Security Agent; the definitions live in zasp_security_agent_definitions,
-- the source the resolver registers for kind 'security_agent'.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_page(o text,w text,e text,a text,n integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_page$
BEGIN
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['listSecurityAgents'],'view');
 IF n IS NULL OR n NOT BETWEEN 1 AND 100 OR(a IS NOT NULL AND NOT public.zasp_valid_product_id(a)) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent page rejected';END IF;
 IF NOT public.zasp_security_agent_principal_ready('zasp_security_agent_api') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization security agent principal rejected';END IF;
 RETURN(WITH candidates AS(SELECT d.definition_id AS id,d.body FROM public.zasp_security_agent_definitions d WHERE(d.organization_id,d.workspace_id,d.environment_id)=(o,w,e) AND d.deleted_at IS NULL AND(a IS NULL OR d.definition_id>a) AND zasp_authorization80.allowed(o,w,e,'security_agent',d.definition_id) ORDER BY d.definition_id LIMIT n+1),visible AS(SELECT * FROM candidates ORDER BY id LIMIT n)
 SELECT jsonb_build_object('items',COALESCE((SELECT jsonb_agg(body ORDER BY id) FROM visible),'[]'::jsonb),'next_id',CASE WHEN(SELECT count(*) FROM candidates)>n THEN(SELECT max(id) FROM visible) END));
END $security_agent_page$;

-- Execution controls (GET /security-agent-execution-controls): browser
-- session only, manage_identity on the current Environment. The payload is
-- the chain's own detail plus the eight action switches of the export release.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_execution_controls(o text,w text,e text,actor text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $execution_controls$
DECLARE result jsonb;
BEGIN
 IF NOT COALESCE(zasp_authorization80.read_request(o,w,e,ARRAY['getSecurityAgentExecutionControls'],'manage_identity',true,actor) AND zasp_authorization80.allowed(o,w,e,'environment',e),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current read purpose required';END IF;
 result:=public.zasp_security_agent_execution_control_detail(o,w,e);
 RETURN jsonb_set(result,'{actions}',(SELECT jsonb_agg(jsonb_build_object('target','action','action_key',k,'enabled',COALESCE(c.execution_enabled,false),'version',COALESCE(c.version,0)) ORDER BY k)
  FROM unnest(ARRAY['create_evidence_export','create_temporary_policy','isolate_session','rerun_test','revoke_integration_connection','run_test','start_attack_lab','update_finding_response']) k
  LEFT JOIN public.zasp_security_agent_kill_switches c ON(c.organization_id,c.workspace_id,c.environment_id,c.action_key)=(o,w,e,k)));
END $execution_controls$;

-- Runs (GET /security-agent-runs). Same selection, order, keyset and item
-- shape as the chain's zasp_security_agent_run_page, restricted to allowed runs.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_run_page(o text,w text,e text,definition_value text,state_value text,before_created_value timestamptz,before_id_value text,n integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_run_page$
DECLARE items_value jsonb;next_created_value timestamptz;next_id_value text;
BEGIN
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['listSecurityAgentRuns'],'view');
 IF n IS NULL OR n NOT BETWEEN 1 AND 100
  OR(definition_value IS NOT NULL AND NOT public.zasp_valid_product_id(definition_value))
  OR(state_value IS NOT NULL AND state_value NOT IN('queued','planning','waiting_approval','running','verifying','contained','remediated','needs_human','failed','inconclusive','cancelled'))
  OR(before_created_value IS NULL)<>(before_id_value IS NULL) OR(before_id_value IS NOT NULL AND NOT public.zasp_valid_product_id(before_id_value))
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent run page rejected';END IF;
 IF NOT public.zasp_security_agent_principal_ready('zasp_security_agent_api') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization security agent principal rejected';END IF;
 WITH candidates AS(
  SELECT run.*,row_number() OVER(ORDER BY run.created_at DESC,run.run_id DESC) AS ordinal
  FROM public.zasp_security_agent_runs run
  WHERE(run.organization_id,run.workspace_id,run.environment_id)=(o,w,e)
   AND run.state<>'simulated' AND(definition_value IS NULL OR run.definition_id=definition_value) AND(state_value IS NULL OR run.state=state_value)
   AND(before_created_value IS NULL OR(run.created_at,run.run_id)<(before_created_value,before_id_value))
   AND zasp_authorization80.allowed(o,w,e,'security_agent_run',run.run_id)
  ORDER BY run.created_at DESC,run.run_id DESC LIMIT n+1
 )
 SELECT COALESCE(jsonb_agg(jsonb_build_object('id',run_id,'agent_id',definition_id,'state',state,'evidence_ids',public.zasp_sa_manual_evidence(o,w,e,run_id,trigger_id),'definition_version',definition_version,'version',version)||public.zasp_sa_manual_fields(o,w,e,run_id) ORDER BY created_at DESC,run_id DESC) FILTER(WHERE ordinal<=n),'[]'::jsonb),
        max(created_at) FILTER(WHERE ordinal=n AND(SELECT count(*) FROM candidates)>n),
        max(run_id) FILTER(WHERE ordinal=n AND(SELECT count(*) FROM candidates)>n)
 INTO items_value,next_created_value,next_id_value FROM candidates;
 RETURN jsonb_build_object('items',items_value,'next_created_at',CASE WHEN next_created_value IS NULL THEN NULL ELSE to_char(next_created_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END,'next_id',next_id_value);
END $security_agent_run_page$;

-- Approvals (GET /security-agent-approvals). The items are produced by the
-- chain's newest actor-bound reader, zasp_temporal78.approval_page, which
-- keeps its own release, principal and viewer checks and assembles each
-- family's item. This function adds the current read purpose and makes the
-- allowed set part of the selection: it reads the reader's keyset forward
-- until it holds the requested number of allowed approvals, so a page is full
-- whenever enough allowed approvals exist, and the cursor it returns is the
-- keyset position of the last approval it returned, never of one it withheld.
-- The scan is bounded; a caller that is allowed almost nothing in a very long
-- list is refused rather than served a cursor over withheld rows.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_approval_page(o text,w text,e text,state_value text,run_value text,before_created_value timestamptz,before_id_value text,n integer,actor text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_approval_page$
DECLARE page_value jsonb;item jsonb;item_id text;kept jsonb:='[]'::jsonb;kept_ids text[]:=ARRAY[]::text[];
 cursor_created timestamptz:=before_created_value;cursor_id text:=before_id_value;rounds integer:=0;next_created_value timestamptz;
BEGIN
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['listSecurityAgentApprovals'],'view',false,actor);
 IF n IS NULL OR n NOT BETWEEN 1 AND 100 OR(before_created_value IS NULL)<>(before_id_value IS NULL) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent approval page rejected';END IF;
 LOOP
  rounds:=rounds+1;
  IF rounds>20 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authorization security agent approval page unavailable';END IF;
  page_value:=zasp_temporal78.approval_page(o,w,e,state_value,run_value,cursor_created,cursor_id,LEAST(100,n+1-cardinality(kept_ids)),actor);
  IF jsonb_typeof(page_value->'items') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authorization security agent approval page unavailable';END IF;
  FOR item IN SELECT x.value FROM jsonb_array_elements(page_value->'items') WITH ORDINALITY x(value,ordinality) ORDER BY x.ordinality LOOP
   item_id:=COALESCE(item->'detail'->>'id',item->>'id');
   IF item_id IS NOT NULL AND zasp_authorization80.allowed(o,w,e,'security_agent_approval',item_id) THEN
    kept:=kept||jsonb_build_array(item);kept_ids:=kept_ids||item_id;
   END IF;
  END LOOP;
  EXIT WHEN cardinality(kept_ids)>n OR page_value->>'next_id' IS NULL OR page_value->>'next_created_at' IS NULL;
  cursor_created:=(page_value->>'next_created_at')::timestamptz;cursor_id:=page_value->>'next_id';
 END LOOP;
 IF cardinality(kept_ids)<=n THEN RETURN jsonb_build_object('items',kept,'next_created_at',NULL,'next_id',NULL);END IF;
 -- More allowed approvals exist: the cursor is the last returned approval.
 SELECT a.created_at INTO next_created_value FROM public.zasp_security_agent_approvals a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.approval_id)=(o,w,e,kept_ids[n]);
 IF next_created_value IS NULL THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authorization security agent approval page unavailable';END IF;
 RETURN jsonb_build_object('items',(SELECT jsonb_agg(x.value ORDER BY x.ordinality) FROM jsonb_array_elements(kept) WITH ORDINALITY x(value,ordinality) WHERE x.ordinality<=n),
  'next_created_at',to_char(next_created_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'next_id',kept_ids[n]);
END $security_agent_approval_page$;

-- ---------------------------------------------------------------------------
-- C. Tests, test runs and Attack Lab runs. Same selection, order, cursor and
-- item shape as zasp_red_team_list_definitions, zasp_red_team_list_runs and
-- zasp_attack_lab_list_runs, restricted to allowed rows.
CREATE OR REPLACE FUNCTION zasp_authorization80.test_page(o text,w text,e text,a text,n integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $test_page$
DECLARE result jsonb;
BEGIN
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['listTests'],'view');
 IF n IS NULL OR n NOT BETWEEN 1 AND 100 OR(a IS NOT NULL AND NOT public.zasp_valid_product_id(a)) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization test page rejected';END IF;
 IF NOT public.zasp_security_agent_principal_ready('zasp_security_agent_api') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization security agent principal rejected';END IF;
 SELECT jsonb_build_object('items',COALESCE(jsonb_agg(public.zasp_red_team_definition_json(definition_row) ORDER BY definition_id),'[]'::jsonb),'next_cursor',CASE WHEN count(*)=n THEN max(definition_id) END) INTO result
 FROM(SELECT * FROM public.zasp_red_team_definitions d WHERE(d.organization_id,d.workspace_id,d.environment_id)=(o,w,e) AND(a IS NULL OR d.definition_id>a) AND zasp_authorization80.allowed(o,w,e,'test',d.definition_id) ORDER BY d.definition_id LIMIT n) definition_row;
 RETURN result;
END $test_page$;

CREATE OR REPLACE FUNCTION zasp_authorization80.test_run_page(o text,w text,e text,before_value timestamptz,before_id_value text,n integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $test_run_page$
DECLARE result jsonb;
BEGIN
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['listTestRuns'],'view');
 IF n IS NULL OR n NOT BETWEEN 1 AND 100 OR(before_value IS NULL AND before_id_value IS NOT NULL) OR(before_value IS NOT NULL AND NOT COALESCE(public.zasp_valid_product_id(before_id_value),false)) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization test run page rejected';END IF;
 IF NOT public.zasp_security_agent_principal_ready('zasp_security_agent_api') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization security agent principal rejected';END IF;
 WITH visible AS(SELECT * FROM public.zasp_red_team_runs r WHERE(r.organization_id,r.workspace_id,r.environment_id)=(o,w,e) AND(before_value IS NULL OR(r.queued_at,r.run_id)<(before_value,before_id_value)) AND zasp_authorization80.allowed(o,w,e,'test_run',r.run_id) ORDER BY r.queued_at DESC,r.run_id DESC LIMIT n),
 cursor_row AS(SELECT queued_at,run_id FROM visible ORDER BY queued_at,run_id LIMIT 1)
 SELECT jsonb_build_object('items',COALESCE((SELECT jsonb_agg(public.zasp_red_team_run_json(run_row) ORDER BY queued_at DESC,run_id DESC) FROM visible run_row),'[]'::jsonb),'next_cursor',CASE WHEN(SELECT count(*) FROM visible)=n THEN(SELECT jsonb_build_object('queued_at',to_char(queued_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'id',run_id) FROM cursor_row) END) INTO result;
 RETURN result;
END $test_run_page$;

CREATE OR REPLACE FUNCTION zasp_authorization80.attack_lab_run_page(o text,w text,e text,before_value timestamptz,before_id_value text,n integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $attack_lab_run_page$
DECLARE result jsonb;
BEGIN
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['listAttackLabRuns'],'view');
 IF n IS NULL OR n NOT BETWEEN 1 AND 100 OR(before_value IS NULL AND before_id_value IS NOT NULL) OR(before_value IS NOT NULL AND NOT COALESCE(public.zasp_valid_product_id(before_id_value),false)) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization attack lab run page rejected';END IF;
 IF NOT public.zasp_security_agent_principal_ready('zasp_security_agent_api') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization security agent principal rejected';END IF;
 WITH visible AS(SELECT * FROM public.zasp_attack_lab_runs r WHERE(r.organization_id,r.workspace_id,r.environment_id)=(o,w,e) AND(before_value IS NULL OR(r.queued_at,r.run_id)<(before_value,before_id_value)) AND zasp_authorization80.allowed(o,w,e,'attack_lab_run',r.run_id) ORDER BY r.queued_at DESC,r.run_id DESC LIMIT n),
 cursor_row AS(SELECT queued_at,run_id FROM visible ORDER BY queued_at,run_id LIMIT 1)
 SELECT jsonb_build_object('items',COALESCE((SELECT jsonb_agg(public.zasp_attack_lab_run_json(run_row) ORDER BY queued_at DESC,run_id DESC) FROM visible run_row),'[]'::jsonb),'next_cursor',CASE WHEN(SELECT count(*) FROM visible)=n THEN(SELECT jsonb_build_object('queued_at',to_char(queued_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'id',run_id) FROM cursor_row) END) INTO result;
 RETURN result;
END $attack_lab_run_page$;

-- ---------------------------------------------------------------------------
-- D. Organization and identity administration reads. Browser session only.
-- zasp_authorization80_identity had the mutations but no read.

-- GET /organization: view on the Organization of the proof.
CREATE OR REPLACE FUNCTION zasp_authorization80.organization(o text,w text,e text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $organization$
DECLARE result jsonb;
BEGIN
 IF NOT COALESCE(public.zasp_discovery_principal_ready('zasp_discovery_api') AND zasp_authorization80.read_request(o,w,e,ARRAY['getOrganization'],'view',true) AND zasp_authorization80.allowed(o,w,e,'organization',o),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current read purpose required';END IF;
 SELECT jsonb_build_object('id',x.id,'name',x.name,'domain',x.domain,'version',x.version) INTO result FROM public.zasp_organizations x WHERE x.id=o;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='organization missing';END IF;
 RETURN result;
END $organization$;

-- Shared admission of the identity administration reads: the verified
-- identity release, the actor of the proof, manage_identity, and the target
-- the operation's policy names (the Organization's identity, or the current
-- Environment).
CREATE OR REPLACE FUNCTION zasp_authorization80.require_identity_read(op text,o text,w text,e text,actor text) RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $require_identity_read$
BEGIN
 IF NOT COALESCE(zasp_authorization80_identity.api_ready()
  AND op IN('listMembers','listGroupMappings','listSSOConnections','listSCIMConnections')
  AND zasp_authorization80.read_request(o,w,e,ARRAY[op],'manage_identity',true,actor)
  AND CASE WHEN op='listGroupMappings' THEN zasp_authorization80.allowed(o,w,e,'environment',e) ELSE zasp_authorization80.allowed(o,w,e,'organization_identity',o) END,false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='checked identity administration read required';END IF;
END $require_identity_read$;

-- GET /admin/members.
CREATE OR REPLACE FUNCTION zasp_authorization80.member_page(o text,w text,e text,actor text,a text,n integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $member_page$
BEGIN
 PERFORM zasp_authorization80.require_identity_read('listMembers',o,w,e,actor);
 IF NOT COALESCE(n BETWEEN 1 AND 101 AND a IS NOT NULL AND(a='' OR public.zasp_valid_product_id(a)),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization member page rejected';END IF;
 RETURN(SELECT jsonb_build_object('items',COALESCE(jsonb_agg(item ORDER BY item->>'id'),'[]'::jsonb)) FROM(
  SELECT jsonb_build_object('id',m.principal_id,'organization_id',m.organization_id,'organization_reference',m.organization_reference,'member_reference',m.member_reference,'role',m.role,'active',m.active,'version',m.version) AS item
  FROM public.zasp_identity_memberships m WHERE m.organization_id=o AND(a='' OR m.principal_id>a) ORDER BY m.principal_id LIMIT n) page);
END $member_page$;

-- GET /admin/group-mappings. The proof authorizes manage_identity on the
-- current Environment, and updateGroupMappings writes mappings for that
-- Environment, so the page lists that Environment's mappings.
CREATE OR REPLACE FUNCTION zasp_authorization80.group_mapping_page(o text,w text,e text,actor text,a text,n integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $group_mapping_page$
BEGIN
 PERFORM zasp_authorization80.require_identity_read('listGroupMappings',o,w,e,actor);
 IF NOT COALESCE(n BETWEEN 1 AND 101 AND a IS NOT NULL AND octet_length(a)<=512,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization group mapping page rejected';END IF;
 RETURN(SELECT jsonb_build_object('items',COALESCE(jsonb_agg(item ORDER BY item->>'group_reference'),'[]'::jsonb)) FROM(
  SELECT jsonb_build_object('group_reference',g.group_reference,'role',g.role,'workspace_id',g.workspace_id,'environment_id',g.environment_id,'version',g.version) AS item
  FROM public.zasp_group_mappings g WHERE(g.organization_id,g.workspace_id,g.environment_id)=(o,w,e) AND(a='' OR g.group_reference>a) ORDER BY g.group_reference LIMIT n) page);
END $group_mapping_page$;

-- The identity provider's reference for the Organization, which the SSO and
-- SCIM connection lists send to the provider. Same rule as the chain's
-- zasp_identity_admin_provider_organization (an active organization or
-- security administrator), under the checked read.
CREATE OR REPLACE FUNCTION zasp_authorization80.identity_provider_organization(o text,w text,e text,actor text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $identity_provider_organization$
DECLARE reference text;op text;
BEGIN
 op:=zasp_authorization80.context()->>'operation_id';
 IF op IS NULL OR op NOT IN('listSSOConnections','listSCIMConnections') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='checked identity administration read required';END IF;
 PERFORM zasp_authorization80.require_identity_read(op,o,w,e,actor);
 SELECT m.organization_reference INTO reference FROM public.zasp_identity_memberships m
 WHERE(m.organization_id,m.principal_id)=(o,actor) AND m.active AND m.role IN('organization_admin','security_admin');
 IF NOT FOUND OR reference IS NULL THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='identity provider organization missing';END IF;
 RETURN to_jsonb(reference);
END $identity_provider_organization$;

-- ---------------------------------------------------------------------------
-- E. Audit events. The audit page (zasp_authorization80.audit_page) existed.
-- Its readiness also asks whether the single-test release (zasp_temporal74)
-- is valid, through zasp_temporal74.api_ready, which only the Security Agent
-- API role may execute and which is true only for that role. The product API
-- role serves the audit page, so its readiness could never pass. This states
-- the same release validity for either API role; it grants nothing in
-- zasp_temporal74.
CREATE OR REPLACE FUNCTION zasp_authorization80.test_release_ready(c text,f text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $test_release_ready$
 SELECT COALESCE(zasp_temporal74.ready(c,f)
 AND(public.zasp_discovery_principal_ready('zasp_discovery_api') OR public.zasp_security_agent_principal_ready('zasp_security_agent_api')),false)
$test_release_ready$;

-- ---------------------------------------------------------------------------
-- Ownership and privileges, as the neighbouring functions have them.
DO $privileges$
DECLARE f record;
BEGIN
 FOR f IN SELECT * FROM(VALUES
  ('zasp_authorization80.security_agent_attack_lab_ready(text,text)','zasp_discovery_api,zasp_security_agent_api'),
  ('zasp_authorization80.security_agent_export_ready(text,text)','zasp_security_agent_api'),
  ('zasp_authorization80.security_agent_page(text,text,text,text,integer)','zasp_security_agent_api'),
  ('zasp_authorization80.security_agent_execution_controls(text,text,text,text)','zasp_security_agent_api'),
  ('zasp_authorization80.security_agent_run_page(text,text,text,text,text,timestamptz,text,integer)','zasp_security_agent_api'),
  ('zasp_authorization80.security_agent_approval_page(text,text,text,text,text,timestamptz,text,integer,text)','zasp_security_agent_api'),
  ('zasp_authorization80.test_page(text,text,text,text,integer)','zasp_security_agent_api'),
  ('zasp_authorization80.test_run_page(text,text,text,timestamptz,text,integer)','zasp_security_agent_api'),
  ('zasp_authorization80.attack_lab_run_page(text,text,text,timestamptz,text,integer)','zasp_security_agent_api'),
  ('zasp_authorization80.organization(text,text,text)','zasp_discovery_api'),
  ('zasp_authorization80.require_identity_read(text,text,text,text,text)',NULL),
  ('zasp_authorization80.member_page(text,text,text,text,text,integer)','zasp_discovery_api'),
  ('zasp_authorization80.group_mapping_page(text,text,text,text,text,integer)','zasp_discovery_api'),
  ('zasp_authorization80.identity_provider_organization(text,text,text,text)','zasp_discovery_api'),
  ('zasp_authorization80.test_release_ready(text,text)','zasp_discovery_api,zasp_security_agent_api')
 ) v(signature,grantees) LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',f.signature::regprocedure);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f.signature::regprocedure);
  IF f.grantees IS NOT NULL THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %s',f.signature::regprocedure,f.grantees);END IF;
 END LOOP;
END $privileges$;

-- ---------------------------------------------------------------------------
-- F. Candidate resolution checks readiness once per call.
--
-- zasp_authorization80.resolve verified the release (reader() and ready())
-- on entry, and every nested resolution repeated it: a mixed collection
-- ('*') resolves 23 kinds, and an audit collection resolves '*' for every
-- Environment of the Organization, so one request evaluated the same
-- readiness about 70 times (16 s for three empty Environments; the audit
-- route never answered inside its deadline). The catalog cannot change
-- between those evaluations in a way the first one would not also see.
--
-- resolve keeps its signature, grants and entry check, and then calls
-- resolve_inner: the same body, verbatim, without the check, whose nested
-- resolutions stay inside it. Only resolve_inner's owner can execute it.
-- parent_targets is reachable without resolve (from parent_allowed, inside a
-- fenced read), so its collection branch performs the check itself before it
-- uses resolve_inner. Its per-object branches still call the checked resolve.
-- No candidate, target or permission rule changes.
DO $resolve_once$
DECLARE d text;
 guard text:=$g$ IF NOT zasp_authorization79.reader() OR NOT zasp_authorization80.ready('d7fbda32a2b3b9ea0ffbd4f7c7a7967a9d4fba2f6573f49e8386e9586a18a1fd') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization resolver rejected';END IF;$g$;
 nested text:=$n$result:=result||zasp_authorization80.resolve(o,scope_value.workspace_id,scope_value.id,'*',NULL);$n$;
 branch text:=$b$ IF i IS NULL THEN$b$;
BEGIN
 IF to_regprocedure('zasp_authorization80.resolve_inner(text,text,text,text,text,text)') IS NOT NULL THEN RETURN;END IF;
 SELECT pg_get_functiondef('zasp_authorization80.resolve(text,text,text,text,text,text)'::regprocedure) INTO STRICT d;
 IF (length(d)-length(replace(d,guard,'')))/length(guard)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authorization resolver predecessor changed';END IF;
 EXECUTE replace(replace(d,guard,''),'zasp_authorization80.resolve(','zasp_authorization80.resolve_inner(');
 SELECT pg_get_functiondef('zasp_authorization80.parent_targets(text,text,text,text,text,text)'::regprocedure) INTO STRICT d;
 IF (length(d)-length(replace(d,nested,'')))/length(nested)<>1 OR (length(d)-length(replace(d,branch,'')))/length(branch)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authorization parent resolver predecessor changed';END IF;
 EXECUTE replace(replace(d,nested,replace(nested,'zasp_authorization80.resolve(','zasp_authorization80.resolve_inner(')),branch,branch||E'\n '||guard);
END $resolve_once$;

CREATE OR REPLACE FUNCTION zasp_authorization80.resolve(o text,w text,e text,k text,i text DEFAULT NULL,selector text DEFAULT NULL) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $resolve$
BEGIN
 IF NOT zasp_authorization79.reader() OR NOT zasp_authorization80.ready('d7fbda32a2b3b9ea0ffbd4f7c7a7967a9d4fba2f6573f49e8386e9586a18a1fd') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization resolver rejected';END IF;
 RETURN zasp_authorization80.resolve_inner(o,w,e,k,i,selector);
END $resolve$;
ALTER FUNCTION zasp_authorization80.resolve_inner(text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.resolve_inner(text,text,text,text,text,text) FROM PUBLIC,zasp_discovery_api,zasp_security_agent_api,zasp_outbox_worker,zasp_security_agent_worker;


-- ---------------------------------------------------------------------------
-- G. Worker startup gate and AWS identity classification.
--
-- Every worker mode asks zasp_authorization80_worker.runtime_ready() at
-- startup unless it uses the runtime profile check. The chain granted that
-- question only to the Temporal, discovery and scheduler roles, so every other
-- worker mode (outbox publishers, projections, Security Agent, Red Team,
-- Attack Lab, policy deployment, recovery, exports, compliance) refused to
-- start on any database. The function returns one boolean about catalog
-- integrity and reads no tenant data.
DO $worker_gate$
DECLARE worker text;
BEGIN
 FOREACH worker IN ARRAY ARRAY[
  'zasp_attack_lab_controller','zasp_attack_lab_outbox_worker','zasp_audit_export_outbox','zasp_audit_export_worker',
  'zasp_compliance_cleanup','zasp_compliance_worker','zasp_outbox_worker','zasp_policy_deployment_worker',
  'zasp_projection_graph_worker','zasp_projection_risk_worker','zasp_projection_search_worker',
  'zasp_recovery_outbox_worker','zasp_recovery_worker','zasp_red_team_outbox_worker','zasp_red_team_worker',
  'zasp_security_agent_action_worker','zasp_security_agent_attack_lab_reconciler','zasp_security_agent_worker'] LOOP
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=worker) THEN
   EXECUTE format('GRANT USAGE ON SCHEMA zasp_authorization80_worker TO %I',worker);
   EXECUTE format('GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.runtime_ready() TO %I',worker);
  END IF;
 END LOOP;
END $worker_gate$;

-- An AWS IAM role is a non-human identity. The chain classified every AWS
-- kind as an asset, and assets have no list route, so nothing an AWS
-- discovery run found could be listed.
UPDATE public.zasp_inventory_identity_rules SET product_kind='identity',rule_version=rule_version+1
 WHERE provider='aws' AND source_kind='aws_role' AND product_kind='asset';

-- ---------------------------------------------------------------------------
-- H. Security Agent writes: create, update, delete, activate, run and the
-- execution controls, plus the two single-object reads those flows need.
--
-- The chain serves each Security Agent family from its own release
-- (finding response: zasp_temporal78; single existing test: zasp_temporal74
-- and zasp_temporal76; ordered containment and re-test: zasp_ordered_public62
-- over release 61; the remaining single actions: the base functions). The API
-- chose the family with several statements per request, none of which is an
-- authorized function, so under the current model every Security Agent write
-- was refused. Each function below is one statement: it binds the request to
-- the attested proof and then calls the chain's own writer for the family,
-- which keeps every check it already had (release, principal, actor
-- permission, optimistic version, idempotent replay, audit and receipt).
--
-- security_agent_write_request is the shared admission. It returns the proof
-- only when the fenced transaction carries exactly this operation with the
-- permission the operation's policy names, for this Organization, Workspace,
-- Environment and actor, as a non-collection request, with fresh
-- authentication and a browser session where the policy requires them, for
-- the object named in the request path, and when that object (or, for
-- Environment-level writes, the Environment) is among the allowed targets.
-- It then re-verifies the credential and membership under row locks.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_write_request(o text,w text,e text,actor text,op text,d text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_write_request$
DECLARE p jsonb:=zasp_authorization80.context();permission_value text;browser boolean:=false;fresh boolean:=false;kind text:='security_agent';target text:=d;
BEGIN
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization security agent principal rejected';END IF;
 CASE op
  WHEN 'createSecurityAgent' THEN permission_value:='manage_workflows';kind:='environment';target:=e;
  WHEN 'updateSecurityAgent','deleteSecurityAgent','runSecurityAgent' THEN permission_value:='manage_workflows';
  WHEN 'activateSecurityAgent' THEN permission_value:='manage_workflows';browser:=true;fresh:=true;
  WHEN 'getSecurityAgent','getSecurityAgentActivation' THEN permission_value:='view';
  WHEN 'setSecurityAgentExecutionControl' THEN permission_value:='manage_identity';browser:=true;fresh:=true;kind:='environment';target:=e;
  ELSE RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current security agent authorization required';
 END CASE;
 IF p IS NULL OR actor IS NULL OR target IS NULL OR NOT COALESCE(public.zasp_valid_product_id(target),false)
  OR NOT COALESCE(zasp_authorization80.read_request(o,w,e,ARRAY[op],permission_value,browser,actor)
   AND p->'collection'='false'::jsonb
   AND(NOT fresh OR p->'fresh_auth'='true'::jsonb)
   AND(kind='environment' OR p#>>'{path_parameters,id}'=d)
   AND zasp_authorization80.allowed(o,w,e,kind,target),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current security agent authorization required';END IF;
 PERFORM zasp_authorization80.identity_fence(p);
 RETURN p;
END $security_agent_write_request$;

-- The proof must still be the one the function started with when it returns:
-- an expired or replaced proof fails the statement and rolls the write back.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_write_settled(p jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_write_settled$
BEGIN
 IF p IS NULL OR p IS DISTINCT FROM zasp_authorization80.context() OR NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false)
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='current security agent proof expired';END IF;
 PERFORM zasp_authorization80.identity_fence(p);
END $security_agent_write_settled$;

-- A definition body whose only action is the evidence export belongs to
-- release 58, whose own readiness pins a 60-release catalog and can never
-- pass here. Its writer is therefore not offered; the request is refused.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_export_family(o text,w text,e text,d text,body_value jsonb) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_export_family$
 SELECT COALESCE(body_value->'allowed_actions' ? 'create_evidence_export',false)
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_definitions x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.definition_id)=(o,w,e,d) AND x.body->'allowed_actions' ? 'create_evidence_export')
$security_agent_export_family$;

-- GET /security-agents/{id}, and the current value an update or delete reads.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_definition_value(o text,w text,e text,d text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_definition_value$
DECLARE p jsonb:=zasp_authorization80.context();op text;result jsonb;
BEGIN
 op:=p->>'operation_id';
 IF op IS NULL OR op NOT IN('getSecurityAgent','updateSecurityAgent','deleteSecurityAgent') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current security agent authorization required';END IF;
 p:=zasp_authorization80.security_agent_write_request(o,w,e,p->>'principal_id',op,d);
 result:=public.zasp_security_agent_definition_value(o,w,e,d);
 IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='security agent definition missing';END IF;
 RETURN result;
END $security_agent_definition_value$;

-- GET /security-agents/{id}/activation.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_activation(o text,w text,e text,d text,actor text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_activation$
DECLARE p jsonb;result jsonb;
BEGIN
 p:=zasp_authorization80.security_agent_write_request(o,w,e,actor,'getSecurityAgentActivation',d);
 result:=zasp_temporal78.definition(o,w,e,d,actor);
 IF result IS NULL THEN result:=zasp_temporal74.definition(o,w,e,d,actor);END IF;
 IF result IS NULL THEN result:=public.zasp_security_agent_definition_detail(o,w,e,d);END IF;
 IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='security agent definition missing';END IF;
 RETURN result;
END $security_agent_activation$;

-- Idempotent replay of a definition write (the API asks before it writes).
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_definition_replay(o text,w text,e text,actor text,operation_value text,k text,intent_value jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_definition_replay$
DECLARE p jsonb;result jsonb;d text;
BEGIN
 IF operation_value IS NULL OR operation_value NOT IN('createSecurityAgent','updateSecurityAgent','deleteSecurityAgent') OR jsonb_typeof(intent_value) IS DISTINCT FROM 'object' OR octet_length(intent_value::text)>65536
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent replay rejected';END IF;
 d:=CASE operation_value WHEN 'createSecurityAgent' THEN NULL ELSE intent_value->>'resource_id' END;
 p:=zasp_authorization80.security_agent_write_request(o,w,e,actor,operation_value,d);
 result:=zasp_temporal78.configuration_replay(o,w,e,actor,operation_value,k,intent_value);
 IF result IS NULL THEN result:=zasp_temporal74.configuration_replay(o,w,e,actor,operation_value,k,intent_value);END IF;
 IF result IS NULL THEN result:=public.zasp_security_agent_replay_definition(o,w,e,actor,operation_value,k,intent_value);END IF;
 RETURN result;
END $security_agent_definition_replay$;

-- POST /security-agents, PATCH and DELETE /security-agents/{id}. Argument
-- order is the chain's (mutation, id, scope, actor, operation, key, version,
-- intent, body, audit, correlation, receipt).
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_definition_mutate(mutation_value text,d text,o text,w text,e text,actor text,operation_value text,k text,v bigint,intent_value jsonb,body_value jsonb,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_definition_mutate$
DECLARE p jsonb;result jsonb;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='authorization security agent write requires read committed';END IF;
 IF NOT COALESCE((mutation_value,operation_value) IN(('create','createSecurityAgent'),('update','updateSecurityAgent'),('delete','deleteSecurityAgent'))
  AND public.zasp_valid_product_id(d) AND public.zasp_valid_product_id(audit_value) AND public.zasp_valid_product_id(correlation_value)
  AND length(k) BETWEEN 16 AND 128 AND k~'^[A-Za-z0-9][A-Za-z0-9._:-]*$'
  AND v BETWEEN 0 AND 1000000 AND(mutation_value='create')=(v=0)
  AND jsonb_typeof(intent_value)='object' AND jsonb_typeof(body_value)='object' AND octet_length(body_value::text)<=65536 AND octet_length(intent_value::text)<=131072
  AND(mutation_value='delete' OR body_value->>'id'=d),false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent definition rejected';END IF;
 p:=zasp_authorization80.security_agent_write_request(o,w,e,actor,operation_value,d);
 -- A browser session carries a mutation receipt; an API token carries none.
 IF NOT COALESCE((p->>'credential_kind'='1' AND public.zasp_valid_product_id(receipt_value)) OR(p->>'credential_kind'='2' AND receipt_value=''),false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent receipt rejected';END IF;
 IF zasp_authorization80.security_agent_export_family(o,w,e,d,body_value) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent export definitions unavailable';END IF;
 -- Configured trigger rules are admitted only by the automatic-sources release.
 IF mutation_value<>'delete' AND body_value ? 'trigger_rules' AND NOT COALESCE(zasp_temporal77.api_ready('3b6117ba1b9b0e9cc2871bc89bf0027b7ca3d400b1354f0550c068f2145de3fb','8cac13406a1886a98cd327065e5525be28997add7a9bd359d12e7b4ed219f5ef'),false)
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent automatic sources unavailable';END IF;
 result:=zasp_temporal78.configuration_write(mutation_value,d,o,w,e,actor,operation_value,k,v,intent_value,body_value,audit_value,correlation_value,receipt_value);
 IF result IS NULL THEN result:=zasp_temporal74.configuration_write(mutation_value,d,o,w,e,actor,operation_value,k,v,intent_value,body_value,audit_value,correlation_value,receipt_value);END IF;
 IF result IS NULL THEN result:=public.zasp_security_agent_mutate_definition(mutation_value,d,o,w,e,actor,operation_value,k,v,intent_value,body_value,audit_value,correlation_value,receipt_value);END IF;
 IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent definition writer unavailable';END IF;
 PERFORM zasp_authorization80.security_agent_write_settled(p);
 RETURN result;
END $security_agent_definition_mutate$;

-- POST /security-agents/{id}/activation: browser session, fresh
-- authentication. The result names the family that performed the activation.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_activate(o text,w text,e text,d text,actor text,k text,v bigint,activation_value text,fresh_value timestamptz,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_activate$
DECLARE p jsonb;result jsonb;family text;body_value jsonb;scope_value jsonb;
 c CONSTANT text:='e4dfae0a990718c2c6b7518b07d7c146cfb9025656378d423c8d96188bcf1b96';f CONSTANT text:='07e774a28105095c73275ad959c765a3fddda9ee9aa81e81cd3828222e40aad3';
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='authorization security agent write requires read committed';END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(d) AND public.zasp_valid_product_id(audit_value) AND public.zasp_valid_product_id(correlation_value) AND public.zasp_valid_product_id(receipt_value)
  AND length(k) BETWEEN 16 AND 128 AND k~'^[A-Za-z0-9][A-Za-z0-9._:-]*$' AND v BETWEEN 1 AND 999999
  AND activation_value IN('validated','supervised','autonomous') AND fresh_value>clock_timestamp() AND fresh_value<=clock_timestamp()+interval '5 minutes 5 seconds',false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent activation rejected';END IF;
 p:=zasp_authorization80.security_agent_write_request(o,w,e,actor,'activateSecurityAgent',d);
 SELECT x.body INTO body_value FROM public.zasp_security_agent_definitions x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.definition_id)=(o,w,e,d) AND x.deleted_at IS NULL;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='security agent definition missing';END IF;
 IF zasp_authorization80.security_agent_export_family(o,w,e,d,body_value) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent export definitions unavailable';END IF;
 IF body_value ? 'trigger_rules' AND NOT COALESCE(zasp_temporal77.api_ready('3b6117ba1b9b0e9cc2871bc89bf0027b7ca3d400b1354f0550c068f2145de3fb','8cac13406a1886a98cd327065e5525be28997add7a9bd359d12e7b4ed219f5ef'),false)
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent automatic sources unavailable';END IF;
 -- A Monitor-mode temporary policy has no admitted executor: draft only.
 IF body_value->>'temporary_policy_mode'='monitor' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent monitor activation unavailable';END IF;
 scope_value:=jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'actor_id',actor);
 family:=zasp_ordered_public62.api(c,f,scope_value||jsonb_build_object('operation','classify_mutation','mutation_kind','activate','definition_id',d,'idempotency_key',k))->>'family';
 IF family='ordered_release61' THEN
  IF activation_value<>'supervised' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent activation rejected';END IF;
  result:=zasp_ordered_public62.api(c,f,scope_value||jsonb_build_object('operation','activate_resource','definition_id',d,'definition_version',v,'activation',activation_value,'idempotency_key',k));
  family:='ordered';
 ELSIF body_value->'allowed_actions' IN('["run_test"]'::jsonb,'["rerun_test"]'::jsonb) THEN
  result:=zasp_authorization80_worker.test74_activate(o,w,e,d,actor,k,v,activation_value,fresh_value,audit_value,correlation_value,receipt_value);
  family:='test';
 ELSE
  result:=zasp_temporal78.activate(o,w,e,d,actor,k,v,activation_value,fresh_value,audit_value,correlation_value,receipt_value);
  family:='finding';
  IF result IS NULL THEN
   result:=public.zasp_security_agent_activate(o,w,e,d,actor,k,v,activation_value,fresh_value,audit_value,correlation_value,receipt_value);
   family:='legacy';
  END IF;
 END IF;
 IF result IS NULL OR jsonb_typeof(result) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent activation unavailable';END IF;
 PERFORM zasp_authorization80.security_agent_write_settled(p);
 RETURN jsonb_build_object('family',family,'result',result);
END $security_agent_activate$;

-- POST /security-agents/{id}/runs. q is the closed request the chain's
-- admissions take; its scope, actor and definition must equal the arguments,
-- which must equal the proof. A manual trigger is not offered here.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_run(o text,w text,e text,d text,actor text,q jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_run$
DECLARE p jsonb;result jsonb;family text;scope_value jsonb;sourced boolean;
 c CONSTANT text:='e4dfae0a990718c2c6b7518b07d7c146cfb9025656378d423c8d96188bcf1b96';f CONSTANT text:='07e774a28105095c73275ad959c765a3fddda9ee9aa81e81cd3828222e40aad3';
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='authorization security agent write requires read committed';END IF;
 sourced:=COALESCE(q ? 'trigger_version' OR q ? 'trigger_source',false);
 IF q IS NULL OR jsonb_typeof(q)<>'object' OR octet_length(q::text)>8192
  OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','definition_id','actor_id','idempotency_key','definition_version','run_id','trigger_kind','trigger_id','audit_id','correlation_id','receipt_id']||CASE WHEN sourced THEN ARRAY['trigger_version','trigger_source'] ELSE ARRAY[]::text[] END)
  OR(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'definition_id',q->>'actor_id') IS DISTINCT FROM(o,w,e,d,actor)
  OR NOT COALESCE(public.zasp_valid_product_id(d) AND public.zasp_valid_product_id(q->>'run_id') AND public.zasp_valid_product_id(q->>'trigger_id') AND public.zasp_valid_product_id(q->>'audit_id') AND public.zasp_valid_product_id(q->>'correlation_id') AND public.zasp_valid_product_id(q->>'receipt_id')
   AND jsonb_typeof(q->'idempotency_key')='string' AND length(q->>'idempotency_key') BETWEEN 16 AND 128 AND q->>'idempotency_key'~'^[A-Za-z0-9][A-Za-z0-9._:-]*$'
   AND jsonb_typeof(q->'definition_version')='number' AND q->>'definition_version'~'^([1-9][0-9]{0,5}|1000000)$'
   AND jsonb_typeof(q->'trigger_kind')='string' AND q->>'trigger_kind' IN('finding','session','attack_path')
   AND(NOT sourced OR(jsonb_typeof(q->'trigger_version')='number' AND q->>'trigger_version'~'^[1-9][0-9]{0,15}$' AND jsonb_typeof(q->'trigger_source')='string' AND length(q->>'trigger_source') BETWEEN 1 AND 128)),false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent run rejected';END IF;
 p:=zasp_authorization80.security_agent_write_request(o,w,e,actor,'runSecurityAgent',d);
 IF zasp_authorization80.security_agent_export_family(o,w,e,d,NULL) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent export definitions unavailable';END IF;
 result:=zasp_temporal78.resource(q);family:='finding';
 IF result IS NULL OR result='null'::jsonb THEN result:=zasp_temporal76.resource(q);family:='test';END IF;
 IF(result IS NULL OR result='null'::jsonb) AND sourced AND(q->>'trigger_version')::numeric<=1000000 THEN
  scope_value:=jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'actor_id',actor);
  IF zasp_ordered_public62.api(c,f,scope_value||jsonb_build_object('operation','classify_mutation','mutation_kind','trigger','definition_id',d,'idempotency_key',q->'idempotency_key','trigger',jsonb_build_object('trigger_id',q->'trigger_id','trigger_version',q->'trigger_version')))->>'family'='ordered_release61' THEN
   result:=zasp_ordered_public62.api(c,f,scope_value||jsonb_build_object('operation','trigger_resource','definition_id',d,'definition_version',q->'definition_version','trigger_id',q->'trigger_id','trigger_version',q->'trigger_version','trigger_kind',q->'trigger_kind','trigger_source',q->'trigger_source','idempotency_key',q->'idempotency_key'));
   family:='ordered';
  END IF;
 END IF;
 IF(result IS NULL OR result='null'::jsonb) AND NOT sourced THEN
  result:=public.zasp_security_agent_run_v24(o,w,e,d,actor,q->>'idempotency_key',(q->>'definition_version')::bigint,q->>'run_id',q->>'trigger_kind',q->>'trigger_id',q->>'audit_id',q->>'correlation_id',q->>'receipt_id');
  family:='legacy';
 END IF;
 IF result IS NULL OR jsonb_typeof(result) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent run family rejected';END IF;
 PERFORM zasp_authorization80.security_agent_write_settled(p);
 RETURN jsonb_build_object('family',family,'result',result);
END $security_agent_run$;

-- PUT /security-agent-execution-controls: browser session, fresh
-- authentication, manage_identity on the current Environment. The writer is
-- the chain's newest control core (all eight action switches) with the lock
-- order and the expiry re-check of its release wrappers; those wrappers
-- themselves pin a 60-release catalog. The evidence-export switch can be
-- enabled only while the export capability is ready for the current catalog.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_set_execution_control(o text,w text,e text,actor text,k text,target_value text,action_value text,enabled_value boolean,v bigint,fresh_value timestamptz,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_set_execution_control$
DECLARE p jsonb;result jsonb;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='authorization security agent write requires read committed';END IF;
 p:=zasp_authorization80.security_agent_write_request(o,w,e,actor,'setSecurityAgentExecutionControl',NULL);
 IF NOT COALESCE((target_value,action_value)=('environment','*') OR(target_value='action' AND action_value IN('create_evidence_export','create_temporary_policy','isolate_session','rerun_test','revoke_integration_connection','run_test','start_attack_lab','update_finding_response')),false)
  OR enabled_value IS NULL OR fresh_value IS NULL
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent execution control rejected';END IF;
 IF action_value='create_evidence_export' AND enabled_value AND NOT COALESCE(zasp_authorization80.security_agent_export_ready('5ee183aae4e67f55c6e1ed89b2d020266b3160e0df8e3101ba51faa705f4c985','8ddd2617904003772da27cdf92dd48fcc3714596d773a144f67dc8abf175ca1f'),false)
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent export controls unavailable';END IF;
 PERFORM 1 FROM public.zasp_security_agent_kill_switches WHERE(organization_id,workspace_id,environment_id,action_key)=('*','*','*','*') FOR SHARE;
 IF target_value='action' THEN PERFORM 1 FROM public.zasp_security_agent_kill_switches WHERE(organization_id,workspace_id,environment_id,action_key)=(o,w,e,'*') FOR SHARE;END IF;
 result:=zasp_sa_export_prior.definition_control_core(o,w,e,actor,k,target_value,action_value,enabled_value,v,fresh_value,audit_value,correlation_value,receipt_value);
 IF result IS NULL OR fresh_value<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent control authority expired';END IF;
 PERFORM zasp_authorization80.security_agent_write_settled(p);
 RETURN result;
END $security_agent_set_execution_control$;

DO $security_agent_write_privileges$
DECLARE f record;
BEGIN
 FOR f IN SELECT * FROM(VALUES
  ('zasp_authorization80.security_agent_write_request(text,text,text,text,text,text)',NULL),
  ('zasp_authorization80.security_agent_write_settled(jsonb)',NULL),
  ('zasp_authorization80.security_agent_export_family(text,text,text,text,jsonb)',NULL),
  ('zasp_authorization80.security_agent_definition_value(text,text,text,text)','zasp_security_agent_api'),
  ('zasp_authorization80.security_agent_activation(text,text,text,text,text)','zasp_security_agent_api'),
  ('zasp_authorization80.security_agent_definition_replay(text,text,text,text,text,text,jsonb)','zasp_security_agent_api'),
  ('zasp_authorization80.security_agent_definition_mutate(text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','zasp_security_agent_api'),
  ('zasp_authorization80.security_agent_activate(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text)','zasp_security_agent_api'),
  ('zasp_authorization80.security_agent_run(text,text,text,text,text,jsonb)','zasp_security_agent_api'),
  ('zasp_authorization80.security_agent_set_execution_control(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text)','zasp_security_agent_api')
 ) v(signature,grantees) LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',f.signature::regprocedure);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f.signature::regprocedure);
  IF f.grantees IS NOT NULL THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %s',f.signature::regprocedure,f.grantees);END IF;
 END LOOP;
END $security_agent_write_privileges$;

-- ---------------------------------------------------------------------------
-- I. Security Agent planner pricing binding, per scope.
--
-- The planner may be called only under an administrator-approved pricing
-- policy and account (zasp_sa_multistep_prior.pricing_policies and
-- pricing_accounts, written by pricing_admin). The worker took the pins of
-- that approval (profile, credential reference, policy and account versions,
-- policy digest) from a static file listing every Organization, Workspace and
-- Environment, which a multi-tenant deployment cannot maintain. This function
-- returns the same pins for one scope from the approval itself, at use time.
--
-- It returns references and pins only: no credential, no credential digest
-- and no price. It is not an approval: the worker still passes the pins with
-- its own credential digest and prepared request to the chain's
-- pricing_lookup, which verifies them against the current rows exactly as
-- before (canonical identities, single unambiguous policy and account, policy
-- digest, account version, credential reference and digest, effective and
-- expiry instants, model, request policy version and token limit).
--
-- NULL means the scope has no single current approval for this provider and
-- model: none, more than one account profile, a disabled or expired policy,
-- or a policy that names a superseded account version. Only the Security
-- Agent worker's own database role may ask, the role pricing_lookup serves.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_pricing_binding(o text,w text,e text,provider_value text,model_value text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_pricing_binding$
DECLARE p zasp_sa_multistep_prior.pricing_policies%ROWTYPE;a zasp_sa_multistep_prior.pricing_accounts%ROWTYPE;
BEGIN
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_worker'),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='pricing binding principal rejected';END IF;
 IF NOT COALESCE(public.zasp_sa_multistep_readiness('033bf2ffa9d4a60121d4f20436ff7de36d1421b62f849254a09048caf75998e6','6b6a74cba9ee791d8b23c08df2f3d08949a339e23460694bc0e2d2d3f25c8e92'),false)
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='pricing release unavailable';END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e)
  AND provider_value='openrouter' AND length(model_value) BETWEEN 1 AND 128 AND model_value~'^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$',false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='pricing binding request rejected';END IF;
 IF(SELECT count(DISTINCT x.policy_id) FROM zasp_sa_multistep_prior.pricing_policies x WHERE(x.organization_id,x.workspace_id,x.environment_id)=(o,w,e) AND x.policy->>'provider'=provider_value AND x.policy->>'model'=model_value)<>1 THEN RETURN NULL;END IF;
 SELECT x.* INTO p FROM zasp_sa_multistep_prior.pricing_policies x WHERE(x.organization_id,x.workspace_id,x.environment_id)=(o,w,e) AND x.policy->>'provider'=provider_value AND x.policy->>'model'=model_value ORDER BY x.version DESC LIMIT 1;
 SELECT x.* INTO a FROM zasp_sa_multistep_prior.pricing_accounts x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.account_id)=(o,w,e,p.account_id) ORDER BY x.version DESC LIMIT 1;
 IF p.policy_id IS NULL OR a.account_id IS NULL OR p.disabled OR p.account_version<>a.version OR a.provider<>provider_value OR a.account_profile IS DISTINCT FROM p.policy->>'account_profile'
  OR p.policy_id<>public.zasp_discovery_canonical_id(o,w,e,'security_agent_pricing_policy',concat_ws(chr(31),provider_value,model_value,a.account_profile))
  OR a.account_id<>public.zasp_discovery_canonical_id(o,w,e,'security_agent_pricing_account',concat_ws(chr(31),provider_value,a.account_profile))
  OR(SELECT count(DISTINCT x.account_id) FROM zasp_sa_multistep_prior.pricing_accounts x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.provider,x.account_profile)=(o,w,e,provider_value,a.account_profile))<>1
  OR p.policy->>'credential_reference' IS DISTINCT FROM a.credential_reference
  OR NOT COALESCE((p.policy->>'effective_at')::timestamptz<=clock_timestamp() AND(p.policy->>'expires_at')::timestamptz>clock_timestamp(),false)
 THEN RETURN NULL;END IF;
 RETURN jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'account_profile',a.account_profile,'credential_reference',a.credential_reference,
  'policy_id',p.policy_id,'policy_version',p.version,'policy_digest',p.policy_digest,'account_id',a.account_id,'account_version',a.version);
END $security_agent_pricing_binding$;
ALTER FUNCTION zasp_authorization80.security_agent_pricing_binding(text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.security_agent_pricing_binding(text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.security_agent_pricing_binding(text,text,text,text,text) TO zasp_security_agent_worker;

-- ---------------------------------------------------------------------------
-- J. Single sign-on and SCIM connection writes. Browser session only.
--
-- Creating, deleting or testing a connection is a provider call bracketed by
-- a durable reservation: reserve, then complete (or mark the outcome unknown).
-- The chain's functions (zasp_identity_admin_reserve_mutation, _mark_unknown,
-- _complete_mutation, _reveal_secret) keep the reservation lease, the owner
-- token, idempotent replay, the audit record and the one-time secret grant,
-- and authorize the actor by role. They had no authorized form, so under the
-- current model the routes were refused. Each function below binds one of
-- them to the proof: the identity release, exactly this operation with
-- manage_identity, this Organization, Workspace, Environment and actor, a
-- browser session with fresh authentication, a non-collection request, and
-- the Organization's identity among the allowed targets. A delete or a test
-- must name the connection of the request path.
CREATE OR REPLACE FUNCTION zasp_authorization80.identity_provider_request(o text,w text,e text,actor text,op text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $identity_provider_request$
DECLARE p jsonb:=zasp_authorization80.context();
BEGIN
 IF p IS NULL OR actor IS NULL OR NOT COALESCE(zasp_authorization80_identity.api_ready()
  AND op IN('createSSOConnection','deleteSSOConnection','testSSOConnection','createSCIMConnection','deleteSCIMConnection')
  AND zasp_authorization80.read_request(o,w,e,ARRAY[op],'manage_identity',true,actor)
  AND p->'collection'='false'::jsonb AND p->'fresh_auth'='true'::jsonb
  AND zasp_authorization80.allowed(o,w,e,'organization_identity',o),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='checked identity administration required';END IF;
 PERFORM zasp_authorization80.identity_fence(p);
 RETURN p;
END $identity_provider_request$;

CREATE OR REPLACE FUNCTION zasp_authorization80.identity_provider_reserve(o text,w text,e text,actor text,op text,k text,mutation_value text,digest_value bytea,intent_value jsonb,audit_value text,correlation_value text,receipt_value text,owner_value bytea,lease_value integer) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $identity_provider_reserve$
DECLARE p jsonb;
BEGIN
 p:=zasp_authorization80.identity_provider_request(o,w,e,actor,op);
 IF jsonb_typeof(intent_value) IS DISTINCT FROM 'object' OR octet_length(intent_value::text)>4096
  OR(op IN('deleteSSOConnection','testSSOConnection','deleteSCIMConnection') AND p#>>'{path_parameters,id}' IS DISTINCT FROM intent_value->>'reference')
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='checked identity administration required';END IF;
 RETURN public.zasp_identity_admin_reserve_mutation(o,actor,op,k,mutation_value,digest_value,intent_value,audit_value,correlation_value,receipt_value,owner_value,lease_value);
END $identity_provider_reserve$;

CREATE OR REPLACE FUNCTION zasp_authorization80.identity_provider_mark_unknown(o text,w text,e text,actor text,op text,k text,mutation_value text,owner_value bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $identity_provider_mark_unknown$
BEGIN
 PERFORM zasp_authorization80.identity_provider_request(o,w,e,actor,op);
 RETURN public.zasp_identity_admin_mark_unknown(o,actor,op,k,mutation_value,owner_value);
END $identity_provider_mark_unknown$;

CREATE OR REPLACE FUNCTION zasp_authorization80.identity_provider_complete(o text,w text,e text,actor text,op text,k text,mutation_value text,owner_value bytea,connection_value jsonb,grant_value text,ciphertext_value bytea,nonce_value bytea,tag_value bytea,expires_value timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $identity_provider_complete$
DECLARE p jsonb;result jsonb;
BEGIN
 p:=zasp_authorization80.identity_provider_request(o,w,e,actor,op);
 result:=public.zasp_identity_admin_complete_mutation(o,actor,op,k,mutation_value,owner_value,connection_value,grant_value,ciphertext_value,nonce_value,tag_value,expires_value);
 IF p IS DISTINCT FROM zasp_authorization80.context() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='identity administration proof expired';END IF;
 RETURN result;
END $identity_provider_complete$;

-- The one-time SCIM bearer secret, returned to the administrator who created
-- the connection, inside that same checked request.
CREATE OR REPLACE FUNCTION zasp_authorization80.identity_provider_reveal_secret(o text,w text,e text,actor text,grant_value text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $identity_provider_reveal_secret$
BEGIN
 IF NOT COALESCE(public.zasp_valid_product_id(grant_value),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='identity administration input rejected';END IF;
 PERFORM zasp_authorization80.identity_provider_request(o,w,e,actor,'createSCIMConnection');
 RETURN public.zasp_identity_admin_reveal_secret(o,actor,grant_value);
END $identity_provider_reveal_secret$;

DO $identity_provider_privileges$
DECLARE f record;
BEGIN
 FOR f IN SELECT * FROM(VALUES
  ('zasp_authorization80.identity_provider_request(text,text,text,text,text)',NULL),
  ('zasp_authorization80.identity_provider_reserve(text,text,text,text,text,text,text,bytea,jsonb,text,text,text,bytea,integer)','zasp_discovery_api'),
  ('zasp_authorization80.identity_provider_mark_unknown(text,text,text,text,text,text,text,bytea)','zasp_discovery_api'),
  ('zasp_authorization80.identity_provider_complete(text,text,text,text,text,text,text,bytea,jsonb,text,bytea,bytea,bytea,timestamptz)','zasp_discovery_api'),
  ('zasp_authorization80.identity_provider_reveal_secret(text,text,text,text,text)','zasp_discovery_api')
 ) v(signature,grantees) LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',f.signature::regprocedure);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f.signature::regprocedure);
  IF f.grantees IS NOT NULL THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %s',f.signature::regprocedure,f.grantees);END IF;
 END LOOP;
END $identity_provider_privileges$;

-- ---------------------------------------------------------------------------
-- K. Direct grants the authorized functions replace.
--
-- Each historical reader below returned tenant data to an API service role
-- on its own authority (role membership and its own actor checks), with no
-- attested proof. The authorized functions of sections B, C and D replace
-- them and call them (or read the same tables) with their owner's rights, so
-- the API roles no longer need to execute them directly: a compromised API
-- process could otherwise read the same data without a checked request. No
-- product statement, worker or readiness check uses these direct grants (the
-- API refuses the historical statements under the current model).
--
-- Left in place on purpose:
--   * EXECUTE on public.zasp_security_agent_execution_control_detail for
--     zasp_security_agent_api: the historical role-shape checks of the
--     Security Agent control releases (and every release built on them)
--     require exactly this grant, so revoking it turns their readiness false.
--     The function returns only the execution switches of one Environment.
--   * EXECUTE on public.zasp_identity_admin_provider_organization for
--     zasp_discovery_api: the identity administration release's role-shape
--     check (zasp_identity_admin_security_ready) requires this grant. The
--     function returns the caller-named administrator's own provider
--     Organization reference only.
--   * the table privileges of zasp_discovery_api on zasp_identity_memberships
--     and zasp_group_mappings: the integration rejection transaction locks
--     those rows directly (SELECT ... FOR SHARE), and the identity write guard
--     already refuses any direct write.
REVOKE EXECUTE ON FUNCTION public.zasp_security_agent_run_page(text,text,text,text,text,timestamptz,text,integer) FROM zasp_security_agent_api;
REVOKE EXECUTE ON FUNCTION public.zasp_red_team_list_definitions(text,text,text,text,integer) FROM zasp_security_agent_api;
REVOKE EXECUTE ON FUNCTION public.zasp_red_team_list_runs(text,text,text,timestamptz,text,integer) FROM zasp_security_agent_api;
REVOKE EXECUTE ON FUNCTION public.zasp_attack_lab_list_runs(text,text,text,timestamptz,text,integer) FROM zasp_security_agent_api;
REVOKE EXECUTE ON FUNCTION zasp_temporal78.approval_page(text,text,text,text,text,timestamptz,text,integer,text) FROM zasp_security_agent_api;
-- The Organization row is served by zasp_authorization80.organization; no
-- statement of the API role reads the table directly.
REVOKE SELECT ON TABLE public.zasp_organizations FROM zasp_discovery_api;

-- ---------------------------------------------------------------------------
-- L. The audit page checks resolver readiness once per page.
--
-- zasp_authorization80.audit_page decides each event's visibility with
-- parent_allowed, which resolves the event's parent object through the
-- checked resolve: reader() and ready() (the catalog integrity check, about
-- 170 ms) once per event. Beyond about 25 events the page exceeded its own
-- five-second deadline. The catalog cannot change between two events of one
-- page in a way the first check would not also see.
--
-- parent_targets_inner and parent_allowed_inner are the same bodies, verbatim,
-- whose per-object resolutions use resolve_inner (section F); only their
-- owner can execute them. audit_page keeps every rule and its two authority
-- brackets, performs the resolver readiness check itself before the first
-- event and again after the last, and uses parent_allowed_inner in between.
-- parent_targets and parent_allowed are unchanged for every other caller.
DO $audit_page_once$
DECLARE d text;
 guard text:=$g$ IF NOT zasp_authorization79.reader() OR NOT zasp_authorization80.ready('d7fbda32a2b3b9ea0ffbd4f7c7a7967a9d4fba2f6573f49e8386e9586a18a1fd') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization resolver rejected';END IF;$g$;
 scan text:=$s$ FOR entry IN$s$;
 result_line text:=$r$ result:=jsonb_build_object('items',items,'has_more',seen>retained);$r$;
 visible text:=$v$zasp_authorization80.parent_allowed(s.organization_id,s.workspace_id,s.environment_id,'audit_event',s.id,s.source_kind)$v$;
BEGIN
 IF to_regprocedure('zasp_authorization80.parent_targets_inner(text,text,text,text,text,text)') IS NOT NULL THEN RETURN;END IF;
 SELECT pg_get_functiondef('zasp_authorization80.parent_targets(text,text,text,text,text,text)'::regprocedure) INTO STRICT d;
 IF position('zasp_authorization80.resolve(' in d)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authorization parent resolver predecessor changed';END IF;
 EXECUTE replace(replace(replace(d,'zasp_authorization80.parent_targets(','zasp_authorization80.parent_targets_inner('),'zasp_authorization80.resolve(','zasp_authorization80.resolve_inner('),'zasp_authorization80.resolve_inner_inner(','zasp_authorization80.resolve_inner(');
 SELECT pg_get_functiondef('zasp_authorization80.parent_allowed(text,text,text,text,text,text)'::regprocedure) INTO STRICT d;
 IF (length(d)-length(replace(d,'zasp_authorization80.parent_targets(','')))/length('zasp_authorization80.parent_targets(')<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authorization parent check predecessor changed';END IF;
 EXECUTE replace(replace(d,'zasp_authorization80.parent_allowed(','zasp_authorization80.parent_allowed_inner('),'zasp_authorization80.parent_targets(','zasp_authorization80.parent_targets_inner(');
 SELECT pg_get_functiondef('zasp_authorization80.audit_page(text,text,text,text,bytea,text,jsonb,timestamptz,text,integer,text,text)'::regprocedure) INTO STRICT d;
 IF (length(d)-length(replace(d,visible,'')))/length(visible)<>1 OR (length(d)-length(replace(d,scan,'')))/length(scan)<>1 OR (length(d)-length(replace(d,result_line,'')))/length(result_line)<>1
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authorization audit page predecessor changed';END IF;
 EXECUTE replace(replace(replace(d,visible,replace(visible,'parent_allowed(','parent_allowed_inner(')),scan,guard||E'\n'||scan),result_line,result_line||E'\n'||guard);
END $audit_page_once$;
ALTER FUNCTION zasp_authorization80.parent_targets_inner(text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION zasp_authorization80.parent_allowed_inner(text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.parent_targets_inner(text,text,text,text,text,text) FROM PUBLIC,zasp_discovery_api,zasp_security_agent_api,zasp_outbox_worker,zasp_security_agent_worker;
REVOKE ALL ON FUNCTION zasp_authorization80.parent_allowed_inner(text,text,text,text,text,text) FROM PUBLIC,zasp_discovery_api,zasp_security_agent_api,zasp_outbox_worker,zasp_security_agent_worker;

-- ---------------------------------------------------------------------------
-- Discovery follow-ups
--
-- M. Integration setup status (GET /integrations/{id}/setup-status).
--
-- The chain's reader, public.zasp_execution_integration_setup_status, admits
-- a call only when zasp_production_integration_setup_readiness holds: the
-- recorded identity of releases 34 to 55 at exactly that catalog. On the
-- baseline those historical predicates are false for ever, so the route
-- answered 'provider unavailable'. That reader is left as it is (it keeps
-- refusing). This function states the same computation under the current
-- authorization model:
--   * SECURITY DEFINER, owned by zasp_discovery_authority, fixed search_path,
--     executable only by zasp_discovery_api;
--   * the session must be the bound API principal;
--   * it returns data only inside a fenced transaction whose attested proof
--     names this organization, workspace and environment, the operation
--     getIntegrationSetupStatus and the permission 'view' (read_request);
--   * the proof must be for one object, and that object, the integration in
--     the path, must be the integration asked for;
--   * the integration must be among the objects the decision allows.
-- The payload is the chain reader's, field for field.
-- Microsoft and Salesforce (section X3b) are reference-authorized like AWS and
-- Kubernetes: a verified connection with a bound subject is verified, and the
-- scope is the subject (microsoft_tenant or salesforce_org).
CREATE OR REPLACE FUNCTION zasp_authorization80.integration_setup_status(o text,w text,e text,i text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $integration_setup_status$
DECLARE p jsonb:=zasp_authorization80.context();integration_row public.zasp_integrations%ROWTYPE;connection_row public.zasp_integration_connections%ROWTYPE;subject_row public.zasp_discovery_connection_subjects%ROWTYPE;credential_row public.zasp_connector_credentials%ROWTYPE;authorization_state text:='pending';scope_kind_value text:='none';scope_label_value text;repository_selection_value text;permissions_value jsonb:='[]'::jsonb;sensor_count_value integer:=0;healthy_count_value integer:=0;missing_count_value integer:=0;unsupported_count_value integer:=0;coverage_state text:='not_applicable';coverage_reason text:='not_applicable';updated_value timestamptz;
BEGIN
 IF p IS NULL OR NOT COALESCE(public.zasp_valid_product_id(i),false)
  OR NOT COALESCE(public.zasp_discovery_principal_ready('zasp_discovery_api')
   AND zasp_authorization80.read_request(o,w,e,ARRAY['getIntegrationSetupStatus'],'view')
   AND p->'collection'='false'::jsonb
   AND p#>>'{path_parameters,id}'=i
   AND zasp_authorization80.allowed(o,w,e,'integration',i),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current read purpose required';END IF;
 SELECT * INTO integration_row FROM public.zasp_integrations integration WHERE (integration.organization_id,integration.workspace_id,integration.environment_id,integration.id)=(o,w,e,i) AND integration.kind IN('aws','kubernetes','github','okta','microsoft','salesforce') AND integration.state<>'deleted';
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='integration setup status missing';END IF;
 updated_value:=integration_row.updated_at;
 IF (SELECT count(*) FROM public.zasp_integration_connections connection WHERE (connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,connection.provider,connection.state)=(o,w,e,i,integration_row.kind,'verified'))=1 THEN
  SELECT * INTO STRICT connection_row FROM public.zasp_integration_connections connection WHERE (connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,connection.provider,connection.state)=(o,w,e,i,integration_row.kind,'verified');
  SELECT * INTO subject_row FROM public.zasp_discovery_connection_subjects subject WHERE (subject.organization_id,subject.workspace_id,subject.environment_id,subject.integration_id,subject.connection_id,subject.provider,subject.connection_version,subject.configuration_digest)=(o,w,e,i,connection_row.id,integration_row.kind,connection_row.version,digest(convert_to(integration_row.configuration::text,'UTF8'),'sha256'));
  IF FOUND THEN
   updated_value:=greatest(updated_value,connection_row.updated_at,subject_row.verified_at);
   IF integration_row.kind IN('aws','kubernetes','microsoft','salesforce') THEN
    authorization_state:='verified';scope_kind_value:=subject_row.subject_kind;scope_label_value:=subject_row.subject_id;
   ELSIF (SELECT count(*) FROM public.zasp_connector_credentials credential WHERE (credential.organization_id,credential.workspace_id,credential.environment_id,credential.integration_id,credential.provider,credential.status,credential.credential_reference)=(o,w,e,i,integration_row.kind,'active',connection_row.connection_reference))=1 THEN
    SELECT * INTO STRICT credential_row FROM public.zasp_connector_credentials credential WHERE (credential.organization_id,credential.workspace_id,credential.environment_id,credential.integration_id,credential.provider,credential.status,credential.credential_reference)=(o,w,e,i,integration_row.kind,'active',connection_row.connection_reference);
    updated_value:=greatest(updated_value,credential_row.updated_at);
    IF integration_row.kind='github' AND subject_row.subject_kind='github_installation' AND credential_row.metadata->>'installation_id'=subject_row.subject_id AND credential_row.metadata->>'account_type'='Organization' AND credential_row.metadata->>'account_login'~'^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$' AND credential_row.metadata->>'repository_selection' IN('all','selected') AND credential_row.metadata->'permissions'='{"actions":"read","contents":"read","metadata":"read"}'::jsonb THEN
     authorization_state:='verified';scope_kind_value:='github_organization';scope_label_value:=credential_row.metadata->>'account_login';repository_selection_value:=credential_row.metadata->>'repository_selection';permissions_value:='["actions:read","contents:read","metadata:read"]'::jsonb;
    ELSIF integration_row.kind='okta' AND subject_row.subject_kind='okta_tenant' AND credential_row.metadata->>'tenant'=subject_row.subject_id AND credential_row.metadata->'scopes'='["offline_access","okta.apps.read","okta.groups.read","okta.users.read"]'::jsonb THEN
     authorization_state:='verified';scope_kind_value:='okta_tenant';scope_label_value:=subject_row.subject_id;permissions_value:=credential_row.metadata->'scopes';
    ELSE authorization_state:='degraded';END IF;
   ELSE authorization_state:='degraded';END IF;
  END IF;
 END IF;
 IF integration_row.kind='kubernetes' THEN
  SELECT count(*),count(*) FILTER(WHERE sensor.state='active' AND heartbeat.status='healthy' AND heartbeat.observed_at>=transaction_timestamp()-interval '5 minutes' AND COALESCE((heartbeat.metadata->>'btf')::boolean,false)),count(*) FILTER(WHERE heartbeat.sensor_id IS NULL OR heartbeat.observed_at<transaction_timestamp()-interval '5 minutes'),count(*) FILTER(WHERE heartbeat.observed_at>=transaction_timestamp()-interval '5 minutes' AND NOT COALESCE((heartbeat.metadata->>'btf')::boolean,false)),greatest(updated_value,COALESCE(max(sensor.updated_at),updated_value),COALESCE(max(heartbeat.observed_at),updated_value)) INTO sensor_count_value,healthy_count_value,missing_count_value,unsupported_count_value,updated_value
  FROM public.zasp_sensors sensor LEFT JOIN public.zasp_sensor_heartbeats heartbeat ON (heartbeat.organization_id,heartbeat.workspace_id,heartbeat.environment_id,heartbeat.sensor_id)=(sensor.organization_id,sensor.workspace_id,sensor.environment_id,sensor.id)
  WHERE (sensor.organization_id,sensor.workspace_id,sensor.environment_id,sensor.kind)=(o,w,e,'tetragon') AND sensor.state NOT IN('revoked','deleted');
  IF sensor_count_value=0 THEN coverage_state:='not_enrolled';coverage_reason:='not_enrolled';
  ELSIF missing_count_value>0 THEN coverage_state:='awaiting_heartbeat';coverage_reason:='missing_gateway';
  ELSIF unsupported_count_value>0 THEN coverage_state:='degraded';coverage_reason:='unsupported_kernel';
  ELSIF healthy_count_value=sensor_count_value THEN coverage_state:='healthy';coverage_reason:='verified';
  ELSE coverage_state:='degraded';coverage_reason:='degraded';END IF;
 END IF;
 RETURN jsonb_build_object('integration_id',i,'connector_key',integration_row.kind,'authorization',jsonb_build_object('state',authorization_state,'scope_kind',scope_kind_value,'scope_label',scope_label_value,'repository_selection',repository_selection_value,'permissions',permissions_value),'runtime_coverage',jsonb_build_object('state',coverage_state,'reason',coverage_reason,'sensor_count',sensor_count_value,'healthy_sensor_count',healthy_count_value),'updated_at',to_char(updated_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
END $integration_setup_status$;
ALTER FUNCTION zasp_authorization80.integration_setup_status(text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.integration_setup_status(text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.integration_setup_status(text,text,text,text) TO zasp_discovery_api;

-- N. Release of abandoned discovery runs.
--
-- A Temporal discovery run owns its integration (zasp_temporal72.active_owners)
-- from its first page until its snapshot is committed. Ownership is what stops
-- two runs collecting one integration and is decided from durable evidence
-- only. A run whose evidence stopped moving kept it for ever:
--   * a worker killed inside a page leaves a page effect without a result; the
--     workflow settles the run as outcome_unknown, which is an owning state;
--   * an apply that failed leaves an apply effect without a result;
--   * a workflow that itself failed (its settlement refused, for instance
--     while the catalog was being re-sealed) leaves the run admitted,
--     collecting or partial and its sync queued or running.
-- Every later sync of that integration then waited in five-second retries and
-- nothing released it.
--
-- zasp_temporal72.release_abandoned ends such a run. It runs inside
-- prepare_page, the authorized statement every run executes before it may
-- collect, under the advisory lock that already serializes one integration
-- and provider; no new worker operation, grant or principal exists. For each
-- other run of the same integration that still owns it, or whose sync is
-- still queued or running, it takes the run row FOR UPDATE SKIP LOCKED (every
-- statement that advances a run holds that lock, so a run something is
-- working on right now is skipped) and releases it only when all of this
-- holds:
--   * nothing is committed: no apply effect has a result and the snapshot of
--     the run's generation is not committed. commit_apply writes the
--     snapshot, the apply result and the state 'succeeded' in one local
--     transaction under the same row lock, so an apply either happened
--     entirely, and the run is never released, or did not happen at all;
--   * the evidence has been quiet for a fixed time, measured on the database
--     clock from the newest of admission, page preparation, page receipt,
--     apply preparation, capacity wait and retry-not-before:
--       - 10 minutes for a run inside a page or an apply (collecting,
--         applying) or already ended (outcome_unknown, or a terminal page
--         outcome that was never settled). One Activity attempt is bounded
--         by its five-minute start-to-close timeout and only the attempt
--         that prepared the effect performs I/O for it; a later attempt
--         replays the stored receipt;
--       - 35 minutes for a run between Activities (partial, retryable,
--         complete) and for a run that never prepared a page although its
--         start was published (admitted). The workflow bounds every Activity
--         by a 30-minute schedule-to-close timeout and its settlement by one
--         minute, and sleeps only for retry delays that are persisted here,
--         so a live workflow cannot leave these states untouched that long
--         unless no discovery worker ran at all.
-- A release is one transaction:
--   * the release is recorded (zasp_temporal72.releases, immutable) and
--     active_owners no longer lists a released run, so guard_page_effect
--     refuses any further provider request of that run ('discovery effect
--     ownership rejected') and its capacity is free;
--   * every page effect without a result receives the receipt
--     'outcome_unknown' (what prepare_page already answers for it), so a late
--     record_page for it is refused as 'discovery receipt immutable';
--   * the run state becomes outcome_unknown when a page or apply effect was
--     unresolved, otherwise incomplete (a terminal page outcome is kept).
--     None of these is a state from which prepare_page, guard_page_effect,
--     prepare_apply or commit_apply proceed, and settle writes only such
--     states, so a released run can never collect or apply again;
--   * a sync that is still queued or running is failed with last_error
--     'discovery abandoned' and the public code outcome_unknown or partial
--     (the public code list is closed; the distinct reason is the release
--     row and the last_error text).
-- The generation reservation stays as evidence; the next run reserves a
-- higher generation.
CREATE TABLE IF NOT EXISTS zasp_temporal72.releases(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,job_id text NOT NULL,
 sync_id text NOT NULL,integration_id text NOT NULL,provider text NOT NULL,
 prior_state text NOT NULL,
 reason text NOT NULL CHECK(reason IN('page_unresolved','apply_unresolved','ended_unsettled','idle','never_started')),
 uncertain boolean NOT NULL,
 quiet_since timestamptz NOT NULL,
 released_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 released_by_job_id text NOT NULL CHECK(public.zasp_valid_product_id(released_by_job_id)),
 PRIMARY KEY(organization_id,workspace_id,environment_id,job_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,job_id) REFERENCES zasp_temporal72.runs(organization_id,workspace_id,environment_id,job_id),
 CHECK(released_at>quiet_since AND released_by_job_id<>job_id)
);
ALTER TABLE zasp_temporal72.releases OWNER TO zasp_discovery_authority;
REVOKE ALL ON TABLE zasp_temporal72.releases FROM PUBLIC;
ALTER TABLE zasp_temporal72.releases ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_temporal72.releases FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS authority ON zasp_temporal72.releases;
CREATE POLICY authority ON zasp_temporal72.releases USING(CURRENT_USER='zasp_discovery_authority'::name) WITH CHECK(CURRENT_USER='zasp_discovery_authority'::name);
DROP TRIGGER IF EXISTS immutable ON zasp_temporal72.releases;
CREATE TRIGGER immutable BEFORE DELETE OR UPDATE OR TRUNCATE ON zasp_temporal72.releases FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();

CREATE OR REPLACE FUNCTION zasp_temporal72.release_abandoned(o text,w text,e text,i text,provider_value text,j text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $release_abandoned$
DECLARE x zasp_temporal72.runs%ROWTYPE;quiet timestamptz;bound interval;reason_value text;page_open boolean;page_unknown boolean;apply_open boolean;uncertain_value boolean;receipt text;released integer:=0;
BEGIN
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(i) AND public.zasp_valid_product_id(j) AND provider_value IN('aws','kubernetes','github','okta','microsoft','salesforce'),false)
  OR current_setting('transaction_isolation')<>'read committed'
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery release rejected';END IF;
 FOR x IN SELECT r.* FROM zasp_temporal72.runs r
  WHERE(r.organization_id,r.workspace_id,r.environment_id,r.integration_id,r.provider)=(o,w,e,i,provider_value) AND r.job_id<>j AND r.state<>'succeeded'
  AND NOT EXISTS(SELECT 1 FROM zasp_temporal72.releases d WHERE(d.organization_id,d.workspace_id,d.environment_id,d.job_id)=(r.organization_id,r.workspace_id,r.environment_id,r.job_id))
  AND(EXISTS(SELECT 1 FROM public.zasp_discovery_syncs s WHERE(s.organization_id,s.workspace_id,s.environment_id,s.id)=(r.organization_id,r.workspace_id,r.environment_id,r.sync_id) AND s.state IN('queued','running'))
   OR r.job_id IN(SELECT owner.job_id FROM zasp_temporal72.active_owners(o) owner WHERE(owner.workspace_id,owner.environment_id,owner.integration_id,owner.provider,owner.ownership)=(w,e,i,provider_value,'temporal')))
  ORDER BY r.admitted_at,r.job_id FOR UPDATE OF r SKIP LOCKED
 LOOP
  -- Decided again under the row lock.
  IF EXISTS(SELECT 1 FROM zasp_temporal72.apply_effects a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.job_id)=(o,w,e,x.job_id) AND a.result IS NOT NULL)
   OR zasp_temporal72.snapshot_committed(o,w,e,x.sync_id)
   OR EXISTS(SELECT 1 FROM zasp_temporal72.releases d WHERE(d.organization_id,d.workspace_id,d.environment_id,d.job_id)=(o,w,e,x.job_id)) THEN CONTINUE;END IF;
  SELECT COALESCE(bool_or(p.result IS NULL),false),COALESCE(bool_or(p.result->>'outcome'='outcome_unknown'),false),greatest(max(p.prepared_at),max(p.recorded_at))
  INTO page_open,page_unknown,quiet FROM zasp_temporal72.page_effects p WHERE(p.organization_id,p.workspace_id,p.environment_id,p.job_id)=(o,w,e,x.job_id);
  SELECT EXISTS(SELECT 1 FROM zasp_temporal72.apply_effects a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.job_id)=(o,w,e,x.job_id)) INTO apply_open;
  quiet:=greatest(x.admitted_at,x.retry_not_before,quiet,
   (SELECT max(a.prepared_at) FROM zasp_temporal72.apply_effects a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.job_id)=(o,w,e,x.job_id)),
   (SELECT max(q.not_before) FROM zasp_temporal72.page_waits q WHERE(q.organization_id,q.workspace_id,q.environment_id,q.job_id)=(o,w,e,x.job_id)));
  IF x.state='admitted' THEN
   -- Never started: only once its start was published, so a start that is
   -- still waiting in the outbox is not taken for an abandoned run.
   IF NOT EXISTS(SELECT 1 FROM public.zasp_discovery_outbox b WHERE(b.organization_id,b.workspace_id,b.environment_id,b.id)=(o,w,e,x.outbox_id) AND b.state='published') THEN CONTINUE;END IF;
   quiet:=greatest(quiet,(SELECT b.published_at FROM public.zasp_discovery_outbox b WHERE(b.organization_id,b.workspace_id,b.environment_id,b.id)=(o,w,e,x.outbox_id)));
   bound:=interval '35 minutes';reason_value:='never_started';
  ELSIF x.state IN('partial','retryable','complete') AND NOT page_open AND NOT apply_open THEN bound:=interval '35 minutes';reason_value:='idle';
  ELSIF apply_open THEN bound:=interval '10 minutes';reason_value:='apply_unresolved';
  ELSIF page_open OR page_unknown OR x.state='collecting' THEN bound:=interval '10 minutes';reason_value:='page_unresolved';
  ELSE bound:=interval '10 minutes';reason_value:='ended_unsettled';END IF;
  IF quiet IS NULL OR clock_timestamp()<quiet+bound THEN CONTINUE;END IF;
  uncertain_value:=page_open OR page_unknown OR apply_open;
  INSERT INTO zasp_temporal72.releases(organization_id,workspace_id,environment_id,job_id,sync_id,integration_id,provider,prior_state,reason,uncertain,quiet_since,released_by_job_id)
  VALUES(o,w,e,x.job_id,x.sync_id,x.integration_id,x.provider,x.state,reason_value,uncertain_value,quiet,j);
  receipt:=encode(digest(convert_to(jsonb_build_object('kind','discovery72-release','organization_id',o,'workspace_id',w,'environment_id',e,'job_id',x.job_id,'released_by_job_id',j,'quiet_since',quiet)::text,'UTF8'),'sha256'),'hex');
  UPDATE zasp_temporal72.page_effects p SET result=jsonb_build_object('outcome','outcome_unknown','checkpoint_version',x.checkpoint_version,'receipt_digest',receipt,'retry_after_seconds',0),record_digest=receipt,recorded_at=clock_timestamp()
  WHERE(p.organization_id,p.workspace_id,p.environment_id,p.job_id)=(o,w,e,x.job_id) AND p.result IS NULL;
  UPDATE zasp_temporal72.runs r SET state=CASE WHEN uncertain_value THEN 'outcome_unknown' WHEN x.state IN('incomplete','denied','revoked','malformed','terminal','cancelled') THEN x.state ELSE 'incomplete' END,retry_not_before=NULL
  WHERE(r.organization_id,r.workspace_id,r.environment_id,r.job_id)=(o,w,e,x.job_id);
  UPDATE public.zasp_discovery_syncs s SET state='failed',completed_at=COALESCE(s.completed_at,clock_timestamp()),last_error='discovery abandoned',last_error_code=CASE WHEN uncertain_value THEN 'outcome_unknown' ELSE 'partial' END
  WHERE(s.organization_id,s.workspace_id,s.environment_id,s.id)=(o,w,e,x.sync_id) AND s.state IN('queued','running');
  released:=released+1;
 END LOOP;
 IF released>0 THEN PERFORM public.zasp_execution_bump_freshness(o,w,e,i);END IF;
 RETURN released;
END $release_abandoned$;
ALTER FUNCTION zasp_temporal72.release_abandoned(text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_temporal72.release_abandoned(text,text,text,text,text,text) FROM PUBLIC;

-- active_owners stops listing a released run, and prepare_page releases the
-- abandoned runs of its own integration before it asks for capacity. Both are
-- the installed bodies with one insertion each; the predecessor shape is
-- checked, and a body that already carries the insertion is left alone.
DO $release_wiring$
DECLARE d text;
 owner_needle text:=$n$ WHERE r.organization_id=o AND EXISTS(SELECT 1 FROM public.zasp_discovery_generation_reservations g$n$;
 owner_insert text:=$n$ WHERE r.organization_id=o AND NOT EXISTS(SELECT 1 FROM zasp_temporal72.releases released WHERE(released.organization_id,released.workspace_id,released.environment_id,released.job_id)=(r.organization_id,r.workspace_id,r.environment_id,r.job_id)) AND EXISTS(SELECT 1 FROM public.zasp_discovery_generation_reservations g$n$;
 page_needle text:=$n$ PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),o,w,e,i,r.provider),0));$n$;
 page_insert text:=$n$ PERFORM zasp_temporal72.release_abandoned(o,w,e,i,r.provider,j);$n$;
BEGIN
 SELECT pg_get_functiondef('zasp_temporal72.active_owners(text)'::regprocedure) INTO STRICT d;
 IF position('zasp_temporal72.releases' in d)=0 THEN
  IF (length(d)-length(replace(d,owner_needle,'')))/length(owner_needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='discovery owner predecessor changed';END IF;
  EXECUTE replace(d,owner_needle,owner_insert);
 END IF;
 SELECT pg_get_functiondef('zasp_temporal72.prepare_page(text,text,text,text,text,text,timestamptz,bigint,text)'::regprocedure) INTO STRICT d;
 IF position('zasp_temporal72.release_abandoned(' in d)=0 THEN
  IF (length(d)-length(replace(d,page_needle,'')))/length(page_needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='discovery page predecessor changed';END IF;
  EXECUTE replace(d,page_needle,page_needle||E'\n'||page_insert);
 END IF;
END $release_wiring$;

-- ---------------------------------------------------------------------------
-- Authorization hardening
--
-- Under the current authorization model the sealed request proof
-- (zasp_authorization80.fence) is meant to be the only way an API process
-- reaches tenant data: its database logins should be able to do nothing
-- useful without one. The authorized functions above are that way. The
-- historical objects underneath them were still directly usable by the API
-- roles (zasp_discovery_api, zasp_security_agent_api) on their own authority:
-- legacy writers with a caller-asserted actor, legacy readers, and plain table
-- privileges. A compromised API process could use them with no checked
-- request. Sections X1 to X9 close that, in this order of preference:
--   * revoke the direct grant, where its only callers are the authorized
--     functions (SECURITY DEFINER, owned by zasp_discovery_authority, so they
--     run with their owner's rights) or nothing;
--   * where a historical role-shape check requires the grant itself (revoking
--     it turns that release's readiness false), keep the grant and make the
--     object refuse an API session that carries no sealed proof;
--   * keep the grant where a statement the API sends before or outside a
--     checked request needs it; each of those is named.
--
-- X1. Direct grants on historical functions.
--
-- zasp_authorization80.direct_guard is the refusal used by the kept objects.
-- A session whose login is bound to an API role must be inside a fenced
-- transaction (zasp_authorization80.context() is the sealed proof of this
-- session and transaction), and the scope and the actor the caller names must
-- be the proof's. Every other session (workers, the operator) is unaffected: their
-- roles and their own checks are unchanged. The context seal binds the login
-- and the transaction, so the proof cannot be replayed or lent.
CREATE OR REPLACE FUNCTION zasp_authorization80.direct_guard(o text DEFAULT NULL,w text DEFAULT NULL,e text DEFAULT NULL,actor text DEFAULT NULL) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $direct_guard$
DECLARE p jsonb;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles l ON l.oid=m.member JOIN pg_roles g ON g.oid=m.roleid
  WHERE l.rolname=session_user AND g.rolname IN('zasp_discovery_api','zasp_security_agent_api')) THEN RETURN true;END IF;
 p:=zasp_authorization80.context();
 IF p IS NULL OR(o IS NOT NULL AND p->>'organization_id' IS DISTINCT FROM o) OR(w IS NOT NULL AND p->>'workspace_id' IS DISTINCT FROM w) OR(e IS NOT NULL AND p->>'environment_id' IS DISTINCT FROM e)
  OR(actor IS NOT NULL AND p->>'principal_id' IS DISTINCT FROM actor)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='checked request required';END IF;
 RETURN true;
END $direct_guard$;
ALTER FUNCTION zasp_authorization80.direct_guard(text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.direct_guard(text,text,text,text) FROM PUBLIC;

-- Revoked: every direct EXECUTE grant of the two API roles on a function
-- outside the authorized schemas, except
--   * readiness predicates (boolean, named ..._ready or ..._readiness): the
--     API asks them at startup and on its periodic readiness probe, before any
--     request exists (apiserver/postgres_database.go, authorization_readiness.go
--     and the capability probes); they return one boolean about the catalog;
--   * the statements listed in `kept`, each with its caller;
--   * the grants a historical role-shape check requires (`pinned`): these
--     functions are guarded in section X3 instead.
-- The list is computed so that a function added to a historical schema later
-- is not reachable by default.
DO $legacy_function_grants$
DECLARE f record;
 kept CONSTANT text[]:=ARRAY[
  -- Projection revision read by the authorizer before every Check, and its
  -- re-validation (authorization/projection_postgres.go). No tenant content.
  'zasp_authorization79.revision(text)','zasp_authorization79.revalidate(text,bigint,bigint,text,text)',
  -- Approval-notification profile state read at startup
  -- (authorization/approval_maintenance_projection.go).
  'zasp_approval_maintenance.projection_profile_state()',
  -- Connector reconciliation, a background loop with no request
  -- (apiserver/connector_maintenance_authorization.go). Each statement is
  -- bound in SQL to the lease the reconciler itself claimed.
  'zasp_connector_recover_final_attempts(text,integer,integer)','zasp_connector_claim_reconciliation(text,integer,integer)',
  'zasp_connector_complete_reconciliation(text,text,text,text,text,text,text,text,text,text,text,text,jsonb,bytea)',
  'zasp_connector_fail_reconciliation(text,text,text,text,text,text,text)','zasp_connector_complete_revocation(text,text,text,text,text,text)',
  'zasp_connector_complete_pkce_cleanup(text,text,text,text,text,text)',
  'zasp_connector_quarantine_reconciliation(text,text,text,text,text,text,text)',
  -- Discovery statements the API sends inside a fenced transaction
  -- (apiserver/authorization_discovery_statement.go). The three writes bind
  -- the proof themselves; the four reads are bound in section X3.
  'zasp_temporal72.public_request_sync(text,text,text,text,text,text,bigint,text,text,text,bytea,text,text,text,text,text)',
  'zasp_temporal72.public_put_schedule(text,text,text,text,text,text,bigint,integer,text,text,text,text)',
  'zasp_temporal72.public_delete_schedule(text,text,text,text,text,text,bigint,text,text,text)',
  'zasp_temporal72.sync_detail(text,text,text,text,text)','zasp_temporal72.sync_history(text,text,text,text,timestamp with time zone,text,integer)',
  'zasp_temporal72.schedule_detail(text,text,text,text)','zasp_temporal72.last_good_freshness(text,text,text,text)',
  -- Single finding and attack path reads inside a fenced transaction
  -- (apiserver/authorization_statement.go). SECURITY INVOKER: they read the
  -- risk tables as the API role, whose only row policy is the proof's.
  'zasp_risk_finding_get(text,text,text,text)','zasp_risk_attack_path_get(text,text,text,text)','zasp_risk_break_options_get(text,text,text,text)',
  'zasp_risk_attack_path_valid(zasp_risk_attack_paths)','zasp_risk_finding_visible(zasp_risk_findings)',
  -- Ordered Security Agent release: the deployment readiness question at
  -- startup and the approval decision inside a fenced transaction
  -- (apiserver/security_agent_ordered_production.go,
  -- authorization_ordered_approval_statement.go). Guarded in section X3.
  'zasp_ordered_public62.api(text,text,jsonb)'];
 pinned CONSTANT text[]:=ARRAY[
  'zasp_attack_lab_cancel_run','zasp_attack_lab_create_run','zasp_attack_lab_preflight','zasp_red_team_cancel_run','zasp_red_team_run_test',
  'zasp_security_agent_approval_detail_v22','zasp_security_agent_approval_page_v22','zasp_security_agent_cancel_run','zasp_security_agent_claim_approval_notification',
  'zasp_security_agent_decide_approval_v22','zasp_security_agent_decide_approval_v23','zasp_security_agent_decide_approval_v24',
  'zasp_security_agent_execution_control_detail','zasp_security_agent_mutate_execution_control',
  'zasp_security_agent_run_detail_v22','zasp_security_agent_run_detail_v23','zasp_security_agent_run_detail_v24','zasp_security_agent_run_v24',
  'zasp_execution_integration_setup_status','zasp_identity_admin_ack_secret','zasp_identity_admin_complete_mutation','zasp_identity_admin_connection_page',
  'zasp_identity_admin_effective_scopes','zasp_identity_admin_mark_unknown','zasp_identity_admin_provider_organization','zasp_identity_admin_reconcile_deprovision',
  'zasp_identity_admin_reserve_mutation','zasp_identity_admin_resolve_session','zasp_identity_admin_reveal_secret',
  'zasp_integration_webhook_test_complete','zasp_integration_webhook_test_reserve','zasp_integration_webhook_test_status','zasp_inventory_home_summary',
  'zasp_policy_list_runtime_decisions','zasp_recovery_create_backup','zasp_recovery_create_restore','zasp_runtime_issue_gateway_enrollment',
  'zasp_runtime_public_create_sensor','zasp_runtime_public_delete_sensor','zasp_runtime_public_rotate_sensor','zasp_runtime_public_sensor_coverage',
  'zasp_runtime_public_sensor_detail','zasp_runtime_public_sensor_page','zasp_runtime_public_sensor_token_authority','zasp_runtime_public_update_sensor',
  'zasp_runtime_sandbox_query_hydrate','zasp_runtime_sandbox_query_status','zasp_runtime_sandbox_session_event_get','zasp_runtime_sandbox_session_event_page'];
BEGIN
 FOR f IN SELECT p.oid::regprocedure AS signature,g.rolname AS grantee
  FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL aclexplode(p.proacl) a JOIN pg_roles g ON g.oid=a.grantee
  WHERE a.privilege_type='EXECUTE' AND g.rolname IN('zasp_discovery_api','zasp_security_agent_api')
   AND(n.nspname='public' OR n.nspname LIKE 'zasp\_%') AND n.nspname NOT LIKE 'zasp\_authorization80%' AND n.nspname<>'zasp_baseline'
   AND NOT(p.prorettype='boolean'::regtype AND p.proname~'(ready|readiness)(_v[0-9]+)?$')
   AND NOT(p.oid::regprocedure::text=ANY(kept)) AND NOT(n.nspname='public' AND p.proname=ANY(pinned))
  ORDER BY 1,2 LOOP
  EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM %I',f.signature,f.grantee);
 END LOOP;
END $legacy_function_grants$;
-- The pairing form of the sensor creation shares its name with a function a
-- role-shape check requires, but no check requires this form itself.
REVOKE EXECUTE ON FUNCTION public.zasp_runtime_public_create_sensor(text,text,text,text,text,text,text,text,text,bytea,text,bigint,bytea,bytea,bytea,timestamp with time zone,text) FROM zasp_discovery_api;

-- public.zasp_core_read (SECURITY DEFINER) was executable by PUBLIC: every
-- database login could read the inventory of any Organization it named. Its
-- only callers are the inventory backfill and equivalence procedures, which
-- run as zasp_discovery_authority.
REVOKE EXECUTE ON FUNCTION public.zasp_core_read(text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_core_read(text,text,text,text) TO zasp_discovery_authority;

-- ---------------------------------------------------------------------------
-- X2. Direct table privileges of the API role.
--
-- zasp_discovery_api held INSERT, UPDATE, DELETE (and mostly SELECT) on 30
-- product tables. No statement of the API uses them under the current model:
-- every read and write goes through an authorized function that runs as
-- zasp_discovery_authority. With them a session with no proof could rename or
-- delete every Organization, delete workflow records, audit, receipts and
-- idempotency rows, and read sessions (CSRF tokens, token digests), API
-- tokens, memberships, scopes and audit.
--
-- Kept:
--   * SELECT on the seven risk tables. The single finding and attack path
--     reads are SECURITY INVOKER (section X1). Row security is forced on these
--     tables and the API role's only policy is zasp_authorization80
--     .risk_read_allowed, which requires the proof and its allowed target.
--   * SELECT on zasp_product_sessions and zasp_identity_memberships until
--     section X6 replaces the direct session lookup.
--   * INSERT on zasp_admin_audit and zasp_workflow_audit: some thirty
--     historical role-shape checks require exactly this privilege. Both tables
--     refuse the insert of an API session in a statement trigger (below).
REVOKE ALL ON TABLE public.zasp_organizations,public.zasp_workspaces,public.zasp_environments,public.zasp_authorized_scopes,public.zasp_core_payloads,
 public.zasp_group_mappings,public.zasp_identity_states,public.zasp_product_api_tokens,public.zasp_api_token_reveal_grants,public.zasp_session_events,
 public.zasp_admin_idempotency,public.zasp_compliance_controls,public.zasp_compliance_evidence,public.zasp_data_controls,
 public.zasp_schema_metadata,public.zasp_schema_versions,public.zasp_workflow_idempotency,public.zasp_workflow_receipts,public.zasp_workflow_records
 FROM zasp_discovery_api;
REVOKE INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON TABLE public.zasp_product_sessions,public.zasp_identity_memberships,
 public.zasp_risk_findings,public.zasp_risk_finding_evidence,public.zasp_risk_finding_factors,public.zasp_risk_attack_paths,
 public.zasp_risk_attack_path_nodes,public.zasp_risk_attack_path_evidence,public.zasp_risk_break_options
 FROM zasp_discovery_api;

-- The audit tables. The audit export release recorded the privileges of
-- zasp_admin_audit and zasp_workflow_audit when it was installed and compares
-- the live privileges with that record (zasp_audit_export_source_acl_ready,
-- zasp_audit_export_workflow_acl_ready). The record includes SELECT, UPDATE
-- and DELETE for the API role, which nothing uses: audit is read through
-- zasp_authorization80.audit_page and written by the authorized functions.
-- Those three privileges are revoked and the record is restated to the
-- privileges the release now has, in one statement, so the comparison keeps
-- its meaning (the live privileges are the accepted ones). The record's
-- immutability trigger is suspended for that statement only.
DO $audit_table_privileges$
BEGIN
 REVOKE SELECT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON TABLE public.zasp_admin_audit,public.zasp_workflow_audit FROM zasp_discovery_api;
 ALTER TABLE public.zasp_audit_export_source_acl DISABLE TRIGGER zasp_audit_export_immutable_source_acl;
 UPDATE public.zasp_audit_export_source_acl s SET
  before_state=jsonb_set(s.before_state,'{grants}',(SELECT jsonb_agg(g ORDER BY g->>'grantor',g->>'grantee',g->>'privilege',(g->>'grantable')::boolean)
   FROM jsonb_array_elements(s.before_state->'grants') g WHERE NOT(g->>'grantee'='zasp_discovery_api' AND g->>'privilege' IN('SELECT','UPDATE','DELETE')))),
  workflow_state=public.zasp_audit_export_workflow_acl_snapshot();
 UPDATE public.zasp_audit_export_source_acl s SET after_state=public.zasp_audit_export_source_acl_expected(s.before_state);
 ALTER TABLE public.zasp_audit_export_source_acl ENABLE TRIGGER zasp_audit_export_immutable_source_acl;
 IF NOT public.zasp_audit_export_source_acl_ready() OR NOT public.zasp_audit_export_workflow_acl_ready() THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='audit source privilege record rejected';
 END IF;
END $audit_table_privileges$;

-- zasp_workflow_audit had no write guard. Only its owner and the authorized
-- functions (running as zasp_discovery_authority) write it.
CREATE OR REPLACE FUNCTION zasp_authorization80.direct_write_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $direct_write_guard$
BEGIN
 IF TG_NARGS<>1 OR TG_LEVEL<>'STATEMENT' OR TG_WHEN<>'BEFORE' OR TG_RELID<>'public.zasp_workflow_audit'::regclass THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='direct writer contract rejected';
 END IF;
 IF current_user IN(TG_ARGV[0],'zasp_discovery_authority') THEN RETURN NULL;END IF;
 RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='checked audit writer required';
END $direct_write_guard$;
ALTER FUNCTION zasp_authorization80.direct_write_guard() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.direct_write_guard() FROM PUBLIC;
DO $workflow_audit_guard$
DECLARE owner_name text;
BEGIN
 SELECT r.rolname INTO STRICT owner_name FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner WHERE c.oid='public.zasp_workflow_audit'::regclass;
 DROP TRIGGER IF EXISTS zasp_authorization80_direct_write_guard ON public.zasp_workflow_audit;
 EXECUTE format('CREATE TRIGGER zasp_authorization80_direct_write_guard BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON public.zasp_workflow_audit FOR EACH STATEMENT EXECUTE FUNCTION zasp_authorization80.direct_write_guard(%L)',owner_name);
END $workflow_audit_guard$;

-- The identity and audit write guards refused an API session only through an
-- incidental error: their first test reads zasp_discovery_principal_bindings,
-- which the API role cannot read, and PostgreSQL checks that privilege before
-- it evaluates the rest of the condition. Both guards admit exactly two
-- users (the registered owner and zasp_discovery_authority); every other user
-- is now refused by name before anything is read.
DO $write_guards$
DECLARE target record;d text;refusal text;
BEGIN
 FOR target IN SELECT * FROM(VALUES
  ('zasp_authorization80_audit.write_guard()','checked audit writer required'),
  ('zasp_authorization80_identity.write_guard()','checked identity writer required')) v(signature,message) LOOP
  d:=pg_get_functiondef(target.signature::regprocedure);
  refusal:=format(' IF current_user NOT IN(TG_ARGV[0],''zasp_discovery_authority'') THEN RAISE EXCEPTION USING ERRCODE=''42501'',MESSAGE=%L;END IF; -- direct_guard',target.message);
  IF position('-- direct_guard' in d)>0 THEN CONTINUE;END IF;
  IF d!~'\nBEGIN\s' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='write guard predecessor changed';END IF;
  EXECUTE regexp_replace(d,'\nBEGIN(\s)',E'\nBEGIN\n'||replace(refusal,'\','\\')||'\1');
 END LOOP;
END $write_guards$;

-- ---------------------------------------------------------------------------
-- X3. Historical functions whose direct grant a role-shape check requires.
--
-- Each function below must stay executable by its API role: a historical
-- release's security check names the grant, and every later release's
-- readiness includes that check. The authorized functions call them with
-- their owner's rights, inside the fenced transaction. A direct call from an
-- API session is therefore admitted only inside a fenced transaction, for the
-- proof's own Organization, Workspace, Environment and principal: the first
-- statement of each function is zasp_authorization80.direct_guard. The
-- function's own checks (release, principal, actor role, versions) follow
-- unchanged. Worker and operator sessions are not affected.
--
-- Not guarded, on purpose:
--   * zasp_identity_admin_effective_scopes: zasp_authorization80.fence itself
--     calls it before the proof is sealed, and so do the sign-in functions of
--     zasp_authorization80_identity. It returns the scopes and permissions of
--     one named principal.
--   * zasp_identity_admin_resolve_session and
--     zasp_identity_admin_reconcile_deprovision: the sign-in callback and the
--     verified deprovision webhook reach them through
--     zasp_authorization80_identity before any proof exists. A direct call
--     writes nothing: the identity write guard requires the permit only those
--     functions issue.
--   * zasp_connector_claim_reconciliation: connector maintenance (section X1).
DO $direct_guards$
DECLARE target record;d text;tag text;
BEGIN
 FOR target IN SELECT v.signature::regprocedure AS procedure,v.guard,l.lanname FROM(VALUES
  ('zasp_attack_lab_cancel_run(text,text,text,text,text,text,bigint,text)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value,actor_value)'),
  ('zasp_attack_lab_create_run(text,text,text,text,text,text,text,bytea,text)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value,actor_value)'),
  ('zasp_attack_lab_preflight(text,text,text,text)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value)'),
  ('zasp_execution_integration_setup_status(text,text,text,text,text,text)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value)'),
  ('zasp_identity_admin_ack_secret(text,text,text)','zasp_authorization80.direct_guard(organization_value,NULL,NULL,principal_value)'),
  ('zasp_identity_admin_complete_mutation(text,text,text,text,text,bytea,jsonb,text,bytea,bytea,bytea,timestamp with time zone)','zasp_authorization80.direct_guard(organization_value,NULL,NULL,principal_value)'),
  ('zasp_identity_admin_connection_page(text,text,text,text,integer)','zasp_authorization80.direct_guard(organization_value,NULL,NULL,principal_value)'),
  ('zasp_identity_admin_mark_unknown(text,text,text,text,text,bytea)','zasp_authorization80.direct_guard(organization_value,NULL,NULL,principal_value)'),
  ('zasp_identity_admin_provider_organization(text,text)','zasp_authorization80.direct_guard(organization_value,NULL,NULL,principal_value)'),
  ('zasp_identity_admin_reserve_mutation(text,text,text,text,text,bytea,jsonb,text,text,text,bytea,integer)','zasp_authorization80.direct_guard(organization_value,NULL,NULL,principal_value)'),
  ('zasp_identity_admin_reveal_secret(text,text,text)','zasp_authorization80.direct_guard(organization_value,NULL,NULL,principal_value)'),
  ('zasp_integration_webhook_test_complete(text,text,text,text,text,text,boolean)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value)'),
  ('zasp_integration_webhook_test_reserve(text,text,text,text,text,bigint,text,text,text,text,text,integer)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value,principal_value)'),
  ('zasp_integration_webhook_test_status(text,text,text,text)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value)'),
  ('zasp_inventory_home_summary(text,text,text)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value)'),
  ('zasp_policy_list_runtime_decisions(text,text,text,text,integer)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value)'),
  ('zasp_recovery_create_backup(text,text,text,text,text,text,text,integer,text,text,bytea)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value,actor_value)'),
  ('zasp_recovery_create_restore(text,text,text,text,text,text,text,text,text,text,bytea,jsonb,bytea)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value,actor_value)'),
  ('zasp_red_team_cancel_run(text,text,text,text,text,text,bigint,text)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value,actor_value)'),
  ('zasp_red_team_run_test(text,text,text,text,text,text,bigint,text,text)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value,actor_value)'),
  ('zasp_runtime_issue_gateway_enrollment(text,text,text,text,text,bigint,bigint,bytea,bytea,bytea,timestamp with time zone)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value)'),
  ('zasp_runtime_public_create_sensor(text,text,text,text,text,text,text,text,text,bytea,text,bigint,bytea,bytea,bytea,timestamp with time zone)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value,principal_value)'),
  ('zasp_runtime_public_delete_sensor(text,text,text,text,text,bigint,text,bytea)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value,principal_value)'),
  ('zasp_runtime_public_rotate_sensor(text,text,text,text,text,bigint,text,bytea,text,bigint,bytea,bytea,bytea,timestamp with time zone)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value,principal_value)'),
  ('zasp_runtime_public_sensor_coverage(text,text,text,text)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value)'),
  ('zasp_runtime_public_sensor_detail(text,text,text,text)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value)'),
  ('zasp_runtime_public_sensor_page(text,text,text,text,integer)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value)'),
  ('zasp_runtime_public_sensor_token_authority(text,text,text,text)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value)'),
  ('zasp_runtime_public_update_sensor(text,text,text,text,text,bigint,text,text,text,bytea)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value,principal_value)'),
  ('zasp_runtime_sandbox_query_hydrate(text,text,text,text,text[])','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value,principal_value)'),
  ('zasp_runtime_sandbox_query_status(text,text,text,text)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value,principal_value)'),
  ('zasp_runtime_sandbox_session_event_get(text,text,text,text,text,text)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value,principal_value)'),
  ('zasp_runtime_sandbox_session_event_page(text,text,text,text,text,timestamp with time zone,text,integer)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value,principal_value)'),
  ('zasp_security_agent_approval_detail_v22(text,text,text,text)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value)'),
  ('zasp_security_agent_approval_page_v22(text,text,text,text,text,timestamp with time zone,text,integer)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value)'),
  ('zasp_security_agent_cancel_run(text,text,text,text,text,text,bigint,text,text,text)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value)'),
  ('zasp_security_agent_claim_approval_notification(text,text,integer)','zasp_authorization80.direct_guard()'),
  ('zasp_security_agent_decide_approval_v22(text,text,text,text,text,text,bigint,text,timestamp with time zone,text,text,text)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value)'),
  ('zasp_security_agent_decide_approval_v23(text,text,text,text,text,text,bigint,text,timestamp with time zone,text,text,text)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value)'),
  ('zasp_security_agent_decide_approval_v24(text,text,text,text,text,text,bigint,text,timestamp with time zone,text,text,text)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value)'),
  ('zasp_security_agent_execution_control_detail(text,text,text)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value)'),
  ('zasp_security_agent_mutate_execution_control(text,text,text,text,text,text,text,boolean,bigint,timestamp with time zone,text,text,text)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value,actor_value)'),
  ('zasp_security_agent_run_detail_v22(text,text,text,text)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value)'),
  ('zasp_security_agent_run_detail_v23(text,text,text,text)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value)'),
  ('zasp_security_agent_run_detail_v24(text,text,text,text)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value)'),
  ('zasp_security_agent_run_v24(text,text,text,text,text,text,bigint,text,text,text,text,text,text)','zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value)')
 ) v(signature,guard) JOIN pg_proc p ON p.oid=v.signature::regprocedure JOIN pg_language l ON l.oid=p.prolang LOOP
  d:=pg_get_functiondef(target.procedure);
  IF position('zasp_authorization80.direct_guard(' in d)>0 THEN CONTINUE;END IF;
  IF target.lanname='plpgsql' THEN
   IF d!~'\nBEGIN\s' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='guarded function predecessor changed: '||target.procedure::text;END IF;
   EXECUTE regexp_replace(d,'\nBEGIN(\s)',E'\nBEGIN\n PERFORM '||target.guard||E';\\1');
  ELSIF target.lanname='sql' THEN
   tag:=(regexp_match(d,'\nAS (\$[A-Za-z_]*\$)'))[1];
   IF tag IS NULL THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='guarded function predecessor changed: '||target.procedure::text;END IF;
   EXECUTE replace(d,E'\nAS '||tag,E'\nAS '||tag||E'\n  SELECT '||target.guard||';');
  ELSE RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='guarded function language rejected: '||target.procedure::text;
  END IF;
 END LOOP;
END $direct_guards$;

-- The ordered Security Agent release (zasp_ordered_public62.api) authorizes
-- by the actor's stored role only, except for an approval decision, which
-- binds the proof itself. An API session may ask the deployment readiness
-- question with no proof (startup); every other operation needs the proof of
-- the scope and actor the request names.
DO $ordered_guard$
DECLARE d text;
BEGIN
 d:=pg_get_functiondef('zasp_ordered_public62.api(text,text,jsonb)'::regprocedure);
 IF position('zasp_authorization80.direct_guard(' in d)>0 THEN RETURN;END IF;
 IF d!~'\nBEGIN\s' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered public predecessor changed';END IF;
 EXECUTE regexp_replace(d,'\nBEGIN(\s)',E'\nBEGIN\n IF q->>''operation'' IS DISTINCT FROM ''deployment_ready'' THEN PERFORM zasp_authorization80.direct_guard(q->>''organization_id'',q->>''workspace_id'',q->>''environment_id'',q->>''actor_id'');END IF;\\1');
END $ordered_guard$;

-- The four discovery reads the API sends inside a fenced transaction checked
-- only that the session was the API principal: with no proof they returned
-- the sync, history, schedule or freshness of any integration the caller
-- named. Each is now bound to its own operation with the permission 'view',
-- to the proof's scope and to an allowed target: the sync for one sync, the
-- integration for the rest (the same rule the API applies before it sends the
-- statement, apiserver/authorization_discovery_statement.go).
CREATE OR REPLACE FUNCTION zasp_authorization80.direct_read_guard(o text,w text,e text,operation_value text,kind_value text,target_value text) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $direct_read_guard$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles l ON l.oid=m.member JOIN pg_roles g ON g.oid=m.roleid
  WHERE l.rolname=session_user AND g.rolname IN('zasp_discovery_api','zasp_security_agent_api')) THEN RETURN true;END IF;
 IF NOT COALESCE(zasp_authorization80.read_request(o,w,e,ARRAY[operation_value],'view')
  AND zasp_authorization80.context()->'collection'='false'::jsonb
  AND zasp_authorization80.allowed(o,w,e,kind_value,target_value),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current read purpose required';END IF;
 RETURN true;
END $direct_read_guard$;
ALTER FUNCTION zasp_authorization80.direct_read_guard(text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.direct_read_guard(text,text,text,text,text,text) FROM PUBLIC;
DO $discovery_read_guards$
DECLARE target record;d text;
BEGIN
 FOR target IN SELECT * FROM(VALUES
  ('zasp_temporal72.sync_detail(text,text,text,text,text)','zasp_authorization80.direct_read_guard(o,w,e,''getIntegrationSync'',''discovery_sync'',s)'),
  ('zasp_temporal72.sync_history(text,text,text,text,timestamp with time zone,text,integer)','zasp_authorization80.direct_read_guard(o,w,e,''listIntegrationSyncs'',''integration'',i)'),
  ('zasp_temporal72.schedule_detail(text,text,text,text)','zasp_authorization80.direct_read_guard(o,w,e,''getIntegrationSchedule'',''integration'',i)'),
  ('zasp_temporal72.last_good_freshness(text,text,text,text)','zasp_authorization80.direct_read_guard(o,w,e,''getIntegrationFreshness'',''integration'',i)')
 ) v(signature,guard) LOOP
  d:=pg_get_functiondef(target.signature::regprocedure);
  IF position('zasp_authorization80.direct_read_guard(' in d)>0 THEN CONTINUE;END IF;
  IF d!~'\nBEGIN\s' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='discovery read predecessor changed';END IF;
  EXECUTE regexp_replace(d,'\nBEGIN(\s)',E'\nBEGIN\n PERFORM '||target.guard||E';\\1');
 END LOOP;
END $discovery_read_guards$;

-- ---------------------------------------------------------------------------
-- X3b. Microsoft and Salesforce as discovery providers.
--
-- The chain knew four discovery providers (aws, kubernetes, github, okta) and
-- named them in ten CHECK constraints and in the bodies of the functions
-- below. Two more are added: microsoft (Entra agent identities, AI
-- applications and Copilot Studio agents of one tenant) and salesforce
-- (Agentforce agents of one org). Both are reference-authorized like AWS and
-- Kubernetes: the integration configuration names a client secret by
-- reference (ref:<provider>/client-secret/<id>, held in Secrets Manager) and
-- never carries the secret.
--
-- Released migrations are immutable, so the lists are widened here. A CHECK
-- constraint is found by its definition, dropped and re-added under the same
-- name. A function body is read with pg_get_functiondef, one exact text is
-- replaced, and the result is executed, which keeps the function's owner,
-- grants and settings. An edit whose replacement is already present is
-- skipped (the file is re-runnable); an edit whose anchor is not present
-- exactly once raises, so a predecessor that changed stops the transaction.
-- Nothing here creates a role, changes an owner or grants a privilege.
--
-- What each provider adds beyond the lists:
--   * subject: microsoft_tenant (the directory GUID, equal to tenant_id of
--     the configuration) and salesforce_org (the 18-character organization
--     id, equal to organization_id of the configuration);
--   * credential class of a collection: microsoft_client_credentials and
--     salesforce_client_credentials;
--   * configuration: the exact key sets and value grammars the API validates
--     (apiserver.parseReferenceAuthorizationConfiguration);
--   * zasp_reference_only refuses any configuration key that names a secret.
--     client_secret_reference is admitted the way signing_secret_reference
--     already is: only as a reference of the fixed grammar.
DO $saas_providers$
DECLARE four CONSTANT text:=$v$'aws','kubernetes','github','okta'$v$;
 six CONSTANT text:=$v$'aws','kubernetes','github','okta','microsoft','salesforce'$v$;
 guid CONSTANT text:='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
 org CONSTANT text:='^00D[A-Za-z0-9]{15}$';
 secret_reference CONSTANT text:='/client-secret/[a-z0-9][a-z0-9._-]{7,127}$';
 dataverse CONSTANT text:='^https://[a-z0-9][a-z0-9-]{0,62}\.crm[0-9]{0,2}\.dynamics\.com$';
 instance CONSTANT text:='^https://[a-z0-9][a-z0-9-]{0,62}(\.[a-z0-9][a-z0-9-]{0,62}){0,3}\.my\.salesforce\.com$';
 -- A consumer key is 16 to 256 printable characters; a bound is at most 255.
 consumer_key CONSTANT text:='^[!-~]{16,255}[!-~]?$';
 provider_columns CONSTANT text[]:=ARRAY[
  'public.zasp_discovery_connection_subjects.provider','public.zasp_discovery_generation_reservations.source',
  'public.zasp_discovery_job_authorities.provider','public.zasp_discovery_job_checkpoints.provider',
  'public.zasp_discovery_snapshot_inputs.source','public.zasp_discovery_projection_cursors.source',
  'public.zasp_discovery_risk_projection_current.source','public.zasp_inventory_identity_rules.provider',
  'zasp_temporal72.runs.provider','public.zasp_discovery_connection_subjects.subject_kind'];
 listed_column text;relation regclass;column_name text;old_values text[];new_values text[];old_definition text;new_definition text;
 edit record;found_name name;found_definition text;matches integer;d text;
BEGIN
 -- CHECK constraints that list the providers, and the one that lists the
 -- subject kinds. pg_get_constraintdef prints such a list as
 -- CHECK ((col = ANY (ARRAY['a'::text, 'b'::text]))).
 FOREACH listed_column IN ARRAY provider_columns LOOP
  relation:=substring(listed_column FROM '^(.*)\.[a-z_]+$')::regclass;
  column_name:=substring(listed_column FROM '\.([a-z_]+)$');
  IF column_name='subject_kind' THEN
   old_values:=ARRAY['aws_account','kubernetes_cluster','github_installation','okta_tenant'];
   new_values:=old_values||ARRAY['microsoft_tenant','salesforce_org'];
  ELSE
   old_values:=ARRAY['aws','kubernetes','github','okta'];
   new_values:=old_values||ARRAY['microsoft','salesforce'];
  END IF;
  old_definition:=format('CHECK ((%I = ANY (ARRAY[%s])))',column_name,(SELECT string_agg(quote_literal(item)||'::text',', ' ORDER BY position) FROM unnest(old_values) WITH ORDINALITY AS listed(item,position)));
  new_definition:=format('CHECK ((%I = ANY (ARRAY[%s])))',column_name,(SELECT string_agg(quote_literal(item)||'::text',', ' ORDER BY position) FROM unnest(new_values) WITH ORDINALITY AS listed(item,position)));
  SELECT count(*),min(c.conname::text),min(pg_get_constraintdef(c.oid)) INTO matches,found_name,found_definition FROM pg_constraint c
   WHERE c.conrelid=relation AND c.contype='c' AND pg_get_constraintdef(c.oid) IN(old_definition,new_definition);
  IF matches<>1 THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE=format('provider list constraint predecessor changed: %s',listed_column);
  END IF;
  IF found_definition=old_definition THEN
   EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',relation,found_name);
   EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I CHECK(%I IN(%s))',relation,found_name,column_name,(SELECT string_agg(quote_literal(item),',' ORDER BY position) FROM unnest(new_values) WITH ORDINALITY AS listed(item,position)));
  END IF;
 END LOOP;

 -- Function bodies.
 FOR edit IN SELECT * FROM (VALUES
   -- The provider lists.
   ('public.zasp_connector_provider_valid(text)',format('value IN (%s)',four),format('value IN (%s)',six)),
   ('public.zasp_discovery_apply_snapshot(text,text,text,text,text,text,bigint,text,text,bytea,timestamptz,text,text,jsonb,jsonb,jsonb)',format('IN(%s)',four),format('IN(%s)',six)),
   ('public.zasp_execution_checkpoint_partial(text,text,text,text,text,text,bigint,text,text,text,text,text,text,bytea,bigint,text,text,text,text)',format('IN(%s)',four),format('IN(%s)',six)),
   ('public.zasp_execution_apply_risk_projection(text,text,text,text,text,text,text,text,text,bigint,bytea,jsonb)',format('IN(%s)',four),format('IN(%s)',six)),
   ('public.zasp_inventory_apply_findings(text,text,text,jsonb)',format('IN(%s)',four),format('IN(%s)',six)),
   ('public.zasp_inventory_validate_typed_entities(text,jsonb)',format('IN(%s)',four),format('IN(%s)',six)),
   ('zasp_temporal72.normalize_relationships(text,text,text,text,text,jsonb)',format('IN(%s)',four),format('IN(%s)',six)),
   -- The reference-authorized providers.
   ('public.zasp_complete_reference_authorization(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)',$v$provider_value NOT IN('aws','kubernetes')$v$,$v$provider_value NOT IN('aws','kubernetes','microsoft','salesforce')$v$),
   ('zasp_authorization80.integration_reference_native_complete(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)',$v$provider_value NOT IN('aws','kubernetes')$v$,$v$provider_value NOT IN('aws','kubernetes','microsoft','salesforce')$v$),
   ('zasp_authorization80.integration_reference_complete(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text,text,text)',$v$provider_value IN('aws','kubernetes')$v$,$v$provider_value IN('aws','kubernetes','microsoft','salesforce')$v$),
   -- The reference a connection is bound to is the one its configuration names.
   ('public.zasp_complete_reference_authorization(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)',$v$WHEN 'aws' THEN configuration_value->>'external_id_reference' ELSE configuration_value->>'connection_reference' END$v$,$v$WHEN 'aws' THEN configuration_value->>'external_id_reference' WHEN 'kubernetes' THEN configuration_value->>'connection_reference' ELSE configuration_value->>'client_secret_reference' END$v$),
   ('zasp_authorization80.integration_reference_native_complete(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)',$v$WHEN 'aws' THEN configuration_value->>'external_id_reference' ELSE configuration_value->>'connection_reference' END$v$,$v$WHEN 'aws' THEN configuration_value->>'external_id_reference' WHEN 'kubernetes' THEN configuration_value->>'connection_reference' ELSE configuration_value->>'client_secret_reference' END$v$),
   -- Subject of a connection.
   ('public.zasp_execution_subject_valid(text,text,text)',$v$  ELSE false END$v$,format($v$  WHEN 'microsoft' THEN kind_value='microsoft_tenant' AND id_value ~ %L
  WHEN 'salesforce' THEN kind_value='salesforce_org' AND id_value ~ %L
  ELSE false END$v$,guid,org)),
   -- Configuration accepted at reference authorization.
   ('public.zasp_reference_authorization_configuration_valid(text,jsonb)',$v$      AND configuration_value->>'connection_reference' ~ '^ref:kubernetes/connection/[A-Za-z0-9][A-Za-z0-9._-]{7,127}$'$v$,format($v$      AND configuration_value->>'connection_reference' ~ '^ref:kubernetes/connection/[A-Za-z0-9][A-Za-z0-9._-]{7,127}$'
    OR provider_value='microsoft'
      AND (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(configuration_value) key) IN(ARRAY['client_id','client_secret_reference','tenant_id']::text[],ARRAY['client_id','client_secret_reference','dataverse_url','tenant_id']::text[])
      AND NOT EXISTS(SELECT 1 FROM jsonb_each(configuration_value) member WHERE jsonb_typeof(member.value)<>'string')
      AND configuration_value->>'tenant_id' ~ %1$L AND configuration_value->>'client_id' ~ %1$L
      AND configuration_value->>'client_secret_reference' ~ %2$L
      AND (NOT configuration_value ? 'dataverse_url' OR configuration_value->>'dataverse_url' ~ %3$L)
    OR provider_value='salesforce'
      AND (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(configuration_value) key)=ARRAY['client_id','client_secret_reference','instance_url','organization_id']::text[]
      AND NOT EXISTS(SELECT 1 FROM jsonb_each(configuration_value) member WHERE jsonb_typeof(member.value)<>'string')
      AND configuration_value->>'instance_url' ~ %4$L AND configuration_value->>'organization_id' ~ %5$L
      AND configuration_value->>'client_id' ~ %6$L
      AND configuration_value->>'client_secret_reference' ~ %7$L$v$,guid,'^ref:microsoft'||secret_reference,dataverse,instance,org,consumer_key,'^ref:salesforce'||secret_reference)),
   -- Configuration accepted when the integration is created or updated.
   ('zasp_authorization80.integration_setup_valid(text,jsonb)',$v$ WHEN 'slack' THEN$v$,format($v$ WHEN 'microsoft' THEN RETURN (keys=ARRAY['client_id','client_secret_reference','tenant_id'] OR keys=ARRAY['client_id','client_secret_reference','dataverse_url','tenant_id'])
  AND c->>'tenant_id'~%1$L AND c->>'client_id'~%1$L AND c->>'client_secret_reference'~%2$L
  AND (NOT c ? 'dataverse_url' OR c->>'dataverse_url'~%3$L);
 WHEN 'salesforce' THEN RETURN keys=ARRAY['client_id','client_secret_reference','instance_url','organization_id']
  AND c->>'instance_url'~%4$L AND c->>'organization_id'~%5$L AND c->>'client_id'~%6$L AND c->>'client_secret_reference'~%7$L;
 WHEN 'slack' THEN$v$,guid,'^ref:microsoft'||secret_reference,dataverse,instance,org,consumer_key,'^ref:salesforce'||secret_reference)),
   -- A configuration may name its client secret by reference.
   ('public.zasp_reference_only(jsonb)',$v$       AND (value-'signing_secret_reference')::text !~*$v$,format($v$       AND (NOT value ? 'client_secret_reference'
            OR jsonb_typeof(value->'client_secret_reference')='string'
               AND value->>'client_secret_reference' ~ %L)
       AND (value-'signing_secret_reference'-'client_secret_reference')::text !~*$v$,'^ref:(microsoft|salesforce)'||secret_reference)),
   -- A run stays current only while its subject is the one its configuration names.
   ('zasp_temporal72.require_current_run(zasp_temporal72.runs,timestamptz)',$v$ WHEN 'kubernetes' THEN r.subject_kind='kubernetes_cluster' ELSE false END FOR SHARE OF i,c,s;$v$,$v$ WHEN 'kubernetes' THEN r.subject_kind='kubernetes_cluster'
 WHEN 'microsoft' THEN r.subject_kind='microsoft_tenant' AND r.subject_id=i.configuration->>'tenant_id'
 WHEN 'salesforce' THEN r.subject_kind='salesforce_org' AND r.subject_id=i.configuration->>'organization_id' ELSE false END FOR SHARE OF i,c,s;$v$),
   ('public.zasp_typed_inventory_job_input_v13(text,text,text,text,text,text)',$v$     WHEN 'kubernetes' THEN subject.subject_kind='kubernetes_cluster'
     ELSE false END;$v$,$v$     WHEN 'kubernetes' THEN subject.subject_kind='kubernetes_cluster'
     WHEN 'microsoft' THEN subject.subject_kind='microsoft_tenant' AND subject.subject_id=integration.configuration->>'tenant_id'
     WHEN 'salesforce' THEN subject.subject_kind='salesforce_org' AND subject.subject_id=integration.configuration->>'organization_id'
     ELSE false END;$v$),
   -- Credential class of a collection.
   ('zasp_temporal72.prepare_page(text,text,text,text,text,text,timestamptz,bigint,text)',$v$WHEN 'github' THEN 'github_installation' ELSE 'okta_refresh' END$v$,$v$WHEN 'github' THEN 'github_installation' WHEN 'microsoft' THEN 'microsoft_client_credentials' WHEN 'salesforce' THEN 'salesforce_client_credentials' ELSE 'okta_refresh' END$v$),
   ('public.zasp_typed_inventory_job_input_v13(text,text,text,text,text,text)',$v$WHEN 'github' THEN 'github_installation' ELSE 'okta_refresh' END$v$,$v$WHEN 'github' THEN 'github_installation' WHEN 'microsoft' THEN 'microsoft_client_credentials' WHEN 'salesforce' THEN 'salesforce_client_credentials' ELSE 'okta_refresh' END$v$)
  ) AS listed(target,old_text,new_text) LOOP
  d:=pg_get_functiondef(edit.target::regprocedure);
  CONTINUE WHEN position(edit.new_text in d)>0;
  IF length(d)-length(replace(d,edit.old_text,''))<>length(edit.old_text) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE=format('provider predecessor changed: %s',edit.target);
  END IF;
  EXECUTE replace(d,edit.old_text,edit.new_text);
 END LOOP;
END $saas_providers$;

-- ---------------------------------------------------------------------------
-- X4. Inventory rule catalog: discovered agent kinds, and the catalog digest.
--
-- The chain's catalog knew one agent kind, a Kubernetes Deployment its owner
-- labelled zasp.ai/entity-kind=agent. The collectors now also report agents
-- nobody declared: the ones a provider's control plane lists (Bedrock agents,
-- AgentCore runtimes) at the confidence of a provider record, and the ones the
-- product infers from signals (a Lambda function whose role may invoke a
-- model, an unlabelled workload carrying an agent framework, a repository
-- with an agent manifest, an AI application connected in the identity
-- provider) at a lower confidence. An AgentCore gateway is a tool.
-- The Microsoft and Salesforce providers (section X3b, which widens the
-- provider CHECK these rows need) report the agents their control planes list
-- (Entra agent identities, Copilot Studio agents, Agentforce agents), the AI
-- applications of an Entra tenant at the confidence of an inference, and the
-- tenant or org itself as an asset.
INSERT INTO public.zasp_inventory_identity_rules(provider,source_kind,identity_namespace,product_kind,rule_version,priority,confidence_basis_points,freshness_seconds) VALUES
 ('aws','aws_agentcore_gateway','aws_agentcore_gateway','tool',1,100,9000,86400),
 ('aws','aws_agentcore_runtime','aws_agentcore_runtime','agent',1,100,9500,86400),
 ('aws','aws_bedrock_agent','aws_bedrock_agent','agent',1,100,9500,86400),
 ('aws','aws_inferred_agent','aws_inferred_agent','agent',1,100,6000,86400),
 ('github','github_agent_project','github_agent_project','agent',1,120,6000,86400),
 ('kubernetes','kubernetes_inferred_agent','kubernetes_inferred_agent','agent',1,80,6000,900),
 ('okta','okta_ai_application','okta_ai_application','agent',1,110,7000,86400),
 ('microsoft','microsoft_agent_identity','microsoft_agent_identity','agent',1,130,9500,86400),
 ('microsoft','microsoft_ai_application','microsoft_ai_application','agent',1,130,7000,86400),
 ('microsoft','microsoft_copilot_agent','microsoft_copilot_agent','agent',1,130,9500,86400),
 ('microsoft','microsoft_tenant','microsoft_tenant','asset',1,130,9500,86400),
 ('salesforce','salesforce_agent','salesforce_agent','agent',1,140,9500,86400),
 ('salesforce','salesforce_org','salesforce_org','asset',1,140,9500,86400)
ON CONFLICT(provider,source_kind) DO NOTHING;

-- Section G reclassified AWS IAM roles as identities (rule version 2) and the
-- rows above add thirteen kinds. The typed inventory release pins the digest of
-- the rule catalog in a CHECK constraint, in its cutover rows, in
-- zasp_schema_metadata and in two function bodies; all still named an earlier
-- catalog. They now name the catalog the rules table and the compiled catalog
-- (inventoryprojection.RuleCatalogDigest) both hold. The earlier digests are
-- the chain's, the one a baseline before the discovered agent kinds pinned,
-- and the one a baseline before the Microsoft and Salesforce kinds pinned.
DO $rule_catalog_digest$
DECLARE earlier CONSTANT text[]:=ARRAY['44820a38e96d80318165fc2333fd851cd932d2704d380a1199d569d1d0778f30','9397691244ac0b8befd2790fed3ca2e71f2114eba44001cc3d5634f86b6044ed','f67df9589cf0d41f4b2a98a5161353100e2ff3ed61cfc188c1447d2dd14c4192'];
 current_value CONSTANT text:='2af0dce065caff0c7093dfecede207658bf1973cfcc53911bfae7faef33b1809';
 previous text;f regprocedure;d text;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.zasp_inventory_identity_rules WHERE(provider,source_kind,product_kind,rule_version)=('aws','aws_role','identity',2))
  OR (SELECT count(*) FROM public.zasp_inventory_identity_rules)<>43 THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='inventory rule catalog predecessor changed';
 END IF;
 ALTER TABLE public.zasp_inventory_cutover_state DROP CONSTRAINT IF EXISTS zasp_inventory_cutover_state_rule_catalog_digest_check;
 UPDATE public.zasp_inventory_cutover_state SET rule_catalog_digest=current_value WHERE rule_catalog_digest=ANY(earlier);
 EXECUTE format('ALTER TABLE public.zasp_inventory_cutover_state ADD CONSTRAINT zasp_inventory_cutover_state_rule_catalog_digest_check CHECK(rule_catalog_digest=%L)',current_value);
 UPDATE public.zasp_schema_metadata SET value=current_value WHERE key='typed_inventory_rule_catalog_digest' AND value=ANY(earlier);
 FOREACH f IN ARRAY ARRAY['public.zasp_inventory_advance_scope(text,text,text,text,bytea,bytea)'::regprocedure,'public.zasp_inventory_readiness(text,text)'::regprocedure] LOOP
  FOREACH previous IN ARRAY earlier LOOP
   d:=pg_get_functiondef(f);
   IF position(previous in d)>0 THEN EXECUTE replace(d,previous,current_value);END IF;
  END LOOP;
 END LOOP;
END $rule_catalog_digest$;

-- ---------------------------------------------------------------------------
-- X5. How an inventory object was found, on every inventory read.
--
-- The inventory summary said what an object is and how fresh it is, not which
-- provider reported it, whether it was declared or inferred, or whether
-- anyone has taken ownership of an agent nobody declared. The lists
-- (zasp_authorization80.inventory_page), the detail and the agent update all
-- read the summary zasp_inventory_detail builds, and the historical page
-- (zasp_inventory_page) builds the same summary itself, so both gain four
-- members:
--   provider          the winning observation's provider
--   source_kind       the provider kind the collector reported, read from
--                     the winning source observation (the entity row keeps
--                     only the product kind)
--   discovery         method (declared, provider_api or inferred), platform
--                     and the catalog signals an inference rests on
--   management_state  for an agent: dismissed when a person marked it as not
--                     an agent (the reserved annotation tag not-an-agent on
--                     an agent that was found without a declaration; the tag
--                     means nothing on a declared agent, whose owner
--                     labelled it); otherwise unmanaged while it was found
--                     without a declaration and has no owner, managed
--                     otherwise; for every other kind not_applicable
--
-- Re-run: a function that already holds exactly these members is left alone;
-- one that holds the members of the completion before 'dismissed' existed has
-- them replaced by these; one that holds neither gains them at its anchor.
-- Any other definition naming management_state is refused.
DO $inventory_discovery_summary$
DECLARE detail CONSTANT regprocedure:='public.zasp_inventory_detail(text,text,text,text,text)'::regprocedure;
 page CONSTANT regprocedure:='public.zasp_inventory_page(text,text,text,text,text,integer)'::regprocedure;
 source_kind CONSTANT text:=$source_kind$(SELECT observation.source_kind FROM public.zasp_inventory_source_observations observation WHERE (observation.organization_id,observation.workspace_id,observation.environment_id,observation.integration_id,observation.source,observation.entity_id)=(row_value.organization_id,row_value.workspace_id,row_value.environment_id,row_value.winning_integration_id,row_value.winning_source,row_value.id))$source_kind$;
 template CONSTANT text:=replace($members$jsonb_build_object('provider',row_value.winning_provider,'source_kind',SOURCE_KIND,'discovery',jsonb_build_object('method',CASE WHEN row_value.product_kind<>'agent' THEN 'provider_api' ELSE COALESCE(row_value.winning_attributes->'discovery'->>'method','declared') END,'platform',COALESCE(row_value.winning_attributes->'discovery'->>'platform',SOURCE_KIND),'signals',COALESCE(row_value.winning_attributes->'discovery'->'signals','[]'::jsonb)),'management_state',MANAGEMENT_STATE)$members$,'SOURCE_KIND',source_kind);
 members CONSTANT text:=replace(template,'MANAGEMENT_STATE',$state$CASE WHEN row_value.product_kind<>'agent' THEN 'not_applicable' WHEN COALESCE(row_value.winning_attributes->'discovery'->>'method','declared')<>'declared' AND COALESCE(annotation_value->'tags','[]'::jsonb) ? 'not-an-agent' THEN 'dismissed' WHEN row_value.winning_attributes->'discovery' IS NULL OR COALESCE(annotation_value->>'owner','')<>'' THEN 'managed' ELSE 'unmanaged' END$state$);
 earlier CONSTANT text:=replace(template,'MANAGEMENT_STATE',$state$CASE WHEN row_value.product_kind<>'agent' THEN 'not_applicable' WHEN row_value.winning_attributes->'discovery' IS NULL OR COALESCE(annotation_value->>'owner','')<>'' THEN 'managed' ELSE 'unmanaged' END$state$);
 detail_anchor CONSTANT text:='INTO summary_value;';
 page_anchor CONSTANT text:=$anchor$'version',annotation_version) ORDER BY id)$anchor$;
 target record;d text;
BEGIN
 FOR target IN SELECT * FROM(VALUES
  (detail,'entity_record.',detail_anchor,detail_anchor||' summary_value:=summary_value||MEMBERS;','inventory detail summary predecessor changed'),
  (page,'visible.',page_anchor,$head$'version',annotation_version)||MEMBERS ORDER BY id)$head$,'inventory page summary predecessor changed')
 ) listed(signature,row_name,anchor,patched,refusal) LOOP
  d:=pg_get_functiondef(target.signature);
  IF position(replace(members,'row_value.',target.row_name) in d)>0 THEN CONTINUE;END IF;
  IF position(replace(earlier,'row_value.',target.row_name) in d)>0 THEN
   EXECUTE replace(d,replace(earlier,'row_value.',target.row_name),replace(members,'row_value.',target.row_name));
   CONTINUE;
  END IF;
  IF position('management_state' in d)>0 OR length(d)-length(replace(d,target.anchor,''))<>length(target.anchor) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE=target.refusal;END IF;
  EXECUTE replace(d,target.anchor,replace(target.patched,'MEMBERS',replace(members,'row_value.',target.row_name)));
 END LOOP;
END $inventory_discovery_summary$;

-- X5a. A dismissed agent raises no posture finding.
--
-- zasp_inventory_refresh_posture_findings raises the agent posture findings
-- (ownerless_agent and eleven more) and resolves every posture finding its
-- rules no longer match. An agent a person marked as not an agent (section
-- X5: found without a declaration, annotation tag not-an-agent) is not an
-- agent to hold to those rules, so it leaves the set the rules read: nothing
-- is raised for it, and the findings it had are resolved by the same call.
-- zasp_inventory_update_agent, which records the mark, calls the refresh in
-- its own transaction; the risk projection apply calls it after every
-- collection.
DO $inventory_posture_dismissal$
DECLARE target CONSTANT regprocedure:='public.zasp_inventory_refresh_posture_findings(text,text,text)'::regprocedure;
 anchor CONSTANT text:=$anchor$   AND entity_value.winning_evidence_id IS NOT NULL$anchor$;
 condition CONSTANT text:=$condition$
   AND NOT (COALESCE(entity_value.winning_attributes->'discovery'->>'method','declared')<>'declared' AND COALESCE(annotation.tags,'[]'::jsonb) ? 'not-an-agent')$condition$;
 d text:=pg_get_functiondef(target);
BEGIN
 IF position(anchor||condition in d)=0 THEN
  IF position('not-an-agent' in d)>0 OR length(d)-length(replace(d,anchor,''))<>length(anchor) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='inventory posture refresh predecessor changed';END IF;
  EXECUTE replace(d,anchor,anchor||condition);
 END IF;
END $inventory_posture_dismissal$;

-- X5b. AI service coverage gaps on the integration freshness.
--
-- The AWS collector records, per AI service it asks for agents (Bedrock
-- agents, AgentCore, Lambda), an aws_service observation whose attributes say
-- whether the service was collected, refused the read role (access_denied) or
-- is not offered in the account's regions (unavailable). Nothing showed it:
-- agents were missing and the integration looked healthy. The freshness read
-- (GET /integrations/{id}/freshness, zasp_temporal72.last_good_freshness)
-- gains the member coverage_gaps: one {service,name,status} per service of
-- this integration whose current present observation is access_denied or
-- unavailable, at most 16, ordered by service. It is [] for an integration
-- with no such observation. A Kubernetes integration has one possible gap,
-- service runtime-observations: its cluster record says the discovery
-- credential may not list ConfigMaps, so what the node sensor saw the
-- workloads call at run time is not counted. The chain's reader
-- (public.zasp_execution_last_good_freshness) is left as it is.
DO $integration_coverage_gaps$
DECLARE target CONSTANT regprocedure:='zasp_temporal72.last_good_freshness(text,text,text,text)'::regprocedure;
 anchor CONSTANT text:=E'\n RETURN b;';
 gaps CONSTANT text:=$gaps$
 b:=b||jsonb_build_object('coverage_gaps',COALESCE((SELECT jsonb_agg(jsonb_build_object('service',gap.service,'name',gap.name,'status',gap.status) ORDER BY gap.service) FROM(
  (SELECT DISTINCT ON(observation.stable_fields->>'service') observation.stable_fields->>'service' service,COALESCE(NULLIF(observation.stable_fields->>'name',''),observation.display_name) name,observation.attributes->>'status' status
  FROM public.zasp_inventory_source_observations observation
  WHERE (observation.organization_id,observation.workspace_id,observation.environment_id,observation.integration_id)=(o,w,e,i)
   AND observation.provider='aws' AND observation.source_kind='aws_service' AND observation.source_state='present'
   AND observation.attributes->>'status' IN('access_denied','unavailable')
   AND observation.stable_fields->>'service' ~ '^[a-z][a-z0-9-]{0,63}$'
   AND length(COALESCE(NULLIF(observation.stable_fields->>'name',''),observation.display_name)) BETWEEN 1 AND 128
  ORDER BY observation.stable_fields->>'service',observation.last_seen_at DESC,observation.source
  LIMIT 15)
  UNION ALL
  (SELECT 'runtime-observations','Runtime agent discovery','access_denied'
  FROM public.zasp_inventory_source_observations observation
  WHERE (observation.organization_id,observation.workspace_id,observation.environment_id,observation.integration_id)=(o,w,e,i)
   AND observation.provider='kubernetes' AND observation.source_kind='kubernetes_cluster' AND observation.source_state='present'
   AND observation.attributes->>'runtime_observations'='access_denied'
  LIMIT 1)) gap),'[]'::jsonb));$gaps$;
 d text:=pg_get_functiondef(target);
BEGIN
 IF position(gaps in d)=0 THEN
  IF position('coverage_gaps' in d)>0 OR length(d)-length(replace(d,anchor,''))<>length(anchor) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='integration freshness predecessor changed';END IF;
  EXECUTE replace(d,anchor,gaps||anchor);
 END IF;
END $integration_coverage_gaps$;

-- ---------------------------------------------------------------------------
-- X5. Security Agent counts of the home summary.
--
-- zasp_authorization80.home_summary runs on the product database, whose row
-- security hides Temporal-owned Security Agent runs from it. The API resolved
-- the candidate targets of a home or search request on both databases and
-- attested their union; fence() re-reads every target on the executing
-- session, could not see those runs, and refused the request ('authorization
-- target version changed') as soon as one existed. A proof now names only
-- targets its own database resolved. The run and approval counts are served
-- here, on the Security Agent database, under a second proof of the same
-- operation whose targets that database resolved.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_home_summary(o text,w text,e text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_home_summary$
DECLARE pending_value bigint;oldest_value bigint;needs_human_value bigint;failed_value bigint;inconclusive_value bigint;contained_value bigint;remediated_value bigint;
BEGIN
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['getHomeSummary'],'view');
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization security agent principal rejected';END IF;
 SELECT count(*),COALESCE(floor(extract(epoch FROM transaction_timestamp()-min(a.created_at)))::bigint,0) INTO pending_value,oldest_value
  FROM public.zasp_security_agent_approvals a
  WHERE(a.organization_id,a.workspace_id,a.environment_id,a.state)=(o,w,e,'pending') AND zasp_authorization80.allowed(o,w,e,'security_agent_approval',a.approval_id);
 SELECT count(*) FILTER(WHERE r.state='needs_human'),count(*) FILTER(WHERE r.state='failed'),count(*) FILTER(WHERE r.state='inconclusive'),
  count(*) FILTER(WHERE r.state='contained' AND r.updated_at>=transaction_timestamp()-interval '24 hours'),count(*) FILTER(WHERE r.state='remediated' AND r.updated_at>=transaction_timestamp()-interval '24 hours')
  INTO needs_human_value,failed_value,inconclusive_value,contained_value,remediated_value
  FROM public.zasp_security_agent_runs r
  WHERE(r.organization_id,r.workspace_id,r.environment_id)=(o,w,e) AND zasp_authorization80.allowed(o,w,e,'security_agent_run',r.run_id);
 RETURN jsonb_build_object('pending_approvals',pending_value,'oldest_approval_age_seconds',GREATEST(oldest_value,0),'needs_human_runs',needs_human_value,'failed_runs',failed_value,
  'inconclusive_runs',inconclusive_value,'recent_contained',contained_value,'recent_remediated',remediated_value);
END $security_agent_home_summary$;
ALTER FUNCTION zasp_authorization80.security_agent_home_summary(text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.security_agent_home_summary(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.security_agent_home_summary(text,text,text) TO zasp_security_agent_api;

-- ---------------------------------------------------------------------------
-- X6. Browser session lookup.
--
-- A browser request is authenticated before any proof exists. The API did
-- that with a direct query over zasp_product_sessions and
-- zasp_identity_memberships, which required SELECT on both tables: a session
-- of the API role could read every session's CSRF token and token digest and
-- every membership. The lookup is now this function: it takes the presented
-- session token and returns that one live session, exactly the fields the
-- query returned. The table privileges are revoked.
CREATE OR REPLACE FUNCTION zasp_authorization80_identity.authenticate_session(token_value text) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $authenticate_session$
 SELECT jsonb_build_object('credential_id',s.session_id,'principal_id',s.principal_id,'organization_id',s.organization_id,'workspace_id',s.workspace_id,'environment_id',s.environment_id,
  'permissions','[]'::jsonb,'csrf_token',s.csrf_token,'fresh_authenticated',s.authenticated_at>clock_timestamp()-interval '5 minutes','fresh_auth_expires_at',s.authenticated_at+interval '5 minutes')
 FROM public.zasp_product_sessions s JOIN public.zasp_identity_memberships m ON(m.principal_id,m.organization_id)=(s.principal_id,s.organization_id) AND m.active
 WHERE s.token_digest=public.digest(token_value,'sha256') AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
  AND EXISTS(SELECT 1 FROM public.zasp_identity_admin_effective_scopes(s.principal_id,s.organization_id) x WHERE(x.workspace_id,x.environment_id)=(s.workspace_id,s.environment_id))
$authenticate_session$;
ALTER FUNCTION zasp_authorization80_identity.authenticate_session(text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80_identity.authenticate_session(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80_identity.authenticate_session(text) TO zasp_discovery_api;
REVOKE ALL ON TABLE public.zasp_product_sessions,public.zasp_identity_memberships FROM zasp_discovery_api;

-- ---------------------------------------------------------------------------
-- X7. The one-time SCIM bearer secret is revealed once.
--
-- zasp_authorization80.identity_provider_reveal_secret (section J) returned
-- the secret of any unexpired grant of the caller for as long as the grant
-- lived (ten minutes), as often as it was asked, and did not require the
-- grant to belong to a completed creation. The API never acknowledged a
-- grant. The reveal now
--   * locks the grant and requires the mutation that created it: a completed
--     createSCIMConnection of this Organization and administrator whose
--     recorded response names exactly this grant;
--   * acknowledges the grant in the same statement, which removes the
--     ciphertext: a second reveal finds nothing.
CREATE OR REPLACE FUNCTION zasp_authorization80.identity_provider_reveal_secret(o text,w text,e text,actor text,grant_value text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $identity_provider_reveal_secret$
DECLARE p jsonb;result jsonb;
BEGIN
 IF NOT COALESCE(public.zasp_valid_product_id(grant_value),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='identity administration input rejected';END IF;
 p:=zasp_authorization80.identity_provider_request(o,w,e,actor,'createSCIMConnection');
 PERFORM 1 FROM public.zasp_identity_secret_reveal_grants g
  WHERE(g.organization_id,g.principal_id,g.grant_id)=(o,actor,grant_value) AND g.acknowledged_at IS NULL AND g.expires_at>clock_timestamp()
   AND EXISTS(SELECT 1 FROM public.zasp_identity_provider_mutations m WHERE(m.organization_id,m.principal_id,m.mutation_id)=(g.organization_id,g.principal_id,g.mutation_id)
    AND m.operation='createSCIMConnection' AND m.state='completed' AND m.response->>'secret_grant_id'=g.grant_id AND m.response->>'mutation_id'=g.mutation_id)
  FOR UPDATE OF g;
 IF NOT FOUND THEN RETURN NULL;END IF;
 result:=public.zasp_identity_admin_reveal_secret(o,actor,grant_value);
 IF result IS NULL THEN RETURN NULL;END IF;
 PERFORM public.zasp_identity_admin_ack_secret(o,actor,grant_value);
 IF p IS DISTINCT FROM zasp_authorization80.context() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='identity administration proof expired';END IF;
 RETURN result;
END $identity_provider_reveal_secret$;
ALTER FUNCTION zasp_authorization80.identity_provider_reveal_secret(text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.identity_provider_reveal_secret(text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.identity_provider_reveal_secret(text,text,text,text,text) TO zasp_discovery_api;

-- ---------------------------------------------------------------------------
-- X8. Planner pricing approval.
--
-- zasp_sa_multistep_prior.pricing_admin writes the administrator's pricing
-- approval. It took the actor and the time of fresh authentication from its
-- caller and was executable by the API role directly (revoked in section X1),
-- so a session with no proof could approve, replace or disable the pricing of
-- any Environment in an administrator's name. This function is its authorized
-- form: a browser session with fresh authentication, the operation
-- setSecurityAgentPlannerPricing with manage_identity on the current
-- Environment, a non-collection request of this actor. The scope and actor of
-- the request must be the proof's, and the time of fresh authentication is
-- read from the verified session, never from the request.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_pricing_admin(o text,w text,e text,actor text,q jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_pricing_admin$
DECLARE p jsonb:=zasp_authorization80.context();fresh timestamptz;result jsonb;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='authorization pricing write requires read committed';END IF;
 IF p IS NULL OR actor IS NULL OR NOT COALESCE(public.zasp_discovery_principal_ready('zasp_discovery_api')
  AND zasp_authorization80.read_request(o,w,e,ARRAY['setSecurityAgentPlannerPricing'],'manage_identity',true,actor)
  AND p->'collection'='false'::jsonb AND p->'fresh_auth'='true'::jsonb
  AND zasp_authorization80.allowed(o,w,e,'environment',e),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current pricing authorization required';END IF;
 PERFORM zasp_authorization80.identity_fence(p);
 IF q IS NULL OR jsonb_typeof(q)<>'object' OR octet_length(q::text)>8192 OR q ? 'fresh_auth_at'
  OR(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'actor_id') IS DISTINCT FROM(o,w,e,actor)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization pricing request rejected';END IF;
 SELECT s.authenticated_at INTO fresh FROM public.zasp_product_sessions s
  WHERE s.session_id=p->>'credential_id' AND s.token_digest=decode(p->>'credential_digest','hex') AND s.principal_id=actor AND s.revoked_at IS NULL;
 IF fresh IS NULL OR fresh<=clock_timestamp()-interval '5 minutes' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current pricing authorization required';END IF;
 result:=zasp_sa_multistep_prior.pricing_admin('033bf2ffa9d4a60121d4f20436ff7de36d1421b62f849254a09048caf75998e6','6b6a74cba9ee791d8b23c08df2f3d08949a339e23460694bc0e2d2d3f25c8e92',
  q||jsonb_build_object('fresh_auth_at',to_char(fresh AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')));
 IF result IS NULL OR p IS DISTINCT FROM zasp_authorization80.context() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='current pricing proof expired';END IF;
 PERFORM zasp_authorization80.identity_fence(p);
 RETURN result;
END $security_agent_pricing_admin$;
ALTER FUNCTION zasp_authorization80.security_agent_pricing_admin(text,text,text,text,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.security_agent_pricing_admin(text,text,text,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.security_agent_pricing_admin(text,text,text,text,jsonb) TO zasp_discovery_api;

-- The worker's pricing binding (section I) is unchanged. It returns the pins
-- of any scope the worker names; restricting it to a scope with an unfinished
-- run is not possible from that function: row security on
-- zasp_security_agent_runs shows a Temporal-owned run only to the session of
-- the principal that owns it, so the worker's session (and this function,
-- which runs for it) sees no run of a scope it is about to plan for. The pins
-- are references, never a credential or an approval, and pricing_lookup
-- verifies them against the current approval.

-- ---------------------------------------------------------------------------
-- X9. A run is started only on a trigger its requester may read.
--
-- zasp_authorization80.security_agent_run (section H) binds the request to
-- the Security Agent definition. The triggering finding or attack path is
-- named in the request body, so the proof of the definition says nothing
-- about it: a principal allowed to run the agent could start a run on a
-- finding it is not allowed to see. The API now makes a second decision for
-- the trigger (getFinding or getAttackPath, permission 'view', the trigger as
-- the object) and passes its attestation. This function verifies that
-- attestation with the same key as fence(), requires it to be the decision of
-- the same principal, credential, scope and projection revision as the
-- request's own proof, for exactly this trigger, with the trigger among its
-- allowed targets, and only then starts the run. The six-argument form stays
-- as the body it calls; the API role can no longer execute it directly.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_run(o text,w text,e text,d text,actor text,q jsonb,trigger_proof text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_run_trigger$
DECLARE p jsonb:=zasp_authorization80.context();t jsonb;kind_value text;operation_value text;
BEGIN
 kind_value:=q->>'trigger_kind';
 operation_value:=CASE kind_value WHEN 'finding' THEN 'getFinding' WHEN 'attack_path' THEN 'getAttackPath' END;
 IF operation_value IS NULL THEN
  IF trigger_proof IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent run rejected';END IF;
 ELSE
  IF p IS NULL OR trigger_proof IS NULL OR NOT COALESCE(public.zasp_valid_product_id(q->>'trigger_id'),false)
  THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current security agent trigger authorization required';END IF;
  t:=zasp_authorization80.verify_attestation(trigger_proof);
  IF NOT COALESCE(t->>'operation_id'=operation_value AND t->>'permission'='view' AND t->'collection'='false'::jsonb
   AND(t->>'organization_id',t->>'workspace_id',t->>'environment_id',t->>'principal_id')=(o,w,e,actor)
   AND(t->>'organization_id',t->>'workspace_id',t->>'environment_id',t->>'principal_id',t->>'credential_kind',t->>'credential_id',t->>'credential_digest')
    =(p->>'organization_id',p->>'workspace_id',p->>'environment_id',p->>'principal_id',p->>'credential_kind',p->>'credential_id',p->>'credential_digest')
   AND t->'revision'=p->'revision' AND t->>'key_version'=p->>'key_version'
   AND t#>>'{path_parameters,id}'=q->>'trigger_id'
   AND EXISTS(SELECT 1 FROM jsonb_array_elements(t->'allowed') x
    WHERE(x->>'organization_id',x->>'workspace_id',x->>'environment_id',x->>'kind',COALESCE(NULLIF(x->>'source_id',''),x->>'id'))=(o,w,e,kind_value,q->>'trigger_id')),false)
  THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current security agent trigger authorization required';END IF;
 END IF;
 RETURN zasp_authorization80.security_agent_run(o,w,e,d,actor,q);
END $security_agent_run_trigger$;
ALTER FUNCTION zasp_authorization80.security_agent_run(text,text,text,text,text,jsonb,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.security_agent_run(text,text,text,text,text,jsonb,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.security_agent_run(text,text,text,text,text,jsonb,text) TO zasp_security_agent_api;
REVOKE EXECUTE ON FUNCTION zasp_authorization80.security_agent_run(text,text,text,text,text,jsonb) FROM zasp_security_agent_api;

-- ---------------------------------------------------------------------------
-- Y1. Security Agent action worker readiness.
--
-- The action worker (temporary policy, session isolation and connector
-- revocation effects) asks at startup, and before every batch, whether its
-- release is installed: zasp_recovery_execution_readiness for release 27.
-- That function follows the historical chain release by release up to a
-- 60-release pin (the same pin section B describes), so on the 61-release
-- baseline it is false for ever and the worker refused to start on any
-- database. Its statements themselves (claim, heartbeat, store, read, finish,
-- reconcile) already run under the current worker authorization.
--
-- This function states the same capability for the current catalog: the
-- release row and its recorded identity, the role shape the action releases
-- require, and the current worker release, whose readiness includes the
-- catalog integrity check (zasp_baseline.intact()). The principal answer is
-- the chain's own. It returns two booleans about the catalog and the calling
-- login and reads no tenant data. Only the action worker's role may ask.
CREATE OR REPLACE FUNCTION zasp_authorization80_worker.security_agent_action_ready(c text,f text) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_action_ready$
 SELECT jsonb_build_object('release',COALESCE(c='08f72ed9fc5bf2ef979cea65672aa26d6a8e60f096c050aa5ea1a6ba0586f6b7' AND f='12487d82d24fd4de68fc595e57306a085cc237218597c039f90477ce1ba7f364'
  AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=27 AND name='production_recovery' AND checksum=c)
  AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_recovery_fingerprint' AND value=f)
  AND public.zasp_security_agent_temporary_policy_security_ready() AND public.zasp_security_agent_connector_revocation_security_ready()
  AND public.zasp_security_agent_session_isolation_security_ready() AND public.zasp_recovery_execution_security_ready()
  AND zasp_authorization80_worker.runtime_ready(),false),
  'principal',COALESCE(public.zasp_security_agent_action_principal_ready(),false))
$security_agent_action_ready$;
ALTER FUNCTION zasp_authorization80_worker.security_agent_action_ready(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80_worker.security_agent_action_ready(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.security_agent_action_ready(text,text) TO zasp_security_agent_action_worker;

-- ---------------------------------------------------------------------------
-- Y2. Lock order of the single-test start consumer.
--
-- Every admission of a Security Agent run locks the Organization's
-- authorization row (zasp_authorization79.organizations, FOR UPDATE) and then
-- takes the Organization's budget-admission advisory lock:
-- zasp_temporal78.admit_occurrence (behind zasp_temporal77.dispatch_page and
-- catchup_definition) and zasp_temporal74.takeover both do. The start
-- consumer zasp_temporal74.pending() took the advisory lock first (without
-- waiting) and then called takeover, which waits for the row. With an
-- automatic admission of the same Organization in flight the two waited for
-- each other, and PostgreSQL ended one of them as a deadlock about once a
-- minute; the consumer swallows that error only for some states, so starts and
-- admissions were retried at random.
--
-- The consumer now takes the Organization row first, without waiting (SKIP
-- LOCKED), then the advisory lock as before, and only then touches the
-- delivery row. It never waits for either lock and takes them in the order
-- every admission does: when an admission holds the row, the candidate is
-- left for the next poll, exactly as when the advisory lock is busy. takeover
-- then finds both locks already held by its own transaction.
DO $pending_lock_order$
DECLARE d text;
 needle text:=$n$  IF NOT pg_try_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||candidate.organization_id,0)) THEN CONTINUE;END IF;$n$;
 added text:=$n$  PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=candidate.organization_id FOR UPDATE SKIP LOCKED;
  IF NOT FOUND THEN CONTINUE;END IF;$n$;
BEGIN
 SELECT pg_get_functiondef('zasp_temporal74.pending()'::regprocedure) INTO STRICT d;
 IF position('FOR UPDATE SKIP LOCKED' in d)=0 THEN
  IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='single-test start consumer predecessor changed';END IF;
  EXECUTE replace(d,needle,added||E'\n'||needle);
 END IF;
END $pending_lock_order$;

-- ---------------------------------------------------------------------------
-- Y3. Security Agent runs and approvals: detail, cancellation, decision,
-- simulation and the manual trigger.
--
-- Section H moved the definition writes, activation and the triggered run to
-- one authorized statement each. The remaining Security Agent routes still
-- chose the family with several statements, none of which is an authorized
-- function, and since sections X1 and X3 their historical statements are no
-- longer reachable without a proof, so the API refused all of them:
--   GET  /security-agent-runs/{id}               getSecurityAgentRun
--   POST /security-agent-runs/{id}/cancel        cancelSecurityAgentRun
--   GET  /security-agent-approvals/{id}          getSecurityAgentApproval
--   POST /security-agent-approvals/{id}/decision decideSecurityAgentApproval
--   POST /security-agents/{id}/simulate          simulateSecurityAgent
--   POST /security-agents/{id}/runs without a trigger (the manual trigger)
-- Each function below is one statement. It binds the request to the attested
-- proof and then calls the chain's own reader or writer for the family that
-- owns the object, in the order the API used (ordered release 61, finding
-- response zasp_temporal78, single existing test zasp_temporal74, then the
-- retained functions through zasp_temporal66). Every check those functions
-- already had stays: release, principal, actor permission, optimistic
-- version, idempotent replay, audit and receipt. The result names the family
-- so the API decodes that family's shape.
--
-- security_agent_object_request is the shared admission. It returns the proof
-- only when the fenced transaction carries exactly this operation with the
-- permission the operation's policy names, for this Organization, Workspace,
-- Environment and actor, as a non-collection request, with a browser session
-- and fresh authentication where the policy requires them, for the object
-- named in the request path, and when that object is among the allowed
-- targets. It then re-verifies the credential and membership under row locks.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_object_request(o text,w text,e text,actor text,op text,i text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_object_request$
DECLARE p jsonb:=zasp_authorization80.context();permission_value text;browser boolean:=false;fresh boolean:=false;kind text;
BEGIN
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization security agent principal rejected';END IF;
 CASE op
  WHEN 'getSecurityAgentRun' THEN permission_value:='view';kind:='security_agent_run';
  WHEN 'cancelSecurityAgentRun' THEN permission_value:='manage_workflows';kind:='security_agent_run';
  WHEN 'getSecurityAgentApproval' THEN permission_value:='view';kind:='security_agent_approval';
  WHEN 'decideSecurityAgentApproval' THEN permission_value:='manage_workflows';kind:='security_agent_approval';browser:=true;fresh:=true;
  WHEN 'simulateSecurityAgent' THEN permission_value:='manage_workflows';kind:='security_agent';
  ELSE RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current security agent authorization required';
 END CASE;
 IF p IS NULL OR actor IS NULL OR i IS NULL OR NOT COALESCE(public.zasp_valid_product_id(i),false)
  OR NOT COALESCE(zasp_authorization80.read_request(o,w,e,ARRAY[op],permission_value,browser,actor)
   AND p->'collection'='false'::jsonb
   AND(NOT fresh OR p->'fresh_auth'='true'::jsonb)
   AND p#>>'{path_parameters,id}'=i
   AND zasp_authorization80.allowed(o,w,e,kind,i),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current security agent authorization required';END IF;
 PERFORM zasp_authorization80.identity_fence(p);
 RETURN p;
END $security_agent_object_request$;

-- GET /security-agent-runs/{id}.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_run_detail(o text,w text,e text,r text,actor text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_run_detail$
DECLARE p jsonb;result jsonb;family text;
 c CONSTANT text:='e4dfae0a990718c2c6b7518b07d7c146cfb9025656378d423c8d96188bcf1b96';f CONSTANT text:='07e774a28105095c73275ad959c765a3fddda9ee9aa81e81cd3828222e40aad3';
BEGIN
 p:=zasp_authorization80.security_agent_object_request(o,w,e,actor,'getSecurityAgentRun',r);
 IF zasp_ordered_public62.classify(o,w,e,'run',r)='ordered_release61' THEN
  -- The ordered release serves its resources to a browser session only.
  IF p->>'credential_kind'<>'1' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent ordered credential rejected';END IF;
  result:=zasp_ordered_public62.api(c,f,jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'actor_id',actor,'operation','resource_run','run_id',r));
  family:='ordered';
 ELSE
  result:=zasp_temporal78.run_context(o,w,e,r);family:='finding';
  IF result IS NULL THEN
   SELECT value INTO result FROM zasp_temporal66.run_context(o,w,e,r,'6e2fbdef64421286476be12a02188d7936e81db3126764bf2ab55e099fcb12cb','422b211febdd6e2b37882dc3f5961a79ca5c58f3f87f1642f7babf1224fbe94a') rows(value);
   family:='legacy';
  END IF;
 END IF;
 IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='security agent run missing';END IF;
 IF p IS DISTINCT FROM zasp_authorization80.context() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='current security agent proof expired';END IF;
 RETURN jsonb_build_object('family',family,'result',result);
END $security_agent_run_detail$;

-- POST /security-agent-runs/{id}/cancel. The ordered result carries the
-- resource read before the cancellation and the retained mutation result.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_cancel_run(o text,w text,e text,r text,actor text,k text,v bigint,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_cancel_run$
DECLARE p jsonb;result jsonb;family text;scope_value jsonb;
 c CONSTANT text:='e4dfae0a990718c2c6b7518b07d7c146cfb9025656378d423c8d96188bcf1b96';f CONSTANT text:='07e774a28105095c73275ad959c765a3fddda9ee9aa81e81cd3828222e40aad3';
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='authorization security agent write requires read committed';END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(r) AND public.zasp_valid_product_id(audit_value) AND public.zasp_valid_product_id(correlation_value) AND public.zasp_valid_product_id(receipt_value)
  AND length(k) BETWEEN 16 AND 128 AND k~'^[A-Za-z0-9][A-Za-z0-9._:-]*$' AND v BETWEEN 1 AND 1000000,false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent cancellation rejected';END IF;
 p:=zasp_authorization80.security_agent_object_request(o,w,e,actor,'cancelSecurityAgentRun',r);
 IF zasp_ordered_public62.classify(o,w,e,'run',r)='ordered_release61' THEN
  IF p->>'credential_kind'<>'1' OR v>999999 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent ordered credential rejected';END IF;
  scope_value:=jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'actor_id',actor);
  result:=jsonb_build_object('resource',zasp_ordered_public62.api(c,f,scope_value||jsonb_build_object('operation','resource_run','run_id',r)));
  result:=result||jsonb_build_object('mutation',zasp_ordered_public62.api(c,f,scope_value||jsonb_build_object('operation','cancel','run_id',r,'run_version',v,'idempotency_key',k)));
  family:='ordered';
 ELSE
  result:=zasp_temporal74.cancel(o,w,e,r,actor,k,v,audit_value,correlation_value,receipt_value);family:='test';
  IF result IS NULL OR result='null'::jsonb THEN
   result:=zasp_temporal66.cancel_parent(o,w,e,r,actor,k,v,audit_value,correlation_value,receipt_value,'6e2fbdef64421286476be12a02188d7936e81db3126764bf2ab55e099fcb12cb','422b211febdd6e2b37882dc3f5961a79ca5c58f3f87f1642f7babf1224fbe94a');
   family:='legacy';
  END IF;
 END IF;
 IF result IS NULL OR jsonb_typeof(result) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent cancellation unavailable';END IF;
 PERFORM zasp_authorization80.security_agent_write_settled(p);
 RETURN jsonb_build_object('family',family,'result',result);
END $security_agent_cancel_run$;

-- GET /security-agent-approvals/{id}. The ordered release answers with the
-- approval's run resource; the other families with the approval envelope of
-- the newest actor-bound reader that owns it.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_approval(o text,w text,e text,a text,actor text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_approval$
DECLARE p jsonb;result jsonb;family text;
 c CONSTANT text:='e4dfae0a990718c2c6b7518b07d7c146cfb9025656378d423c8d96188bcf1b96';f CONSTANT text:='07e774a28105095c73275ad959c765a3fddda9ee9aa81e81cd3828222e40aad3';
BEGIN
 p:=zasp_authorization80.security_agent_object_request(o,w,e,actor,'getSecurityAgentApproval',a);
 IF zasp_ordered_public62.classify(o,w,e,'approval',a)='ordered_release61' THEN
  IF p->>'credential_kind'<>'1' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent ordered credential rejected';END IF;
  result:=zasp_ordered_public62.api(c,f,jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'actor_id',actor,'operation','resource_approval','approval_id',a));
  family:='ordered';
 ELSE
  result:=zasp_temporal78.approval(o,w,e,a,actor);family:='finding';
  IF result IS NULL THEN result:=zasp_temporal74.approval(o,w,e,a,actor);family:='legacy';END IF;
 END IF;
 IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='approval not found';END IF;
 IF p IS DISTINCT FROM zasp_authorization80.context() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='current security agent proof expired';END IF;
 RETURN jsonb_build_object('family',family,'result',result);
END $security_agent_approval$;

-- POST /security-agent-approvals/{id}/decision for every family but the
-- ordered release, whose decision already binds the proof itself
-- (zasp_ordered_public62.api 'decide_resource' through
-- zasp_authorization80_worker.require_ordered62_approval); an ordered approval
-- is refused here. Browser session, fresh authentication. The time of fresh
-- authentication the request names must be the verified session's.
--
-- An approval no Temporal release owns is decided as the chain's
-- existing-tests release decides it (the same statements, without that
-- release's 60-release readiness pin, which the baseline can never satisfy).
-- Attack Lab and evidence-export approvals have no ready release here and
-- are refused.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_decide_approval(o text,w text,e text,a text,actor text,k text,v bigint,decision_value text,fresh_value timestamptz,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_decide_approval$
DECLARE p jsonb;result jsonb;family text;authenticated timestamptz;action_value text;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='authorization security agent write requires read committed';END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(a) AND public.zasp_valid_product_id(audit_value) AND public.zasp_valid_product_id(correlation_value) AND public.zasp_valid_product_id(receipt_value)
  AND length(k) BETWEEN 16 AND 128 AND k~'^[A-Za-z0-9][A-Za-z0-9._:-]*$' AND v BETWEEN 1 AND 1000000
  AND decision_value IN('approved','rejected','cancelled') AND fresh_value IS NOT NULL,false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent decision rejected';END IF;
 p:=zasp_authorization80.security_agent_object_request(o,w,e,actor,'decideSecurityAgentApproval',a);
 SELECT s.authenticated_at INTO authenticated FROM public.zasp_product_sessions s
  WHERE s.session_id=p->>'credential_id' AND s.token_digest=decode(p->>'credential_digest','hex') AND s.principal_id=actor AND s.revoked_at IS NULL;
 IF authenticated IS NULL OR authenticated<=clock_timestamp()-interval '5 minutes' OR fresh_value IS DISTINCT FROM authenticated
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current security agent authorization required';END IF;
 IF zasp_ordered_public62.classify(o,w,e,'approval',a)='ordered_release61' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent decision family rejected';END IF;
 result:=zasp_temporal78.decide_approval(o,w,e,a,actor,k,v,decision_value,fresh_value,audit_value,correlation_value,receipt_value);family:='finding';
 IF result IS NULL OR result='null'::jsonb THEN
  result:=zasp_temporal74.decide_approval(o,w,e,a,actor,k,v,decision_value,fresh_value,audit_value,correlation_value,receipt_value);family:='test';
 END IF;
 IF result IS NULL OR result='null'::jsonb THEN
  family:='legacy';
  SELECT s.action_key INTO action_value FROM public.zasp_security_agent_approvals x
   JOIN public.zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id,step_id)
   WHERE(x.organization_id,x.workspace_id,x.environment_id,x.approval_id)=(o,w,e,a);
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='approval not found';END IF;
  IF action_value IN('start_attack_lab','create_evidence_export') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent approval release unavailable';END IF;
  IF action_value NOT IN('run_test','rerun_test','send_response_webhook') THEN
   result:=public.zasp_security_agent_decide_approval_v24(o,w,e,a,actor,k,v,decision_value,fresh_value,audit_value,correlation_value,receipt_value);
  ELSE
   result:=public.zasp_security_agent_decide_approval(o,w,e,a,actor,k,v,decision_value,fresh_value,audit_value,correlation_value,receipt_value);
   IF result->>'replayed' IS DISTINCT FROM 'true' THEN
    IF action_value='send_response_webhook' AND decision_value='approved' THEN PERFORM public.zasp_sa_webhook_approved(o,w,e,a);END IF;
    result:=result||public.zasp_production_security_agent_existing_tests_approval_value(o,w,e,a);
    UPDATE public.zasp_security_agent_request_receipts SET response=result
     WHERE(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,receipt_id)=(o,w,e,actor,'decideSecurityAgentApproval',k,a,receipt_value);
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent approval receipt unavailable';END IF;
   END IF;
  END IF;
 END IF;
 IF result IS NULL OR jsonb_typeof(result) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent decision unavailable';END IF;
 PERFORM zasp_authorization80.security_agent_write_settled(p);
 RETURN jsonb_build_object('family',family,'result',result);
END $security_agent_decide_approval$;

-- POST /security-agents/{id}/simulate: a stored plan with no effects. The
-- writer is the chain's newest simulation core with the table locks and the
-- expiry re-check of its release wrapper; that wrapper itself pins a
-- 60-release catalog. The capability is the single-test release
-- (zasp_temporal74), the same question the API asks before it offers it.
--
-- The evidence a simulation names must exist in the Environment of the proof
-- (the core refuses anything else); the proof is for the Security Agent, so a
-- requester learns no more about an evidence identifier than that it exists
-- in an Environment it may manage workflows in.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_simulate(o text,w text,e text,d text,actor text,k text,v bigint,run_value text,goal_value text,evidence_value jsonb,expires_value timestamptz,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_simulate$
DECLARE p jsonb;result jsonb;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='authorization security agent write requires read committed';END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(d) AND public.zasp_valid_product_id(run_value) AND public.zasp_valid_product_id(audit_value) AND public.zasp_valid_product_id(correlation_value) AND public.zasp_valid_product_id(receipt_value)
  AND length(k) BETWEEN 16 AND 128 AND k~'^[A-Za-z0-9][A-Za-z0-9._:-]*$' AND v BETWEEN 1 AND 1000000
  AND jsonb_typeof(evidence_value)='array' AND octet_length(evidence_value::text)<=8192 AND expires_value>clock_timestamp(),false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent simulation rejected';END IF;
 p:=zasp_authorization80.security_agent_object_request(o,w,e,actor,'simulateSecurityAgent',d);
 IF NOT COALESCE(zasp_temporal74.api_ready('6ecde7cb0053af3378f47aef84ecbe99ca31d9cdced9fbe6d0dc64ee7e01b39e','0be1a2bfe93c30928eb03eae744993df6ec6c4db692b909aed9b7c486de6aca5'),false)
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent simulation release unavailable';END IF;
 IF zasp_authorization80.security_agent_export_family(o,w,e,d,NULL) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent export definitions unavailable';END IF;
 LOCK TABLE public.zasp_workflow_records,public.zasp_security_agent_definitions,public.zasp_security_agent_definition_versions IN ROW EXCLUSIVE MODE;
 result:=public.zasp_production_security_agent_existing_tests_simulate_core(o,w,e,d,actor,k,v,run_value,goal_value,evidence_value,expires_value,audit_value,correlation_value,receipt_value);
 IF result IS NULL OR expires_value<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent simulation authority expired';END IF;
 PERFORM zasp_authorization80.security_agent_write_settled(p);
 RETURN result;
END $security_agent_simulate$;

-- POST /security-agents/{id}/runs with no trigger: the manual trigger. The
-- admission is the Temporal ownership release's (zasp_temporal66.manual_run),
-- which decides whether the definition may be started by hand at all. A
-- finding-response definition has no manual trigger.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_manual_run(o text,w text,e text,d text,actor text,k text,v bigint,run_value text,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_manual_run$
DECLARE p jsonb;result jsonb;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='authorization security agent write requires read committed';END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(d) AND public.zasp_valid_product_id(run_value) AND public.zasp_valid_product_id(audit_value) AND public.zasp_valid_product_id(correlation_value) AND public.zasp_valid_product_id(receipt_value)
  AND length(k) BETWEEN 16 AND 128 AND k~'^[A-Za-z0-9][A-Za-z0-9._:-]*$' AND v BETWEEN 1 AND 1000000,false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent run rejected';END IF;
 p:=zasp_authorization80.security_agent_write_request(o,w,e,actor,'runSecurityAgent',d);
 IF zasp_authorization80.security_agent_export_family(o,w,e,d,NULL) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent export definitions unavailable';END IF;
 IF COALESCE(zasp_temporal78.family(o,w,e,d,actor),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent run family rejected';END IF;
 result:=zasp_temporal66.manual_run(o,w,e,d,actor,k,v,run_value,audit_value,correlation_value,receipt_value,'6e2fbdef64421286476be12a02188d7936e81db3126764bf2ab55e099fcb12cb','422b211febdd6e2b37882dc3f5961a79ca5c58f3f87f1642f7babf1224fbe94a');
 IF result IS NULL OR jsonb_typeof(result) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent manual admission unavailable';END IF;
 PERFORM zasp_authorization80.security_agent_write_settled(p);
 RETURN result;
END $security_agent_manual_run$;

DO $security_agent_object_privileges$
DECLARE f record;
BEGIN
 FOR f IN SELECT * FROM(VALUES
  ('zasp_authorization80.security_agent_object_request(text,text,text,text,text,text)',NULL),
  ('zasp_authorization80.security_agent_run_detail(text,text,text,text,text)','zasp_security_agent_api'),
  ('zasp_authorization80.security_agent_cancel_run(text,text,text,text,text,text,bigint,text,text,text)','zasp_security_agent_api'),
  ('zasp_authorization80.security_agent_approval(text,text,text,text,text)','zasp_security_agent_api'),
  ('zasp_authorization80.security_agent_decide_approval(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text)','zasp_security_agent_api'),
  ('zasp_authorization80.security_agent_simulate(text,text,text,text,text,text,bigint,text,text,jsonb,timestamptz,text,text,text)','zasp_security_agent_api'),
  ('zasp_authorization80.security_agent_manual_run(text,text,text,text,text,text,bigint,text,text,text,text)','zasp_security_agent_api')
 ) v(signature,grantees) LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',f.signature::regprocedure);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f.signature::regprocedure);
  IF f.grantees IS NOT NULL THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %s',f.signature::regprocedure,f.grantees);END IF;
 END LOOP;
END $security_agent_object_privileges$;

-- ---------------------------------------------------------------------------
-- W1. A Security Agent run is an authorization object from admission.
--
-- The permission projector reads its objects from zasp_authorization79.resources.
-- Row security hides a run that a Temporal release owns from every session but
-- the Security Agent API and the Temporal executors, so the projector saw such
-- a run only through the worker's own state tables
-- (zasp_authorization80_worker.run_state, test_state, ordered_state), whose
-- rows a worker writes when it first prepares the run. Until then the run had
-- no object in the permission store: its detail and its cancellation were
-- refused (403) and it was absent from the list, for every principal. A run
-- whose worker never prepared it (the planner was unavailable, the workflow
-- failed) stayed invisible for ever while it held its agent's capacity.
--
-- The owner tables are written by the admission itself, in the transaction
-- that inserts the run, and are immutable. The view now also lists every run
-- an owner table names. It adds rows only; the object, its kind and its scope
-- are the run's own.
DO $owned_run_resources$
DECLARE d text;
BEGIN
 SELECT pg_get_viewdef('zasp_authorization79.resources'::regclass) INTO STRICT d;
 IF position('zasp_temporal78.run_owners' in d)=0 THEN
  EXECUTE 'CREATE OR REPLACE VIEW zasp_authorization79.resources AS '||regexp_replace(d,';\s*$','')||$v$
UNION
 SELECT x.organization_id,x.workspace_id,x.environment_id,'security_agent_run'::text AS kind,x.run_id AS id FROM zasp_temporal78.run_owners x
UNION
 SELECT x.organization_id,x.workspace_id,x.environment_id,'security_agent_run'::text AS kind,x.run_id AS id FROM zasp_temporal74.run_owners x
UNION
 SELECT x.organization_id,x.workspace_id,x.environment_id,'security_agent_run'::text AS kind,x.run_id AS id FROM zasp_temporal66.run_owners x WHERE x.execution_owner='temporal'$v$;
 END IF;
END $owned_run_resources$;

-- ---------------------------------------------------------------------------
-- W2. A planner request the provider refused is a definite failure.
--
-- Planning records the send before the request leaves ('started'). Every
-- outcome but a captured response was then reconciled as unknown usage
-- (budget_usage_unknown): the reservation stays open, the run needs a human,
-- and its agent's capacity stays held. That is right when the outcome is
-- unknown. It is wrong when the provider answered that it refused the request
-- before any generation.
--
-- The provider contract (OpenRouter, "Errors and debugging") returns a request
-- error as an HTTP status equal to error.code, and reports an error that
-- occurs during generation with HTTP 200. 401 (invalid credentials), 402
-- (insufficient credits) and 429 (rate limited) are request errors raised
-- before a model is called: nothing was generated and nothing is charged.
-- 403 covers moderation and guardrail blocks, which can follow prompt
-- processing by the upstream provider, and 408/502/503 can follow a dispatch;
-- those stay unknown.
--
-- The worker reports such an answer as the reconciliation payload
-- {"rejected":{"status":N,"raw":"<provider body>"}}. It is accepted only for a
-- started job with no response, for one of the three statuses, when the body
-- is the provider's error envelope with the same code and carries no
-- response identifier, choice or usage. The reservation is then released (no
-- usage), the run ends needs_human with the reason planner_provider_rejected,
-- and the evidence (status, code, digest of the body; never its text) is an
-- audit record the terminal proof requires. Nothing else about reconciliation
-- changes: any other payload, state or status is treated exactly as before.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_provider_rejection(payload jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,public AS $security_agent_provider_rejection$
DECLARE q jsonb;body_value jsonb;raw_value text;
BEGIN
 IF jsonb_typeof(payload) IS DISTINCT FROM 'object' OR NOT(payload ? 'rejected') OR payload-'rejected'<>'{}'::jsonb THEN RETURN NULL;END IF;
 q:=payload->'rejected';
 IF jsonb_typeof(q) IS DISTINCT FROM 'object' OR q-ARRAY['status','raw']<>'{}'::jsonb OR jsonb_typeof(q->'status') IS DISTINCT FROM 'number' OR jsonb_typeof(q->'raw') IS DISTINCT FROM 'string'
  OR q->>'status' NOT IN('401','402','429') THEN RETURN NULL;END IF;
 raw_value:=q->>'raw';
 IF octet_length(raw_value) NOT BETWEEN 2 AND 16384 OR NOT zasp_authorization80.unique_json(raw_value::json) THEN RETURN NULL;END IF;
 body_value:=raw_value::jsonb;
 IF jsonb_typeof(body_value) IS DISTINCT FROM 'object' OR jsonb_typeof(body_value->'error') IS DISTINCT FROM 'object' OR jsonb_typeof(body_value->'error'->'code') IS DISTINCT FROM 'number'
  OR body_value->'error'->>'code' IS DISTINCT FROM q->>'status' OR body_value ?| ARRAY['id','choices','usage'] THEN RETURN NULL;END IF;
 RETURN jsonb_build_object('status',(q->>'status')::integer,'code',(body_value->'error'->>'code')::integer,'body_digest','sha256:'||encode(public.digest(convert_to(raw_value,'UTF8'),'sha256'),'hex'));
EXCEPTION WHEN OTHERS THEN RETURN NULL;
END $security_agent_provider_rejection$;

CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_record_provider_rejection(o text,w text,e text,r text,reservation_value text,request_value text,payload jsonb) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $security_agent_record_provider_rejection$
DECLARE evidence jsonb:=zasp_authorization80.security_agent_provider_rejection(payload);body_value jsonb;audit_value text;
BEGIN
 IF evidence IS NULL OR reservation_value IS NULL OR request_value IS NULL THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor provider rejection evidence rejected';END IF;
 body_value:=evidence||jsonb_build_object('run_id',r,'reservation_id',reservation_value,'request_digest',request_value);
 audit_value:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_temporal_planning_provider_rejected',r);
 INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,actor_id,event_kind,event_digest,body)
  VALUES(o,w,e,audit_value,audit_value,r,session_user,'temporal_planning_provider_rejected',public.digest(convert_to(body_value::text,'UTF8'),'sha256'),body_value);
END $security_agent_record_provider_rejection$;

CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_provider_rejection_valid(o text,w text,e text,r text,reservation_value text,request_value text) RETURNS boolean
LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $security_agent_provider_rejection_valid$
 SELECT COALESCE((SELECT a.audit_id=public.zasp_discovery_canonical_id(o,w,e,'security_agent_temporal_planning_provider_rejected',r) AND a.correlation_id=a.audit_id
   AND a.event_digest=public.digest(convert_to(a.body::text,'UTF8'),'sha256')
   AND a.body-ARRAY['status','code','body_digest']=jsonb_build_object('run_id',r,'reservation_id',reservation_value,'request_digest',request_value)
   AND a.body->>'status' IN('401','402','429') AND a.body->'code'=a.body->'status' AND a.body->>'body_digest'~'^sha256:[a-f0-9]{64}$'
  FROM public.zasp_security_agent_audit a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.event_kind)=(o,w,e,r,'temporal_planning_provider_rejected')),false)
$security_agent_provider_rejection_valid$;

DO $security_agent_provider_rejection_privileges$
DECLARE f text;
BEGIN
 FOREACH f IN ARRAY ARRAY['zasp_authorization80.security_agent_provider_rejection(jsonb)','zasp_authorization80.security_agent_record_provider_rejection(text,text,text,text,text,text,jsonb)','zasp_authorization80.security_agent_provider_rejection_valid(text,text,text,text,text,text)'] LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',f::regprocedure);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f::regprocedure);
 END LOOP;
END $security_agent_provider_rejection_privileges$;

-- The single-test and the finding-response releases reconcile with the same
-- statements. Each is changed in three places, found by their exact text; a
-- predecessor that no longer contains them stops the installation.
DO $planner_provider_rejection$
DECLARE s text;d text;needle text;added text;
 payload_needle CONSTANT text:=$n$OR NOT(zasp_sa_multistep_prior.closed(q->'payload',ARRAY[]::text[]) OR $n$;
 branch_needle CONSTANT text:=$n$ IF q->'payload'<>'{}'::jsonb THEN
  IF j.state='started' THEN$n$;
 branch_added CONSTANT text:=$n$ IF zasp_authorization80.security_agent_provider_rejection(q->'payload') IS NOT NULL THEN
  IF j.state<>'started' OR j.raw_result IS NOT NULL OR p.run_id IS NULL OR p.settled_at IS NOT NULL OR p.released_at IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor provider rejection evidence rejected';END IF;
  UPDATE SCHEMA.provider_reservations SET released_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=(o,w,e,r,1);
  PERFORM zasp_authorization80.security_agent_record_provider_rejection(o,w,e,r,j.reservation_id,j.request_digest,q->'payload');
  PERFORM SCHEMA.planning_terminal(o,w,e,r,'planner_provider_rejected');
  IF NOT SCHEMA.planning_terminal_valid(o,w,e,r) OR NOT SCHEMA.current_ready() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor provider rejection terminal rejected';END IF;
  SELECT * INTO j FROM SCHEMA.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
  RETURN to_jsonb(j);
 END IF;
$n$;
 valid_needle CONSTANT text:=$n$AND CASE WHEN a.body->>'reason'='planner_not_sent' THEN $n$;
 valid_added CONSTANT text:=$n$AND CASE WHEN a.body->>'reason'='planner_provider_rejected' THEN a.body->>'dispatch_state'='started' AND j.lookup_request IS NOT NULL AND j.raw_result IS NULL AND j.result_value IS NULL AND j.provider_digest IS NULL AND j.output_body IS NULL AND j.output_digest IS NULL
   AND p.released_at IS NOT NULL AND p.settled_at IS NULL AND p.output_digest IS NULL AND p.total_tokens IS NULL AND p.cost_nano_credits IS NULL AND zasp_authorization80.security_agent_provider_rejection_valid(o,w,e,r,j.reservation_id,j.request_digest)
  WHEN a.body->>'reason'='planner_not_sent' THEN $n$;
BEGIN
 FOREACH s IN ARRAY ARRAY['zasp_temporal74','zasp_temporal78'] LOOP
  SELECT pg_get_functiondef((s||'.recover_plan(jsonb)')::regprocedure) INTO STRICT d;
  IF position('security_agent_provider_rejection' in d)=0 THEN
   IF (length(d)-length(replace(d,payload_needle,'')))/length(payload_needle)<>1 OR (length(d)-length(replace(d,branch_needle,'')))/length(branch_needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='planning recovery predecessor changed';END IF;
   d:=replace(d,payload_needle,payload_needle||$n$zasp_authorization80.security_agent_provider_rejection(q->'payload') IS NOT NULL OR $n$);
   d:=replace(d,branch_needle,replace(branch_added,'SCHEMA',s)||branch_needle);
   EXECUTE d;
  END IF;
  SELECT pg_get_functiondef((s||'.planning_terminal_valid(text,text,text,text)')::regprocedure) INTO STRICT d;
  IF position('planner_provider_rejected' in d)=0 THEN
   IF (length(d)-length(replace(d,valid_needle,'')))/length(valid_needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='planning terminal predecessor changed';END IF;
   EXECUTE replace(d,valid_needle,valid_added);
  END IF;
 END LOOP;
END $planner_provider_rejection$;

-- ---------------------------------------------------------------------------
-- W3. A human closes a run that needs a human.
--
-- A run that ends needs_human is terminal for the product but could keep its
-- agent's capacity for ever: zasp_temporal73.unresolved counts a provider
-- reservation whose outcome is unknown, and nothing but a late provider
-- report settles one. There was no product action for the human the state
-- asks for; cancellation refuses a terminal run.
--
-- POST /security-agent-runs/{id}/close (closeSecurityAgentRun, permission
-- manage_workflows on the run) records that a human reviewed the run and
-- closed it. The closure is an immutable row and an audit record that name
-- the actor, the reason and every provider reservation that was still
-- unknown at that moment, with its reserved maximum. Nothing is rewritten:
-- the run keeps its state and its reason, the reservation stays unsettled
-- and unreleased (its usage is still unknown, never zero), and the budget
-- stop stays. What changes is the answer to "does this run still hold
-- capacity": for a closed run only effects, cleanups and controls count;
-- an unknown provider reservation no longer does. A run with any such
-- unfinished effect cannot be closed. A run with an unknown reservation can
-- be closed only with the reason that says so (usage_unknown_accepted).
--
-- The finding-response workflow of such a run observes 'pending' while the
-- run is unresolved and 'terminal' as soon as it is not, so it ends on its
-- next observation after the closure.
CREATE TABLE IF NOT EXISTS zasp_authorization80.security_agent_run_closures(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 actor_id text NOT NULL CHECK(public.zasp_valid_product_id(actor_id)),
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 16 AND 128 AND idempotency_key~'^[A-Za-z0-9][A-Za-z0-9._:-]*$'),
 expected_version bigint NOT NULL CHECK(expected_version BETWEEN 1 AND 1000000),
 reason text NOT NULL CHECK(reason IN('no_action_required','resolved_outside_product','usage_unknown_accepted')),
 note text CHECK(note IS NULL OR length(note) BETWEEN 1 AND 500),
 prior_reason text,
 outstanding jsonb NOT NULL CHECK(jsonb_typeof(outstanding)='array'),
 audit_id text NOT NULL CHECK(public.zasp_valid_product_id(audit_id)),
 correlation_id text NOT NULL CHECK(public.zasp_valid_product_id(correlation_id)),
 receipt_id text NOT NULL CHECK(public.zasp_valid_product_id(receipt_id)),
 response jsonb NOT NULL CHECK(jsonb_typeof(response)='object'),
 closed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
 UNIQUE(organization_id,workspace_id,environment_id,actor_id,idempotency_key),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES public.zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id),
 CHECK((reason='usage_unknown_accepted')=(jsonb_array_length(outstanding)>0))
);
ALTER TABLE zasp_authorization80.security_agent_run_closures OWNER TO zasp_discovery_authority;
REVOKE ALL ON TABLE zasp_authorization80.security_agent_run_closures FROM PUBLIC;
ALTER TABLE zasp_authorization80.security_agent_run_closures ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_authorization80.security_agent_run_closures FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS authority ON zasp_authorization80.security_agent_run_closures;
CREATE POLICY authority ON zasp_authorization80.security_agent_run_closures USING(CURRENT_USER='zasp_discovery_authority'::name) WITH CHECK(CURRENT_USER='zasp_discovery_authority'::name);
DROP TRIGGER IF EXISTS immutable ON zasp_authorization80.security_agent_run_closures;
CREATE TRIGGER immutable BEFORE DELETE OR UPDATE OR TRUNCATE ON zasp_authorization80.security_agent_run_closures FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();

CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_run_closed(o text,w text,e text,r text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_run_closed$
 SELECT EXISTS(SELECT 1 FROM zasp_authorization80.security_agent_run_closures x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r))
$security_agent_run_closed$;

-- What a closure never discharges: the conditions of
-- zasp_temporal78.predecessor73_unresolved other than a provider reservation.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_run_open_effects(o text,w text,e text,r text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_run_open_effects$
 SELECT EXISTS(SELECT 1 FROM zasp_temporal68.effects x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND (x.state IN('started','unknown','cleanup_pending') OR x.action_key='create_temporary_policy' AND x.state='verified'))
 OR EXISTS(SELECT 1 FROM zasp_temporal68.cleanups x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND x.state<>'cleaned')
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_effects x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND x.state IN('leased','unknown_outcome','cleanup_pending','cleanup_failed'))
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_controls x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND x.state<>'disabled')
 OR EXISTS(SELECT 1 FROM public.zasp_sa_attack_lab_links x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND x.settled_at IS NULL)
 OR EXISTS(SELECT 1 FROM public.zasp_sa_export_links x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND x.settled_at IS NULL)
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_test_links x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND (x.reconcile_state<>'settled' OR EXISTS(SELECT 1 FROM public.zasp_security_agent_test_invocations j WHERE (j.organization_id,j.workspace_id,j.environment_id,j.test_run_id,j.state)=(o,w,e,x.test_run_id,'started'))))
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_webhook_deliveries x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND (x.settlement_state<>'settled' OR x.state IN('dispatching','uncertain')))
$security_agent_run_open_effects$;

-- The provider reservations of a run whose outcome is unknown.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_run_unknown_reservations(o text,w text,e text,r text) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_run_unknown_reservations$
 SELECT COALESCE(jsonb_agg(jsonb_build_object('release',x.release,'reservation_id',x.reservation_id,'model',x.model,'cost_unit',x.cost_unit,'maximum_tokens',x.maximum_tokens,'maximum_cost_nano_credits',x.maximum_cost_nano_credits,
  'reserved_at',to_char(x.reserved_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) ORDER BY x.release,x.reservation_id),'[]'::jsonb)
 FROM(
  SELECT 'temporal78' release,reservation_id,model,cost_unit,maximum_tokens,maximum_cost_nano_credits,reserved_at FROM zasp_temporal78.provider_reservations WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND settled_at IS NULL AND released_at IS NULL
  UNION ALL SELECT 'temporal74',reservation_id,model,cost_unit,maximum_tokens,maximum_cost_nano_credits,reserved_at FROM zasp_temporal74.provider_reservations WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND settled_at IS NULL AND released_at IS NULL
  UNION ALL SELECT 'temporal68',reservation_id,model,cost_unit,maximum_tokens,maximum_cost_nano_credits,reserved_at FROM zasp_temporal68.provider_reservations WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND settled_at IS NULL AND released_at IS NULL
  UNION ALL SELECT 'retained',reservation_id,model,cost_unit,maximum_tokens,maximum_cost_nano_credits,reserved_at FROM public.zasp_security_agent_provider_reservations WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND settled_at IS NULL
 ) x
$security_agent_run_unknown_reservations$;

-- zasp_temporal73.unresolved keeps its answer for every run that is not
-- closed. For a closed run it answers only for unfinished effects.
CREATE OR REPLACE FUNCTION zasp_temporal73.unresolved(o text,w text,e text,r text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $unresolved$
 SELECT CASE WHEN zasp_authorization80.security_agent_run_closed(o,w,e,r) THEN zasp_authorization80.security_agent_run_open_effects(o,w,e,r)
 ELSE zasp_temporal78.predecessor73_unresolved(o,w,e,r) OR EXISTS(SELECT 1 FROM zasp_temporal78.provider_reservations x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND x.settled_at IS NULL AND x.released_at IS NULL) END
$unresolved$;

-- The shared admission of section Y3 with the operations this section and
-- section W4 add. Its checks are unchanged. An audit record is authorized
-- through the run it belongs to.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_object_request(o text,w text,e text,actor text,op text,i text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_object_request$
DECLARE p jsonb:=zasp_authorization80.context();permission_value text;browser boolean:=false;fresh boolean:=false;kind text;
BEGIN
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization security agent principal rejected';END IF;
 CASE op
  WHEN 'getSecurityAgentRun' THEN permission_value:='view';kind:='security_agent_run';
  WHEN 'cancelSecurityAgentRun','closeSecurityAgentRun' THEN permission_value:='manage_workflows';kind:='security_agent_run';
  WHEN 'getSecurityAgentApproval' THEN permission_value:='view';kind:='security_agent_approval';
  WHEN 'decideSecurityAgentApproval' THEN permission_value:='manage_workflows';kind:='security_agent_approval';browser:=true;fresh:=true;
  WHEN 'simulateSecurityAgent' THEN permission_value:='manage_workflows';kind:='security_agent';
  WHEN 'listSecurityAgentRunActivity','getSecurityAgentExport','createSecurityAgentExportDownloadGrant','downloadSecurityAgentExport' THEN permission_value:='view';kind:='security_agent_run';browser:=true;
  WHEN 'getSecurityAgentAuditEvent' THEN permission_value:='view_audit';kind:='security_agent_audit';browser:=true;
  ELSE RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current security agent authorization required';
 END CASE;
 IF p IS NULL OR actor IS NULL OR i IS NULL OR NOT COALESCE(public.zasp_valid_product_id(i),false)
  OR NOT COALESCE(zasp_authorization80.read_request(o,w,e,ARRAY[op],permission_value,browser,actor)
   AND p->'collection'='false'::jsonb
   AND(NOT fresh OR p->'fresh_auth'='true'::jsonb)
   AND p#>>'{path_parameters,id}'=i
   AND CASE kind WHEN 'security_agent_audit' THEN zasp_authorization80.parent_allowed(o,w,e,kind,i,NULL) ELSE zasp_authorization80.allowed(o,w,e,kind,i) END,false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current security agent authorization required';END IF;
 PERFORM zasp_authorization80.identity_fence(p);
 RETURN p;
END $security_agent_object_request$;

CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_close_run(o text,w text,e text,r text,actor text,k text,v bigint,reason_value text,note_value text,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_close_run$
DECLARE p jsonb;rr public.zasp_security_agent_runs%ROWTYPE;c zasp_authorization80.security_agent_run_closures%ROWTYPE;outstanding_value jsonb;closure_value jsonb;response_value jsonb;body_value jsonb;now_value timestamptz;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='authorization security agent write requires read committed';END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(r) AND public.zasp_valid_product_id(audit_value) AND public.zasp_valid_product_id(correlation_value) AND public.zasp_valid_product_id(receipt_value)
  AND audit_value<>receipt_value AND length(k) BETWEEN 16 AND 128 AND k~'^[A-Za-z0-9][A-Za-z0-9._:-]*$' AND v BETWEEN 1 AND 1000000
  AND reason_value IN('no_action_required','resolved_outside_product','usage_unknown_accepted')
  AND(note_value IS NULL OR length(note_value) BETWEEN 1 AND 500 AND btrim(note_value)=note_value AND note_value!~'[[:cntrl:]]'),false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent closure rejected';END IF;
 p:=zasp_authorization80.security_agent_object_request(o,w,e,actor,'closeSecurityAgentRun',r);
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND OR rr.state='simulated' THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='security agent run missing';END IF;
 SELECT * INTO c FROM zasp_authorization80.security_agent_run_closures WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF FOUND THEN
  -- The same request again is answered with the first answer.
  IF(c.actor_id,c.idempotency_key,c.expected_version,c.reason) IS DISTINCT FROM(actor,k,v,reason_value) OR c.note IS DISTINCT FROM note_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent run already closed';END IF;
  PERFORM zasp_authorization80.security_agent_write_settled(p);
  RETURN c.response||jsonb_build_object('replayed',true);
 END IF;
 IF EXISTS(SELECT 1 FROM zasp_authorization80.security_agent_run_closures WHERE(organization_id,workspace_id,environment_id,actor_id,idempotency_key)=(o,w,e,actor,k)) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='security agent closure replay conflict';END IF;
 IF rr.state<>'needs_human' OR rr.version<>v OR rr.completed_at IS NULL OR rr.lease_owner IS NOT NULL OR rr.lease_token IS NOT NULL OR rr.lease_expires_at IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent closure conflict';END IF;
 IF zasp_authorization80.security_agent_run_open_effects(o,w,e,r) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent closure refused: unfinished effects';END IF;
 outstanding_value:=zasp_authorization80.security_agent_run_unknown_reservations(o,w,e,r);
 IF(jsonb_array_length(outstanding_value)>0) IS DISTINCT FROM(reason_value='usage_unknown_accepted') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent closure reason rejected';END IF;
 now_value:=clock_timestamp();
 closure_value:=jsonb_strip_nulls(jsonb_build_object('closed_at',to_char(now_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'closed_by',actor,'reason',reason_value,'note',note_value));
 response_value:=jsonb_build_object('id',r,'agent_id',rr.definition_id,'state',rr.state,'definition_version',rr.definition_version,'version',rr.version,'closure',closure_value,
  'audit_id',audit_value,'correlation_id',correlation_value,'receipt_id',receipt_value,'replayed',false);
 INSERT INTO zasp_authorization80.security_agent_run_closures(organization_id,workspace_id,environment_id,run_id,actor_id,idempotency_key,expected_version,reason,note,prior_reason,outstanding,audit_id,correlation_id,receipt_id,response,closed_at)
  VALUES(o,w,e,r,actor,k,v,reason_value,note_value,rr.last_error_code,outstanding_value,audit_value,correlation_value,receipt_value,response_value,now_value);
 body_value:=jsonb_strip_nulls(jsonb_build_object('run_id',r,'state',rr.state,'prior_reason',rr.last_error_code,'version',rr.version,'reason',reason_value,'note',note_value))||jsonb_build_object('unknown_provider_reservations',outstanding_value);
 INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,actor_id,event_kind,event_digest,body)
  VALUES(o,w,e,audit_value,correlation_value,r,actor,'run_closed',public.digest(convert_to(body_value::text,'UTF8'),'sha256'),body_value);
 -- The closure must have released the run: nothing unfinished remains.
 IF zasp_temporal73.unresolved(o,w,e,r) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent closure refused: unfinished effects';END IF;
 PERFORM zasp_authorization80.security_agent_write_settled(p);
 RETURN response_value;
END $security_agent_close_run$;

-- GET /security-agent-runs/{id} (section Y3) with the run's lifecycle: the
-- recorded reason it stopped (a closed code, never provider text) and its
-- closure, when there is one.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_run_lifecycle(o text,w text,e text,r text) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_run_lifecycle$
 SELECT jsonb_strip_nulls(jsonb_build_object(
  'stop_reason',(SELECT CASE WHEN x.last_error_code~'^[a-z][a-z0-9_]{0,63}$' THEN x.last_error_code END FROM public.zasp_security_agent_runs x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r)),
  'closure',(SELECT jsonb_strip_nulls(jsonb_build_object('closed_at',to_char(c.closed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'closed_by',c.actor_id,'reason',c.reason,'note',c.note))
   FROM zasp_authorization80.security_agent_run_closures c WHERE(c.organization_id,c.workspace_id,c.environment_id,c.run_id)=(o,w,e,r))))
$security_agent_run_lifecycle$;

CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_run_detail(o text,w text,e text,r text,actor text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_run_detail$
DECLARE p jsonb;result jsonb;family text;
 c CONSTANT text:='e4dfae0a990718c2c6b7518b07d7c146cfb9025656378d423c8d96188bcf1b96';f CONSTANT text:='07e774a28105095c73275ad959c765a3fddda9ee9aa81e81cd3828222e40aad3';
BEGIN
 p:=zasp_authorization80.security_agent_object_request(o,w,e,actor,'getSecurityAgentRun',r);
 IF zasp_ordered_public62.classify(o,w,e,'run',r)='ordered_release61' THEN
  -- The ordered release serves its resources to a browser session only.
  IF p->>'credential_kind'<>'1' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent ordered credential rejected';END IF;
  result:=zasp_ordered_public62.api(c,f,jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'actor_id',actor,'operation','resource_run','run_id',r));
  family:='ordered';
 ELSE
  result:=zasp_temporal78.run_context(o,w,e,r);family:='finding';
  IF result IS NULL THEN
   SELECT value INTO result FROM zasp_temporal66.run_context(o,w,e,r,'6e2fbdef64421286476be12a02188d7936e81db3126764bf2ab55e099fcb12cb','422b211febdd6e2b37882dc3f5961a79ca5c58f3f87f1642f7babf1224fbe94a') rows(value);
   family:='legacy';
  END IF;
 END IF;
 IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='security agent run missing';END IF;
 IF p IS DISTINCT FROM zasp_authorization80.context() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='current security agent proof expired';END IF;
 RETURN jsonb_build_object('family',family,'result',result,'lifecycle',zasp_authorization80.security_agent_run_lifecycle(o,w,e,r));
END $security_agent_run_detail$;

-- The home summary (section X5) counts a run as needing a human until a human
-- has closed it.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_home_summary(o text,w text,e text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_home_summary$
DECLARE pending_value bigint;oldest_value bigint;needs_human_value bigint;failed_value bigint;inconclusive_value bigint;contained_value bigint;remediated_value bigint;
BEGIN
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['getHomeSummary'],'view');
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization security agent principal rejected';END IF;
 SELECT count(*),COALESCE(floor(extract(epoch FROM transaction_timestamp()-min(a.created_at)))::bigint,0) INTO pending_value,oldest_value
  FROM public.zasp_security_agent_approvals a
  WHERE(a.organization_id,a.workspace_id,a.environment_id,a.state)=(o,w,e,'pending') AND zasp_authorization80.allowed(o,w,e,'security_agent_approval',a.approval_id);
 SELECT count(*) FILTER(WHERE r.state='needs_human' AND NOT zasp_authorization80.security_agent_run_closed(o,w,e,r.run_id)),count(*) FILTER(WHERE r.state='failed'),count(*) FILTER(WHERE r.state='inconclusive'),
  count(*) FILTER(WHERE r.state='contained' AND r.updated_at>=transaction_timestamp()-interval '24 hours'),count(*) FILTER(WHERE r.state='remediated' AND r.updated_at>=transaction_timestamp()-interval '24 hours')
  INTO needs_human_value,failed_value,inconclusive_value,contained_value,remediated_value
  FROM public.zasp_security_agent_runs r
  WHERE(r.organization_id,r.workspace_id,r.environment_id)=(o,w,e) AND zasp_authorization80.allowed(o,w,e,'security_agent_run',r.run_id);
 RETURN jsonb_build_object('pending_approvals',pending_value,'oldest_approval_age_seconds',GREATEST(oldest_value,0),'needs_human_runs',needs_human_value,'failed_runs',failed_value,
  'inconclusive_runs',inconclusive_value,'recent_contained',contained_value,'recent_remediated',remediated_value);
END $security_agent_home_summary$;

DO $security_agent_closure_privileges$
DECLARE f record;
BEGIN
 FOR f IN SELECT * FROM(VALUES
  ('zasp_authorization80.security_agent_run_closed(text,text,text,text)',NULL),
  ('zasp_authorization80.security_agent_run_open_effects(text,text,text,text)',NULL),
  ('zasp_authorization80.security_agent_run_unknown_reservations(text,text,text,text)',NULL),
  ('zasp_authorization80.security_agent_run_lifecycle(text,text,text,text)',NULL),
  ('zasp_authorization80.security_agent_close_run(text,text,text,text,text,text,bigint,text,text,text,text,text)','zasp_security_agent_api')
 ) v(signature,grantees) LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',f.signature::regprocedure);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f.signature::regprocedure);
  IF f.grantees IS NOT NULL THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %s',f.signature::regprocedure,f.grantees);END IF;
 END LOOP;
END $security_agent_closure_privileges$;

-- ---------------------------------------------------------------------------
-- W4. Security Agent activity, audit record and export reads.
--
-- These six operations still sent the chain's readers directly:
--   GET  /security-agent-runs/{id}/activity/{kind}       listSecurityAgentRunActivity
--   GET  /security-agent-activity/{kind}/{id}/runs       listSecurityAgentActivityRuns
--   GET  /security-agent-audit-events/{id}               getSecurityAgentAuditEvent
--   GET  /security-agent-runs/{id}/steps/{stepId}/export                  getSecurityAgentExport
--   POST /security-agent-runs/{id}/steps/{stepId}/export/download-grants  createSecurityAgentExportDownloadGrant
--   POST /security-agent-runs/{id}/steps/{stepId}/export/download         downloadSecurityAgentExport
-- None of those readers is an authorized function, and the activity and audit
-- readers also ask for a readiness that pins a 60-release catalog, so the API
-- refused every one of these requests.
--
-- Each function below is one statement bound to the attested proof: a browser
-- session, the operation, permission 'view' ('view_audit' for the audit
-- record) for this scope and actor, a non-collection request for the object
-- in the request path, with that object among the allowed targets. A session
-- or audit activity kind additionally requires investigate_sessions or
-- view_audit of the actor in this Environment, as before. The run context is
-- read with the readers the run detail uses (section Y3). The related-runs
-- page names runs, which the proof of the activity record says nothing
-- about, so it requires a second decision (listSecurityAgentRuns) and returns
-- only runs that decision allows.
--
-- The export readers are the chain's own (zasp_sa_export_get and
-- zasp_sa_export_grant), reached only when the export capability is ready
-- for the current catalog (section H); otherwise the request is unavailable.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_second_decision(p jsonb,proof text,operation_value text,collection_value boolean) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_second_decision$
DECLARE t jsonb;
BEGIN
 IF p IS NULL OR proof IS NULL OR operation_value IS NULL OR collection_value IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current security agent second authorization required';END IF;
 t:=zasp_authorization80.verify_attestation(proof);
 IF NOT COALESCE(t->>'operation_id'=operation_value AND t->>'permission'='view' AND t->'collection'=to_jsonb(collection_value)
  AND(t->>'organization_id',t->>'workspace_id',t->>'environment_id',t->>'principal_id',t->>'credential_kind',t->>'credential_id',t->>'credential_digest')
   =(p->>'organization_id',p->>'workspace_id',p->>'environment_id',p->>'principal_id',p->>'credential_kind',p->>'credential_id',p->>'credential_digest')
  AND t->'revision'=p->'revision' AND t->>'key_version'=p->>'key_version' AND jsonb_typeof(t->'allowed')='array',false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current security agent second authorization required';END IF;
 RETURN t;
END $security_agent_second_decision$;

CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_attested_allowed(t jsonb,o text,w text,e text,k text,i text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,public AS $security_agent_attested_allowed$
 SELECT EXISTS(SELECT 1 FROM jsonb_array_elements(COALESCE(t->'allowed','[]'::jsonb)) x WHERE(x->>'organization_id',x->>'workspace_id',x->>'environment_id',x->>'kind',COALESCE(NULLIF(x->>'source_id',''),x->>'id'))=(o,w,e,k,i))
$security_agent_attested_allowed$;

CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_activity_permission(o text,w text,e text,actor text,kind_value text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_activity_permission$
DECLARE permission_value text;
BEGIN
 permission_value:=CASE kind_value WHEN 'session' THEN 'investigate_sessions' WHEN 'audit' THEN 'view_audit' WHEN 'finding' THEN 'view' WHEN 'attack_path' THEN 'view' END;
 PERFORM 1 FROM public.zasp_identity_memberships WHERE(organization_id,principal_id,active)=(o,actor,true) FOR SHARE;
 IF NOT FOUND OR permission_value IS NULL OR NOT EXISTS(SELECT 1 FROM public.zasp_identity_admin_effective_scopes(actor,o) scope
  WHERE(scope.organization_id,scope.workspace_id,scope.environment_id)=(o,w,e) AND scope.permissions ? 'view' AND scope.permissions ? permission_value)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current security agent authorization required';END IF;
END $security_agent_activity_permission$;

CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_run_envelope(o text,w text,e text,r text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_run_envelope$
DECLARE result jsonb;
BEGIN
 IF zasp_ordered_public62.classify(o,w,e,'run',r)='ordered_release61' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent activity context unavailable';END IF;
 result:=zasp_temporal78.run_context(o,w,e,r);
 IF result IS NULL THEN
  SELECT value INTO result FROM zasp_temporal66.run_context(o,w,e,r,'6e2fbdef64421286476be12a02188d7936e81db3126764bf2ab55e099fcb12cb','422b211febdd6e2b37882dc3f5961a79ca5c58f3f87f1642f7babf1224fbe94a') rows(value);
 END IF;
 IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent activity context unavailable';END IF;
 RETURN result;
END $security_agent_run_envelope$;

-- GET /security-agent-runs/{id}/activity/{kind}.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_run_activity(o text,w text,e text,r text,actor text,kind_value text,after_id_value text,limit_value integer) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_run_activity$
DECLARE p jsonb;envelope jsonb;ids_value jsonb:='[]'::jsonb;audit_value text;last_id text;count_value integer:=0;more_value boolean:=false;
BEGIN
 IF NOT COALESCE(public.zasp_valid_product_id(r) AND kind_value IN('finding','attack_path','session','audit') AND limit_value BETWEEN 1 AND 100
  AND(after_id_value IS NULL OR public.zasp_valid_product_id(after_id_value)),false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent activity rejected';END IF;
 p:=zasp_authorization80.security_agent_object_request(o,w,e,actor,'listSecurityAgentRunActivity',r);
 IF p#>>'{path_parameters,kind}' IS DISTINCT FROM kind_value THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current security agent authorization required';END IF;
 PERFORM zasp_authorization80.security_agent_activity_permission(o,w,e,actor,kind_value);
 IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_runs run WHERE(run.organization_id,run.workspace_id,run.environment_id,run.run_id)=(o,w,e,r) AND run.state<>'simulated')
 THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='security agent run missing';END IF;
 envelope:=zasp_authorization80.security_agent_run_envelope(o,w,e,r);
 IF kind_value='audit' THEN
  FOR audit_value IN SELECT audit.audit_id FROM public.zasp_security_agent_audit audit
   WHERE(audit.organization_id,audit.workspace_id,audit.environment_id,audit.run_id)=(o,w,e,r) AND(after_id_value IS NULL OR audit.audit_id>after_id_value)
   ORDER BY audit.audit_id LIMIT limit_value+1
  LOOP
   IF NOT COALESCE(public.zasp_valid_product_id(audit_value),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent activity audit target unavailable';END IF;
   count_value:=count_value+1;
   IF count_value>limit_value THEN more_value:=true;EXIT;END IF;
   ids_value:=ids_value||jsonb_build_array(audit_value);last_id:=audit_value;
  END LOOP;
 END IF;
 IF p IS DISTINCT FROM zasp_authorization80.context() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='current security agent proof expired';END IF;
 RETURN jsonb_build_object('context',envelope,'audit_ids',ids_value,'next_audit_id',CASE WHEN more_value THEN last_id ELSE NULL END);
END $security_agent_run_activity$;

-- GET /security-agent-activity/{kind}/{id}/runs. The selection, the order,
-- the cursor and the coverage rule are the chain's reader's.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_activity_runs(org_value text,workspace_value text,environment_value text,principal_value text,kind_value text,entity_value text,before_created_value timestamptz,before_id_value text,limit_value integer,runs_proof text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_activity_runs$
DECLARE p jsonb:=zasp_authorization80.context();t jsonb;audit_run_value text;candidate record;envelope jsonb;items_value jsonb:='[]'::jsonb;last_created timestamptz;last_id text;count_value integer:=0;more_value boolean:=false;partial_value boolean:=false;
BEGIN
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization security agent principal rejected';END IF;
 IF NOT COALESCE(kind_value IN('finding','attack_path','session','audit'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent relation page rejected';END IF;
 IF p IS NULL OR principal_value IS NULL OR NOT COALESCE(public.zasp_valid_product_id(entity_value),false)
  OR NOT COALESCE(zasp_authorization80.read_request(org_value,workspace_value,environment_value,ARRAY['listSecurityAgentActivityRuns'],'view',true,principal_value)
   AND p->'collection'='false'::jsonb AND p#>>'{path_parameters,id}'=entity_value AND p#>>'{path_parameters,kind}'=kind_value
   AND CASE kind_value WHEN 'audit' THEN zasp_authorization80.parent_allowed(org_value,workspace_value,environment_value,'security_agent_audit',entity_value,NULL)
    ELSE zasp_authorization80.allowed(org_value,workspace_value,environment_value,kind_value,entity_value) END,false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current security agent authorization required';END IF;
 PERFORM zasp_authorization80.identity_fence(p);
 PERFORM zasp_authorization80.security_agent_activity_permission(org_value,workspace_value,environment_value,principal_value,kind_value);
 t:=zasp_authorization80.security_agent_second_decision(p,runs_proof,'listSecurityAgentRuns',true);
 IF kind_value='audit' THEN
  SELECT audit.run_id INTO audit_run_value FROM public.zasp_security_agent_audit audit
   WHERE(audit.organization_id,audit.workspace_id,audit.environment_id,audit.audit_id)=(org_value,workspace_value,environment_value,entity_value);
 END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(entity_value) AND limit_value BETWEEN 1 AND 100,false)
  OR (before_created_value IS NULL)<>(before_id_value IS NULL)
  OR (before_id_value IS NOT NULL AND NOT COALESCE(public.zasp_valid_product_id(before_id_value) AND isfinite(before_created_value),false)) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent relation page rejected';
 END IF;
 IF kind_value<>'audit' THEN
  SELECT EXISTS(SELECT 1 FROM public.zasp_security_agent_runs run
   LEFT JOIN public.zasp_security_agent_trigger_receipts receipt USING(organization_id,workspace_id,environment_id,run_id)
   LEFT JOIN public.zasp_security_agent_plans plan USING(organization_id,workspace_id,environment_id,run_id)
   WHERE (run.organization_id,run.workspace_id,run.environment_id)=(org_value,workspace_value,environment_value) AND run.state<>'simulated'
    AND (receipt.run_id IS NULL
     OR (plan.run_id IS NULL AND (run.plan_hash IS NOT NULL OR EXISTS(SELECT 1 FROM public.zasp_security_agent_steps execution
      WHERE (execution.organization_id,execution.workspace_id,execution.environment_id,execution.run_id)=(run.organization_id,run.workspace_id,run.environment_id,run.run_id))))
     OR plan.run_id IS NOT NULL AND (
     plan.plan_hash IS DISTINCT FROM run.plan_hash
     OR plan.plan_hash IS DISTINCT FROM digest(convert_to(plan.plan::text,'UTF8'),'sha256')
     OR (plan.definition_id,plan.definition_version) IS DISTINCT FROM (run.definition_id,run.definition_version)
     OR jsonb_typeof(plan.plan->'steps') IS DISTINCT FROM 'array'
     OR CASE WHEN jsonb_typeof(plan.plan->'steps')='array' THEN jsonb_array_length(plan.plan->'steps') ELSE NULL END
      IS DISTINCT FROM (SELECT count(*) FROM public.zasp_security_agent_steps execution
       WHERE (execution.organization_id,execution.workspace_id,execution.environment_id,execution.run_id)=(run.organization_id,run.workspace_id,run.environment_id,run.run_id))
     OR EXISTS(SELECT 1 FROM public.zasp_security_agent_steps execution
      WHERE (execution.organization_id,execution.workspace_id,execution.environment_id,execution.run_id)=(run.organization_id,run.workspace_id,run.environment_id,run.run_id)
       AND ((plan.plan->'steps'->execution.step_index)->>'step_id' IS DISTINCT FROM execution.step_id
        OR (plan.plan->'steps'->execution.step_index)->'index' IS DISTINCT FROM to_jsonb(execution.step_index)
        OR (plan.plan->'steps'->execution.step_index)->>'action' IS DISTINCT FROM execution.action_key
        OR digest(convert_to((plan.plan->'steps'->execution.step_index)::text,'UTF8'),'sha256') IS DISTINCT FROM execution.input_digest))
     OR EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(plan.plan->'steps')='array' THEN plan.plan->'steps' ELSE '[]'::jsonb END) step(value)
      WHERE jsonb_typeof(step.value) IS DISTINCT FROM 'object'
       OR NOT COALESCE(step.value->>'action' IN('update_finding_response','create_temporary_policy','isolate_session','revoke_integration_connection'),false)
       OR (kind_value='finding' AND step.value->>'action'='update_finding_response'
        AND NOT COALESCE(jsonb_typeof(step.value->'target_id')='string' AND public.zasp_valid_product_id(step.value->>'target_id'),false))
       OR (kind_value='session' AND step.value->>'action'='isolate_session'
        AND NOT COALESCE(jsonb_typeof(step.value->'target_id')='string' AND public.zasp_valid_product_id(step.value->>'target_id')
         AND jsonb_typeof(step.value->'session_id')='string' AND step.value->>'session_id'=step.value->>'target_id',false)))))
    )
  INTO partial_value;
 END IF;
 FOR candidate IN
  WITH ids AS (
   SELECT receipt.run_id FROM public.zasp_security_agent_trigger_receipts receipt
   WHERE (receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.trigger_id)=(org_value,workspace_value,environment_value,entity_value)
    AND receipt.trigger_kind=CASE kind_value WHEN 'finding' THEN 'finding' WHEN 'attack_path' THEN 'attack_path' WHEN 'session' THEN 'runtime_decision' ELSE NULL END
   UNION
   SELECT plan.run_id FROM public.zasp_security_agent_plans plan
   WHERE (plan.organization_id,plan.workspace_id,plan.environment_id)=(org_value,workspace_value,environment_value)
    AND kind_value='finding' AND plan.plan @> jsonb_build_object('steps',jsonb_build_array(jsonb_build_object('action','update_finding_response','target_id',entity_value)))
   UNION
   SELECT plan.run_id FROM public.zasp_security_agent_plans plan
   WHERE (plan.organization_id,plan.workspace_id,plan.environment_id)=(org_value,workspace_value,environment_value)
    AND kind_value='session' AND plan.plan @> jsonb_build_object('steps',jsonb_build_array(jsonb_build_object('action','isolate_session','target_id',entity_value)))
   UNION
   SELECT audit.run_id FROM public.zasp_security_agent_audit audit
   WHERE kind_value='audit' AND (audit.organization_id,audit.workspace_id,audit.environment_id,audit.audit_id)=(org_value,workspace_value,environment_value,entity_value)
  )
  SELECT run.run_id,run.created_at FROM ids JOIN public.zasp_security_agent_runs run USING(run_id)
  WHERE (run.organization_id,run.workspace_id,run.environment_id)=(org_value,workspace_value,environment_value) AND run.state<>'simulated'
   AND zasp_authorization80.security_agent_attested_allowed(t,org_value,workspace_value,environment_value,'security_agent_run',run.run_id)
   AND (before_created_value IS NULL OR (run.created_at,run.run_id)<(before_created_value,before_id_value))
  ORDER BY run.created_at DESC,run.run_id DESC LIMIT limit_value+1
 LOOP
  count_value:=count_value+1;
  IF count_value>limit_value THEN more_value:=true;EXIT;END IF;
  envelope:=zasp_authorization80.security_agent_run_envelope(org_value,workspace_value,environment_value,candidate.run_id);
  items_value:=items_value||jsonb_build_array(envelope);last_created:=candidate.created_at;last_id:=candidate.run_id;
 END LOOP;
 IF p IS DISTINCT FROM zasp_authorization80.context() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='current security agent proof expired';END IF;
 RETURN jsonb_build_object('audit_run_id',audit_run_value,'items',items_value,'coverage',CASE WHEN partial_value THEN 'partial' ELSE 'complete' END,
  'next_created_at',CASE WHEN more_value THEN to_char(last_created AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') ELSE NULL END,
  'next_id',CASE WHEN more_value THEN last_id ELSE NULL END);
END $security_agent_activity_runs$;

-- GET /security-agent-audit-events/{id}. The record is returned without its
-- private body, as before.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_audit_event(o text,w text,e text,a text,actor text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_audit_event$
DECLARE p jsonb;audit_row public.zasp_security_agent_audit%ROWTYPE;
BEGIN
 p:=zasp_authorization80.security_agent_object_request(o,w,e,actor,'getSecurityAgentAuditEvent',a);
 SELECT audit.* INTO audit_row FROM public.zasp_security_agent_audit audit
  JOIN public.zasp_security_agent_runs run ON(run.organization_id,run.workspace_id,run.environment_id,run.run_id)=(audit.organization_id,audit.workspace_id,audit.environment_id,audit.run_id)
  WHERE(audit.organization_id,audit.workspace_id,audit.environment_id,audit.audit_id)=(o,w,e,a) AND run.state<>'simulated';
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='security agent audit record missing';END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(audit_row.run_id) AND public.zasp_valid_product_id(audit_row.correlation_id)
  AND octet_length(audit_row.actor_id) BETWEEN 1 AND 128 AND audit_row.actor_id!~'[[:cntrl:]]'
  AND octet_length(audit_row.event_kind) BETWEEN 1 AND 128 AND audit_row.event_kind!~'[[:cntrl:]]' AND isfinite(audit_row.created_at),false)
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent audit record unavailable';END IF;
 IF p IS DISTINCT FROM zasp_authorization80.context() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='current security agent proof expired';END IF;
 RETURN jsonb_build_object('id',audit_row.audit_id,'run_id',audit_row.run_id,'organization_id',audit_row.organization_id,'workspace_id',audit_row.workspace_id,'environment_id',audit_row.environment_id,
  'actor_reference',audit_row.actor_id,'event_kind',audit_row.event_kind,'correlation_id',audit_row.correlation_id,
  'occurred_at',to_char(audit_row.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
END $security_agent_audit_event$;

-- The export capability for the current catalog, or 'unavailable' (never a
-- refusal that reads as missing permission).
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_export_available(expected_checksum text,expected_fingerprint text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_export_available$
DECLARE ready boolean:=false;
BEGIN
 BEGIN
  ready:=COALESCE(zasp_authorization80.security_agent_export_ready(expected_checksum,expected_fingerprint),false);
 EXCEPTION WHEN OTHERS THEN ready:=false;END;
 IF NOT ready THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent export release unavailable';END IF;
END $security_agent_export_available$;

-- The export status and the export grant. The session the request names must
-- be the session of the proof.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_export_get(o text,w text,e text,r text,s text,actor text,session_value bytea,csrf_value text,expected_checksum text,expected_fingerprint text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_export_get$
DECLARE p jsonb;result jsonb;
BEGIN
 p:=zasp_authorization80.security_agent_object_request(o,w,e,actor,'getSecurityAgentExport',r);
 IF NOT COALESCE(public.zasp_valid_product_id(s) AND p#>>'{path_parameters,stepId}'=s AND p->>'credential_digest'=encode(session_value,'hex'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current security agent authorization required';END IF;
 PERFORM zasp_authorization80.security_agent_export_available(expected_checksum,expected_fingerprint);
 result:=public.zasp_sa_export_get(o,w,e,r,s,actor,session_value,csrf_value,expected_checksum,expected_fingerprint);
 IF p IS DISTINCT FROM zasp_authorization80.context() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='current security agent proof expired';END IF;
 RETURN result;
END $security_agent_export_get$;

CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_export_grant(o text,w text,e text,r text,s text,actor text,session_value bytea,csrf_value text,token_value text,format_value text,operation_value text,expected_checksum text,expected_fingerprint text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_export_grant$
DECLARE p jsonb:=zasp_authorization80.context();op text;result jsonb;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='authorization security agent write requires read committed';END IF;
 op:=CASE WHEN operation_value='issue' THEN 'createSecurityAgentExportDownloadGrant' WHEN operation_value IN('read','consume','integrity_failure') THEN 'downloadSecurityAgentExport' END;
 IF op IS NULL OR p->>'operation_id' IS DISTINCT FROM op THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current security agent authorization required';END IF;
 p:=zasp_authorization80.security_agent_object_request(o,w,e,actor,op,r);
 IF NOT COALESCE(public.zasp_valid_product_id(s) AND p#>>'{path_parameters,stepId}'=s AND p->>'credential_digest'=encode(session_value,'hex'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current security agent authorization required';END IF;
 PERFORM zasp_authorization80.security_agent_export_available(expected_checksum,expected_fingerprint);
 result:=public.zasp_sa_export_grant(o,w,e,r,s,actor,session_value,csrf_value,token_value,format_value,operation_value,expected_checksum,expected_fingerprint);
 PERFORM zasp_authorization80.security_agent_write_settled(p);
 RETURN result;
END $security_agent_export_grant$;

DO $security_agent_activity_privileges$
DECLARE f record;
BEGIN
 FOR f IN SELECT * FROM(VALUES
  ('zasp_authorization80.security_agent_second_decision(jsonb,text,text,boolean)',NULL),
  ('zasp_authorization80.security_agent_attested_allowed(jsonb,text,text,text,text,text)',NULL),
  ('zasp_authorization80.security_agent_activity_permission(text,text,text,text,text)',NULL),
  ('zasp_authorization80.security_agent_run_envelope(text,text,text,text)',NULL),
  ('zasp_authorization80.security_agent_export_available(text,text)',NULL),
  ('zasp_authorization80.security_agent_run_activity(text,text,text,text,text,text,text,integer)','zasp_security_agent_api'),
  ('zasp_authorization80.security_agent_activity_runs(text,text,text,text,text,text,timestamptz,text,integer,text)','zasp_security_agent_api'),
  ('zasp_authorization80.security_agent_audit_event(text,text,text,text,text)','zasp_security_agent_api'),
  ('zasp_authorization80.security_agent_export_get(text,text,text,text,text,text,bytea,text,text,text)','zasp_security_agent_api'),
  ('zasp_authorization80.security_agent_export_grant(text,text,text,text,text,text,bytea,text,text,text,text,text,text)','zasp_security_agent_api')
 ) v(signature,grantees) LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',f.signature::regprocedure);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f.signature::regprocedure);
  IF f.grantees IS NOT NULL THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %s',f.signature::regprocedure,f.grantees);END IF;
 END LOOP;
END $security_agent_activity_privileges$;

-- ---------------------------------------------------------------------------
-- W5. A simulation is stored only for evidence its requester may read.
--
-- zasp_authorization80.security_agent_simulate (section Y3) binds the request
-- to the Security Agent definition. The evidence is named in the request
-- body, so the proof of the definition says nothing about it: a principal
-- allowed to manage the agent could store a plan over, and so confirm the
-- existence of, a finding, attack path or inventory object it may not see.
-- The API now makes a second decision for the evidence: the mixed collection
-- of the Environment (globalSearch, permission 'view'), whose attestation
-- lists every object the requester may read. This function verifies that
-- attestation with the same key as fence(), requires it to be the decision
-- of the same principal, credential, scope and projection revision as the
-- request's own proof, and requires every evidence identifier to be an
-- allowed finding, attack path or inventory object, or an inventory evidence
-- record whose finding or inventory object is allowed. Only then does it
-- store the simulation. The fourteen-argument form stays as the body it
-- calls; the API role can no longer execute it directly.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_simulate(o text,w text,e text,d text,actor text,k text,v bigint,run_value text,goal_value text,evidence_value jsonb,expires_value timestamptz,audit_value text,correlation_value text,receipt_value text,evidence_proof text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_simulate_evidence$
DECLARE p jsonb:=zasp_authorization80.context();t jsonb;item text;kinds CONSTANT text[]:=ARRAY['finding','attack_path','agent','tool','identity','runtime','asset'];
BEGIN
 IF p IS NULL OR evidence_proof IS NULL OR jsonb_typeof(evidence_value) IS DISTINCT FROM 'array' OR jsonb_array_length(evidence_value) NOT BETWEEN 1 AND 100
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(evidence_value) x WHERE jsonb_typeof(x) IS DISTINCT FROM 'string')
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current security agent evidence authorization required';END IF;
 t:=zasp_authorization80.security_agent_second_decision(p,evidence_proof,'globalSearch',true);
 IF(t->>'organization_id',t->>'workspace_id',t->>'environment_id',t->>'principal_id') IS DISTINCT FROM(o,w,e,actor) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current security agent evidence authorization required';END IF;
 FOR item IN SELECT jsonb_array_elements_text(evidence_value) LOOP
  IF NOT COALESCE(public.zasp_valid_product_id(item) AND(
    EXISTS(SELECT 1 FROM unnest(kinds) kind WHERE zasp_authorization80.security_agent_attested_allowed(t,o,w,e,kind,item))
    OR EXISTS(SELECT 1 FROM public.zasp_inventory_evidence x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.id)=(o,w,e,item)
     AND(x.finding_id IS NOT NULL AND zasp_authorization80.security_agent_attested_allowed(t,o,w,e,'finding',x.finding_id)
      OR x.entity_id IS NOT NULL AND EXISTS(SELECT 1 FROM unnest(kinds) kind WHERE kind NOT IN('finding','attack_path') AND zasp_authorization80.security_agent_attested_allowed(t,o,w,e,kind,x.entity_id))))),false)
  THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current security agent evidence authorization required';END IF;
 END LOOP;
 RETURN zasp_authorization80.security_agent_simulate(o,w,e,d,actor,k,v,run_value,goal_value,evidence_value,expires_value,audit_value,correlation_value,receipt_value);
END $security_agent_simulate_evidence$;
ALTER FUNCTION zasp_authorization80.security_agent_simulate(text,text,text,text,text,text,bigint,text,text,jsonb,timestamptz,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.security_agent_simulate(text,text,text,text,text,text,bigint,text,text,jsonb,timestamptz,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.security_agent_simulate(text,text,text,text,text,text,bigint,text,text,jsonb,timestamptz,text,text,text,text) TO zasp_security_agent_api;
REVOKE EXECUTE ON FUNCTION zasp_authorization80.security_agent_simulate(text,text,text,text,text,text,bigint,text,text,jsonb,timestamptz,text,text,text) FROM zasp_security_agent_api;

-- ---------------------------------------------------------------------------
-- W6. A closure and the single-test release's own debts.
--
-- zasp_temporal74.unresolved, which the Organization-wide planning capacity
-- uses (zasp_temporal74.capacity), adds the single-test release's own
-- provider reservation, effects and invocations to zasp_temporal73.unresolved.
-- A closure (section W3) discharges an unknown provider reservation of that
-- release like any other, and never an effect or an invocation that has
-- started: those are part of what a closure refuses.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_run_open_effects(o text,w text,e text,r text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_run_open_effects$
 SELECT EXISTS(SELECT 1 FROM zasp_temporal68.effects x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND (x.state IN('started','unknown','cleanup_pending') OR x.action_key='create_temporary_policy' AND x.state='verified'))
 OR EXISTS(SELECT 1 FROM zasp_temporal68.cleanups x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND x.state<>'cleaned')
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_effects x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND x.state IN('leased','unknown_outcome','cleanup_pending','cleanup_failed'))
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_controls x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND x.state<>'disabled')
 OR EXISTS(SELECT 1 FROM public.zasp_sa_attack_lab_links x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND x.settled_at IS NULL)
 OR EXISTS(SELECT 1 FROM public.zasp_sa_export_links x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND x.settled_at IS NULL)
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_test_links x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND (x.reconcile_state<>'settled' OR EXISTS(SELECT 1 FROM public.zasp_security_agent_test_invocations j WHERE (j.organization_id,j.workspace_id,j.environment_id,j.test_run_id,j.state)=(o,w,e,x.test_run_id,'started'))))
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_webhook_deliveries x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND (x.settlement_state<>'settled' OR x.state IN('dispatching','uncertain')))
 OR EXISTS(SELECT 1 FROM zasp_temporal74.effects x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND x.state IN('started','unknown'))
 OR EXISTS(SELECT 1 FROM zasp_temporal74.invocations x JOIN zasp_temporal74.run_owners a USING(organization_id,workspace_id,environment_id,test_run_id) WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,x.state)=(o,w,e,r,'started'))
$security_agent_run_open_effects$;

CREATE OR REPLACE FUNCTION zasp_temporal74.unresolved(o text,w text,e text,r text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $unresolved$
 SELECT CASE WHEN zasp_authorization80.security_agent_run_closed(o,w,e,r) THEN zasp_authorization80.security_agent_run_open_effects(o,w,e,r)
 ELSE zasp_temporal73.unresolved(o,w,e,r)
 OR EXISTS(SELECT 1 FROM zasp_temporal74.provider_reservations x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND x.settled_at IS NULL AND x.released_at IS NULL)
 OR EXISTS(SELECT 1 FROM zasp_temporal74.effects x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND x.state IN('started','unknown'))
 OR EXISTS(SELECT 1 FROM zasp_temporal74.invocations x JOIN zasp_temporal74.run_owners a USING(organization_id,workspace_id,environment_id,test_run_id) WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,x.state)=(o,w,e,r,'started')) END
$unresolved$;

-- ---------------------------------------------------------------------------
-- Z0. Shared admission of the product routes moved in sections Z2 to Z7.
--
-- A browser pass over the signed-in product found routes whose statements
-- were still the chain's direct functions. Sections X1 to X3 closed those
-- direct paths, and the API's statement allowlist never named them, so each
-- route answered 'provider unavailable'. Every function in the Z sections is
-- one statement of one route under the current model, in the manner of
-- sections H, M and Y3:
--   * SECURITY DEFINER, owned by zasp_discovery_authority, fixed search_path,
--     executable only by zasp_discovery_api;
--   * the session must be the bound API principal;
--   * it works only inside a fenced transaction whose attested proof names
--     exactly this operation with the permission the operation's policy
--     names, for this Organization, Workspace and Environment (and actor,
--     where the statement has one), as a non-collection request, with a
--     browser session and fresh authentication where the policy requires
--     them, for the object in the request path, and only when that object
--     (for creations, the Environment) is among the allowed targets;
--   * a write re-verifies the credential and the membership under row locks
--     before it writes and requires the same unexpired proof when it returns.
-- product_request is that admission; product_settled is the closing check.
--
-- Existing function bodies the Z sections change, each keeping its rules:
-- parent_targets and parent_targets_inner (Z1: the parent of a receipt),
-- receipt_page and compliance_read (Z8: resolver readiness once per
-- statement). Everything else is a new function.
CREATE OR REPLACE FUNCTION zasp_authorization80.product_request(o text,w text,e text,actor text,op text,permission_value text,kind text,target text,path_bound boolean,browser boolean,fresh boolean,write_value boolean) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $product_request$
DECLARE p jsonb:=zasp_authorization80.context();
BEGIN
 IF p IS NULL OR op IS NULL OR permission_value IS NULL OR kind IS NULL OR target IS NULL OR path_bound IS NULL OR browser IS NULL OR fresh IS NULL OR write_value IS NULL
  OR(write_value AND actor IS NULL)
  OR NOT COALESCE(public.zasp_discovery_principal_ready('zasp_discovery_api')
   AND zasp_authorization80.read_request(o,w,e,ARRAY[op],permission_value,browser,actor)
   AND p->'collection'='false'::jsonb
   AND(NOT fresh OR p->'fresh_auth'='true'::jsonb)
   AND(NOT path_bound OR p#>>'{path_parameters,id}'=target)
   AND zasp_authorization80.allowed(o,w,e,kind,target),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current product authorization required';END IF;
 IF write_value THEN PERFORM zasp_authorization80.identity_fence(p);END IF;
 RETURN p;
END $product_request$;

CREATE OR REPLACE FUNCTION zasp_authorization80.product_settled(p jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $product_settled$
BEGIN
 IF p IS NULL OR p IS DISTINCT FROM zasp_authorization80.context() OR NOT COALESCE(public.zasp_discovery_principal_ready('zasp_discovery_api'),false)
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='current product proof expired';END IF;
 PERFORM zasp_authorization80.identity_fence(p);
END $product_settled$;
ALTER FUNCTION zasp_authorization80.product_request(text,text,text,text,text,text,text,text,boolean,boolean,boolean,boolean) OWNER TO zasp_discovery_authority;
ALTER FUNCTION zasp_authorization80.product_settled(jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.product_request(text,text,text,text,text,text,text,text,boolean,boolean,boolean,boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION zasp_authorization80.product_settled(jsonb) FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Z1. A receipt's parent object, for every operation that writes a receipt.
--
-- GET /workflow-mutation-receipts shows a principal its own unacknowledged
-- receipts, each only while its parent object passes the request's check
-- (receipt_page -> parent_allowed -> parent_targets). parent_targets took the
-- receipt's resource_kind as the authorization kind. That holds for six of
-- the nine receipt kinds. The discovery writer
-- (zasp_execution_record_public_mutation) records 'integration_sync' for
-- syncIntegration and 'integration_schedule' for putIntegrationSchedule and
-- deleteIntegrationSchedule; neither is an authorization kind, so resolution
-- raised 'authorization resource identity unavailable' and one such receipt
-- failed every receipt page of its principal until it expired (seven days).
--
-- The receipt kinds and their parents:
--   policy                  createPolicy updatePolicy rolloutPolicy
--                           disablePolicy deletePolicy          -> policy
--   integration             createIntegration updateIntegration
--                           deleteIntegration completeIntegrationOAuth
--                           remediateIntegrationAuthorization
--                           completeIntegrationReferenceAuthorization
--                                                               -> integration
--   integration_sync        syncIntegration (resource_id is the sync)
--                                                               -> discovery_sync
--   integration_schedule    putIntegrationSchedule deleteIntegrationSchedule
--                           (resource_id is the integration)    -> integration
--   security_agent          createSecurityAgent updateSecurityAgent
--                           deleteSecurityAgent                 -> security_agent
--   security_agent_run, security_agent_approval, sensor, finding -> themselves
-- A delete leaves no live parent. Its receipt belongs to the principal that
-- deleted the object and says only that the delete happened, so, like the
-- administration audit events of a deleted sensor, it is shown under the
-- Environment's own check. Nothing else falls back to the Environment: a
-- receipt whose live parent the request may not view stays hidden.
DO $receipt_parents$
DECLARE d text;name text;callee text;
 old_line text:=$o$  parent_kind:=row_value->>'resource_kind';parent_id:=row_value->>'resource_id';$o$;
 new_line text:=$n$  parent_kind:=CASE row_value->>'resource_kind' WHEN 'integration_sync' THEN 'discovery_sync' WHEN 'integration_schedule' THEN 'integration' ELSE row_value->>'resource_kind' END;parent_id:=row_value->>'resource_id';
  IF row_value->>'operation' IN('deletePolicy','deleteIntegration','deleteSecurityAgent','deleteSensor') THEN
   IF jsonb_array_length(zasp_authorization80.@callee@(o,w,e,parent_kind,parent_id))=0 THEN parent_kind:='environment';parent_id:=e;END IF;
  END IF;$n$;
BEGIN
 FOR name,callee IN VALUES('parent_targets','resolve'),('parent_targets_inner','resolve_inner') LOOP
  SELECT pg_get_functiondef(('zasp_authorization80.'||name||'(text,text,text,text,text,text)')::regprocedure) INTO STRICT d;
  CONTINUE WHEN position('''integration_sync'' THEN ''discovery_sync''' IN d)>0;
  IF (length(d)-length(replace(d,old_line,'')))/length(old_line)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authorization receipt parent predecessor changed';END IF;
  EXECUTE replace(d,old_line,replace(new_line,'@callee@',callee));
 END LOOP;
END $receipt_parents$;

-- ---------------------------------------------------------------------------
-- Z2. POST /workflow-mutation-receipts/{id}/acknowledge.
--
-- The chain's zasp_workflow_receipt_acknowledge updates the receipt table
-- directly as the caller. The API role holds no such privilege any more
-- (section X2) and the statement was never on the allowlist. A receipt is
-- acknowledged by the browser session of the principal it belongs to, as the
-- object of the request path, while its parent passes the request's check
-- (the rule receipt_page shows it by).
CREATE OR REPLACE FUNCTION zasp_authorization80.receipt_acknowledge(o text,w text,e text,actor text,r text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $receipt_acknowledge$
DECLARE p jsonb:=zasp_authorization80.context();
BEGIN
 IF p IS NULL OR actor IS NULL OR NOT COALESCE(public.zasp_valid_product_id(r),false)
  OR NOT COALESCE(public.zasp_discovery_principal_ready('zasp_discovery_api')
   AND zasp_authorization80.read_request(o,w,e,ARRAY['acknowledgeWorkflowMutationReceipt'],'view',true,actor)
   AND p->'collection'='false'::jsonb
   AND p#>>'{path_parameters,id}'=r
   AND zasp_authorization80.parent_allowed(o,w,e,'workflow_receipt',r),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current product authorization required';END IF;
 PERFORM zasp_authorization80.identity_fence(p);
 UPDATE public.zasp_workflow_receipts receipt SET acknowledged_at=COALESCE(receipt.acknowledged_at,transaction_timestamp())
 WHERE(receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.principal_id,receipt.receipt_id)=(o,w,e,actor,r) AND receipt.expires_at>transaction_timestamp();
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='workflow receipt missing';END IF;
 PERFORM zasp_authorization80.product_settled(p);
 RETURN jsonb_build_object('acknowledged',true);
END $receipt_acknowledge$;
ALTER FUNCTION zasp_authorization80.receipt_acknowledge(text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.receipt_acknowledge(text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.receipt_acknowledge(text,text,text,text,text) TO zasp_discovery_api;

-- ---------------------------------------------------------------------------
-- Z3. Policies: create, read, update, delete, rollout (Monitor, Block) and
-- disable, the decisions of a policy, and the policy a simulation reads.
--
-- The policy list was authorized (workflow_page); every other policy route
-- used the chain's zasp_workflow_replay, zasp_workflow_get and
-- zasp_workflow_mutate. zasp_workflow_mutate additionally pins a 60-release
-- catalog and can never pass on the baseline. The writer below is the one the
-- authorized integration writes already use
-- (zasp_authorization80.integration_receipt_mutate over zasp_workflow_mutate_v3):
-- it keeps the chain's own rules for a policy (created as draft; an update
-- keeps the rollout; draft -> monitor -> enforced; monitor or enforced ->
-- disabled; optimistic version; idempotent replay; audit row; receipt).
--
-- workflow_operation names, per operation, the permission, the checked
-- object and the writer's action. It is the single list of operations these
-- functions accept; integration deletion (section Z5) is on it too.
CREATE OR REPLACE FUNCTION zasp_authorization80.workflow_operation(op text) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,public AS $workflow_operation$
 SELECT CASE op
  WHEN 'createPolicy' THEN '{"permission":"manage_workflows","kind":"policy","target":"environment","action":"create"}'::jsonb
  WHEN 'updatePolicy' THEN '{"permission":"manage_workflows","kind":"policy","target":"policy","action":"update"}'::jsonb
  WHEN 'rolloutPolicy' THEN '{"permission":"manage_workflows","kind":"policy","target":"policy","action":"update"}'::jsonb
  WHEN 'disablePolicy' THEN '{"permission":"manage_workflows","kind":"policy","target":"policy","action":"update"}'::jsonb
  WHEN 'deletePolicy' THEN '{"permission":"manage_workflows","kind":"policy","target":"policy","action":"delete"}'::jsonb
  WHEN 'deleteIntegration' THEN '{"permission":"manage_workflows","kind":"integration","target":"integration","action":"delete"}'::jsonb
  ELSE NULL END
$workflow_operation$;

-- The stored policy: GET /policies/{id}, and the value a rollout, a disable,
-- a simulation and the decision list start from.
CREATE OR REPLACE FUNCTION zasp_authorization80.policy_value(o text,w text,e text,i text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $policy_value$
DECLARE p jsonb:=zasp_authorization80.context();op text;result jsonb;
BEGIN
 op:=p->>'operation_id';
 IF op IS NULL OR op NOT IN('getPolicy','listPolicyDecisions','rolloutPolicy','disablePolicy','simulatePolicy') OR i IS NULL OR i!~'^policy-[a-z0-9][a-z0-9-]{0,120}$'
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current product authorization required';END IF;
 p:=zasp_authorization80.product_request(o,w,e,NULL,op,CASE WHEN op IN('getPolicy','listPolicyDecisions') THEN 'view' ELSE 'manage_workflows' END,'policy',i,true,false,false,false);
 SELECT jsonb_build_object('body',r.body,'version',r.version,'secret_generation',r.secret_generation) INTO result FROM public.zasp_workflow_records r
 WHERE(r.organization_id,r.workspace_id,r.environment_id,r.kind,r.id)=(o,w,e,'policy',i) AND r.deleted_at IS NULL;
 IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='workflow record missing';END IF;
 RETURN result;
END $policy_value$;

-- Idempotent replay of a policy write or an integration deletion (the API
-- asks before it writes). The body is the chain's zasp_workflow_replay.
CREATE OR REPLACE FUNCTION zasp_authorization80.workflow_replay(o text,w text,e text,actor text,operation_value text,k text,intent_value jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $workflow_replay$
DECLARE p jsonb;rule jsonb:=zasp_authorization80.workflow_operation(operation_value);target text;prior_digest bytea;prior_response jsonb;
BEGIN
 IF rule IS NULL OR k IS NULL OR k!~'^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$' OR jsonb_typeof(intent_value) IS DISTINCT FROM 'object' OR octet_length(intent_value::text)>65536
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid workflow replay';END IF;
 target:=CASE rule->>'target' WHEN 'environment' THEN e ELSE intent_value->>'resource_id' END;
 p:=zasp_authorization80.product_request(o,w,e,actor,operation_value,rule->>'permission',rule->>'target',target,rule->>'target'<>'environment',false,false,true);
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),o,w,e,actor,operation_value,k),0));
 SELECT x.request_digest,x.response INTO prior_digest,prior_response FROM public.zasp_workflow_idempotency x
 WHERE(x.organization_id,x.workspace_id,x.environment_id,x.principal_id,x.operation,x.idempotency_key)=(o,w,e,actor,operation_value,k);
 IF NOT FOUND THEN RETURN jsonb_build_object('found',false);END IF;
 IF prior_digest<>public.digest(convert_to(intent_value::text,'UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='idempotency conflict';END IF;
 RETURN jsonb_build_object('found',true,'result',prior_response||jsonb_build_object('replayed',true));
END $workflow_replay$;

-- POST /policies, PATCH and DELETE /policies/{id}, POST
-- /policies/{id}/rollout and /disable. Argument order is the chain's.
CREATE OR REPLACE FUNCTION zasp_authorization80.policy_mutate(action_value text,kind_value text,id_value text,o text,w text,e text,actor text,operation_value text,k text,expected_version bigint,intent_value jsonb,body_value jsonb,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $policy_mutate$
DECLARE p jsonb;rule jsonb:=zasp_authorization80.workflow_operation(operation_value);result jsonb;
BEGIN
 IF rule IS NULL OR rule->>'kind'<>'policy' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current product authorization required';END IF;
 PERFORM zasp_authorization80.integration_current_ready();
 p:=zasp_authorization80.product_request(o,w,e,actor,operation_value,rule->>'permission',rule->>'target',CASE rule->>'target' WHEN 'environment' THEN e ELSE id_value END,rule->>'target'<>'environment',false,false,true);
 IF NOT COALESCE(kind_value='policy' AND action_value=rule->>'action' AND id_value~'^policy-[a-z0-9][a-z0-9-]{0,120}$'
  AND k~'^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$'
  AND public.zasp_valid_product_id(audit_value) AND public.zasp_valid_product_id(correlation_value)
  AND((p->>'credential_kind'='1' AND public.zasp_valid_product_id(receipt_value)) OR(p->>'credential_kind'='2' AND receipt_value=''))
  AND jsonb_typeof(intent_value)='object' AND jsonb_typeof(body_value)='object' AND octet_length(intent_value::text)<=65536 AND octet_length(body_value::text)<=65536
  AND intent_value->'expected_version'=to_jsonb(expected_version)
  AND intent_value->>'resource_id'=CASE action_value WHEN 'create' THEN '' ELSE id_value END
  AND((action_value='create' AND expected_version=0 AND body_value->>'id'=id_value) OR(action_value='update' AND expected_version>0 AND body_value->>'id'=id_value) OR(action_value='delete' AND expected_version>0 AND body_value='{}'::jsonb)),false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='policy mutation request rejected';END IF;
 result:=zasp_authorization80.integration_receipt_mutate(action_value,kind_value,id_value,o,w,e,actor,operation_value,k,expected_version,intent_value,body_value,audit_value,correlation_value,receipt_value);
 PERFORM zasp_authorization80.product_settled(p);
 RETURN result;
END $policy_mutate$;

-- GET /policies/{id}/decisions. The reader is the chain's.
CREATE OR REPLACE FUNCTION zasp_authorization80.policy_decisions(o text,w text,e text,i text,n integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $policy_decisions$
BEGIN
 IF i IS NULL OR i!~'^policy-[a-z0-9][a-z0-9-]{0,120}$' OR n IS NULL OR n NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid policy decision list';END IF;
 PERFORM zasp_authorization80.product_request(o,w,e,NULL,'listPolicyDecisions','view','policy',i,true,false,false,false);
 RETURN public.zasp_policy_list_runtime_decisions(o,w,e,i,n);
END $policy_decisions$;

DO $policy_grants$
DECLARE f text;
BEGIN
 FOREACH f IN ARRAY ARRAY['workflow_operation(text)','policy_value(text,text,text,text)','workflow_replay(text,text,text,text,text,text,jsonb)','policy_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','policy_decisions(text,text,text,text,integer)'] LOOP
  EXECUTE format('ALTER FUNCTION zasp_authorization80.%s OWNER TO zasp_discovery_authority',f);
  EXECUTE format('REVOKE ALL ON FUNCTION zasp_authorization80.%s FROM PUBLIC',f);
  IF f<>'workflow_operation(text)' THEN EXECUTE format('GRANT EXECUTE ON FUNCTION zasp_authorization80.%s TO zasp_discovery_api',f);END IF;
 END LOOP;
END $policy_grants$;

-- ---------------------------------------------------------------------------
-- Z4. Inventory detail: GET /agents/{id}, /tools/{id}, /identities/{id},
-- /runtimes/{id} and /assets/{id}, the capabilities, relationships and
-- sessions of an agent, and PATCH /agents/{id}.
--
-- The inventory lists were authorized (inventory_page); the object routes
-- still used the chain's zasp_inventory_* functions. Each function below is
-- the proof check and then the chain's own reader or writer, unchanged.
CREATE OR REPLACE FUNCTION zasp_authorization80.inventory_detail(o text,w text,e text,i text,k text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $inventory_detail$
DECLARE op text:=CASE k WHEN 'agent' THEN 'getAgent' WHEN 'tool' THEN 'getTool' WHEN 'identity' THEN 'getIdentity' WHEN 'runtime' THEN 'getRuntime' WHEN 'asset' THEN 'getAsset' END;
BEGIN
 IF op IS NULL OR NOT COALESCE(public.zasp_valid_product_id(i),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current product authorization required';END IF;
 PERFORM zasp_authorization80.product_request(o,w,e,NULL,op,'view',k,i,true,false,false,false);
 RETURN public.zasp_inventory_detail(o,w,e,i,k);
END $inventory_detail$;

CREATE OR REPLACE FUNCTION zasp_authorization80.inventory_agent_page(o text,w text,e text,i text,section text,after_value text,n integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $inventory_agent_page$
DECLARE op text:=CASE section WHEN 'capabilities' THEN 'getAgentCapabilities' WHEN 'relationships' THEN 'getAgentRelationships' WHEN 'sessions' THEN 'listAgentSessions' END;
BEGIN
 IF op IS NULL OR NOT COALESCE(public.zasp_valid_product_id(i),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current product authorization required';END IF;
 PERFORM zasp_authorization80.product_request(o,w,e,NULL,op,'view','agent',i,true,false,false,false);
 RETURN CASE section
  WHEN 'capabilities' THEN public.zasp_inventory_agent_capabilities_page(o,w,e,i,after_value,n)
  WHEN 'relationships' THEN public.zasp_inventory_agent_relationships_page(o,w,e,i,after_value,n)
  ELSE public.zasp_inventory_agent_sessions_page(o,w,e,i,after_value,n) END;
END $inventory_agent_page$;

CREATE OR REPLACE FUNCTION zasp_authorization80.inventory_update_agent(o text,w text,e text,actor text,i text,k text,expected_version bigint,owner_value text,team_value text,tags_value jsonb,audit_value text,correlation_value text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $inventory_update_agent$
DECLARE p jsonb;result jsonb;
BEGIN
 IF NOT COALESCE(public.zasp_valid_product_id(i),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current product authorization required';END IF;
 p:=zasp_authorization80.product_request(o,w,e,actor,'updateAgent','manage_workflows','agent',i,true,false,false,true);
 result:=public.zasp_inventory_update_agent(o,w,e,actor,i,k,expected_version,owner_value,team_value,tags_value,audit_value,correlation_value);
 PERFORM zasp_authorization80.product_settled(p);
 RETURN result;
END $inventory_update_agent$;

DO $inventory_grants$
DECLARE f text;
BEGIN
 FOREACH f IN ARRAY ARRAY['inventory_detail(text,text,text,text,text)','inventory_agent_page(text,text,text,text,text,text,integer)','inventory_update_agent(text,text,text,text,text,text,bigint,text,text,jsonb,text,text)'] LOOP
  EXECUTE format('ALTER FUNCTION zasp_authorization80.%s OWNER TO zasp_discovery_authority',f);
  EXECUTE format('REVOKE ALL ON FUNCTION zasp_authorization80.%s FROM PUBLIC',f);
  EXECUTE format('GRANT EXECUTE ON FUNCTION zasp_authorization80.%s TO zasp_discovery_api',f);
 END LOOP;
END $inventory_grants$;

-- ---------------------------------------------------------------------------
-- Z5. DELETE /integrations/{id}, GET /integrations/{id}/delivery-status and
-- POST /integrations/{id}/test-delivery.
--
-- Integration create and update were authorized (integration_mutate); the
-- deletion still used zasp_workflow_replay and zasp_connector_workflow_mutate.
-- The writer is the authorized family's own
-- (zasp_authorization80.integration_connector_mutate): an integration with a
-- verified connection or an active credential moves to 'revoking' and its
-- revocation is requested; any other is deleted. The replay is section Z3's.
--
-- The API and the receipt page accept two results of a deletion: the
-- integration in 'revoking', or exactly {"id","status":"deleted"} (what the
-- chain records when a revocation completes). The chain's writer returns the
-- integration's last body for an immediate deletion, which is neither, so
-- the request answered 503 after it had committed and the receipt made every
-- later receipt page of its principal fail. An immediate deletion therefore
-- records and returns the deleted form: in the response, in the stored
-- idempotent response and in the receipt.
CREATE OR REPLACE FUNCTION zasp_authorization80.integration_delete(action_value text,kind_value text,id_value text,o text,w text,e text,actor text,operation_value text,k text,expected_version bigint,intent_value jsonb,body_value jsonb,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $integration_delete$
DECLARE p jsonb;result jsonb;deleted_body jsonb:=jsonb_build_object('id',id_value,'status','deleted');
BEGIN
 PERFORM zasp_authorization80.integration_current_ready();
 IF operation_value IS DISTINCT FROM 'deleteIntegration' OR NOT COALESCE(public.zasp_valid_product_id(id_value),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current product authorization required';END IF;
 p:=zasp_authorization80.product_request(o,w,e,actor,'deleteIntegration','manage_workflows','integration',id_value,true,false,false,true);
 IF NOT COALESCE(kind_value='integration' AND action_value='delete' AND expected_version>0
  AND k~'^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$'
  AND public.zasp_valid_product_id(audit_value) AND public.zasp_valid_product_id(correlation_value)
  AND((p->>'credential_kind'='1' AND public.zasp_valid_product_id(receipt_value)) OR(p->>'credential_kind'='2' AND receipt_value=''))
  AND jsonb_typeof(intent_value)='object' AND octet_length(intent_value::text)<=65536
  AND intent_value->'expected_version'=to_jsonb(expected_version) AND intent_value->>'resource_id'=id_value
  AND body_value='{}'::jsonb,false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='integration mutation request rejected';END IF;
 result:=zasp_authorization80.integration_connector_mutate('delete','integration',id_value,o,w,e,actor,'deleteIntegration',k,expected_version,intent_value,body_value,audit_value,correlation_value,receipt_value);
 IF result#>>'{body,status}' IS DISTINCT FROM 'revoking' AND result->'body' IS DISTINCT FROM deleted_body THEN
  IF NOT EXISTS(SELECT 1 FROM public.zasp_integrations x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.id)=(o,w,e,id_value) AND x.state='deleted')
  THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='integration mutation accounting changed';END IF;
  result:=jsonb_set(result,'{body}',deleted_body);
  UPDATE public.zasp_workflow_idempotency x SET response=jsonb_set(x.response,'{body}',deleted_body)
  WHERE(x.organization_id,x.workspace_id,x.environment_id,x.principal_id,x.operation,x.idempotency_key)=(o,w,e,actor,'deleteIntegration',k);
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='integration mutation accounting changed';END IF;
  UPDATE public.zasp_workflow_receipts r SET result=deleted_body
  WHERE(r.organization_id,r.workspace_id,r.environment_id,r.principal_id,r.operation,r.idempotency_key)=(o,w,e,actor,'deleteIntegration',k);
 END IF;
 PERFORM zasp_authorization80.product_settled(p);
 RETURN result;
END $integration_delete$;

CREATE OR REPLACE FUNCTION zasp_authorization80.integration_webhook_status(o text,w text,e text,i text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $integration_webhook_status$
BEGIN
 IF NOT COALESCE(public.zasp_valid_product_id(i),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current product authorization required';END IF;
 PERFORM zasp_authorization80.product_request(o,w,e,NULL,'getIntegrationWebhookStatus','view','integration',i,true,false,false,false);
 RETURN public.zasp_integration_webhook_test_status(o,w,e,i);
END $integration_webhook_status$;

-- POST /integrations/{id}/test-delivery: the reservation and the completion
-- of one test delivery. Both are the chain's functions behind the proof
-- check; the completion must name a delivery of the integration in the path
-- that the same principal reserved.
CREATE OR REPLACE FUNCTION zasp_authorization80.integration_webhook_test_reserve(o text,w text,e text,actor text,i text,expected_version bigint,k text,audit_value text,correlation_value text,delivery_value text,token_value text,lease_seconds integer) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $integration_webhook_test_reserve$
DECLARE p jsonb;result jsonb;
BEGIN
 IF NOT COALESCE(public.zasp_valid_product_id(i),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current product authorization required';END IF;
 p:=zasp_authorization80.product_request(o,w,e,actor,'testIntegrationWebhook','manage_workflows','integration',i,true,false,false,true);
 result:=public.zasp_integration_webhook_test_reserve(o,w,e,actor,i,expected_version,k,audit_value,correlation_value,delivery_value,token_value,lease_seconds);
 PERFORM zasp_authorization80.product_settled(p);
 RETURN result;
END $integration_webhook_test_reserve$;

CREATE OR REPLACE FUNCTION zasp_authorization80.integration_webhook_test_complete(o text,w text,e text,delivery_value text,token_value text,digest_value text,succeeded_value boolean) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $integration_webhook_test_complete$
DECLARE p jsonb:=zasp_authorization80.context();i text;result jsonb;
BEGIN
 i:=p#>>'{path_parameters,id}';
 IF i IS NULL OR NOT COALESCE(public.zasp_valid_product_id(i) AND public.zasp_valid_product_id(delivery_value),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current product authorization required';END IF;
 p:=zasp_authorization80.product_request(o,w,e,p->>'principal_id','testIntegrationWebhook','manage_workflows','integration',i,true,false,false,true);
 IF NOT EXISTS(SELECT 1 FROM public.zasp_integration_webhook_tests t WHERE(t.organization_id,t.workspace_id,t.environment_id,t.integration_id,t.principal_id,t.delivery_id)=(o,w,e,i,p->>'principal_id',delivery_value))
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current product authorization required';END IF;
 result:=public.zasp_integration_webhook_test_complete(o,w,e,delivery_value,token_value,digest_value,succeeded_value);
 PERFORM zasp_authorization80.product_settled(p);
 RETURN result;
END $integration_webhook_test_complete$;

DO $integration_grants$
DECLARE f text;
BEGIN
 FOREACH f IN ARRAY ARRAY['integration_delete(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','integration_webhook_status(text,text,text,text)','integration_webhook_test_reserve(text,text,text,text,text,bigint,text,text,text,text,text,integer)','integration_webhook_test_complete(text,text,text,text,text,text,boolean)'] LOOP
  EXECUTE format('ALTER FUNCTION zasp_authorization80.%s OWNER TO zasp_discovery_authority',f);
  EXECUTE format('REVOKE ALL ON FUNCTION zasp_authorization80.%s FROM PUBLIC',f);
  EXECUTE format('GRANT EXECUTE ON FUNCTION zasp_authorization80.%s TO zasp_discovery_api',f);
 END LOOP;
END $integration_grants$;

-- ---------------------------------------------------------------------------
-- Z6. The Workspace and the Environment of a path: GET and PATCH
-- /workspaces/{id} and /environments/{id}.
--
-- The lists and the creations were authorized (hierarchy_page,
-- create_workspace, create_environment); the two reads and the two renames
-- were still statements over the tables. As before, a session reads and
-- renames only the Workspace and the Environment it is signed in to, and a
-- rename additionally needs the principal's own direct scope row (the rule
-- require_hierarchy_create applies to creations). The renames are owned by
-- zasp_operator, like the creations: the hierarchy and audit write guards
-- admit only the tables' owner.
CREATE OR REPLACE FUNCTION zasp_authorization80.hierarchy_value(o text,w text,e text,kind_value text,i text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $hierarchy_value$
DECLARE p jsonb;op text:=CASE kind_value WHEN 'workspace' THEN 'getWorkspace' WHEN 'environment' THEN 'getEnvironment' END;result jsonb;
BEGIN
 IF op IS NULL OR NOT COALESCE(public.zasp_valid_product_id(i),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current product authorization required';END IF;
 p:=zasp_authorization80.product_request(o,w,e,NULL,op,'view',kind_value,i,true,true,false,false);
 IF i IS DISTINCT FROM (CASE kind_value WHEN 'workspace' THEN w ELSE e END)
  OR NOT EXISTS(SELECT 1 FROM public.zasp_identity_admin_effective_scopes(p->>'principal_id',o) s WHERE(s.workspace_id,s.environment_id)=(w,e))
 THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='hierarchy object missing';END IF;
 IF kind_value='workspace' THEN
  SELECT jsonb_build_object('id',x.id,'organization_id',x.organization_id,'name',x.name,'version',x.version) INTO result FROM public.zasp_workspaces x WHERE(x.organization_id,x.id)=(o,i);
 ELSE
  SELECT jsonb_build_object('id',x.id,'organization_id',x.organization_id,'workspace_id',x.workspace_id,'name',x.name,'environment_class',x.environment_class,'version',x.version) INTO result FROM public.zasp_environments x WHERE(x.organization_id,x.workspace_id,x.id)=(o,w,i);
 END IF;
 IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='hierarchy object missing';END IF;
 RETURN result;
END $hierarchy_value$;

CREATE OR REPLACE FUNCTION zasp_authorization80.hierarchy_rename(o text,w text,e text,actor text,kind_value text,i text,name_value text,version_value bigint,audit_value text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $hierarchy_rename$
DECLARE p jsonb;op text:=CASE kind_value WHEN 'workspace' THEN 'updateWorkspace' WHEN 'environment' THEN 'updateEnvironment' END;result jsonb;
BEGIN
 IF op IS NULL OR NOT COALESCE(public.zasp_valid_product_id(i),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current product authorization required';END IF;
 p:=zasp_authorization80.product_request(o,w,e,actor,op,'manage_identity',kind_value,i,true,true,true,true);
 IF NOT COALESCE(public.zasp_valid_product_id(audit_value) AND version_value>0 AND length(name_value) BETWEEN 1 AND 256,false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid hierarchy rename';END IF;
 IF i IS DISTINCT FROM (CASE kind_value WHEN 'workspace' THEN w ELSE e END) OR NOT EXISTS(SELECT 1 FROM public.zasp_authorized_scopes s
  JOIN public.zasp_identity_memberships m ON(m.organization_id,m.principal_id)=(s.organization_id,s.principal_id) AND m.active
  WHERE(s.organization_id,s.workspace_id,s.environment_id,s.principal_id)=(o,w,e,actor))
 THEN RETURN jsonb_build_object('_mutation_state','not_found');END IF;
 IF kind_value='workspace' THEN
  WITH updated AS (
   UPDATE public.zasp_workspaces x SET name=name_value,version=x.version+1 WHERE(x.organization_id,x.id)=(o,i) AND x.version=version_value RETURNING x.*
  ),audited AS (
   INSERT INTO public.zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata)
   SELECT o,w,e,audit_value,actor,'workspace.update',i,'succeeded','{}'::jsonb FROM updated
  ) SELECT jsonb_build_object('id',id,'organization_id',organization_id,'name',name,'version',version,'audit_correlation_id',audit_value) INTO result FROM updated;
  IF result IS NULL THEN result:=jsonb_build_object('_mutation_state',CASE WHEN EXISTS(SELECT 1 FROM public.zasp_workspaces x WHERE(x.organization_id,x.id)=(o,i)) THEN 'conflict' ELSE 'not_found' END);END IF;
 ELSE
  WITH updated AS (
   UPDATE public.zasp_environments x SET name=name_value,version=x.version+1 WHERE(x.organization_id,x.workspace_id,x.id)=(o,w,i) AND x.version=version_value RETURNING x.*
  ),audited AS (
   INSERT INTO public.zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata)
   SELECT o,w,e,audit_value,actor,'environment.update',i,'succeeded','{}'::jsonb FROM updated
  ) SELECT jsonb_build_object('id',id,'organization_id',organization_id,'workspace_id',workspace_id,'name',name,'environment_class',environment_class,'version',version,'audit_correlation_id',audit_value) INTO result FROM updated;
  IF result IS NULL THEN result:=jsonb_build_object('_mutation_state',CASE WHEN EXISTS(SELECT 1 FROM public.zasp_environments x WHERE(x.organization_id,x.workspace_id,x.id)=(o,w,i)) THEN 'conflict' ELSE 'not_found' END);END IF;
 END IF;
 PERFORM zasp_authorization80.product_settled(p);
 RETURN result;
END $hierarchy_rename$;
ALTER FUNCTION zasp_authorization80.hierarchy_value(text,text,text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION zasp_authorization80.hierarchy_rename(text,text,text,text,text,text,text,bigint,text) OWNER TO zasp_operator;
REVOKE ALL ON FUNCTION zasp_authorization80.hierarchy_value(text,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION zasp_authorization80.hierarchy_rename(text,text,text,text,text,text,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.hierarchy_value(text,text,text,text,text) TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION zasp_authorization80.hierarchy_rename(text,text,text,text,text,text,text,bigint,text) TO zasp_discovery_api;

-- ---------------------------------------------------------------------------
-- Z7. PATCH /findings/{id} and POST /findings/{id}/accept-risk.
--
-- The finding reads were authorized (risk_page and the finding detail); the
-- status change still called the chain's writer directly. The writer is the
-- chain's current one (zasp_temporal77.risk_mutate), unchanged: readiness,
-- visibility, optimistic version, idempotent replay, audit row and receipt.
CREATE OR REPLACE FUNCTION zasp_authorization80.finding_mutate(operation_value text,i text,o text,w text,e text,actor text,k text,expected_version bigint,status_value text,reason_value text,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $finding_mutate$
DECLARE p jsonb;result jsonb;
BEGIN
 IF operation_value IS NULL OR operation_value NOT IN('updateFinding','acceptFindingRisk') OR NOT COALESCE(public.zasp_valid_product_id(i),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current product authorization required';END IF;
 p:=zasp_authorization80.product_request(o,w,e,actor,operation_value,'manage_findings','finding',i,true,false,false,true);
 IF NOT COALESCE(public.zasp_valid_product_id(audit_value) AND public.zasp_valid_product_id(correlation_value)
  AND((p->>'credential_kind'='1' AND public.zasp_valid_product_id(receipt_value)) OR(p->>'credential_kind'='2' AND receipt_value IS NULL)),false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid risk mutation';END IF;
 result:=zasp_temporal77.risk_mutate(operation_value,i,o,w,e,actor,k,expected_version,status_value,reason_value,audit_value,correlation_value,receipt_value);
 PERFORM zasp_authorization80.product_settled(p);
 RETURN result;
END $finding_mutate$;
ALTER FUNCTION zasp_authorization80.finding_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.finding_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.finding_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text) TO zasp_discovery_api;

-- ---------------------------------------------------------------------------
-- Z8. The receipt page and the compliance reads check resolver readiness
-- once per statement.
--
-- Section L found that parent_allowed costs one resolver readiness check
-- (reader() and ready(), about 170 ms) per row, and moved the audit page to
-- one check before its first event and one after its last. The same per-row
-- cost remained in two places:
--   * receipt_page: one check per unacknowledged receipt of the principal;
--   * compliance_read: one check per compliance source of the Environment,
--     on every call. GET /compliance/controls reads the controls and then
--     the evidence of each control, so a page of ten controls ran the check
--     several hundred times and never answered inside the server's deadline.
-- Both keep every rule and use parent_allowed_inner between a readiness check
-- before the first row and one after the last (section L's brackets).
-- receipt_page performs no check when the principal has no receipt to show.
CREATE OR REPLACE FUNCTION zasp_authorization80.receipt_page(o text,w text,e text,p text,n integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $receipt_page$
DECLARE page_value jsonb;
BEGIN
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['listWorkflowMutationReceipts'],'view',true,p);
 IF n NOT BETWEEN 1 AND 50 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid workflow receipt list';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.zasp_workflow_receipts r WHERE(r.organization_id,r.workspace_id,r.environment_id,r.principal_id)=(o,w,e,p) AND r.acknowledged_at IS NULL AND r.expires_at>transaction_timestamp())
 THEN RETURN jsonb_build_object('items','[]'::jsonb);END IF;
 IF NOT zasp_authorization79.reader() OR NOT zasp_authorization80.ready('d7fbda32a2b3b9ea0ffbd4f7c7a7967a9d4fba2f6573f49e8386e9586a18a1fd') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization resolver rejected';END IF;
 -- Expired receipt cleanup is not a side effect of a user-authorized read.
 SELECT jsonb_build_object('items',COALESCE(jsonb_agg(item ORDER BY created_at DESC,receipt_id),'[]'::jsonb)) INTO page_value FROM(
 SELECT receipt_id,created_at,jsonb_build_object('id',receipt_id,'operation',operation,'idempotency_key',idempotency_key,'intent',intent,'result',result,'resource_kind',resource_kind,'resource_id',resource_id,'resource_version',resource_version,'audit_id',audit_id,'correlation_id',correlation_id,'created_at',created_at,'expires_at',expires_at) item
 FROM public.zasp_workflow_receipts r WHERE(r.organization_id,r.workspace_id,r.environment_id,r.principal_id)=(o,w,e,p) AND acknowledged_at IS NULL AND expires_at>transaction_timestamp() AND zasp_authorization80.parent_allowed_inner(o,w,e,'workflow_receipt',receipt_id) ORDER BY created_at DESC,receipt_id LIMIT n) visible;
 IF NOT zasp_authorization79.reader() OR NOT zasp_authorization80.ready('d7fbda32a2b3b9ea0ffbd4f7c7a7967a9d4fba2f6573f49e8386e9586a18a1fd') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization resolver rejected';END IF;
 RETURN page_value;
END $receipt_page$;

DO $compliance_read_once$
DECLARE d text;
 guard text:=$g$ IF NOT zasp_authorization79.reader() OR NOT zasp_authorization80.ready('d7fbda32a2b3b9ea0ffbd4f7c7a7967a9d4fba2f6573f49e8386e9586a18a1fd') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization resolver rejected';END IF;$g$;
 scan text:=$s$ -- Materialize every eligible row once in this statement.$s$;
 after_scan text:=$r$ IF NOT (result_value->>'valid')::boolean THEN$r$;
 visible text:=$v$zasp_authorization80.parent_allowed(org_value,workspace_value,environment_value,'compliance_evidence',s.source_id,s.source_kind)$v$;
BEGIN
 SELECT pg_get_functiondef('zasp_authorization80.compliance_read(text,text,text,text,bytea,text,jsonb,text,text)'::regprocedure) INTO STRICT d;
 IF position('zasp_authorization80.parent_allowed_inner(' IN d)>0 THEN RETURN;END IF;
 IF (length(d)-length(replace(d,visible,'')))/length(visible)<>1 OR (length(d)-length(replace(d,scan,'')))/length(scan)<>1 OR (length(d)-length(replace(d,after_scan,'')))/length(after_scan)<>1
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authorization compliance read predecessor changed';END IF;
 EXECUTE replace(replace(replace(d,visible,replace(visible,'parent_allowed(','parent_allowed_inner(')),scan,guard||E'\n'||scan),after_scan,guard||E'\n'||after_scan);
END $compliance_read_once$;

-- ---------------------------------------------------------------------------
-- V1. The integration of a leased connector effect.
--
-- The connector reconciler (apiserver/connector_reconciler.go) finishes
-- connector effects in the background: an OAuth authorization whose outcome
-- is unknown, and the revocation that DELETE /integrations/{id} requests for
-- an integration with a verified connection or an active credential. To
-- finish either it must read the integration (its connector and
-- configuration). It read it with the generic workflow reader, a request
-- statement the API role can no longer execute and the API refuses without a
-- request authorization. Every claimed lease therefore failed before any
-- provider work, the effect was claimed again until it was quarantined at
-- attempt 100, and a deleted integration stayed in 'revoking' with its
-- receipt unsettled.
--
-- The read below is bound to the lease the reconciler holds, like the other
-- maintenance statements (claim, complete, fail, quarantine): it returns the
-- integration of one effect, only while that effect is leased to the named
-- owner with the named token and the lease has not expired. It takes no
-- principal and reads nothing a claim has not already selected.
CREATE OR REPLACE FUNCTION zasp_authorization80.connector_leased_integration(o text,w text,e text,effect_value text,owner_value text,token_value text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $connector_leased_integration$
DECLARE result jsonb;
BEGIN
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(effect_value)
  AND length(owner_value) BETWEEN 3 AND 128 AND token_value~'^[0-9a-f]{64}$',false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid connector lease read';END IF;
 SELECT jsonb_build_object('body',r.body,'version',r.version,'secret_generation',r.secret_generation) INTO result
 FROM public.zasp_connector_effects x
 JOIN public.zasp_workflow_records r ON(r.organization_id,r.workspace_id,r.environment_id,r.kind,r.id)=(x.organization_id,x.workspace_id,x.environment_id,'integration',x.integration_id) AND r.deleted_at IS NULL
 WHERE(x.organization_id,x.workspace_id,x.environment_id,x.id)=(o,w,e,effect_value) AND x.status='unknown'
  AND x.lease_owner=owner_value AND x.lease_token=token_value AND x.lease_expires_at>transaction_timestamp();
 IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='connector leased integration unavailable';END IF;
 RETURN result;
END $connector_leased_integration$;
ALTER FUNCTION zasp_authorization80.connector_leased_integration(text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.connector_leased_integration(text,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.connector_leased_integration(text,text,text,text,text,text) TO zasp_discovery_api;

-- ---------------------------------------------------------------------------
-- V2. POST /security-agents/{id}/runs: the documented short request, and a
-- named refusal for a finding of another rule.
--
-- The contract documents two request bodies. The short one names the trigger
-- only ({environment_id, trigger_kind, trigger_id}); the long one adds
-- trigger_version and trigger_source. Section H passed the body unchanged to
-- the finding-response release (zasp_temporal78.resource), which accepts the
-- long form only, so the short form answered 400 for every finding-response
-- Security Agent.
--
-- The short form is now completed here, inside the authorized function and
-- its transaction, after both proofs were checked (the definition's in this
-- function, the trigger's in the seven-argument form of section X9):
--   * trigger_source is the definition's own trigger source;
--   * trigger_version is the finding's current version, or, when the same
--     principal already used this idempotency key for the same definition
--     and finding, the version that request recorded, so a retry replays its
--     own receipt even after the finding changed.
-- Nothing is taken from the caller that the long form would not take, and
-- the release still checks every value: the definition version and its
-- activation, the open finding at that version, the occurrence and the
-- receipt. A caller that names a version states which finding it saw; a
-- caller that names none starts on the finding as it is now, which is what
-- the contract says of the short form.
--
-- A finding-response Security Agent acts on findings of one rule (its
-- trigger source). A run requested on an open finding of another rule was
-- refused by the release with a generic serialization error ('finding human
-- source family changed'), which the API reports as an unexplained conflict.
-- That case is decided here first and named, so the API can say what to
-- change. It is still a refusal: no run is created.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_run(o text,w text,e text,d text,actor text,q jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_run$
DECLARE p jsonb;result jsonb;family text;scope_value jsonb;sourced boolean;definition_source text;prior_intent jsonb;finding_version bigint;finding_rule text;
 c CONSTANT text:='e4dfae0a990718c2c6b7518b07d7c146cfb9025656378d423c8d96188bcf1b96';f CONSTANT text:='07e774a28105095c73275ad959c765a3fddda9ee9aa81e81cd3828222e40aad3';
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='authorization security agent write requires read committed';END IF;
 sourced:=COALESCE(q ? 'trigger_version' OR q ? 'trigger_source',false);
 IF q IS NULL OR jsonb_typeof(q)<>'object' OR octet_length(q::text)>8192
  OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','definition_id','actor_id','idempotency_key','definition_version','run_id','trigger_kind','trigger_id','audit_id','correlation_id','receipt_id']||CASE WHEN sourced THEN ARRAY['trigger_version','trigger_source'] ELSE ARRAY[]::text[] END)
  OR(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'definition_id',q->>'actor_id') IS DISTINCT FROM(o,w,e,d,actor)
  OR NOT COALESCE(public.zasp_valid_product_id(d) AND public.zasp_valid_product_id(q->>'run_id') AND public.zasp_valid_product_id(q->>'trigger_id') AND public.zasp_valid_product_id(q->>'audit_id') AND public.zasp_valid_product_id(q->>'correlation_id') AND public.zasp_valid_product_id(q->>'receipt_id')
   AND jsonb_typeof(q->'idempotency_key')='string' AND length(q->>'idempotency_key') BETWEEN 16 AND 128 AND q->>'idempotency_key'~'^[A-Za-z0-9][A-Za-z0-9._:-]*$'
   AND jsonb_typeof(q->'definition_version')='number' AND q->>'definition_version'~'^([1-9][0-9]{0,5}|1000000)$'
   AND jsonb_typeof(q->'trigger_kind')='string' AND q->>'trigger_kind' IN('finding','session','attack_path')
   AND(NOT sourced OR(jsonb_typeof(q->'trigger_version')='number' AND q->>'trigger_version'~'^[1-9][0-9]{0,15}$' AND jsonb_typeof(q->'trigger_source')='string' AND length(q->>'trigger_source') BETWEEN 1 AND 128)),false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent run rejected';END IF;
 p:=zasp_authorization80.security_agent_write_request(o,w,e,actor,'runSecurityAgent',d);
 IF zasp_authorization80.security_agent_export_family(o,w,e,d,NULL) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent export definitions unavailable';END IF;
 IF q->>'trigger_kind'='finding' AND zasp_temporal78.family(o,w,e,d,actor) THEN
  SELECT x.body->>'trigger_source' INTO definition_source FROM public.zasp_security_agent_definitions x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.definition_id)=(o,w,e,d) AND x.deleted_at IS NULL;
  SELECT r.intent INTO prior_intent FROM public.zasp_security_agent_request_receipts r
  WHERE(r.organization_id,r.workspace_id,r.environment_id,r.principal_id,r.operation,r.idempotency_key)=(o,w,e,actor,'runSecurityAgent',q->>'idempotency_key')
   AND r.resource_id=d AND r.intent->>'trigger_kind'='finding' AND r.intent->>'trigger_id'=q->>'trigger_id'
   AND jsonb_typeof(r.intent->'trigger_version')='number' AND jsonb_typeof(r.intent->'trigger_source')='string';
  IF prior_intent IS NOT NULL THEN
   -- A retry of an admitted request: the release compares the whole intent.
   IF NOT sourced THEN q:=q||jsonb_build_object('trigger_version',prior_intent->'trigger_version','trigger_source',prior_intent->'trigger_source');END IF;
  ELSE
   IF sourced THEN
    SELECT x.version,x.rule INTO finding_version,finding_rule FROM public.zasp_risk_findings x
    WHERE(x.organization_id,x.workspace_id,x.environment_id,x.id,x.status)=(o,w,e,q->>'trigger_id','open') AND x.version::text=q->>'trigger_version';
   ELSE
    SELECT x.version,x.rule INTO finding_version,finding_rule FROM public.zasp_risk_findings x
    WHERE(x.organization_id,x.workspace_id,x.environment_id,x.id,x.status)=(o,w,e,q->>'trigger_id','open');
    IF finding_version IS NULL OR definition_source IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding human source changed';END IF;
    q:=q||jsonb_build_object('trigger_version',finding_version,'trigger_source',definition_source);
   END IF;
   IF finding_version IS NOT NULL AND finding_rule IS DISTINCT FROM definition_source
   THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent trigger source mismatch';END IF;
  END IF;
 END IF;
 result:=zasp_temporal78.resource(q);family:='finding';
 IF result IS NULL OR result='null'::jsonb THEN result:=zasp_temporal76.resource(q);family:='test';END IF;
 IF(result IS NULL OR result='null'::jsonb) AND sourced AND(q->>'trigger_version')::numeric<=1000000 THEN
  scope_value:=jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'actor_id',actor);
  IF zasp_ordered_public62.api(c,f,scope_value||jsonb_build_object('operation','classify_mutation','mutation_kind','trigger','definition_id',d,'idempotency_key',q->'idempotency_key','trigger',jsonb_build_object('trigger_id',q->'trigger_id','trigger_version',q->'trigger_version')))->>'family'='ordered_release61' THEN
   result:=zasp_ordered_public62.api(c,f,scope_value||jsonb_build_object('operation','trigger_resource','definition_id',d,'definition_version',q->'definition_version','trigger_id',q->'trigger_id','trigger_version',q->'trigger_version','trigger_kind',q->'trigger_kind','trigger_source',q->'trigger_source','idempotency_key',q->'idempotency_key'));
   family:='ordered';
  END IF;
 END IF;
 IF(result IS NULL OR result='null'::jsonb) AND NOT sourced THEN
  result:=public.zasp_security_agent_run_v24(o,w,e,d,actor,q->>'idempotency_key',(q->>'definition_version')::bigint,q->>'run_id',q->>'trigger_kind',q->>'trigger_id',q->>'audit_id',q->>'correlation_id',q->>'receipt_id');
  family:='legacy';
 END IF;
 IF result IS NULL OR jsonb_typeof(result) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent run family rejected';END IF;
 PERFORM zasp_authorization80.security_agent_write_settled(p);
 RETURN jsonb_build_object('family',family,'result',result);
END $security_agent_run$;
ALTER FUNCTION zasp_authorization80.security_agent_run(text,text,text,text,text,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.security_agent_run(text,text,text,text,text,jsonb) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION zasp_authorization80.security_agent_run(text,text,text,text,text,jsonb) FROM zasp_security_agent_api;

-- ---------------------------------------------------------------------------
-- V3. A deleted sync schedule can be set again.
--
-- DELETE /integrations/{id}/schedule keeps the schedule row in state
-- 'deleted': the scheduler worker reads it to pause the schedule in Temporal
-- and acknowledges that revision. The schedule then reads as absent (GET
-- answers 404), but PUT could not create it again: with If-Match "0" the row
-- was found ('discovery schedule exists'), and with any other version a
-- deleted row is refused. An integration whose schedule had been deleted once
-- could never be scheduled again.
--
-- A create (expected version 0) over a deleted row now replaces it: the
-- deleted row is removed and a new schedule, with a new identity, starts at
-- version 1. Every layer that checks a schedule mutation (the worker
-- accounting in zasp_authorization80_worker and the API) requires the
-- resulting version to be the expected version plus one, and the Temporal
-- schedule of an identity accepts only rising revisions, so the deleted
-- identity cannot be reused and its version cannot be restarted.
--
-- The deleted row is removed only once the scheduler worker has acknowledged
-- the deletion (acknowledged_revision = version), which it does after the
-- Temporal schedule of that identity is paused. Until then the create is
-- refused as a conflict and can be repeated; otherwise a still active
-- Temporal schedule would keep waking for a schedule that no longer exists.
-- The paused Temporal schedule of the removed identity stays in Temporal, as
-- it did for every deleted schedule before; it never fires.
-- A create over a live schedule is still refused. The body is the installed
-- one with this one branch; the predecessor shape is checked, and a body that
-- already carries the branch is left alone.
DO $schedule_recreate$
DECLARE d text;
 exists_needle text:=$n$  IF FOUND THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='discovery schedule exists';END IF;$n$;
 exists_insert text:=$n$  IF FOUND AND s.state<>'deleted' THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='discovery schedule exists';END IF;
  IF FOUND THEN
   IF s.acknowledged_revision<>s.version THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='discovery schedule withdrawal pending';END IF;
   DELETE FROM zasp_temporal72.schedules WHERE(organization_id,workspace_id,environment_id,id)=(o,w,e,s.id);
  END IF;$n$;
BEGIN
 SELECT pg_get_functiondef('zasp_temporal72.public_put_schedule(text,text,text,text,text,text,bigint,integer,text,text,text,text)'::regprocedure) INTO STRICT d;
 IF position('discovery schedule withdrawal pending' in d)=0 THEN
  IF (length(d)-length(replace(d,exists_needle,'')))/length(exists_needle)<>1
  THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='discovery schedule predecessor changed';END IF;
  EXECUTE replace(d,exists_needle,exists_insert);
 END IF;
END $schedule_recreate$;

-- ---------------------------------------------------------------------------
-- V4. Abandoned discovery runs are released without a later sync.
--
-- Section N releases an abandoned run when the next run of the same
-- integration prepares its first page. An integration that nobody synchronizes
-- again (no schedule, no further request) therefore kept its abandoned sync
-- in 'running', and its integration reserved, for ever.
--
-- zasp_temporal72.release_abandoned_due is the same release, started by the
-- scheduler worker on a timer instead of by a later run. It decides nothing
-- itself: for each integration and provider that has a run release_abandoned
-- would consider (a run whose sync is still queued or running, or a run that
-- still owns the integration, zasp_temporal72.active_owners) it takes the
-- advisory lock that prepare_page takes for that integration and provider,
-- without waiting (an integration a run is working on right now is skipped),
-- and calls release_abandoned, which applies every rule of section N: nothing
-- committed, quiet for the fixed time, the run row not locked. No run asks,
-- so the release row names a fresh sweep identity as released_by_job_id; it
-- is never the identity of a run.
--
-- Only the scheduler principal may call it (zasp_temporal72.require_principal,
-- which also requires read committed and the current catalog). It takes a
-- bound on the integrations examined in one call and no scope, and returns
-- only two counts. When more integrations are candidates than the bound,
-- each call examines a random selection, so no candidate is starved by
-- others that are not yet releasable.
CREATE OR REPLACE FUNCTION zasp_temporal72.release_abandoned_due(limit_value integer) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $release_abandoned_due$
DECLARE c record;examined integer:=0;released integer:=0;
BEGIN
 PERFORM zasp_temporal72.require_principal('zasp_discovery_scheduler');
 IF limit_value IS NULL OR limit_value NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='discovery release sweep rejected';END IF;
 FOR c IN SELECT y.* FROM(SELECT DISTINCT x.organization_id,x.workspace_id,x.environment_id,x.integration_id,x.provider FROM(
   SELECT r.organization_id,r.workspace_id,r.environment_id,r.integration_id,r.provider FROM zasp_temporal72.runs r
   WHERE r.state<>'succeeded'
   AND NOT EXISTS(SELECT 1 FROM zasp_temporal72.releases d WHERE(d.organization_id,d.workspace_id,d.environment_id,d.job_id)=(r.organization_id,r.workspace_id,r.environment_id,r.job_id))
   AND EXISTS(SELECT 1 FROM public.zasp_discovery_syncs s WHERE(s.organization_id,s.workspace_id,s.environment_id,s.id)=(r.organization_id,r.workspace_id,r.environment_id,r.sync_id) AND s.state IN('queued','running'))
   UNION ALL
   SELECT scope.organization_id,owner.workspace_id,owner.environment_id,owner.integration_id,owner.provider
   FROM(SELECT DISTINCT r.organization_id FROM zasp_temporal72.runs r WHERE r.state<>'succeeded') scope
   CROSS JOIN LATERAL zasp_temporal72.active_owners(scope.organization_id) owner WHERE owner.ownership='temporal') x
  WHERE x.provider IN('aws','kubernetes','github','okta')) y
  ORDER BY random() LIMIT limit_value
 LOOP
  examined:=examined+1;
  IF NOT pg_try_advisory_xact_lock(hashtextextended(concat_ws(chr(31),c.organization_id,c.workspace_id,c.environment_id,c.integration_id,c.provider),0)) THEN CONTINUE;END IF;
  released:=released+zasp_temporal72.release_abandoned(c.organization_id,c.workspace_id,c.environment_id,c.integration_id,c.provider,'pid_'||gen_random_uuid()::text);
 END LOOP;
 RETURN jsonb_build_object('examined',examined,'released',released);
END $release_abandoned_due$;
ALTER FUNCTION zasp_temporal72.release_abandoned_due(integer) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_temporal72.release_abandoned_due(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_temporal72.release_abandoned_due(integer) TO zasp_discovery_scheduler;

-- ---------------------------------------------------------------------------
-- V5. Webhook test delivery and delivery status without the release-35 pin.
--
-- GET /integrations/{id}/delivery-status and POST
-- /integrations/{id}/test-delivery answered 503 for every Generic Webhook
-- integration. The three chain functions behind them
-- (public.zasp_integration_webhook_test_status, _reserve and _complete)
-- first ask zasp_production_integration_webhook_readiness, the readiness of
-- release 35. That predicate ends in a chain of later release predicates,
-- each of which pins the exact number of releases installed at its time (the
-- last link requires exactly 60), so it has been false since the releases
-- after it were installed, on the historical chain as well as on this
-- baseline. Nothing external is missing: the gate is a superseded pin.
--
-- The authorized functions of section Z5 already decide the request (the
-- proof, the integration as the object, the permission). They now call cores
-- owned by the authorized schema instead of the chain functions. Each core is
-- the installed chain body with one change: the release-35 gate is replaced
-- by the readiness the other authorized integration statements use
-- (zasp_authorization80.integration_current_ready: the current catalog, the
-- API principal, read committed). The cores are derived from the installed
-- bodies here, so no rule of the chain is restated, and the predecessor shape
-- is checked. The chain functions themselves are unchanged; the API role
-- cannot execute the cores directly.
DO $webhook_cores$
DECLARE f record;d text;
 gate text:=$n$ IF NOT COALESCE(zasp_production_integration_webhook_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=35),(SELECT value FROM zasp_schema_metadata WHERE key='production_integration_webhook_fingerprint')),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='integration webhook unavailable';END IF;$n$;
 current_gate text:=$n$ PERFORM zasp_authorization80.integration_current_ready();$n$;
BEGIN
 FOR f IN SELECT * FROM(VALUES
  ('zasp_integration_webhook_test_status','integration_webhook_test_status_core','text,text,text,text'),
  ('zasp_integration_webhook_test_reserve','integration_webhook_test_reserve_core','text,text,text,text,text,bigint,text,text,text,text,text,integer'),
  ('zasp_integration_webhook_test_complete','integration_webhook_test_complete_core','text,text,text,text,text,text,boolean')
 ) v(source_name,core_name,arguments) LOOP
  SELECT pg_get_functiondef(format('public.%I(%s)',f.source_name,f.arguments)::regprocedure) INTO STRICT d;
  IF (length(d)-length(replace(d,gate,'')))/length(gate)<>1 OR position(format('FUNCTION public.%s(',f.source_name) in d)=0
  THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='integration webhook predecessor changed';END IF;
  EXECUTE replace(replace(d,format('FUNCTION public.%s(',f.source_name),format('FUNCTION zasp_authorization80.%s(',f.core_name)),gate,current_gate);
  EXECUTE format('ALTER FUNCTION zasp_authorization80.%I(%s) OWNER TO zasp_discovery_authority',f.core_name,f.arguments);
  EXECUTE format('REVOKE ALL ON FUNCTION zasp_authorization80.%I(%s) FROM PUBLIC',f.core_name,f.arguments);
 END LOOP;
END $webhook_cores$;

CREATE OR REPLACE FUNCTION zasp_authorization80.integration_webhook_status(o text,w text,e text,i text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $integration_webhook_status$
BEGIN
 IF NOT COALESCE(public.zasp_valid_product_id(i),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current product authorization required';END IF;
 PERFORM zasp_authorization80.product_request(o,w,e,NULL,'getIntegrationWebhookStatus','view','integration',i,true,false,false,false);
 RETURN zasp_authorization80.integration_webhook_test_status_core(o,w,e,i);
END $integration_webhook_status$;

CREATE OR REPLACE FUNCTION zasp_authorization80.integration_webhook_test_reserve(o text,w text,e text,actor text,i text,expected_version bigint,k text,audit_value text,correlation_value text,delivery_value text,token_value text,lease_seconds integer) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $integration_webhook_test_reserve$
DECLARE p jsonb;result jsonb;
BEGIN
 IF NOT COALESCE(public.zasp_valid_product_id(i),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current product authorization required';END IF;
 p:=zasp_authorization80.product_request(o,w,e,actor,'testIntegrationWebhook','manage_workflows','integration',i,true,false,false,true);
 result:=zasp_authorization80.integration_webhook_test_reserve_core(o,w,e,actor,i,expected_version,k,audit_value,correlation_value,delivery_value,token_value,lease_seconds);
 PERFORM zasp_authorization80.product_settled(p);
 RETURN result;
END $integration_webhook_test_reserve$;

CREATE OR REPLACE FUNCTION zasp_authorization80.integration_webhook_test_complete(o text,w text,e text,delivery_value text,token_value text,digest_value text,succeeded_value boolean) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $integration_webhook_test_complete$
DECLARE p jsonb:=zasp_authorization80.context();i text;result jsonb;
BEGIN
 i:=p#>>'{path_parameters,id}';
 IF i IS NULL OR NOT COALESCE(public.zasp_valid_product_id(i) AND public.zasp_valid_product_id(delivery_value),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current product authorization required';END IF;
 p:=zasp_authorization80.product_request(o,w,e,p->>'principal_id','testIntegrationWebhook','manage_workflows','integration',i,true,false,false,true);
 IF NOT EXISTS(SELECT 1 FROM public.zasp_integration_webhook_tests t WHERE(t.organization_id,t.workspace_id,t.environment_id,t.integration_id,t.principal_id,t.delivery_id)=(o,w,e,i,p->>'principal_id',delivery_value))
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current product authorization required';END IF;
 result:=zasp_authorization80.integration_webhook_test_complete_core(o,w,e,delivery_value,token_value,digest_value,succeeded_value);
 PERFORM zasp_authorization80.product_settled(p);
 RETURN result;
END $integration_webhook_test_complete$;

DO $webhook_grants$
DECLARE f text;
BEGIN
 FOREACH f IN ARRAY ARRAY['integration_webhook_status(text,text,text,text)','integration_webhook_test_reserve(text,text,text,text,text,bigint,text,text,text,text,text,integer)','integration_webhook_test_complete(text,text,text,text,text,text,boolean)'] LOOP
  EXECUTE format('ALTER FUNCTION zasp_authorization80.%s OWNER TO zasp_discovery_authority',f);
  EXECUTE format('REVOKE ALL ON FUNCTION zasp_authorization80.%s FROM PUBLIC',f);
  EXECUTE format('GRANT EXECUTE ON FUNCTION zasp_authorization80.%s TO zasp_discovery_api',f);
 END LOOP;
END $webhook_grants$;

-- ---------------------------------------------------------------------------
-- WS2 (plan tasks F1, F2, F3). Red team probe library, agentic categories and
-- continuous re-test.
--
-- WS2a. Categories. A test could name six categories, each with one curated
-- prompt. The probe library adds three agentic categories that exist only as
-- probes: indirect_injection (through tool or MCP output), poisoned_resource
-- and cross_agent_delegation. Tool misuse stays tool_abuse; it is not a
-- second category.
--
-- Only the two functions of the standalone run accept the new names: the
-- definition check and the leased target resolution. The journaled existing
-- test protocols of the Security Agent keep the six categories and their one
-- pinned prompt, so a definition with a new category is refused there, closed.
-- The safety rule (development, test or staging; read_only or test_write) is
-- the same text in the same function and is not touched.
--
-- Re-run: a function that already holds the nine names is left alone; one
-- that does not hold exactly the six names once is refused.
DO $ws2_red_team_probe_categories$
DECLARE
 earlier CONSTANT text:=$list$('prompt_injection','tool_abuse','data_leakage','authorization_bypass','excessive_agency','sensitive_information')$list$;
 current_list CONSTANT text:=$list$('prompt_injection','tool_abuse','data_leakage','authorization_bypass','excessive_agency','sensitive_information','indirect_injection','poisoned_resource','cross_agent_delegation')$list$;
 target regprocedure;d text;
BEGIN
 FOREACH target IN ARRAY ARRAY['public.zasp_red_team_definition_valid(text,text,text,jsonb,jsonb)'::regprocedure,'public.zasp_red_team_resolve_invocation(text,text,text,text,text,text,text,text)'::regprocedure] LOOP
  d:=pg_get_functiondef(target);
  IF position(current_list in d)>0 THEN CONTINUE;END IF;
  IF (length(d)-length(replace(d,earlier,'')))/length(earlier)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team category predecessor changed';END IF;
  EXECUTE replace(d,earlier,current_list);
 END LOOP;
END $ws2_red_team_probe_categories$;

-- WS2b. Which probes ran, and their outcome.
--
-- A standalone run executes a sample of the probe library per category. The
-- run's evidence lines stay one per category (a category is protected only
-- when every sampled probe was); zasp_red_team_probe_results holds one row
-- per executed probe of an attempt: the probe identifier, its category and
-- protected or unsafe. It never holds a prompt or an answer.
--
-- zasp_red_team_record_probe_results is called by the red team worker under
-- the lease of the run, before it finishes the run; it replaces the rows of
-- the leased attempt. zasp_red_team_get_run returns the rows of each attempt
-- as probe_results (an empty array for an attempt that ran one curated check
-- per category, which is every attempt recorded before this section).
DO $ws2_red_team_probe_results$
DECLARE
 get_run CONSTANT regprocedure:='public.zasp_red_team_get_run(text,text,text,text)'::regprocedure;
 anchor CONSTANT text:=$anchor$'completed_at',to_char(completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) ORDER BY attempt)$anchor$;
 patched CONSTANT text:=$patched$'completed_at',to_char(completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'probe_results',(SELECT COALESCE(jsonb_agg(jsonb_build_object('probe_id',probe_row.probe_id,'category',probe_row.category,'outcome',probe_row.outcome) ORDER BY probe_row.ordinal),'[]'::jsonb) FROM zasp_red_team_probe_results probe_row WHERE (probe_row.organization_id,probe_row.workspace_id,probe_row.environment_id,probe_row.run_id,probe_row.attempt)=(organization_value,workspace_value,environment_value,run_value,zasp_red_team_attempts.attempt))) ORDER BY attempt)$patched$;
 owner_value text;d text;
BEGIN
 SELECT pg_get_userbyid(relowner) INTO STRICT owner_value FROM pg_class WHERE oid='public.zasp_red_team_runs'::regclass;
 CREATE TABLE IF NOT EXISTS public.zasp_red_team_probe_results(
  organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,attempt integer NOT NULL,ordinal integer NOT NULL,
  probe_id text NOT NULL,category text NOT NULL,outcome text NOT NULL,recorded_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,attempt,probe_id),
  UNIQUE(organization_id,workspace_id,environment_id,run_id,attempt,ordinal),
  FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES public.zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id) ON DELETE CASCADE,
  CONSTRAINT zasp_red_team_probe_results_attempt_check CHECK(attempt BETWEEN 1 AND 5),
  CONSTRAINT zasp_red_team_probe_results_ordinal_check CHECK(ordinal BETWEEN 1 AND 480),
  CONSTRAINT zasp_red_team_probe_results_probe_check CHECK(length(probe_id)<=128 AND probe_id~'^zasp(\.[a-z][a-z_]{2,40}){4}\.v1$'),
  CONSTRAINT zasp_red_team_probe_results_category_check CHECK(category IN('prompt_injection','tool_abuse','data_leakage','authorization_bypass','excessive_agency','sensitive_information','indirect_injection','poisoned_resource','cross_agent_delegation')),
  CONSTRAINT zasp_red_team_probe_results_outcome_check CHECK(outcome IN('protected','unsafe')));
 EXECUTE format('ALTER TABLE public.zasp_red_team_probe_results OWNER TO %I',owner_value);
 ALTER TABLE public.zasp_red_team_probe_results ENABLE ROW LEVEL SECURITY;
 REVOKE ALL ON TABLE public.zasp_red_team_probe_results FROM PUBLIC;

 CREATE OR REPLACE FUNCTION public.zasp_red_team_record_probe_results(organization_value text,workspace_value text,environment_value text,run_value text,worker_value text,token_value bytea,results_value jsonb) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $record$
 DECLARE run_row zasp_red_team_runs%ROWTYPE;categories_value jsonb;recorded integer;
 BEGIN
  IF NOT COALESCE(zasp_red_team_principal_ready('zasp_red_team_worker') AND zasp_valid_product_id(organization_value) AND zasp_valid_product_id(workspace_value) AND zasp_valid_product_id(environment_value) AND zasp_valid_product_id(run_value)
   AND octet_length(token_value)=32 AND jsonb_typeof(results_value)='array' AND jsonb_array_length(results_value) BETWEEN 1 AND 480,false) THEN
   RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team probe results rejected';
  END IF;
  SELECT * INTO run_row FROM zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id,state)=(organization_value,workspace_value,environment_value,run_value,'leased')
   AND worker_id=worker_value AND lease_token=token_value AND lease_expires_at>transaction_timestamp() FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='red team run lease lost';END IF;
  SELECT categories INTO categories_value FROM zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(organization_value,workspace_value,environment_value,run_row.definition_id,run_row.definition_version);
  IF NOT FOUND OR EXISTS(SELECT 1 FROM jsonb_array_elements(results_value) item WHERE jsonb_typeof(item)<>'object' OR NOT item ?& ARRAY['probe_id','category','outcome'] OR item-ARRAY['probe_id','category','outcome']<>'{}'::jsonb
    OR jsonb_typeof(item->'probe_id')<>'string' OR jsonb_typeof(item->'category')<>'string' OR jsonb_typeof(item->'outcome')<>'string'
    OR NOT categories_value ? (item->>'category') OR position('zasp.'||(item->>'category')||'.' in item->>'probe_id')<>1 OR item->>'outcome' NOT IN('protected','unsafe'))
   OR (SELECT count(*)<>count(DISTINCT item->>'probe_id') FROM jsonb_array_elements(results_value) item) THEN
   RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team probe results rejected';
  END IF;
  DELETE FROM zasp_red_team_probe_results WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=(organization_value,workspace_value,environment_value,run_value,run_row.attempt);
  INSERT INTO zasp_red_team_probe_results(organization_id,workspace_id,environment_id,run_id,attempt,ordinal,probe_id,category,outcome)
   SELECT organization_value,workspace_value,environment_value,run_value,run_row.attempt,item.ordinality,item.value->>'probe_id',item.value->>'category',item.value->>'outcome' FROM jsonb_array_elements(results_value) WITH ORDINALITY item;
  GET DIAGNOSTICS recorded=ROW_COUNT;
  RETURN jsonb_build_object('recorded',recorded);
 END $record$;
 EXECUTE format('ALTER FUNCTION public.zasp_red_team_record_probe_results(text,text,text,text,text,bytea,jsonb) OWNER TO %I',owner_value);
 REVOKE ALL ON FUNCTION public.zasp_red_team_record_probe_results(text,text,text,text,text,bytea,jsonb) FROM PUBLIC;
 GRANT EXECUTE ON FUNCTION public.zasp_red_team_record_probe_results(text,text,text,text,text,bytea,jsonb) TO zasp_red_team_worker;

 d:=pg_get_functiondef(get_run);
 IF position('probe_results' in d)=0 THEN
  IF (length(d)-length(replace(d,anchor,'')))/length(anchor)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team run detail predecessor changed';END IF;
  EXECUTE replace(d,anchor,patched);
 ELSIF position(patched in d)=0 THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team run detail predecessor changed';
 END IF;
END $ws2_red_team_probe_results$;

-- WS2c. Continuous re-test.
--
-- zasp_red_team_schedules holds at most one schedule per test definition: a
-- cadence (one hour to 31 days), a re-test when the inventory record of the
-- target changes, or both. The change is a change of content: the kind, the
-- state, the stable fields or the winning attributes of the target entity
-- (zasp_red_team_target_fingerprint), not a newer observation time.
--
-- zasp_red_team_get_schedule and zasp_red_team_put_schedule are the API. A
-- schedule can be enabled only while the definition is enabled and passes
-- zasp_red_team_safety_authorized, the unchanged non-production rule.
--
-- zasp_red_team_fire_due_schedules is called by the scheduler worker on a
-- timer, next to the discovery schedules. For each due schedule it queues a
-- run exactly as zasp_red_team_run_test does (the run, its outbox row and the
-- red_team_run_queued audit event), requested by the person who last saved
-- the schedule, and only if the definition is still enabled and still passes
-- zasp_red_team_safety_authorized. A definition that no longer passes is not
-- run; the schedule records 'rejected' and waits for its next occurrence. A
-- definition with a run still queued, leased or retryable is not queued
-- again: a cadence occurrence is skipped, a target change is kept for the
-- next sweep.
DO $ws2_red_team_schedules$
DECLARE owner_value text;guard_value text:='';api_role text;
BEGIN
 SELECT pg_get_userbyid(relowner) INTO STRICT owner_value FROM pg_class WHERE oid='public.zasp_red_team_definitions'::regclass;
 -- The authorized API reaches direct functions only inside a checked request
 -- (section X3). An installation without that schema has no such requests.
 IF to_regprocedure('zasp_authorization80.direct_guard(text,text,text,text)') IS NOT NULL THEN
  guard_value:=' PERFORM zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value,actor_value);';
 END IF;
 CREATE TABLE IF NOT EXISTS public.zasp_red_team_schedules(
  organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,definition_id text NOT NULL,
  version bigint NOT NULL DEFAULT 1,enabled boolean NOT NULL,cadence_seconds integer,on_target_change boolean NOT NULL,
  next_run_at timestamptz,target_fingerprint text,last_run_id text,last_trigger text,last_outcome text,last_fired_at timestamptz,
  updated_by text NOT NULL,created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,definition_id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,definition_id) REFERENCES public.zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id) ON DELETE CASCADE,
  CONSTRAINT zasp_red_team_schedules_version_check CHECK(version BETWEEN 1 AND 1000000),
  CONSTRAINT zasp_red_team_schedules_cadence_check CHECK(cadence_seconds IS NULL OR cadence_seconds BETWEEN 3600 AND 2678400),
  CONSTRAINT zasp_red_team_schedules_trigger_check CHECK(NOT enabled OR cadence_seconds IS NOT NULL OR on_target_change),
  CONSTRAINT zasp_red_team_schedules_next_check CHECK((enabled AND cadence_seconds IS NOT NULL)=(next_run_at IS NOT NULL)),
  CONSTRAINT zasp_red_team_schedules_last_trigger_check CHECK(last_trigger IS NULL OR last_trigger IN('cadence','target_change')),
  CONSTRAINT zasp_red_team_schedules_last_outcome_check CHECK(last_outcome IS NULL OR last_outcome IN('queued','rejected','skipped_active')),
  CONSTRAINT zasp_red_team_schedules_id_check CHECK(public.zasp_valid_product_id(updated_by) AND(last_run_id IS NULL OR public.zasp_valid_product_id(last_run_id))));
 CREATE INDEX IF NOT EXISTS zasp_red_team_schedules_due ON public.zasp_red_team_schedules(next_run_at) WHERE enabled;
 EXECUTE format('ALTER TABLE public.zasp_red_team_schedules OWNER TO %I',owner_value);
 ALTER TABLE public.zasp_red_team_schedules ENABLE ROW LEVEL SECURITY;
 REVOKE ALL ON TABLE public.zasp_red_team_schedules FROM PUBLIC;

 CREATE OR REPLACE FUNCTION public.zasp_red_team_target_fingerprint(organization_value text,workspace_value text,environment_value text,target_value text) RETURNS text
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $fingerprint$
  SELECT encode(digest(convert_to(concat_ws(chr(31),entity.kind,entity.state,entity.stable_fields::text,COALESCE(entity.winning_attributes,'null'::jsonb)::text),'UTF8'),'sha256'),'hex')
  FROM zasp_inventory_entities entity WHERE (entity.organization_id,entity.workspace_id,entity.environment_id,entity.id)=(organization_value,workspace_value,environment_value,target_value)
 $fingerprint$;

 CREATE OR REPLACE FUNCTION public.zasp_red_team_schedule_json(organization_value text,workspace_value text,environment_value text,definition_value text) RETURNS jsonb
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $schedule_json$
  SELECT COALESCE((SELECT jsonb_build_object('definition_id',s.definition_id,'version',s.version,'enabled',s.enabled,'cadence_seconds',s.cadence_seconds,'on_target_change',s.on_target_change,
    'next_run_at',to_char(s.next_run_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'last_run_id',s.last_run_id,'last_trigger',s.last_trigger,'last_outcome',s.last_outcome,
    'last_fired_at',to_char(s.last_fired_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'updated_at',to_char(s.updated_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
   FROM zasp_red_team_schedules s WHERE (s.organization_id,s.workspace_id,s.environment_id,s.definition_id)=(organization_value,workspace_value,environment_value,definition_value)),
   jsonb_build_object('definition_id',definition_value,'version',0,'enabled',false,'cadence_seconds',NULL,'on_target_change',false,'next_run_at',NULL,'last_run_id',NULL,'last_trigger',NULL,'last_outcome',NULL,'last_fired_at',NULL,'updated_at',NULL))
 $schedule_json$;

 EXECUTE replace($get$
 CREATE OR REPLACE FUNCTION public.zasp_red_team_get_schedule(organization_value text,workspace_value text,environment_value text,definition_value text) RETURNS jsonb
 LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $get_schedule$
 DECLARE actor_value text:=NULL;
 BEGIN
 GUARD
  IF NOT COALESCE((pg_has_role(session_user,'zasp_security_agent_api','MEMBER') OR pg_has_role(session_user,'zasp_discovery_api','MEMBER')) AND zasp_valid_product_id(organization_value) AND zasp_valid_product_id(workspace_value) AND zasp_valid_product_id(environment_value) AND zasp_valid_product_id(definition_value),false) THEN
   RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team schedule rejected';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=(organization_value,workspace_value,environment_value,definition_value)) THEN
   RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='red team definition not found';
  END IF;
  RETURN zasp_red_team_schedule_json(organization_value,workspace_value,environment_value,definition_value);
 END $get_schedule$ $get$,'GUARD',guard_value);

 EXECUTE replace($put$
 CREATE OR REPLACE FUNCTION public.zasp_red_team_put_schedule(organization_value text,workspace_value text,environment_value text,actor_value text,definition_value text,expected_version_value bigint,enabled_value boolean,cadence_value integer,on_target_change_value boolean) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $put_schedule$
 DECLARE definition_row zasp_red_team_definitions%ROWTYPE;current_version bigint;
 BEGIN
 GUARD
  IF NOT COALESCE((pg_has_role(session_user,'zasp_security_agent_api','MEMBER') OR pg_has_role(session_user,'zasp_discovery_api','MEMBER')) AND zasp_valid_product_id(organization_value) AND zasp_valid_product_id(workspace_value) AND zasp_valid_product_id(environment_value) AND zasp_valid_product_id(actor_value) AND zasp_valid_product_id(definition_value)
   AND expected_version_value BETWEEN 0 AND 999999 AND enabled_value IS NOT NULL AND on_target_change_value IS NOT NULL AND (cadence_value IS NULL OR cadence_value BETWEEN 3600 AND 2678400) AND (NOT enabled_value OR cadence_value IS NOT NULL OR on_target_change_value),false) THEN
   RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team schedule rejected';
  END IF;
  SELECT * INTO definition_row FROM zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=(organization_value,workspace_value,environment_value,definition_value) FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='red team definition not found';END IF;
  IF enabled_value AND NOT (definition_row.enabled AND zasp_red_team_safety_authorized(organization_value,workspace_value,environment_value,definition_row.target_id,definition_row.target_kind,definition_row.safety)) THEN
   RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team schedule rejected';
  END IF;
  SELECT COALESCE((SELECT version FROM zasp_red_team_schedules WHERE (organization_id,workspace_id,environment_id,definition_id)=(organization_value,workspace_value,environment_value,definition_value)),0) INTO current_version;
  IF current_version<>expected_version_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='red team schedule version conflict';END IF;
  INSERT INTO zasp_red_team_schedules(organization_id,workspace_id,environment_id,definition_id,enabled,cadence_seconds,on_target_change,next_run_at,target_fingerprint,updated_by)
   VALUES(organization_value,workspace_value,environment_value,definition_value,enabled_value,cadence_value,on_target_change_value,
    CASE WHEN enabled_value AND cadence_value IS NOT NULL THEN transaction_timestamp()+make_interval(secs=>cadence_value) END,
    zasp_red_team_target_fingerprint(organization_value,workspace_value,environment_value,definition_row.target_id),actor_value)
  ON CONFLICT(organization_id,workspace_id,environment_id,definition_id) DO UPDATE SET version=zasp_red_team_schedules.version+1,enabled=EXCLUDED.enabled,cadence_seconds=EXCLUDED.cadence_seconds,on_target_change=EXCLUDED.on_target_change,
   next_run_at=EXCLUDED.next_run_at,target_fingerprint=EXCLUDED.target_fingerprint,updated_by=EXCLUDED.updated_by,updated_at=transaction_timestamp();
  RETURN zasp_red_team_schedule_json(organization_value,workspace_value,environment_value,definition_value);
 END $put_schedule$ $put$,'GUARD',guard_value);

 CREATE OR REPLACE FUNCTION public.zasp_red_team_fire_due_schedules(worker_value text,limit_value integer) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $fire$
 DECLARE s zasp_red_team_schedules%ROWTYPE;definition_row zasp_red_team_definitions%ROWTYPE;run_row zasp_red_team_runs%ROWTYPE;
  fingerprint_value text;trigger_value text;seed_value text;run_value text;key_value text;digest_value bytea;payload_value jsonb;next_value timestamptz;
  examined integer:=0;queued integer:=0;
 BEGIN
  IF NOT COALESCE(pg_has_role(session_user,'zasp_discovery_scheduler','MEMBER') AND worker_value~'^[A-Za-z0-9._:-]{1,128}$' AND limit_value BETWEEN 1 AND 50,false) THEN
   RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='red team schedule authority denied';
  END IF;
  FOR s IN SELECT schedule.* FROM zasp_red_team_schedules schedule JOIN zasp_red_team_definitions definition USING(organization_id,workspace_id,environment_id,definition_id)
   WHERE schedule.enabled AND(schedule.next_run_at<=transaction_timestamp() OR(schedule.on_target_change AND schedule.target_fingerprint IS DISTINCT FROM zasp_red_team_target_fingerprint(schedule.organization_id,schedule.workspace_id,schedule.environment_id,definition.target_id)))
   ORDER BY schedule.next_run_at NULLS LAST,schedule.definition_id LIMIT limit_value FOR UPDATE OF schedule SKIP LOCKED
  LOOP
   examined:=examined+1;
   SELECT * INTO STRICT definition_row FROM zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=(s.organization_id,s.workspace_id,s.environment_id,s.definition_id) FOR UPDATE;
   fingerprint_value:=zasp_red_team_target_fingerprint(s.organization_id,s.workspace_id,s.environment_id,definition_row.target_id);
   trigger_value:=CASE WHEN s.on_target_change AND s.target_fingerprint IS DISTINCT FROM fingerprint_value THEN 'target_change' ELSE 'cadence' END;
   next_value:=CASE WHEN s.cadence_seconds IS NOT NULL THEN transaction_timestamp()+make_interval(secs=>s.cadence_seconds) END;
   IF EXISTS(SELECT 1 FROM zasp_red_team_runs r WHERE (r.organization_id,r.workspace_id,r.environment_id,r.definition_id)=(s.organization_id,s.workspace_id,s.environment_id,s.definition_id) AND r.state IN('queued','leased','retryable')) THEN
    -- A due cadence occurrence is skipped; a target change stays pending.
    IF s.next_run_at<=transaction_timestamp() THEN
     UPDATE zasp_red_team_schedules SET next_run_at=next_value,last_outcome='skipped_active' WHERE (organization_id,workspace_id,environment_id,definition_id)=(s.organization_id,s.workspace_id,s.environment_id,s.definition_id);
    END IF;
    CONTINUE;
   END IF;
   IF NOT (definition_row.enabled AND zasp_red_team_safety_authorized(s.organization_id,s.workspace_id,s.environment_id,definition_row.target_id,definition_row.target_kind,definition_row.safety)) THEN
    UPDATE zasp_red_team_schedules SET next_run_at=next_value,target_fingerprint=fingerprint_value,last_trigger=trigger_value,last_outcome='rejected',last_fired_at=transaction_timestamp()
     WHERE (organization_id,workspace_id,environment_id,definition_id)=(s.organization_id,s.workspace_id,s.environment_id,s.definition_id);
    CONTINUE;
   END IF;
   seed_value:=concat_ws(chr(31),s.definition_id,definition_row.version::text,s.version::text,trigger_value,COALESCE(fingerprint_value,''),COALESCE(s.next_run_at::text,''),COALESCE(s.last_run_id,''));
   run_value:=zasp_discovery_canonical_id(s.organization_id,s.workspace_id,s.environment_id,'red_team_scheduled_run',seed_value);
   key_value:='schedule:'||encode(digest(convert_to(seed_value,'UTF8'),'sha256'),'hex');
   digest_value:=digest(convert_to(jsonb_build_object('definition_id',s.definition_id,'definition_version',definition_row.version,'run_id',run_value)::text,'UTF8'),'sha256');
   INSERT INTO zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,requested_by,input_digest)
    VALUES(s.organization_id,s.workspace_id,s.environment_id,run_value,s.definition_id,definition_row.version,s.updated_by,digest_value) RETURNING * INTO run_row;
   payload_value:=jsonb_build_object('organization_id',s.organization_id,'workspace_id',s.workspace_id,'environment_id',s.environment_id,'run_id',run_value,'definition_id',s.definition_id,'definition_version',definition_row.version,'input_digest',encode(digest_value,'hex'));
   INSERT INTO zasp_red_team_outbox(organization_id,workspace_id,environment_id,outbox_id,deterministic_key,payload,payload_digest)
    VALUES(s.organization_id,s.workspace_id,s.environment_id,zasp_discovery_canonical_id(s.organization_id,s.workspace_id,s.environment_id,'red_team_outbox',run_value),'test-jobs:'||run_value,payload_value,digest(convert_to(payload_value::text,'UTF8'),'sha256'));
   PERFORM zasp_red_team_mutation_result(s.organization_id,s.workspace_id,s.environment_id,s.updated_by,'runTest',run_value,zasp_discovery_canonical_id(s.organization_id,s.workspace_id,s.environment_id,'red_team_scheduled_correlation',seed_value),key_value,zasp_red_team_run_json(run_row));
   UPDATE zasp_red_team_schedules SET next_run_at=next_value,target_fingerprint=fingerprint_value,last_run_id=run_value,last_trigger=trigger_value,last_outcome='queued',last_fired_at=transaction_timestamp()
    WHERE (organization_id,workspace_id,environment_id,definition_id)=(s.organization_id,s.workspace_id,s.environment_id,s.definition_id);
   queued:=queued+1;
  END LOOP;
  RETURN jsonb_build_object('examined',examined,'queued',queued);
 END $fire$;

 EXECUTE format('ALTER FUNCTION public.zasp_red_team_target_fingerprint(text,text,text,text) OWNER TO %I',owner_value);
 EXECUTE format('ALTER FUNCTION public.zasp_red_team_schedule_json(text,text,text,text) OWNER TO %I',owner_value);
 EXECUTE format('ALTER FUNCTION public.zasp_red_team_get_schedule(text,text,text,text) OWNER TO %I',owner_value);
 EXECUTE format('ALTER FUNCTION public.zasp_red_team_put_schedule(text,text,text,text,text,bigint,boolean,integer,boolean) OWNER TO %I',owner_value);
 EXECUTE format('ALTER FUNCTION public.zasp_red_team_fire_due_schedules(text,integer) OWNER TO %I',owner_value);
 REVOKE ALL ON FUNCTION public.zasp_red_team_target_fingerprint(text,text,text,text) FROM PUBLIC;
 REVOKE ALL ON FUNCTION public.zasp_red_team_schedule_json(text,text,text,text) FROM PUBLIC;
 REVOKE ALL ON FUNCTION public.zasp_red_team_get_schedule(text,text,text,text) FROM PUBLIC;
 REVOKE ALL ON FUNCTION public.zasp_red_team_put_schedule(text,text,text,text,text,bigint,boolean,integer,boolean) FROM PUBLIC;
 REVOKE ALL ON FUNCTION public.zasp_red_team_fire_due_schedules(text,integer) FROM PUBLIC;
 FOREACH api_role IN ARRAY ARRAY['zasp_security_agent_api','zasp_discovery_api'] LOOP
  EXECUTE format('GRANT EXECUTE ON FUNCTION public.zasp_red_team_get_schedule(text,text,text,text) TO %I',api_role);
  EXECUTE format('GRANT EXECUTE ON FUNCTION public.zasp_red_team_put_schedule(text,text,text,text,text,bigint,boolean,integer,boolean) TO %I',api_role);
 END LOOP;
 GRANT EXECUTE ON FUNCTION public.zasp_red_team_fire_due_schedules(text,integer) TO zasp_discovery_scheduler;
END $ws2_red_team_schedules$;

-- WS2d. A standalone red team run is executed where the linked test authority
-- is installed.
--
-- A run queued from the Red Team page (zasp_red_team_run_test) or by a
-- schedule (section WS2c) has no row in zasp_security_agent_test_links: it is
-- not a Security Agent test step. The worker protocols of the installed
-- linked authority (zasp_temporal71) admit only linked runs, by design: op01
-- refuses a run without a parent (zasp_temporal71.require_parent). The red
-- team worker therefore had no way to classify a standalone run there, and
-- never claimed one.
--
-- zasp_red_team_standalone_protocol is that classification for the red team
-- worker principal: 'standalone' for a run without a test link, 'linked' for
-- one with a link. It grants nothing. A standalone run is then claimed,
-- heartbeated, finished, retried and cancelled through the unchanged
-- zasp_red_team_* worker functions, each of which starts with
-- zasp_production_security_agent_existing_tests_legacy_run and so refuses a
-- linked run under the run lock; the adapter resolves its target through the
-- unchanged zasp_temporal68.standalone_resolve. A linked run keeps the
-- journaled protocol of the installed authority, untouched.
DO $ws2_red_team_standalone_protocol$
DECLARE owner_value text;
BEGIN
 SELECT pg_get_userbyid(relowner) INTO STRICT owner_value FROM pg_class WHERE oid='public.zasp_red_team_runs'::regclass;
 CREATE OR REPLACE FUNCTION public.zasp_red_team_standalone_protocol(organization_value text,workspace_value text,environment_value text,run_value text) RETURNS jsonb
 LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $protocol$
 DECLARE linked_value boolean:=false;
 BEGIN
  IF NOT COALESCE(zasp_red_team_principal_ready('zasp_red_team_worker') AND zasp_valid_product_id(organization_value) AND zasp_valid_product_id(workspace_value) AND zasp_valid_product_id(environment_value) AND zasp_valid_product_id(run_value),false) THEN
   RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='red team principal rejected';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value)) THEN
   RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='red team run unavailable';
  END IF;
  -- An installation older than the linked tests has no link table and no linked run.
  IF to_regclass('public.zasp_security_agent_test_links') IS NOT NULL THEN
   EXECUTE 'SELECT EXISTS(SELECT 1 FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,test_run_id)=($1,$2,$3,$4))' INTO linked_value USING organization_value,workspace_value,environment_value,run_value;
  END IF;
  RETURN jsonb_build_object('protocol',CASE WHEN linked_value THEN 'linked' ELSE 'standalone' END);
 END $protocol$;
 EXECUTE format('ALTER FUNCTION public.zasp_red_team_standalone_protocol(text,text,text,text) OWNER TO %I',owner_value);
 REVOKE ALL ON FUNCTION public.zasp_red_team_standalone_protocol(text,text,text,text) FROM PUBLIC;
 GRANT EXECUTE ON FUNCTION public.zasp_red_team_standalone_protocol(text,text,text,text) TO zasp_red_team_worker;
END $ws2_red_team_standalone_protocol$;

-- WS2e. Saving a schedule is audited.
--
-- zasp_red_team_put_schedule (section WS2c) wrote no audit row. It now writes
-- one row to zasp_red_team_audit in the same transaction as the save: the
-- actor, the definition as the resource and the saved schedule as the body
-- ({"schedule": ...}). The event kind is red_team_definition_updated: the
-- schedule is part of how the test definition runs, the public audit source
-- (zasp_audit_export_public_source_v1) already publishes that kind as
-- test.update, and the table's event kinds and that view are part of the
-- audit export source catalog, which this section leaves as it is.
--
-- Re-run: a function that already writes the row is left alone; one that does
-- not hold the anchor exactly once is refused.
DO $ws2_red_team_schedule_audit$
DECLARE put CONSTANT regprocedure:='public.zasp_red_team_put_schedule(text,text,text,text,text,bigint,boolean,integer,boolean)'::regprocedure;
 anchor CONSTANT text:='updated_by=EXCLUDED.updated_by,updated_at=transaction_timestamp();';
 audit CONSTANT text:=$audit$
  INSERT INTO zasp_red_team_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,receipt_id,actor_id,event_kind,resource_id,event_digest,body)
   SELECT organization_value,workspace_value,environment_value,
    zasp_discovery_canonical_id(organization_value,workspace_value,environment_value,'red_team_audit',saved.seed),
    zasp_discovery_canonical_id(organization_value,workspace_value,environment_value,'red_team_schedule_correlation',saved.seed),
    zasp_discovery_canonical_id(organization_value,workspace_value,environment_value,'red_team_receipt',saved.seed),
    actor_value,'red_team_definition_updated',definition_value,digest(convert_to(saved.body::text,'UTF8'),'sha256'),saved.body
   FROM(SELECT jsonb_build_object('schedule',zasp_red_team_schedule_json(organization_value,workspace_value,environment_value,definition_value)) AS body,
    concat_ws(chr(31),actor_value,'putTestSchedule',definition_value,(expected_version_value+1)::text) AS seed) saved;$audit$;
 d text;
BEGIN
 d:=pg_get_functiondef(put);
 IF position('putTestSchedule' in d)>0 THEN RETURN;END IF;
 IF (length(d)-length(replace(d,anchor,'')))/length(anchor)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team schedule predecessor changed';END IF;
 EXECUTE replace(d,anchor,anchor||audit);
END $ws2_red_team_schedule_audit$;

-- WS2f. The Red Team page reaches its tests and runs on the authorized API.
--
-- The API runs every statement of a request inside a checked request. Of the
-- red team functions only zasp_red_team_run_test and zasp_red_team_cancel_run
-- were left executable by the API role, behind the checked-request guard of
-- section X3; reading a test, creating or changing one and reading a run
-- (zasp_red_team_get_definition, _create_definition, _update_definition and
-- _get_run) were executable by nobody but their owner, so a person could list
-- tests and runs but not create a test, open one, or see what a run found.
--
-- The four functions get the same treatment as the two of section X3: their
-- first statement is zasp_authorization80.direct_guard (the request's own
-- Organization, Workspace, Environment and, for a write, principal), and the
-- security agent API role may execute them. Their own checks (principal,
-- versions, the non-production safety rule) follow unchanged, and the API
-- admits each statement only for its own operation and authorized object.
--
-- Re-run: a function that already holds the guard is left alone. A database
-- without the authorized schema is left as it is.
DO $ws2_red_team_api_functions$
DECLARE f record;d text;guarded text;
BEGIN
 IF to_regprocedure('zasp_authorization80.direct_guard(text,text,text,text)') IS NULL THEN RETURN;END IF;
 FOR f IN SELECT * FROM(VALUES
  ('public.zasp_red_team_get_definition(text,text,text,text)',''),
  ('public.zasp_red_team_get_run(text,text,text,text)',''),
  ('public.zasp_red_team_create_definition(text,text,text,text,text,text,text,text,text,jsonb,jsonb,text)',',actor_value'),
  ('public.zasp_red_team_update_definition(text,text,text,text,text,text,bigint,text,text,text,jsonb,jsonb,boolean,text)',',actor_value')
 ) v(signature,actor) LOOP
  d:=pg_get_functiondef(f.signature::regprocedure);
  IF position('zasp_authorization80.direct_guard' in d)=0 THEN
   guarded:=regexp_replace(d,'\mBEGIN\M','BEGIN PERFORM zasp_authorization80.direct_guard(organization_value,workspace_value,environment_value'||f.actor||');');
   IF guarded=d OR position('organization_value' in d)=0 OR(f.actor<>'' AND position('actor_value' in d)=0) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team api predecessor changed';END IF;
   EXECUTE guarded;
  END IF;
  EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zasp_security_agent_api',f.signature);
 END LOOP;
END $ws2_red_team_api_functions$;
