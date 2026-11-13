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
