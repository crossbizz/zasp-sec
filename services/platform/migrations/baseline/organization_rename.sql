-- Change the product display name. The provider identity, login domain and
-- bootstrap configuration remain the identifiers used during provisioning.
CREATE OR REPLACE FUNCTION zasp_authorization80.rename_organization(
 o text, w text, e text, actor text, display_name text, expected_version bigint, audit_id text
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $rename_org$
DECLARE proof jsonb; result jsonb;
BEGIN
 proof := zasp_authorization80.product_request(o,w,e,actor,'updateOrganization','manage_identity','organization_identity',o,false,true,true,true);
 IF NOT COALESCE(public.zasp_valid_product_id(audit_id) AND expected_version > 0
  AND octet_length(display_name) BETWEEN 1 AND 128 AND display_name = btrim(display_name)
  AND display_name !~ '[[:cntrl:]]',false) THEN
  RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid organization display name update';
 END IF;
 UPDATE public.zasp_organizations AS org SET name=display_name,version=org.version+1
 WHERE org.id=o AND org.version=expected_version
 RETURNING jsonb_build_object('id',org.id,'name',org.name,'domain',org.domain,'version',org.version) INTO result;
 IF FOUND THEN
  INSERT INTO public.zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata)
  VALUES(o,w,e,audit_id,actor,'organization.update',o,'succeeded','{}'::jsonb);
 ELSIF EXISTS (SELECT 1 FROM public.zasp_organizations WHERE id=o) THEN
  result := jsonb_build_object('_mutation_state','conflict');
 ELSE
  result := jsonb_build_object('_mutation_state','not_found');
 END IF;
 PERFORM zasp_authorization80.product_settled(proof);
 RETURN result;
END $rename_org$;
ALTER FUNCTION zasp_authorization80.rename_organization(text,text,text,text,text,bigint,text) OWNER TO zasp_operator;
REVOKE ALL ON FUNCTION zasp_authorization80.rename_organization(text,text,text,text,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.rename_organization(text,text,text,text,text,bigint,text) TO zasp_discovery_api;
