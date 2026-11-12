-- Approval-notification delivery, activated for the baseline.
--
-- The approval-maintenance profile shipped as an inactive candidate: nothing
-- installed it, its registration could never become active, every origin was
-- recorded as 'captured_inactive', and no function could activate an
-- Organization. Under the current authorization model the API may deliver
-- approval notifications only through this profile, so with it inactive no
-- notification was ever delivered and API readiness never passed.
--
-- generate.sh applies this file to the superuser installation, as
-- zasp_discovery_authority, after `up-approval-maintenance-profile`. The
-- profile's own signed-origin, delegation, reservation and settlement logic is
-- unchanged. This file adds only what activation needs.

-- An Organization delivers once it has an activation row that matches its
-- current authorization store and model, and the profile is active.
CREATE FUNCTION zasp_approval_maintenance.projection_active(o text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $projection_active$
 SELECT zasp_approval_maintenance.ready() IS TRUE AND EXISTS(
  SELECT 1 FROM zasp_approval_maintenance.projection_activations a
  JOIN zasp_authorization79.organizations v ON(v.organization_id,v.store_id,v.model_id)=(a.organization_id,a.store_id,a.model_id)
  JOIN zasp_approval_maintenance.registration r ON r.singleton AND r.checksum=a.source_checksum
  WHERE a.organization_id=o)
$projection_active$;

-- A validated origin with a genuine delegation starts 'active' in an activated
-- Organization. Everything else about admission is the profile's own code.
DO $admit$
DECLARE d text;needle text:=$n$CASE WHEN delegation_value IS NULL THEN 'paused_unsupported' ELSE 'captured_inactive' END,delegation_value) ON CONFLICT DO NOTHING;$n$;
BEGIN
 SELECT pg_get_functiondef('zasp_approval_maintenance.admit_with_origin(text,jsonb)'::regprocedure) INTO STRICT d;
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='approval admission predecessor changed';END IF;
 EXECUTE replace(d,needle,$r$CASE WHEN delegation_value IS NULL THEN 'paused_unsupported' WHEN zasp_approval_maintenance.projection_active(n.organization_id) THEN 'active' ELSE 'captured_inactive' END,delegation_value) ON CONFLICT DO NOTHING;$r$);
END $admit$;

-- Operator-only. Activates delivery for one Organization that is already bound
-- to an authorization store and model. It holds the Organization's projection
-- lock, records the activation against that exact store and model, promotes
-- the Organization's validated origins and touches the desired revision so the
-- projector writes the delivery grants.
--
-- The profile asks for a receipt that the old external writer was withdrawn.
-- A baseline installation never had one: the current authorization model
-- refuses the legacy delivery statement. The receipt is the digest of that
-- statement of fact.
CREATE FUNCTION zasp_approval_maintenance.activate_projection(o text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $activate$
DECLARE pin text;bound zasp_authorization79.organizations%ROWTYPE;existing zasp_approval_maintenance.projection_activations%ROWTYPE;
BEGIN
 IF zasp_approval_maintenance.operator() IS NOT TRUE OR zasp_approval_maintenance.ready() IS NOT TRUE OR public.zasp_valid_product_id(o) IS NOT TRUE THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval projection activation rejected';
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-auth79/'||o,0));
 SELECT checksum INTO STRICT pin FROM zasp_approval_maintenance.registration WHERE singleton;
 SELECT * INTO bound FROM zasp_authorization79.organizations WHERE organization_id=o;
 IF NOT FOUND OR bound.store_id IS NULL OR bound.model_id IS NULL THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='approval projection activation needs a bound organization';
 END IF;
 SELECT * INTO existing FROM zasp_approval_maintenance.projection_activations WHERE organization_id=o;
 IF FOUND THEN
  IF (existing.source_checksum,existing.store_id,existing.model_id) IS DISTINCT FROM(pin,bound.store_id,bound.model_id) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='approval projection activation changed';
  END IF;
 ELSE
  INSERT INTO zasp_approval_maintenance.projection_activations(organization_id,source_checksum,store_id,model_id,withdrawal_reference)
  VALUES(o,pin,bound.store_id,bound.model_id,encode(digest(convert_to('zasp baseline: the legacy approval-notification writer never ran','UTF8'),'sha256'),'hex'));
 END IF;
 UPDATE zasp_approval_maintenance.origins SET status='active' WHERE organization_id=o AND status='captured_inactive' AND delegation IS NOT NULL;
 PERFORM zasp_authorization79.touch(o);
 RETURN true;
END $activate$;

REVOKE ALL ON FUNCTION zasp_approval_maintenance.projection_active(text),zasp_approval_maintenance.activate_projection(text) FROM PUBLIC;

UPDATE zasp_approval_maintenance.registration SET active=true WHERE singleton;
