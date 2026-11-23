-- The signed-in reviewer can recover their own completed ticket from a finding.
CREATE OR REPLACE FUNCTION zasp_authorization80.finding_with_ticket(o text,w text,e text,actor text,f text)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
DECLARE item jsonb; ticket text; pending_key text;
BEGIN
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['getFinding'],'view',false,actor);
 IF NOT zasp_authorization80.allowed(o,w,e,'finding',f) THEN RAISE EXCEPTION USING ERRCODE='42501'; END IF;
 item:=public.zasp_risk_finding_get(f,o,w,e);
 SELECT d.ticket_id,d.idempotency_key INTO ticket,pending_key FROM public.zasp_finding_ticket_deliveries d
 WHERE (d.organization_id,d.workspace_id,d.environment_id,d.principal_id,d.finding_id,d.expected_version)=
       (o,w,e,actor,f,(item->>'version')::bigint)
 ORDER BY (d.state='completed') DESC,d.updated_at DESC,d.delivery_id LIMIT 1;
 IF ticket IS NOT NULL THEN RETURN item||jsonb_build_object('current_ticket_id',ticket); END IF;
 IF pending_key IS NOT NULL THEN RETURN item||jsonb_build_object('pending_ticket_key',pending_key); END IF;
 RETURN item;
END $body$;
ALTER FUNCTION zasp_authorization80.finding_with_ticket(text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.finding_with_ticket(text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.finding_with_ticket(text,text,text,text,text) TO zasp_discovery_api;
