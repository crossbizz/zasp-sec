DO $guard$
BEGIN
  IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>30)
     OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_approval_notification_fingerprint' AND value='38492f1a329e45c28f2cd982d59b952e5ba42963e7921e8d1711a7a4a2541a58')
     OR NOT public.zasp_production_approval_notification_security_ready()
     OR public.zasp_production_approval_notification_live_fingerprint()<>'38492f1a329e45c28f2cd982d59b952e5ba42963e7921e8d1711a7a4a2541a58'
     OR EXISTS(SELECT 1 FROM public.zasp_security_agent_approval_notifications) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='approval notification rollback rejected';
  END IF;
END
$guard$;

REVOKE ALL ON FUNCTION public.zasp_production_home_attention_readiness(text,text) FROM PUBLIC;
DROP FUNCTION public.zasp_production_home_attention_readiness(text,text);
ALTER FUNCTION public.zasp_production_home_attention_readiness_v29(text,text) RENAME TO zasp_production_home_attention_readiness;

DROP FUNCTION public.zasp_production_approval_notification_readiness(text,text);
DROP FUNCTION public.zasp_production_approval_notification_live_fingerprint();
DROP FUNCTION public.zasp_production_approval_notification_security_ready();
REVOKE ALL ON FUNCTION public.zasp_security_agent_claim_approval_notification(text,text,integer),public.zasp_security_agent_complete_approval_notification(text,text,text,text,text,text),public.zasp_security_agent_fail_approval_notification(text,text,text,text,text,text) FROM PUBLIC,zasp_security_agent_api;
DROP FUNCTION public.zasp_security_agent_claim_approval_notification(text,text,integer);
DROP FUNCTION public.zasp_security_agent_complete_approval_notification(text,text,text,text,text,text);
DROP FUNCTION public.zasp_security_agent_fail_approval_notification(text,text,text,text,text,text);
DROP TRIGGER zasp_security_agent_enqueue_approval_notification_v30 ON public.zasp_security_agent_approvals;
DROP FUNCTION public.zasp_security_agent_enqueue_approval_notification();
DROP TABLE public.zasp_security_agent_approval_notifications;
DELETE FROM public.zasp_schema_metadata WHERE key='production_approval_notification_fingerprint';
