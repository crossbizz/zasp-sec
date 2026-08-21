DO $guard$
BEGIN
  IF public.zasp_identity_administration_live_fingerprint()<>'b37f0ef3be47432d8fb60afb9c7f6c71f91f677fe16b412f1aa3bf28f02775a3'
     OR EXISTS(SELECT 1 FROM public.zasp_identity_administration_state WHERE used_at IS NOT NULL)
     OR EXISTS(SELECT 1 FROM public.zasp_identity_provider_mutations)
     OR EXISTS(SELECT 1 FROM public.zasp_identity_webhook_events) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='identity administration rollback rejected';
  END IF;
END
$guard$;

DROP FUNCTION public.zasp_identity_administration_readiness(text,text);
DROP FUNCTION public.zasp_identity_administration_live_fingerprint();
DROP FUNCTION public.zasp_identity_admin_security_ready();
DROP FUNCTION public.zasp_identity_admin_reconcile_deprovision(text,text,text,text,bytea,text);
DROP FUNCTION public.zasp_identity_admin_ack_secret(text,text,text);
DROP FUNCTION public.zasp_identity_admin_reveal_secret(text,text,text);
DROP FUNCTION public.zasp_identity_admin_connection_page(text,text,text,text,integer);
DROP FUNCTION public.zasp_identity_admin_complete_mutation(text,text,text,text,text,jsonb,text,bytea,bytea,bytea,timestamptz);
DROP FUNCTION public.zasp_identity_admin_mark_unknown(text,text,text,text,text);
DROP FUNCTION public.zasp_identity_admin_reserve_mutation(text,text,text,text,text,bytea,jsonb,text,text,text);
DROP FUNCTION public.zasp_identity_admin_intent_valid(text,jsonb);
DROP FUNCTION public.zasp_identity_admin_authorized(text,text);
REVOKE SELECT,UPDATE ON public.zasp_identity_memberships FROM zasp_discovery_authority;
REVOKE UPDATE ON public.zasp_product_sessions,public.zasp_product_api_tokens FROM zasp_discovery_authority;
REVOKE SELECT,DELETE ON public.zasp_authorized_scopes FROM zasp_discovery_authority;
REVOKE INSERT ON public.zasp_admin_audit FROM zasp_discovery_authority;
DELETE FROM public.zasp_schema_metadata WHERE key='identity_administration_fingerprint';
DROP TABLE public.zasp_identity_webhook_events;
DROP TABLE public.zasp_identity_secret_reveal_grants;
DROP TABLE public.zasp_identity_provider_mutations;
DROP TABLE public.zasp_identity_provider_connections;
DROP TABLE public.zasp_identity_administration_state;

DO $schema_marker$
BEGIN
  UPDATE public.zasp_schema_metadata SET value='security-agent-execution-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='identity-administration-v1';
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='identity administration schema marker drift';END IF;
END
$schema_marker$;
