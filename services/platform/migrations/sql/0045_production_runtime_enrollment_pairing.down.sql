-- Block new enrollments and batch inserts before checking retained provenance.
LOCK TABLE public.zasp_sensors,public.zasp_runtime_batch_authorities,public.zasp_runtime_sensor_pairings,public.zasp_runtime_batch_domains IN SHARE ROW EXCLUSIVE MODE;
DO $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>45) OR NOT public.zasp_production_runtime_enrollment_pairing_security_ready()
 OR public.zasp_production_runtime_enrollment_pairing_live_fingerprint()<>(SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_enrollment_pairing_fingerprint')
 OR EXISTS(SELECT 1 FROM public.zasp_runtime_sensor_pairings) OR EXISTS(SELECT 1 FROM public.zasp_runtime_batch_domains) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime enrollment pairing rollback rejected';
 END IF;
END
$guard$;
DROP FUNCTION public.zasp_production_runtime_session_evidence_readiness(text,text);
ALTER FUNCTION public.zasp_production_runtime_session_evidence_readiness_v44(text,text) RENAME TO zasp_production_runtime_session_evidence_readiness;
DROP FUNCTION public.zasp_runtime_public_create_sensor(text,text,text,text,text,text,text,text,text,bytea,text,bigint,bytea,bytea,bytea,timestamptz);
DROP FUNCTION public.zasp_runtime_public_create_sensor(text,text,text,text,text,text,text,text,text,bytea,text,bigint,bytea,bytea,bytea,timestamptz,text);
ALTER FUNCTION public.zasp_runtime_public_create_sensor_v44(text,text,text,text,text,text,text,text,text,bytea,text,bigint,bytea,bytea,bytea,timestamptz) RENAME TO zasp_runtime_public_create_sensor;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_public_create_sensor(text,text,text,text,text,text,text,text,text,bytea,text,bigint,bytea,bytea,bytea,timestamptz) TO zasp_discovery_api;
DROP FUNCTION public.zasp_runtime_public_sensor_value(text,text,text,text);
ALTER FUNCTION public.zasp_runtime_public_sensor_value_v44(text,text,text,text) RENAME TO zasp_runtime_public_sensor_value;
DROP TRIGGER zasp_runtime_batch_domain_insert ON public.zasp_runtime_batch_authorities;
DROP TABLE public.zasp_runtime_batch_domains;
DROP TABLE public.zasp_runtime_sensor_pairings;
DROP FUNCTION public.zasp_runtime_bind_batch_domain();
DROP FUNCTION public.zasp_runtime_pairing_immutable();
ALTER TABLE public.zasp_runtime_batch_authorities DROP CONSTRAINT zasp_runtime_batch_source_identity_v45;
ALTER TABLE public.zasp_sensors DROP CONSTRAINT zasp_sensor_kind_identity_v45;
DROP FUNCTION public.zasp_production_runtime_enrollment_pairing_readiness(text,text);
DROP FUNCTION public.zasp_production_runtime_enrollment_pairing_live_fingerprint();
DROP FUNCTION public.zasp_production_runtime_enrollment_pairing_security_ready();
DO $compatibility$
DECLARE definition text;prior text;function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 45','later_release."version" > 44'),'later."version">45','later."version">44'),'later."version" > 45','later."version" > 44');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime enrollment compatibility rollback rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;
DELETE FROM public.zasp_schema_metadata WHERE key='production_runtime_enrollment_pairing_fingerprint';
