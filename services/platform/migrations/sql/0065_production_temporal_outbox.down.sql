DO $unused$ BEGIN
 IF EXISTS(SELECT 1 FROM zasp_temporal65.commands) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='outbox contains retained delivery evidence';END IF;
END $unused$;
DROP TRIGGER zasp_temporal65_capture ON public.zasp_security_agent_request_receipts;
DROP SCHEMA zasp_temporal65 CASCADE;
