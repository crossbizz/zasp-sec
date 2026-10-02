DO $retained$
BEGIN
 IF EXISTS(SELECT 1 FROM zasp_ordered_worker63.dispatch_leases WHERE state<>'reconciled') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker dispatch unresolved';END IF;
END $retained$;
DROP FUNCTION zasp_ordered_worker63.worker(text,text,jsonb);
DROP FUNCTION zasp_ordered_worker63.dispatch(jsonb);
DROP FUNCTION zasp_ordered_worker63.recovery_class(text,text,text,text);
DROP FUNCTION zasp_ordered_worker63.handoff(jsonb);
DROP FUNCTION zasp_ordered_worker63.eligible(text,text,text,text,jsonb);
DROP FUNCTION zasp_ordered_worker63.pricing(text,text,text,jsonb);
DROP FUNCTION zasp_ordered_worker63.ready(text,text);
DROP FUNCTION zasp_ordered_worker63.fingerprint();
DROP TABLE zasp_ordered_worker63.registration;
DROP TABLE zasp_ordered_worker63.dispatch_leases;
DROP SCHEMA zasp_ordered_worker63;
