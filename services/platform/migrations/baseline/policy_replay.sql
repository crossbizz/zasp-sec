-- Replay reads at most ten pages. Each independently corroborated tool event
-- remains subject to the original agent/session/scope joins in this function.
DO $replay_budget$
DECLARE d text:=pg_get_functiondef('zasp_authorization80.agent_suggestions_refresh(text,text,text,text,text,bigint,jsonb)'::regprocedure);
 before_value text:='(input->>''examined'')::int BETWEEN 0 AND 100 AND jsonb_array_length';
 after_value text:='(input->>''examined'')::int BETWEEN 0 AND 5000 AND jsonb_array_length';
BEGIN
 IF position(after_value in d)>0 THEN RETURN;END IF;
 IF length(d)-length(replace(d,before_value,''))<>length(before_value) THEN RAISE EXCEPTION 'unsupported suggestion replay predecessor'; END IF;
 EXECUTE replace(d,before_value,after_value);
END $replay_budget$;
