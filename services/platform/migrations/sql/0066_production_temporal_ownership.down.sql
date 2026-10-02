DO $retained$ BEGIN
 RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Temporal ownership and retired authority evidence must be retained';
END $retained$;
