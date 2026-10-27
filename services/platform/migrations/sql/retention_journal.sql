-- Independent complete future-only journal. No original evidence is updated.
REVOKE ALL ON SCHEMA zasp_retention_journal_v1 FROM PUBLIC;
CREATE TABLE zasp_retention_journal_v1.preimages(signature text PRIMARY KEY,target_oid oid NOT NULL UNIQUE,definition text NOT NULL,source text NOT NULL,owner_oid oid NOT NULL,acl text);
CREATE TABLE zasp_retention_journal_v1.successors(signature text PRIMARY KEY REFERENCES zasp_retention_journal_v1.preimages,definition text NOT NULL);
CREATE TABLE zasp_retention_journal_v1.registration(singleton boolean PRIMARY KEY CHECK(singleton),checksum text NOT NULL,parent_checksum text NOT NULL,catalog_digest text NOT NULL);
CREATE TABLE zasp_retention_journal_v1.scopes(organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,enrolled_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(organization_id,workspace_id,environment_id));
CREATE TABLE zasp_retention_journal_v1.executions(execution_id text PRIMARY KEY CHECK(execution_id~'^[0-9a-f]{64}$'),capability_hash text NOT NULL CHECK(capability_hash~'^[0-9a-f]{64}$'),login_oid oid NOT NULL,kind text NOT NULL CHECK(kind IN('raw-index','session-index-v1','session-index-v2')),binding jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE zasp_retention_journal_v1.admission_links(execution_id text NOT NULL REFERENCES zasp_retention_journal_v1.executions,admission_key text NOT NULL CHECK(admission_key~'^[0-9a-f]{64}$'),admission_id text NOT NULL UNIQUE REFERENCES zasp_retention_v1.index_admissions,ordinal integer NOT NULL CHECK(ordinal BETWEEN 0 AND 999),recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(execution_id,admission_key));
CREATE TABLE zasp_retention_journal_v1.requests(execution_id text PRIMARY KEY REFERENCES zasp_retention_journal_v1.executions,descriptor jsonb NOT NULL,reservation_digest text NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE zasp_retention_journal_v1.dispatches(execution_id text PRIMARY KEY REFERENCES zasp_retention_journal_v1.requests,dispatch_digest text NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE zasp_retention_journal_v1.terminals(execution_id text PRIMARY KEY REFERENCES zasp_retention_journal_v1.dispatches,observation jsonb NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE zasp_retention_journal_v1.inventories(execution_id text PRIMARY KEY REFERENCES zasp_retention_journal_v1.executions,admission_ids jsonb NOT NULL,request_count integer NOT NULL CHECK(request_count BETWEEN 0 AND 1),inventory_digest text NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE zasp_retention_journal_v1.partition_seals(execution_id text PRIMARY KEY REFERENCES zasp_retention_journal_v1.inventories,partition_digest text NOT NULL REFERENCES zasp_retention_v1.index_partitions(partition_digest),recorded_at timestamptz NOT NULL DEFAULT clock_timestamp());
-- Ephemeral authorizations are inaccessible to workers, excluded from epoch.
-- They are append-only; xid/backend identity prevents reuse after COMMIT.
CREATE TABLE zasp_retention_journal_v1.admission_authorizations(xid xid8 NOT NULL,backend integer NOT NULL,login_oid oid NOT NULL,execution_id text NOT NULL REFERENCES zasp_retention_journal_v1.executions,admission_key text NOT NULL,binding jsonb NOT NULL,PRIMARY KEY(execution_id,admission_key));
CREATE TABLE zasp_retention_journal_v1.settlement_authorizations(xid xid8 NOT NULL,backend integer NOT NULL,login_oid oid NOT NULL,execution_id text NOT NULL REFERENCES zasp_retention_journal_v1.executions,admission_ids jsonb NOT NULL,partition_digest text NOT NULL,PRIMARY KEY(xid,backend,execution_id));
INSERT INTO zasp_retention_journal_v1.preimages SELECT p.oid::regprocedure::text,p.oid,pg_get_functiondef(p.oid),p.prosrc,p.proowner,p.proacl::text FROM pg_proc p WHERE p.oid IN('zasp_retention_v1.fingerprint()'::regprocedure,'zasp_retention_v1.writers_drained(text,text,text)'::regprocedure,'zasp_retention_v1.writer_history(text,text,text)'::regprocedure);
DO $preimages$ BEGIN IF(SELECT count(*) FROM zasp_retention_journal_v1.preimages)<>3 OR EXISTS(SELECT 1 FROM zasp_retention_journal_v1.preimages WHERE owner_oid<>'zasp_discovery_authority'::regrole) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='journal exact original authority required';END IF;END $preimages$;
CREATE FUNCTION zasp_retention_journal_v1.binding(q jsonb) RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,public AS $binding$
 SELECT(q-ARRAY['lease_token','lease_expires_at','lease_until'])||jsonb_build_object('lease_token_digest',encode(digest(convert_to(q->>'lease_token','UTF8'),'sha256'),'hex'))
$binding$;
CREATE FUNCTION zasp_retention_journal_v1.catalog_digest() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $catalog$
 WITH facts(v) AS(
 SELECT concat_ws('|','namespace',nspowner::regrole::text,nspacl::text) FROM pg_namespace WHERE nspname='zasp_retention_journal_v1'
 UNION ALL SELECT concat_ws('|','function',p.oid::regprocedure::text,pg_get_functiondef(p.oid),p.proowner,p.proacl::text) FROM pg_proc p WHERE pronamespace='zasp_retention_journal_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','table',c.relname,c.relkind,c.relowner,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity) FROM pg_class c WHERE relnamespace='zasp_retention_journal_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,pg_get_expr(d.adbin,d.adrelid),a.attacl::text) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_retention_journal_v1'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_retention_journal_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','index',c.relname,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_retention_journal_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','policy',c.relname,p.polname,p.polcmd,p.polpermissive,p.polroles::text,pg_get_expr(p.polqual,polrelid),pg_get_expr(p.polwithcheck,polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_retention_journal_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','trigger',tgrelid::regclass::text,tgname,tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t WHERE NOT tgisinternal AND(tgrelid IN(SELECT oid FROM pg_class WHERE relnamespace='zasp_retention_journal_v1'::regnamespace) OR(tgrelid='zasp_retention_v1.index_admissions'::regclass AND tgname='zasp_retention_journal_v1_enrollment') OR(tgrelid='zasp_retention_v1.admission_settlements'::regclass AND tgname='zasp_retention_journal_v1_settlement'))
 UNION ALL SELECT concat_ws('|','preimage',signature,target_oid,definition,source,owner_oid,acl) FROM zasp_retention_journal_v1.preimages
 UNION ALL SELECT concat_ws('|','successor',s.signature,s.definition,pg_get_functiondef(p.oid),p.proowner,p.proacl::text) FROM zasp_retention_journal_v1.successors s JOIN pg_proc p ON p.oid=to_regprocedure(s.signature)
 UNION ALL SELECT concat_ws('|','authority',oid,rolname,rolcanlogin,rolinherit,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls) FROM pg_roles WHERE rolname='zasp_discovery_authority'
 ) SELECT encode(digest(convert_to(string_agg(v,E'\n' ORDER BY v),'UTF8'),'sha256'),'hex') FROM facts
$catalog$;
CREATE FUNCTION zasp_retention_journal_v1.raw_ready(pin text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $raw_ready$
 SELECT coalesce(pin='-- journal checksum' AND(SELECT count(*)=1 FROM zasp_retention_journal_v1.registration) AND EXISTS(SELECT 1 FROM zasp_retention_journal_v1.registration WHERE singleton AND checksum=pin AND parent_checksum='-- journal parent checksum' AND catalog_digest=zasp_retention_journal_v1.catalog_digest()) AND(SELECT count(*)=3 FROM zasp_retention_journal_v1.preimages) AND(SELECT count(*)=3 FROM zasp_retention_journal_v1.successors) AND NOT EXISTS(SELECT 1 FROM zasp_retention_journal_v1.successors s JOIN pg_proc p ON p.oid=to_regprocedure(s.signature) JOIN zasp_retention_journal_v1.preimages old USING(signature) WHERE s.definition<>pg_get_functiondef(p.oid) OR p.proowner<>old.owner_oid OR p.proacl::text IS DISTINCT FROM old.acl),false)
$raw_ready$;
CREATE FUNCTION zasp_retention_journal_v1.ready(pin text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $ready$
 SELECT zasp_retention_journal_v1.raw_ready(pin) AND zasp_retention_v1.caller_ready('runtime-index','-- journal parent checksum')
$ready$;
CREATE FUNCTION zasp_retention_journal_v1.require_execution(q jsonb,forward_value boolean) RETURNS zasp_retention_journal_v1.executions LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $execution$
DECLARE x zasp_retention_journal_v1.executions;BEGIN
 IF jsonb_typeof(q->'execution_id') IS DISTINCT FROM 'string' OR jsonb_typeof(q->'capability') IS DISTINCT FROM 'string' OR coalesce(q->>'execution_id','')!~'^[0-9a-f]{64}$' OR coalesce(q->>'capability','')!~'^[0-9a-f]{64}$' OR NOT zasp_retention_journal_v1.raw_ready('-- journal checksum') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='journal execution unavailable';END IF;
 SELECT * INTO x FROM zasp_retention_journal_v1.executions WHERE execution_id=q->>'execution_id' FOR UPDATE;
 IF NOT FOUND OR x.login_oid<>session_user::regrole OR x.capability_hash<>encode(digest(convert_to(q->>'capability','UTF8'),'sha256'),'hex') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='journal private execution required';END IF;
 IF forward_value THEN
  IF NOT zasp_retention_journal_v1.ready('-- journal checksum') OR current_setting('transaction_isolation')<>'read committed' OR(zasp_retention_journal_v1.binding(q->'binding')-'event_ids') IS DISTINCT FROM(x.binding-'event_ids') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='journal original forward binding required';END IF;
  IF x.kind='raw-index' THEN PERFORM zasp_retention_v1.check_index_lease(q->'binding');ELSE PERFORM zasp_retention_v1.check_session_index_lease(q->'binding');END IF;
 END IF;RETURN x;
END $execution$;
CREATE FUNCTION zasp_retention_journal_v1.enroll_scope(o text,w text,e text,pin text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $enroll$
BEGIN
 IF NOT zasp_authorization79.operator() OR NOT zasp_retention_journal_v1.raw_ready(pin) OR NOT zasp_retention_v1.effective_catalog_ready('-- journal parent checksum') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='journal original operator required';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-auth79/'||o,0));PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=o FOR UPDATE;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM zasp_retention_v1.scopes WHERE(organization_id,workspace_id,environment_id)=(o,w,e)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='journal original enrolled retention scope required';END IF;
 INSERT INTO zasp_retention_journal_v1.scopes VALUES(o,w,e,clock_timestamp()) ON CONFLICT DO NOTHING;RETURN true;
END $enroll$;
CREATE FUNCTION zasp_retention_journal_v1.begin_execution(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $begin$
DECLARE x zasp_retention_journal_v1.executions;b jsonb;BEGIN
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['execution_id','capability','kind','binding']) OR jsonb_typeof(q->'execution_id') IS DISTINCT FROM 'string' OR jsonb_typeof(q->'capability') IS DISTINCT FROM 'string' OR coalesce(q->>'execution_id','')!~'^[0-9a-f]{64}$' OR coalesce(q->>'capability','')!~'^[0-9a-f]{64}$' OR q->>'execution_id'=q->>'capability' OR coalesce(q->>'kind','') NOT IN('raw-index','session-index-v1','session-index-v2') OR NOT zasp_retention_journal_v1.ready('-- journal checksum') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='journal begin rejected';END IF;
 b:=q->'binding';IF q->>'kind'='raw-index' THEN PERFORM zasp_retention_v1.check_index_lease(b);ELSE PERFORM zasp_retention_v1.check_session_index_lease(b);IF(b->>'index_family') IS DISTINCT FROM(CASE q->>'kind' WHEN 'session-index-v1' THEN 'session-v1' ELSE 'sandbox-v2' END) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='journal family changed';END IF;END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_retention_journal_v1.scopes WHERE(organization_id,workspace_id,environment_id)=(b->>'organization_id',b->>'workspace_id',b->>'environment_id')) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='journal scope enrollment required';END IF;
 INSERT INTO zasp_retention_journal_v1.executions VALUES(q->>'execution_id',encode(digest(convert_to(q->>'capability','UTF8'),'sha256'),'hex'),session_user::regrole,q->>'kind',zasp_retention_journal_v1.binding(b),clock_timestamp()) ON CONFLICT DO NOTHING;
 x:=zasp_retention_journal_v1.require_execution(q,true);
 IF x.kind<>q->>'kind' OR x.binding IS DISTINCT FROM zasp_retention_journal_v1.binding(b) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='journal execution replay changed';END IF;
 RETURN jsonb_build_object('execution_id',x.execution_id,'state','begun');
END $begin$;
CREATE FUNCTION zasp_retention_journal_v1.enrollment_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $enrollment$
DECLARE a zasp_retention_journal_v1.admission_authorizations;x zasp_retention_journal_v1.executions;BEGIN
 -- Original visibility lease check and enroll_scope take this same org lock.
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-auth79/'||(NEW.binding->>'organization_id'),0));
 IF NOT EXISTS(SELECT 1 FROM zasp_retention_journal_v1.scopes WHERE(organization_id,workspace_id,environment_id)=(NEW.binding->>'organization_id',NEW.binding->>'workspace_id',NEW.binding->>'environment_id')) THEN RETURN NEW;END IF;
 IF NOT zasp_retention_journal_v1.raw_ready('-- journal checksum') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='journal enrollment catalog unavailable';END IF;
 SELECT auth.* INTO a FROM zasp_retention_journal_v1.admission_authorizations auth WHERE auth.xid=pg_current_xact_id() AND auth.backend=pg_backend_pid() AND auth.login_oid=session_user::regrole AND auth.binding=NEW.binding AND NOT EXISTS(SELECT 1 FROM zasp_retention_journal_v1.admission_links l WHERE(l.execution_id,l.admission_key)=(auth.execution_id,auth.admission_key));
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='journal admission transaction authorization required';END IF;
 SELECT * INTO STRICT x FROM zasp_retention_journal_v1.executions WHERE execution_id=a.execution_id;
 IF x.login_oid<>NEW.login_oid OR x.kind<>NEW.kind OR(x.binding-'event_ids') IS DISTINCT FROM(NEW.binding-'event_ids') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='journal admission binding changed';END IF;
 INSERT INTO zasp_retention_journal_v1.admission_links VALUES(x.execution_id,a.admission_key,NEW.admission_id,(SELECT count(*) FROM zasp_retention_journal_v1.admission_links WHERE execution_id=x.execution_id),clock_timestamp());RETURN NEW;
END $enrollment$;
CREATE FUNCTION zasp_retention_journal_v1.admit_execution(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $admit$
DECLARE x zasp_retention_journal_v1.executions;r jsonb;l zasp_retention_journal_v1.admission_links;BEGIN
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['execution_id','capability','admission_key','binding']) OR coalesce(q->>'admission_key','')!~'^[0-9a-f]{64}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='journal admission rejected';END IF;
 x:=zasp_retention_journal_v1.require_execution(q,true);
 IF EXISTS(SELECT 1 FROM zasp_retention_journal_v1.inventories WHERE execution_id=x.execution_id) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='journal inventory closed';END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements_text(q->'binding'->'event_ids') id WHERE NOT id=ANY(ARRAY(SELECT jsonb_array_elements_text(x.binding->'event_ids')))) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='journal original event set changed';END IF;
 SELECT * INTO l FROM zasp_retention_journal_v1.admission_links WHERE execution_id=x.execution_id AND admission_key=q->>'admission_key';
 IF FOUND THEN SELECT jsonb_build_object('admission_id',a.admission_id,'items',a.items) INTO r FROM zasp_retention_v1.index_admissions a WHERE a.admission_id=l.admission_id AND a.binding=zasp_retention_journal_v1.binding(q->'binding');IF r IS NULL THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='journal admission replay changed';END IF;RETURN r;END IF;
 INSERT INTO zasp_retention_journal_v1.admission_authorizations VALUES(pg_current_xact_id(),pg_backend_pid(),session_user::regrole,x.execution_id,q->>'admission_key',zasp_retention_journal_v1.binding(q->'binding'));
 IF x.kind='raw-index' THEN r:=zasp_retention_v1.index_visibility(q->'binding');ELSE r:=zasp_retention_v1.session_index_visibility(q->'binding');END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_retention_journal_v1.admission_links WHERE(execution_id,admission_key,admission_id)=(x.execution_id,q->>'admission_key',r->>'admission_id')) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='journal mandatory admission hook missing';END IF;RETURN r;
END $admit$;
CREATE FUNCTION zasp_retention_journal_v1.reserve_request(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $reserve$
DECLARE x zasp_retention_journal_v1.executions;d jsonb;r zasp_retention_journal_v1.requests;target_value text;BEGIN
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['execution_id','capability','binding','descriptor']) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='journal request rejected';END IF;
 x:=zasp_retention_journal_v1.require_execution(q,true);d:=q->'descriptor';target_value:=CASE x.kind WHEN 'raw-index' THEN 'zasp-runtime-events-v1' WHEN 'session-index-v1' THEN 'zasp-runtime-sessions-v1' ELSE 'zasp-runtime-sessions-v2' END;
 IF NOT zasp_sa_multistep_prior.closed(d,ARRAY['ordinal','method','target','path','query','media_type','body_sha256','body_length','document_ids','event_ids','admission_ids','original_reference','original_version_id','original_digest','serializer_profile'])
 OR EXISTS(SELECT 1 FROM jsonb_each(d-ARRAY['ordinal','body_length','document_ids','event_ids','admission_ids']) field WHERE jsonb_typeof(field.value)<>'string') OR jsonb_typeof(d->'body_length') IS DISTINCT FROM 'number'
 OR d->'ordinal' IS DISTINCT FROM '0'::jsonb OR d->>'method' IS DISTINCT FROM 'POST' OR d->>'target' IS DISTINCT FROM target_value OR d->>'path' IS DISTINCT FROM '/'||target_value||'/_bulk'
 OR coalesce(d->>'query','')!~'^refresh=wait_for&timeout=([1-9]|[1-5][0-9]|60)s$' OR d->>'media_type' IS DISTINCT FROM 'application/x-ndjson' OR coalesce(d->>'body_sha256','')!~'^[0-9a-f]{64}$'
 OR coalesce(d->>'body_length','')!~'^[1-9][0-9]{0,8}$' OR(d->>'body_length')::bigint>67108864 OR d->>'serializer_profile' IS DISTINCT FROM 'runtime-retained-bulk-v1'
 OR d->>'original_digest' IS DISTINCT FROM coalesce(x.binding->>'input_digest',x.binding->>'receipt_digest')
 OR d->>'original_reference' IS DISTINCT FROM coalesce(x.binding->>'input_reference',x.binding->>'receipt_reference') OR d->>'original_version_id' IS DISTINCT FROM coalesce(x.binding->>'input_version_id',x.binding->>'receipt_version')
 OR jsonb_typeof(d->'document_ids') IS DISTINCT FROM 'array' OR jsonb_typeof(d->'event_ids') IS DISTINCT FROM 'array' OR jsonb_typeof(d->'admission_ids') IS DISTINCT FROM 'array'
 OR EXISTS(SELECT 1 FROM jsonb_array_elements((d->'document_ids')||(d->'event_ids')||(d->'admission_ids')) v WHERE jsonb_typeof(v)<>'string')
 OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(d->'document_ids') v GROUP BY v HAVING count(*)<>1) OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(d->'event_ids') v GROUP BY v HAVING count(*)<>1) OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(d->'admission_ids') v GROUP BY v HAVING count(*)<>1)
 OR jsonb_array_length(d->'document_ids') NOT BETWEEN 1 AND 1000 OR jsonb_array_length(d->'event_ids')<>jsonb_array_length(d->'document_ids') OR jsonb_array_length(d->'admission_ids') NOT BETWEEN 1 AND 1000
 OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(d->'event_ids') id WHERE NOT id=ANY(ARRAY(SELECT jsonb_array_elements_text(x.binding->'event_ids'))))
 OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(d->'admission_ids') id WHERE NOT EXISTS(SELECT 1 FROM zasp_retention_journal_v1.admission_links l WHERE l.execution_id=x.execution_id AND l.admission_id=id))
 OR EXISTS(SELECT 1 FROM zasp_retention_journal_v1.inventories WHERE execution_id=x.execution_id)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='journal exact serialized request required';END IF;
 INSERT INTO zasp_retention_journal_v1.requests VALUES(x.execution_id,d,encode(digest(convert_to(d::text,'UTF8'),'sha256'),'hex'),clock_timestamp()) ON CONFLICT DO NOTHING;
 SELECT * INTO STRICT r FROM zasp_retention_journal_v1.requests WHERE execution_id=x.execution_id;
 IF r.descriptor IS DISTINCT FROM d THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='journal request replay changed';END IF;RETURN jsonb_build_object('reservation_digest',r.reservation_digest);
END $reserve$;
CREATE FUNCTION zasp_retention_journal_v1.claim_send(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $claim$
DECLARE x zasp_retention_journal_v1.executions;d text;first_value boolean;BEGIN
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['execution_id','capability','binding','reservation_digest']) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='journal dispatch rejected';END IF;
 x:=zasp_retention_journal_v1.require_execution(q,true);
 IF NOT EXISTS(SELECT 1 FROM zasp_retention_journal_v1.requests WHERE execution_id=x.execution_id AND reservation_digest=q->>'reservation_digest') OR EXISTS(SELECT 1 FROM zasp_retention_journal_v1.inventories WHERE execution_id=x.execution_id) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='journal reserved dispatch required';END IF;
 d:=encode(digest(convert_to('retention-journal-dispatch-v1/'||x.execution_id||'/'||(q->>'reservation_digest'),'UTF8'),'sha256'),'hex');
 INSERT INTO zasp_retention_journal_v1.dispatches VALUES(x.execution_id,d,clock_timestamp()) ON CONFLICT DO NOTHING;first_value:=FOUND;
 RETURN jsonb_build_object('send_permitted',first_value,'dispatch_digest',d);
END $claim$;
-- Receipt writer and original archive/receipt source share the deployed raw
-- bucket. A sibling/foreign bucket or URI suffix cannot supply typed custody.
CREATE FUNCTION zasp_retention_journal_v1.canonical_terminal_reference(b jsonb,reference_value text) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,public AS $terminal_reference$
DECLARE bucket_value text;prefix_value text;artifact_value text;BEGIN
 bucket_value:=substring(coalesce(b->>'input_reference',b->>'receipt_reference','') FROM '^s3://([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])/[^?#[:space:]]+$');
 IF bucket_value IS NULL OR bucket_value LIKE '%..%' THEN RETURN false;END IF;
 prefix_value:='s3://'||bucket_value||'/organizations/'||(b->>'organization_id')||'/workspaces/'||(b->>'workspace_id')||'/environments/'||(b->>'environment_id')||'/artifacts/';
 artifact_value:=substring(reference_value FROM length(prefix_value)+1);
 RETURN coalesce(reference_value=prefix_value||artifact_value AND public.zasp_valid_product_id(artifact_value),false);
END $terminal_reference$;
CREATE FUNCTION zasp_retention_journal_v1.append_terminal(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $terminal$
DECLARE x zasp_retention_journal_v1.executions;o jsonb;BEGIN
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['execution_id','capability','observation']) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='journal observation rejected';END IF;
 x:=zasp_retention_journal_v1.require_execution(q,false);o:=q->'observation';
 IF NOT zasp_sa_multistep_prior.closed(o,ARRAY['reservation_digest','dispatch_digest','reference','version_id','sha256','length','http_status','validator_profile'])
 OR EXISTS(SELECT 1 FROM jsonb_each(o-ARRAY['http_status','length']) field WHERE jsonb_typeof(field.value)<>'string') OR jsonb_typeof(o->'length') IS DISTINCT FROM 'number'
 OR o->'http_status' IS DISTINCT FROM '200'::jsonb OR o->>'validator_profile' IS DISTINCT FROM 'runtime-retained-terminal-v1' OR coalesce(o->>'sha256','')!~'^[0-9a-f]{64}$'
 OR NOT zasp_retention_journal_v1.canonical_terminal_reference(x.binding,o->>'reference') OR length(coalesce(o->>'version_id','')) NOT BETWEEN 1 AND 1024 OR coalesce(o->>'length','')!~'^[1-9][0-9]{0,8}$' OR(o->>'length')::bigint>67108864
 OR NOT EXISTS(SELECT 1 FROM zasp_retention_journal_v1.requests r JOIN zasp_retention_journal_v1.dispatches d USING(execution_id) WHERE r.execution_id=x.execution_id AND r.reservation_digest=o->>'reservation_digest' AND d.dispatch_digest=o->>'dispatch_digest')
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='journal exact captured terminal required';END IF;
 INSERT INTO zasp_retention_journal_v1.terminals VALUES(x.execution_id,o,clock_timestamp()) ON CONFLICT DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM zasp_retention_journal_v1.terminals WHERE execution_id=x.execution_id AND observation=o) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='journal terminal replay changed';END IF;RETURN jsonb_build_object('recorded',true);
END $terminal$;
CREATE FUNCTION zasp_retention_journal_v1.close_inventory(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $inventory$
DECLARE x zasp_retention_journal_v1.executions;ids jsonb;n integer;d text;BEGIN
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['execution_id','capability','binding','admission_ids','request_count']) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='journal inventory rejected';END IF;
 x:=zasp_retention_journal_v1.require_execution(q,true);
 SELECT coalesce(jsonb_agg(admission_id ORDER BY ordinal),'[]') INTO ids FROM zasp_retention_journal_v1.admission_links WHERE execution_id=x.execution_id;
 SELECT count(*) INTO n FROM zasp_retention_journal_v1.requests WHERE execution_id=x.execution_id;
 IF q->'admission_ids' IS DISTINCT FROM ids OR jsonb_array_length(ids) NOT BETWEEN 1 AND 1000 OR q->'request_count' IS DISTINCT FROM to_jsonb(n) OR(n=1 AND NOT EXISTS(SELECT 1 FROM zasp_retention_journal_v1.terminals WHERE execution_id=x.execution_id)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='journal complete inventory required';END IF;
 d:=encode(digest(convert_to(jsonb_build_object('admission_ids',ids,'request_count',n)::text,'UTF8'),'sha256'),'hex');
 INSERT INTO zasp_retention_journal_v1.inventories VALUES(x.execution_id,ids,n,d,clock_timestamp()) ON CONFLICT DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM zasp_retention_journal_v1.inventories WHERE execution_id=x.execution_id AND admission_ids=ids AND request_count=n AND inventory_digest=d) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='journal inventory replay changed';END IF;RETURN jsonb_build_object('inventory_digest',d);
END $inventory$;
CREATE FUNCTION zasp_retention_journal_v1.settlement_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $settlement$
DECLARE l zasp_retention_journal_v1.admission_links;BEGIN
 IF NOT zasp_retention_journal_v1.raw_ready('-- journal checksum') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='journal settlement catalog unavailable';END IF;
 -- BEFORE INSERT also runs for the original immutable ON CONFLICT replay.
 -- An exact existing pair creates no new settlement or historical evidence.
 IF EXISTS(SELECT 1 FROM zasp_retention_v1.admission_settlements settled WHERE(settled.admission_id,settled.partition_digest)=(NEW.admission_id,NEW.partition_digest)) THEN RETURN NEW;END IF;
 SELECT * INTO l FROM zasp_retention_journal_v1.admission_links WHERE admission_id=NEW.admission_id;
 IF NOT FOUND THEN
  IF EXISTS(SELECT 1 FROM zasp_retention_v1.index_admissions a JOIN zasp_retention_journal_v1.scopes s ON(s.organization_id,s.workspace_id,s.environment_id)=(a.binding->>'organization_id',a.binding->>'workspace_id',a.binding->>'environment_id') WHERE a.admission_id=NEW.admission_id) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='journal historical admission cannot be newly resolved';END IF;RETURN NEW;END IF;
 IF NOT zasp_retention_journal_v1.raw_ready('-- journal checksum') OR NOT EXISTS(SELECT 1 FROM zasp_retention_journal_v1.settlement_authorizations a WHERE a.xid=pg_current_xact_id() AND a.backend=pg_backend_pid() AND a.login_oid=session_user::regrole AND a.execution_id=l.execution_id AND a.partition_digest=NEW.partition_digest AND a.admission_ids ? NEW.admission_id) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='journal exact partition transaction required';END IF;RETURN NEW;
END $settlement$;
CREATE FUNCTION zasp_retention_journal_v1.seal_partition(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $partition$
DECLARE x zasp_retention_journal_v1.executions;p jsonb;b jsonb;i zasp_retention_journal_v1.inventories;r zasp_retention_journal_v1.requests;expected text;out_value jsonb;BEGIN
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['execution_id','capability','partition']) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='journal partition rejected';END IF;
 p:=q->'partition';b:=p-ARRAY['full_document_ids','written_document_ids','suppressed_document_ids','original_content_digest','provider_content_digest','admission_ids'];
 x:=zasp_retention_journal_v1.require_execution((q-'partition')||jsonb_build_object('binding',b),true);
 SELECT * INTO i FROM zasp_retention_journal_v1.inventories WHERE execution_id=x.execution_id;
 IF NOT FOUND OR i.admission_ids IS DISTINCT FROM p->'admission_ids' OR x.binding IS DISTINCT FROM zasp_retention_journal_v1.binding(b) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='journal exact closed original partition required';END IF;
 SELECT * INTO r FROM zasp_retention_journal_v1.requests WHERE execution_id=x.execution_id;
 IF i.request_count=0 THEN
  IF p->'written_document_ids' IS DISTINCT FROM '[]'::jsonb THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='journal missing dispatch inventory';END IF;
 ELSE
  IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM zasp_retention_journal_v1.terminals WHERE execution_id=x.execution_id) OR r.descriptor->'document_ids' IS DISTINCT FROM p->'written_document_ids' OR r.descriptor->'event_ids' IS DISTINCT FROM(SELECT coalesce(jsonb_agg(event ORDER BY ordinal),'[]') FROM jsonb_array_elements_text(p->'full_document_ids') WITH ORDINALITY d(doc,ordinal) JOIN jsonb_array_elements_text(p->'event_ids') WITH ORDINALITY ev(event,ordinal) USING(ordinal) WHERE p->'written_document_ids' ? doc) OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(r.descriptor->'admission_ids') id WHERE NOT i.admission_ids ? id) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='journal terminal request partition changed';END IF;
 END IF;
 expected:=encode(digest(convert_to(zasp_retention_journal_v1.binding(p-'admission_ids')::text,'UTF8'),'sha256'),'hex');
 INSERT INTO zasp_retention_journal_v1.settlement_authorizations VALUES(pg_current_xact_id(),pg_backend_pid(),session_user::regrole,x.execution_id,i.admission_ids,expected) ON CONFLICT DO NOTHING;
 IF x.kind='raw-index' THEN out_value:=zasp_retention_v1.record_index_partition(p);ELSE out_value:=zasp_retention_v1.record_session_index_partition(p);END IF;
 IF out_value->>'partition_digest' IS DISTINCT FROM expected THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='journal original partition digest changed';END IF;
 INSERT INTO zasp_retention_journal_v1.partition_seals VALUES(x.execution_id,expected,clock_timestamp()) ON CONFLICT DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM zasp_retention_journal_v1.partition_seals WHERE execution_id=x.execution_id AND partition_digest=expected) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='journal sealed partition replay changed';END IF;RETURN out_value;
END $partition$;
CREATE FUNCTION zasp_retention_journal_v1.execution_status(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $status$
DECLARE x zasp_retention_journal_v1.executions;BEGIN
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['execution_id','capability']) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='journal lookup rejected';END IF;
 x:=zasp_retention_journal_v1.require_execution(q,false);
 RETURN jsonb_build_object('execution_id',x.execution_id,'kind',x.kind,'binding',x.binding,'descriptor',(SELECT descriptor FROM zasp_retention_journal_v1.requests WHERE execution_id=x.execution_id),'inventory',(SELECT jsonb_build_object('admission_ids',admission_ids,'request_count',request_count,'inventory_digest',inventory_digest) FROM zasp_retention_journal_v1.inventories WHERE execution_id=x.execution_id),'partition',(SELECT p.binding FROM zasp_retention_journal_v1.partition_seals s JOIN zasp_retention_v1.index_partitions p USING(partition_digest) WHERE s.execution_id=x.execution_id),'state',CASE WHEN EXISTS(SELECT 1 FROM zasp_retention_journal_v1.partition_seals WHERE execution_id=x.execution_id) THEN 'sealed' WHEN EXISTS(SELECT 1 FROM zasp_retention_journal_v1.inventories WHERE execution_id=x.execution_id) THEN 'closed' WHEN EXISTS(SELECT 1 FROM zasp_retention_journal_v1.terminals WHERE execution_id=x.execution_id) THEN 'terminal' WHEN EXISTS(SELECT 1 FROM zasp_retention_journal_v1.dispatches WHERE execution_id=x.execution_id) THEN 'dispatched' WHEN EXISTS(SELECT 1 FROM zasp_retention_journal_v1.requests WHERE execution_id=x.execution_id) THEN 'reserved' ELSE 'begun' END,
 'admissions',(SELECT coalesce(jsonb_agg(jsonb_build_object('admission_key',l.admission_key,'admission_id',l.admission_id,'items',a.items) ORDER BY l.ordinal),'[]') FROM zasp_retention_journal_v1.admission_links l JOIN zasp_retention_v1.index_admissions a USING(admission_id) WHERE l.execution_id=x.execution_id),
 'reservation_digest',(SELECT reservation_digest FROM zasp_retention_journal_v1.requests WHERE execution_id=x.execution_id),'dispatch_digest',(SELECT dispatch_digest FROM zasp_retention_journal_v1.dispatches WHERE execution_id=x.execution_id),'terminal',(SELECT observation FROM zasp_retention_journal_v1.terminals WHERE execution_id=x.execution_id),'inventory_digest',(SELECT inventory_digest FROM zasp_retention_journal_v1.inventories WHERE execution_id=x.execution_id),'partition_digest',(SELECT partition_digest FROM zasp_retention_journal_v1.partition_seals WHERE execution_id=x.execution_id),'send_permitted',false);
END $status$;
-- Materialize exact original live history bodies under sealed helper names.
-- Original results are recomputed on every call, never cached as truth.
DO $original_helpers$ DECLARE p record;name_value text;d text;BEGIN
 FOR p IN SELECT * FROM zasp_retention_journal_v1.preimages WHERE signature<>'zasp_retention_v1.fingerprint()' ORDER BY signature LOOP
  name_value:=split_part(p.signature,'(',1);
  d:=zasp_retention_v1.replace_exact(p.definition,'FUNCTION '||name_value||'(','FUNCTION zasp_retention_journal_v1.original_'||substring(name_value FROM length('zasp_retention_v1.')+1)||'(',1);EXECUTE d;
 END LOOP;
END $original_helpers$;
CREATE FUNCTION zasp_retention_journal_v1.journal_drained(o text,w text,e text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $journal_drained$
 SELECT zasp_retention_journal_v1.raw_ready('-- journal checksum') AND NOT EXISTS(
 SELECT 1 FROM zasp_retention_journal_v1.executions x LEFT JOIN zasp_retention_journal_v1.inventories i USING(execution_id) LEFT JOIN zasp_retention_journal_v1.partition_seals s USING(execution_id)
 WHERE(x.binding->>'organization_id',x.binding->>'workspace_id',x.binding->>'environment_id')=(o,w,e)
 AND(i.execution_id IS NULL OR s.execution_id IS NULL OR NOT EXISTS(SELECT 1 FROM zasp_retention_v1.partition_completions c WHERE c.partition_digest=s.partition_digest)
 OR(i.request_count=1 AND NOT EXISTS(SELECT 1 FROM zasp_retention_journal_v1.dispatches d JOIN zasp_retention_journal_v1.terminals t USING(execution_id) WHERE d.execution_id=x.execution_id))
 OR EXISTS(SELECT 1 FROM zasp_retention_journal_v1.admission_links l WHERE l.execution_id=x.execution_id AND NOT EXISTS(SELECT 1 FROM zasp_retention_v1.admission_settlements a WHERE a.admission_id=l.admission_id AND a.partition_digest=s.partition_digest))))
$journal_drained$;
CREATE FUNCTION zasp_retention_journal_v1.journal_history(o text,w text,e text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public SET timezone='UTC' AS $journal_history$
DECLARE old_value jsonb;digest_value text;max_value timestamptz;BEGIN
 IF NOT zasp_retention_journal_v1.raw_ready('-- journal checksum') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='journal history catalog unavailable';END IF;
 old_value:=zasp_retention_journal_v1.original_writer_history(o,w,e);
 WITH selected AS(SELECT * FROM zasp_retention_journal_v1.executions x WHERE(x.binding->>'organization_id',x.binding->>'workspace_id',x.binding->>'environment_id')=(o,w,e)),facts(v) AS(
 SELECT concat_ws('|','scope',to_jsonb(s)::text) FROM zasp_retention_journal_v1.scopes s WHERE(s.organization_id,s.workspace_id,s.environment_id)=(o,w,e)
 UNION ALL SELECT concat_ws('|','execution',(to_jsonb(x)-'capability_hash')::text) FROM selected x
 UNION ALL SELECT concat_ws('|','admission',to_jsonb(a)::text) FROM zasp_retention_journal_v1.admission_links a JOIN selected USING(execution_id)
 UNION ALL SELECT concat_ws('|','request',to_jsonb(r)::text) FROM zasp_retention_journal_v1.requests r JOIN selected USING(execution_id)
 UNION ALL SELECT concat_ws('|','dispatch',to_jsonb(d)::text) FROM zasp_retention_journal_v1.dispatches d JOIN selected USING(execution_id)
 UNION ALL SELECT concat_ws('|','terminal',to_jsonb(t)::text) FROM zasp_retention_journal_v1.terminals t JOIN selected USING(execution_id)
 UNION ALL SELECT concat_ws('|','inventory',to_jsonb(i)::text) FROM zasp_retention_journal_v1.inventories i JOIN selected USING(execution_id)
 UNION ALL SELECT concat_ws('|','seal',to_jsonb(s)::text) FROM zasp_retention_journal_v1.partition_seals s JOIN selected USING(execution_id)
 ) SELECT encode(digest(convert_to('retention-journal-history-v1/'||(old_value->>'history_digest')||'/'||coalesce(string_agg(v,E'\n' ORDER BY v),''),'UTF8'),'sha256'),'hex') INTO digest_value FROM facts;
 SELECT greatest((old_value->>'max_completion_at')::timestamptz,max(s.recorded_at)) INTO max_value FROM zasp_retention_journal_v1.partition_seals s JOIN zasp_retention_journal_v1.executions x USING(execution_id) WHERE(x.binding->>'organization_id',x.binding->>'workspace_id',x.binding->>'environment_id')=(o,w,e);
 RETURN jsonb_build_object('history_digest',digest_value,'max_completion_at',max_value);
END $journal_history$;
-- Exactly these three owned successors and exactly these two trigger tuples
-- are projected by the original complete live fingerprint query.
DO $successors$ DECLARE p zasp_retention_journal_v1.preimages;d text;BEGIN
 SELECT * INTO STRICT p FROM zasp_retention_journal_v1.preimages WHERE signature='zasp_retention_v1.fingerprint()';
 d:=zasp_retention_v1.replace_exact(p.definition,
 'p.oid::regprocedure::text,pg_get_functiondef(p.oid),p.proowner::regrole::text,p.proacl::text) FROM pg_proc p WHERE pronamespace=',
 'p.oid::regprocedure::text,coalesce((SELECT definition FROM zasp_retention_journal_v1.preimages WHERE target_oid=p.oid),pg_get_functiondef(p.oid)),p.proowner::regrole::text,p.proacl::text) FROM pg_proc p WHERE pronamespace=',1);
 d:=zasp_retention_v1.replace_exact(d,
 'AND NOT t.tgisinternal',
 'AND NOT t.tgisinternal AND NOT((t.tgrelid=''zasp_retention_v1.index_admissions''::regclass AND t.tgname=''zasp_retention_journal_v1_enrollment'') OR(t.tgrelid=''zasp_retention_v1.admission_settlements''::regclass AND t.tgname=''zasp_retention_journal_v1_settlement''))',1);
 d:=zasp_retention_v1.replace_exact(d,'FROM facts', 'FROM facts WHERE zasp_retention_journal_v1.raw_ready(''-- journal checksum'')',1);EXECUTE d;
 EXECUTE 'CREATE OR REPLACE FUNCTION zasp_retention_v1.writers_drained(o text,w text,e text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS '||quote_literal('SELECT zasp_retention_journal_v1.original_writers_drained(o,w,e) AND zasp_retention_journal_v1.journal_drained(o,w,e)');
 EXECUTE 'CREATE OR REPLACE FUNCTION zasp_retention_v1.writer_history(o text,w text,e text) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS '||quote_literal('SELECT zasp_retention_journal_v1.journal_history(o,w,e)');
 INSERT INTO zasp_retention_journal_v1.successors SELECT signature,pg_get_functiondef(target_oid) FROM zasp_retention_journal_v1.preimages;
END $successors$;
CREATE TRIGGER zasp_retention_journal_v1_enrollment AFTER INSERT ON zasp_retention_v1.index_admissions FOR EACH ROW EXECUTE FUNCTION zasp_retention_journal_v1.enrollment_guard();
CREATE TRIGGER zasp_retention_journal_v1_settlement BEFORE INSERT ON zasp_retention_v1.admission_settlements FOR EACH ROW EXECUTE FUNCTION zasp_retention_journal_v1.settlement_guard();
DO $journal_permissions$ DECLARE n record;g record;login_value text;BEGIN
 -- New objects may inherit non-PUBLIC grants from existing default ACLs.
 -- Normalize only these new objects; leave unrelated default rules untouched.
 FOR g IN SELECT DISTINCT a.grantee FROM pg_namespace n CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a WHERE n.nspname='zasp_retention_journal_v1' AND a.grantee<>n.nspowner LOOP
  IF g.grantee=0 THEN REVOKE ALL ON SCHEMA zasp_retention_journal_v1 FROM PUBLIC;ELSE EXECUTE format('REVOKE ALL ON SCHEMA zasp_retention_journal_v1 FROM %I',pg_get_userbyid(g.grantee));END IF;
 END LOOP;
 FOR n IN SELECT c.oid,c.relname,c.relowner,c.relacl FROM pg_class c JOIN pg_namespace ns ON ns.oid=c.relnamespace WHERE ns.nspname='zasp_retention_journal_v1' AND c.relkind='r' LOOP
  FOR g IN SELECT DISTINCT a.grantee FROM pg_catalog.aclexplode(coalesce(n.relacl,pg_catalog.acldefault('r',n.relowner))) a WHERE a.grantee<>n.relowner LOOP
   IF g.grantee=0 THEN EXECUTE format('REVOKE ALL ON TABLE zasp_retention_journal_v1.%I FROM PUBLIC',n.relname);ELSE EXECUTE format('REVOKE ALL ON TABLE zasp_retention_journal_v1.%I FROM %I',n.relname,pg_get_userbyid(g.grantee));END IF;
  END LOOP;
 END LOOP;
 FOR n IN SELECT p.oid::regprocedure signature,p.proowner,p.proacl FROM pg_proc p WHERE pronamespace='zasp_retention_journal_v1'::regnamespace LOOP
  FOR g IN SELECT DISTINCT a.grantee FROM pg_catalog.aclexplode(coalesce(n.proacl,pg_catalog.acldefault('f',n.proowner))) a WHERE a.grantee<>n.proowner LOOP
   IF g.grantee=0 THEN EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',n.signature);ELSE EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',n.signature,pg_get_userbyid(g.grantee));END IF;
  END LOOP;
 END LOOP;
 FOR n IN SELECT tablename FROM pg_tables WHERE schemaname='zasp_retention_journal_v1' LOOP
  EXECUTE format('ALTER TABLE zasp_retention_journal_v1.%I ENABLE ROW LEVEL SECURITY',n.tablename);
  EXECUTE format('ALTER TABLE zasp_retention_journal_v1.%I FORCE ROW LEVEL SECURITY',n.tablename);
  EXECUTE format('CREATE POLICY authority ON zasp_retention_journal_v1.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',n.tablename);
  EXECUTE format('REVOKE ALL ON TABLE zasp_retention_journal_v1.%I FROM PUBLIC',n.tablename);
  EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_retention_journal_v1.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n.tablename);
 END LOOP;
 FOR n IN SELECT oid::regprocedure signature FROM pg_proc WHERE pronamespace='zasp_retention_journal_v1'::regnamespace LOOP EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',n.signature);END LOOP;
 -- Direct captured-only access survives removal of inherited index membership.
 -- This immutable original principal is already purpose registered by v1.
 SELECT login_name INTO STRICT login_value FROM zasp_retention_v1.principals WHERE purpose='runtime-index';
 EXECUTE format('GRANT USAGE ON SCHEMA zasp_retention_journal_v1 TO %I',login_value);
 EXECUTE format('GRANT EXECUTE ON FUNCTION zasp_retention_journal_v1.append_terminal(jsonb),zasp_retention_journal_v1.execution_status(jsonb) TO %I',login_value);
END $journal_permissions$;
GRANT USAGE ON SCHEMA zasp_retention_journal_v1 TO zasp_runtime_index_worker;
GRANT EXECUTE ON FUNCTION zasp_retention_journal_v1.ready(text),zasp_retention_journal_v1.begin_execution(jsonb),zasp_retention_journal_v1.admit_execution(jsonb),zasp_retention_journal_v1.reserve_request(jsonb),zasp_retention_journal_v1.claim_send(jsonb),zasp_retention_journal_v1.append_terminal(jsonb),zasp_retention_journal_v1.close_inventory(jsonb),zasp_retention_journal_v1.seal_partition(jsonb),zasp_retention_journal_v1.execution_status(jsonb) TO zasp_runtime_index_worker;
INSERT INTO zasp_retention_journal_v1.registration VALUES(true,'-- journal checksum','-- journal parent checksum',zasp_retention_journal_v1.catalog_digest());
