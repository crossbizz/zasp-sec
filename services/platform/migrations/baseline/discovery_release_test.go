package baseline

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// The release of abandoned discovery runs (completion.sql, section N) against
// an installed and completed catalog. The scenario clones the newest
// committed discovery run of the database it is given into runs in every
// abandoned and not-abandoned shape, calls the release exactly as
// prepare_page does, and checks each run. Everything happens in one
// transaction that is rolled back.
//
// ZASP_BASELINE_RELEASE_TEST_DSN names a superuser connection to a database
// that holds at least one committed discovery run.
func TestAbandonedDiscoveryRunsAreReleasedOnlyWhenQuietAndUncommitted(t *testing.T) {
	dsn := os.Getenv("ZASP_BASELINE_RELEASE_TEST_DSN")
	if dsn == "" {
		t.Skip("ZASP_BASELINE_RELEASE_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, discoveryReleaseScenario, pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatalf("release scenario: %v", err)
	}
	rows, err := tx.Query(ctx, `SELECT label,problem FROM pg_temp.release_report ORDER BY label`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	checked := 0
	for rows.Next() {
		var label, problem string
		if err := rows.Scan(&label, &problem); err != nil {
			t.Fatal(err)
		}
		checked++
		if problem != "" {
			t.Errorf("%s: %s", label, problem)
		}
	}
	if rows.Err() != nil || checked != 14 {
		t.Fatalf("checked %d scenarios, err=%v", checked, rows.Err())
	}
}

const discoveryReleaseScenario = `
CREATE TEMP TABLE release_seed(label text PRIMARY KEY,job_id text,sync_id text,want_released boolean,want_reason text,want_state text,want_sync text,want_code text) ON COMMIT DROP;
CREATE TEMP TABLE release_report(label text PRIMARY KEY,problem text) ON COMMIT DROP;

-- One run cloned from the newest committed run. quiet is how long ago its
-- newest evidence was written. page: none, open, unknown or partial.
-- apply: none, open or committed. Triggers are off while seeding only.
CREATE FUNCTION pg_temp.seed(label_value text,state_value text,quiet interval,page text,apply_value text,outbox_state text,sync_state text,
 want_released boolean,want_reason text,want_state text,want_sync text,want_code text) RETURNS void LANGUAGE plpgsql AS $seed$
DECLARE t zasp_temporal72.runs%ROWTYPE;job text:='pid_'||gen_random_uuid();sync text:='pid_'||gen_random_uuid();box text:='pid_'||gen_random_uuid();at_value timestamptz:=clock_timestamp()-quiet;started timestamptz:=clock_timestamp()-quiet-interval '1 minute';generation_value bigint;
BEGIN
 SELECT r.* INTO STRICT t FROM zasp_temporal72.runs r WHERE r.state='succeeded' ORDER BY r.admitted_at DESC LIMIT 1;
 SET LOCAL session_replication_role=replica;
 INSERT INTO public.zasp_discovery_syncs SELECT(jsonb_populate_record(s,jsonb_build_object('id',sync,'idempotency_key','release-scenario-'||sync,'state',sync_state,'requested_at',started,'started_at',started,'snapshot_id',NULL,
  'completed_at',CASE WHEN sync_state='failed' THEN at_value END,'last_error',CASE WHEN sync_state='failed' THEN 'discovery outcome_unknown' END,'last_error_code',CASE WHEN sync_state='failed' THEN 'outcome_unknown' END))).*
  FROM public.zasp_discovery_syncs s WHERE(s.organization_id,s.workspace_id,s.environment_id,s.id)=(t.organization_id,t.workspace_id,t.environment_id,t.sync_id);
 INSERT INTO public.zasp_discovery_outbox SELECT(jsonb_populate_record(b,jsonb_build_object('id',box,'deterministic_key','sync:'||sync,'state',outbox_state,'created_at',started,'available_at',started,
  'published_at',CASE WHEN outbox_state='published' THEN at_value END,'provider_ack',CASE WHEN outbox_state='published' THEN 'ack' END))).*
  FROM public.zasp_discovery_outbox b WHERE(b.organization_id,b.workspace_id,b.environment_id,b.id)=(t.organization_id,t.workspace_id,t.environment_id,t.outbox_id);
 INSERT INTO zasp_temporal72.runs SELECT(jsonb_populate_record(t,jsonb_build_object('job_id',job,'sync_id',sync,'outbox_id',box,'state',state_value,'admitted_at',started,'deadline',started+interval '24 hours',
  'schedule_id',NULL,'scheduled_for',NULL,'checkpoint_version',0,'checkpoint_digest','','retry_not_before',NULL))).*;
 IF state_value<>'admitted' THEN
  SELECT greatest(COALESCE((SELECT max(generation) FROM public.zasp_discovery_snapshots WHERE(organization_id,workspace_id,environment_id,integration_id,source)=(t.organization_id,t.workspace_id,t.environment_id,t.integration_id,t.provider)),0),
   COALESCE((SELECT max(generation) FROM public.zasp_discovery_generation_reservations WHERE(organization_id,workspace_id,environment_id,integration_id,source)=(t.organization_id,t.workspace_id,t.environment_id,t.integration_id,t.provider)),0))+1 INTO generation_value;
  INSERT INTO public.zasp_discovery_generation_reservations(organization_id,workspace_id,environment_id,sync_id,integration_id,source,generation,snapshot_id,reserved_at)
  VALUES(t.organization_id,t.workspace_id,t.environment_id,sync,t.integration_id,t.provider,generation_value,'pid_'||gen_random_uuid(),started);
 END IF;
 IF page<>'none' THEN
  INSERT INTO zasp_temporal72.page_effects(organization_id,workspace_id,environment_id,job_id,expected_version,expected_digest,effect_id,prepared_at,result,record_digest,recorded_at)
  VALUES(t.organization_id,t.workspace_id,t.environment_id,job,0,'',encode(digest(job||'page','sha256'),'hex'),at_value,
   CASE page WHEN 'unknown' THEN '{"outcome":"outcome_unknown"}'::jsonb WHEN 'partial' THEN '{"outcome":"partial"}'::jsonb END,
   CASE WHEN page<>'open' THEN encode(digest(job||'receipt','sha256'),'hex') END,CASE WHEN page<>'open' THEN at_value END);
 END IF;
 IF apply_value<>'none' THEN
  INSERT INTO zasp_temporal72.apply_effects(organization_id,workspace_id,environment_id,job_id,effect_id,complete_digest,prepared_at,result,committed_at)
  VALUES(t.organization_id,t.workspace_id,t.environment_id,job,encode(digest(job||'apply','sha256'),'hex'),encode(digest(job||'complete','sha256'),'hex'),at_value,
   CASE WHEN apply_value='committed' THEN '{"outcome":"succeeded"}'::jsonb END,CASE WHEN apply_value='committed' THEN at_value END);
 END IF;
 SET LOCAL session_replication_role=origin;
 INSERT INTO release_seed VALUES(label_value,job,sync,want_released,want_reason,want_state,want_sync,want_code);
END $seed$;

-- A worker killed inside a page: released after ten quiet minutes, not before.
SELECT pg_temp.seed('01 page open, 11 min','collecting','11 minutes','open','none','published','running',true,'page_unresolved','outcome_unknown','failed','outcome_unknown');
SELECT pg_temp.seed('02 page open, 9 min','collecting','9 minutes','open','none','published','running',false,NULL,'collecting','running',NULL);
-- The same run after its workflow settled it: still an owner until released.
SELECT pg_temp.seed('03 settled unknown, 11 min','outcome_unknown','11 minutes','open','none','published','failed',true,'page_unresolved','outcome_unknown','failed','outcome_unknown');
SELECT pg_temp.seed('04 recorded unknown, 11 min','outcome_unknown','11 minutes','unknown','none','published','failed',true,'page_unresolved','outcome_unknown','failed','outcome_unknown');
-- An apply that did not commit is released; a committed one never is.
SELECT pg_temp.seed('05 apply open, 11 min','applying','11 minutes','partial','open','published','running',true,'apply_unresolved','outcome_unknown','failed','outcome_unknown');
SELECT pg_temp.seed('06 apply open, 9 min','applying','9 minutes','partial','open','published','running',false,NULL,'applying','running',NULL);
SELECT pg_temp.seed('07 apply committed, 2 h','applying','2 hours','partial','committed','published','running',false,NULL,'applying','running',NULL);
-- Between Activities the workflow may wait for a worker: 35 minutes.
SELECT pg_temp.seed('08 partial, 34 min','partial','34 minutes','partial','none','published','running',false,NULL,'partial','running',NULL);
SELECT pg_temp.seed('09 partial, 36 min','partial','36 minutes','partial','none','published','running',true,'idle','incomplete','failed','partial');
SELECT pg_temp.seed('10 retryable, 36 min','retryable','36 minutes','none','none','published','queued',true,'idle','incomplete','failed','partial');
-- Never started: only once its start was published.
SELECT pg_temp.seed('11 admitted published, 36 min','admitted','36 minutes','none','none','published','queued',true,'never_started','incomplete','failed','partial');
SELECT pg_temp.seed('12 admitted unpublished, 2 h','admitted','2 hours','none','none','pending','queued',false,NULL,'admitted','queued',NULL);
-- A terminal page outcome that was never settled keeps its outcome.
SELECT pg_temp.seed('13 denied unsettled, 11 min','denied','11 minutes','none','none','published','running',true,'ended_unsettled','denied','failed','partial');
-- The run that asks is never its own candidate.
SELECT pg_temp.seed('14 caller','admitted','2 hours','none','none','published','queued',false,NULL,'admitted','queued',NULL);

DO $run$
DECLARE t zasp_temporal72.runs%ROWTYPE;caller text;s release_seed%ROWTYPE;r zasp_temporal72.runs%ROWTYPE;d zasp_temporal72.releases%ROWTYPE;y public.zasp_discovery_syncs%ROWTYPE;owner boolean;problem text;first_count integer;second_count integer;
BEGIN
 SELECT x.* INTO STRICT t FROM zasp_temporal72.runs x WHERE x.state='succeeded' ORDER BY x.admitted_at DESC LIMIT 1;
 SELECT job_id INTO STRICT caller FROM release_seed WHERE label='14 caller';
 first_count:=zasp_temporal72.release_abandoned(t.organization_id,t.workspace_id,t.environment_id,t.integration_id,t.provider,caller);
 second_count:=zasp_temporal72.release_abandoned(t.organization_id,t.workspace_id,t.environment_id,t.integration_id,t.provider,caller);
 FOR s IN SELECT * FROM release_seed ORDER BY label LOOP
  problem:='';
  SELECT x.* INTO STRICT r FROM zasp_temporal72.runs x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.job_id)=(t.organization_id,t.workspace_id,t.environment_id,s.job_id);
  SELECT x.* INTO STRICT y FROM public.zasp_discovery_syncs x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.id)=(t.organization_id,t.workspace_id,t.environment_id,s.sync_id);
  SELECT x.* INTO d FROM zasp_temporal72.releases x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.job_id)=(t.organization_id,t.workspace_id,t.environment_id,s.job_id);
  SELECT EXISTS(SELECT 1 FROM zasp_temporal72.active_owners(t.organization_id) a WHERE a.job_id=s.job_id) INTO owner;
  IF(d.job_id IS NOT NULL)<>s.want_released THEN problem:=problem||format('released=%s; ',d.job_id IS NOT NULL);END IF;
  IF d.reason IS DISTINCT FROM s.want_reason THEN problem:=problem||format('reason=%s; ',d.reason);END IF;
  IF r.state<>s.want_state THEN problem:=problem||format('run state=%s; ',r.state);END IF;
  IF y.state<>s.want_sync THEN problem:=problem||format('sync state=%s; ',y.state);END IF;
  IF s.want_released THEN
   IF y.last_error_code IS DISTINCT FROM s.want_code THEN problem:=problem||format('sync code=%s; ',y.last_error_code);END IF;
   IF y.completed_at IS NULL THEN problem:=problem||'sync not completed; ';END IF;
   -- A sync the workflow had already failed keeps its own error text.
   IF s.label NOT LIKE '03%' AND s.label NOT LIKE '04%' AND y.last_error<>'discovery abandoned' THEN problem:=problem||format('sync error=%s; ',y.last_error);END IF;
   IF owner THEN problem:=problem||'still an active owner; ';END IF;
   IF EXISTS(SELECT 1 FROM zasp_temporal72.page_effects p WHERE p.job_id=s.job_id AND p.result IS NULL) THEN problem:=problem||'page effect still open; ';END IF;
   IF r.state IN('admitted','collecting','partial','retryable','complete','applying','succeeded') THEN problem:=problem||'run can still proceed; ';END IF;
   IF d.released_by_job_id<>caller OR d.uncertain<>(r.state='outcome_unknown') THEN problem:=problem||'release row inconsistent; ';END IF;
  ELSIF s.label LIKE '02%' OR s.label LIKE '06%' OR s.label LIKE '08%' THEN
   -- Not yet quiet: it keeps the integration.
   IF NOT owner THEN problem:=problem||'lost ownership early; ';END IF;
  END IF;
  INSERT INTO release_report VALUES(s.label,problem);
 END LOOP;
 IF first_count<(SELECT count(*) FROM release_seed WHERE want_released) OR second_count<>0 THEN
  UPDATE release_report SET problem=problem||format('release counts %s then %s; ',first_count,second_count) WHERE label='14 caller';
 END IF;
 -- The release record is immutable.
 BEGIN
  UPDATE zasp_temporal72.releases SET reason='idle';
  UPDATE release_report SET problem=problem||'release rows are mutable; ' WHERE label='14 caller';
 EXCEPTION WHEN SQLSTATE '55000' THEN NULL;END;
END $run$;
`
