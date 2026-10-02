package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// These are retained, reachable single-step compatibility writers. Their rows
// are explicit owner fixtures, not evidence of admitted Ordered68 execution or
// signing. The registered action login must serialize before locking an effect,
// not merely reach an organization capture trigger after changing that effect.
func TestP7OrderedLegacyWriterOrganizationSerialization(t *testing.T) {
	runOrderedLegacyWriterFixture(t, false, false)
}

func TestP7OrderedConnectedCatalogInstall(t *testing.T) {
	runOrderedLegacyWriterFixture(t, true, false)
}

func TestP7OrderedLegacyWriterFinishFixture(t *testing.T) {
	runOrderedLegacyWriterFixture(t, false, true)
}

func runOrderedLegacyWriterFixture(t *testing.T, catalogOnly, finishOnly bool) {
	t.Helper()
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		diagnostic := &orderedWriterMigrationDatabase{workerObservedMigrationDatabase: workerObservedMigrationDatabase{integrationMigrationDatabase{connection: owner}, t}}
		runner, err := migrations.NewRunner(diagnostic)
		if err != nil {
			t.Fatal(err)
		}
		// Legacy fixtures predate73's admission boundary; create them before
		// installing it, then exercise only the fully installed current profile.
		if _, err := owner.Exec(ctx, `CREATE ROLE p4c_test_scheduler LOGIN INHERIT;CREATE ROLE p4c_test_risk LOGIN INHERIT;CREATE ROLE p4c_test_graph LOGIN INHERIT;CREATE ROLE p4c_test_search LOGIN INHERIT;SELECT zasp_execution_register_principals(session_user,'p4c_test_scheduler','security_agent_v33_discovery_worker_login','p4c_test_risk','p4c_test_graph','p4c_test_search')`); err != nil {
			t.Fatal(err)
		}
		for _, up := range []func(context.Context) error{runner.UpProductionTemporalDomain, runner.UpProductionTemporalExecutor, runner.UpProductionTemporalWorkflow, runner.UpProductionTemporalCompatibility, runner.UpProductionTemporalLegacyTests, runner.UpProductionTemporalDiscovery} {
			if err := up(ctx); err != nil {
				t.Fatal("legacy fixture predecessor", err)
			}
		}
		runs := make([]string, 2)
		for index := range runs {
			runs[index], _ = seedOrderedActionFence(t, ctx, owner, worker, api, o, w, e, testID, actor, 570+index, false)
		}
		for _, up := range []func(context.Context) error{runner.UpProductionTemporalAdmission, runner.UpProductionTemporalTestExecutor, runner.UpProductionTemporalTestSelector, runner.UpProductionTemporalHumanAdmission, runner.UpProductionTemporalAutomaticSources, runner.UpProductionTemporalFindingResponse} {
			if err := up(ctx); err != nil {
				t.Fatal("current profile predecessor", err)
			}
		}
		if _, err := owner.Exec(ctx, `CREATE ROLE worker_test_executor LOGIN;CREATE ROLE worker_test_compensation LOGIN;SELECT zasp_temporal68.register_principals('worker_test_executor','worker_test_compensation')`); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionAuthorizationTemporalProfile(ctx); err != nil {
			t.Fatal(err)
		}
		diagnostic.before = orderedWriterIdentityRows(t, ctx, owner)
		if err := runner.UpProductionAuthorizationWorkerProfile(ctx); err != nil {
			t.Fatal(err)
		}
		if !finishOnly {
			assertOrderedWriterCatalogControls(t, ctx, owner)
		}
		if catalogOnly {
			assertOrderedConnectedTriggerPins(t, ctx, owner)
			var ready, runtime bool
			if err := owner.QueryRow(ctx, `SELECT zasp_temporal78.current_ready(),zasp_authorization80_worker.runtime_ready()`).Scan(&ready, &runtime); err != nil || !ready || runtime {
				t.Fatal("connected catalog readiness or closed runtime differs", err)
			}
			return
		}
		action := orderedActionFenceConnection(t, ctx, owner)
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			action.Close(cleanup)
		}()
		for index, family := range []string{"temporary", "session"} {
			if finishOnly && index > 0 {
				break
			}
			barriers := []string{"organization", "schema", "principal-revoked"}
			if finishOnly {
				barriers = nil
			}
			r := runs[index]
			if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`, r); err != nil {
				t.Fatal(err)
			}
			for _, barrier := range barriers {
				t.Run(family+"-claim-"+barrier, func(t *testing.T) {
					query := `SELECT public.zasp_security_agent_claim_` + family + `_policy_effects('legacy-action','legacy-action-lease',60,25)`
					assertOrderedLegacyOrganizationWait(t, ctx, owner, action, o, r, barrier, func(call context.Context, tx pgx.Tx) error {
						var result json.RawMessage
						if err := tx.QueryRow(call, query).Scan(&result); err != nil {
							return err
						}
						if !strings.Contains(string(result), r) {
							return errors.New("expected retained claim absent")
						}
						return nil
					})
				})
			}
			// Obtain targets from the actual retained claim before testing point
			// stores. The opaque legacy fixture signature below is not claimed as
			// a valid current signed-policy envelope or an Ordered68 proof.
			var claimed json.RawMessage
			if err := action.QueryRow(ctx, `SELECT public.zasp_security_agent_claim_`+family+`_policy_effects('legacy-action','legacy-action-lease',60,25)`).Scan(&claimed); err != nil || !strings.Contains(string(claimed), r) {
				t.Fatal("retained point fixture claim", err)
			}
			var sequence, version int64
			if err := owner.QueryRow(ctx, `SELECT sequence,policy_version FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$1 AND step_id=$1 AND device_id=$1 AND phase='apply'`, r).Scan(&sequence, &version); err != nil {
				t.Fatal("actual claimed target", err)
			}
			issued := time.Now().UTC().Truncate(time.Second)
			for _, suffix := range []string{"", "_v27"} {
				query := `SELECT public.zasp_security_agent_store_` + family + `_policy_target` + suffix + `($1,$2,$3,$4,$4,'apply','legacy-action','legacy-action-lease',$4,$4,$5,$6,'fixture-key-01',$7,$8,'closed',decode(repeat('ab',32),'hex'),'[]',decode(repeat('ab',64),'hex'),decode(repeat('ab',32),'hex'))`
				for _, barrier := range barriers {
					t.Run(family+"-store"+suffix+"-"+barrier, func(t *testing.T) {
						assertOrderedLegacyOrganizationWait(t, ctx, owner, action, o, r, barrier, func(call context.Context, tx pgx.Tx) error {
							var result json.RawMessage
							return tx.QueryRow(call, query, o, w, e, r, sequence, version, issued, issued.Add(10*time.Minute)).Scan(&result)
						})
					})
				}
			}
			// Finish consumes a genuinely stored retained target. Calculate its
			// required aggregate from those native rows, never an invented audit.
			var targetRows json.RawMessage
			if err := owner.QueryRow(ctx, `SELECT jsonb_agg(jsonb_build_object('device',device_id,'credential',credential_id,'sequence',sequence,'version',policy_version) ORDER BY device_id) FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$1 AND step_id=$1 AND phase='apply'`, r).Scan(&targetRows); err != nil {
				t.Fatal("retained finish actual destinations", err)
			}
			var actualTargets []struct {
				Device, Credential string
				Sequence, Version  int64
			}
			if json.Unmarshal(targetRows, &actualTargets) != nil || len(actualTargets) < 1 {
				t.Fatal("retained finish destination decode")
			}
			for _, target := range actualTargets {
				var stored json.RawMessage
				store := `SELECT public.zasp_security_agent_store_` + family + `_policy_target($1,$2,$3,$4,$4,'apply','legacy-action','legacy-action-lease',$5,$6,$7,$8,'fixture-key-01',$9,$10,'closed',decode(repeat('ab',32),'hex'),'[]',decode(repeat('ab',64),'hex'),decode(repeat('ab',32),'hex'))`
				if err := action.QueryRow(ctx, store, o, w, e, r, target.Device, target.Credential, target.Sequence, target.Version, issued, issued.Add(10*time.Minute)).Scan(&stored); err != nil {
					t.Fatal("retained finish fixture store", err)
				}
			}
			var digest []byte
			completeOrderedLegacyDeployment(t, ctx, owner, r)
			if err := owner.QueryRow(ctx, `SELECT digest(effect.input_digest||decode(string_agg(encode(target.envelope_digest,'hex'),'' ORDER BY target.device_id),'hex'),'sha256') FROM zasp_security_agent_effects effect JOIN zasp_security_agent_temporary_policy_targets target USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE effect.run_id=$1 AND target.phase='apply' AND target.state='stored' GROUP BY effect.input_digest`, r).Scan(&digest); err != nil || len(digest) != 32 {
				t.Fatal("actual finish target digest", err)
			}
			if finishOnly {
				barriers = []string{"organization"}
			}
			for _, barrier := range barriers {
				t.Run(family+"-finish-"+barrier, func(t *testing.T) {
					query := `SELECT public.zasp_security_agent_finish_` + family + `_policy_effect($1,$2,$3,$4,$4,'apply','legacy-action','legacy-action-lease',$5,$4,$4)`
					assertOrderedLegacyOrganizationWait(t, ctx, owner, action, o, r, barrier, func(call context.Context, tx pgx.Tx) error {
						var result json.RawMessage
						if err := tx.QueryRow(call, query, o, w, e, r, digest).Scan(&result); err != nil {
							return err
						}
						var receipt struct {
							State string `json:"effect_state"`
						}
						if json.Unmarshal(result, &receipt) != nil || receipt.State != "cleanup_pending" {
							return errors.New("retained finish outcome differs")
						}
						return nil
					})
				})
			}
			if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET lease_expires_at=clock_timestamp()+interval '1 hour' WHERE run_id=$1`, r); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func assertOrderedConnectedTriggerPins(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	for _, pair := range []struct{ table, trigger string }{
		{"public.zasp_gateway_devices", "zasp_authorization80_worker_ordered_gateway"},
		{"public.zasp_gateway_credentials", "zasp_authorization80_worker_ordered_gateway"},
		{"public.zasp_gateway_devices", "zasp_authorization80_worker_ordered_no_truncate"},
		{"public.zasp_gateway_credentials", "zasp_authorization80_worker_ordered_no_truncate"},
		{"public.zasp_workflow_records", "zasp_authorization80_worker_ordered_policy"},
		{"public.zasp_security_agent_temporary_policy_targets", "zasp_authorization80_worker_ordered_policy"},
		{"public.zasp_workflow_records", "zasp_authorization80_worker_ordered_policy_no_truncate"},
		{"public.zasp_security_agent_temporary_policy_targets", "zasp_authorization80_worker_ordered_policy_no_truncate"},
		{"zasp_temporal68.deliveries", "ordered_policy_capture"},
		{"zasp_temporal68.deliveries", "ordered_policy_no_truncate"},
	} {
		t.Run(pair.table+"/"+pair.trigger, func(t *testing.T) {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := tx.Rollback(cleanup); err != nil {
					t.Error("trigger control rollback", err)
				}
			}()
			var ready bool
			if err := tx.QueryRow(ctx, `SELECT zasp_authorization80_worker.catalog_ready() AND zasp_temporal78.current_ready()`).Scan(&ready); err != nil || !ready {
				t.Fatal("unchanged connected trigger catalog", err)
			}
			if _, err := tx.Exec(ctx, "ALTER TABLE "+pair.table+" DISABLE TRIGGER "+pair.trigger); err != nil {
				t.Fatal(err)
			}
			if err := tx.QueryRow(ctx, `SELECT zasp_authorization80_worker.catalog_ready() OR zasp_temporal78.current_ready()`).Scan(&ready); err != nil || ready {
				t.Fatal("disabled connected trigger accepted", err)
			}
		})
	}
}

// Read-only installer diagnostics run inside the failed readiness transaction,
// before the runner rolls it back. Only fixed labels and booleans are logged.
type orderedWriterMigrationDatabase struct {
	workerObservedMigrationDatabase
	before map[string][]string
}

func (d *orderedWriterMigrationDatabase) Begin(ctx context.Context) (migrations.Transaction, error) {
	tx, err := d.connection.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &orderedWriterMigrationTransaction{workerObservedMigrationTransaction{integrationMigrationTransaction{transaction: tx}, d.t}, d.before}, nil
}

type orderedWriterMigrationTransaction struct {
	workerObservedMigrationTransaction
	before map[string][]string
}

func (tx *orderedWriterMigrationTransaction) QueryRow(ctx context.Context, q string, args ...any) migrations.Row {
	row := tx.transaction.QueryRow(ctx, q, args...)
	if strings.HasPrefix(q, "SELECT EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE checksum=$1)") {
		return orderedWriterReadinessRow{row, tx, ctx}
	}
	return row
}

type orderedWriterReadinessRow struct {
	migrations.Row
	tx  *orderedWriterMigrationTransaction
	ctx context.Context
}

func (r orderedWriterReadinessRow) Scan(dest ...any) error {
	err := r.Row.Scan(dest...)
	if err != nil || len(dest) != 1 {
		return err
	}
	ready, ok := dest[0].(*bool)
	if !ok || *ready {
		return err
	}
	checks := []struct{ name, expression string }{
		{"worker_catalog", "zasp_authorization80_worker.catalog_ready()"},
		{"temporal_profile", "zasp_authorization80_temporal.ready()"},
		{"base67", "zasp_temporal67.base_ready()"},
		{"scope67", "zasp_temporal67.scope_authority_ready()"},
		{"public62", "COALESCE((SELECT fingerprint=zasp_ordered_public62.fingerprint() FROM zasp_ordered_public62.registration),false)"},
		{"outbox65", "COALESCE((SELECT fingerprint=zasp_temporal65.fingerprint() FROM zasp_temporal65.registration),false)"},
		{"owner66", "COALESCE((SELECT fingerprint=zasp_temporal66.fingerprint() FROM zasp_temporal66.registration),false)"},
	}
	for version := 67; version <= 78; version++ {
		schema := fmt.Sprintf("zasp_temporal%d", version)
		checks = append(checks, struct{ name, expression string }{fmt.Sprintf("fingerprint%d", version), "COALESCE((SELECT fingerprint=" + schema + ".fingerprint() FROM " + schema + ".registration),false)"})
	}
	for _, legacy := range [][3]string{
		{"legacy18", "zasp_security_agent_live_fingerprint", "security_agent_execution_fingerprint"},
		{"legacy22", "zasp_security_agent_temporary_policy_live_fingerprint", "security_agent_temporary_policy_fingerprint"},
		{"legacy24", "zasp_security_agent_session_isolation_live_fingerprint", "security_agent_session_isolation_fingerprint"},
		{"legacy27", "zasp_recovery_execution_live_fingerprint", "production_recovery_fingerprint"},
		{"legacy60", "zasp_discovery_schedule_replay_live_fingerprint", "production_discovery_schedule_replay_fingerprint"},
	} {
		checks = append(checks, struct{ name, expression string }{legacy[0], "EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='" + legacy[2] + "' AND value=public." + legacy[1] + "())"})
	}
	for _, check := range checks {
		var equal bool
		if queryErr := r.tx.transaction.QueryRow(r.ctx, "SELECT "+check.expression).Scan(&equal); queryErr != nil {
			var native *pgconn.PgError
			code := "non_pg"
			if errors.As(queryErr, &native) {
				code = native.Code
			}
			r.tx.t.Logf("ordered installer diagnostic %s error_class=%s", check.name, code)
			break
		}
		r.tx.t.Logf("ordered installer diagnostic %s equal=%v", check.name, equal)
	}
	after := orderedWriterIdentityRows(r.tx.t, r.ctx, r.tx.transaction)
	for _, message := range orderedWriterRecipeChanges(r.tx.before, after) {
		r.tx.t.Log(message)
	}
	return err
}

func orderedWriterRecipeChanges(before, after map[string][]string) []string {
	var messages, recipes []string
	for recipe := range before {
		recipes = append(recipes, recipe)
	}
	sort.Strings(recipes)
	for _, recipe := range recipes {
		previous := map[string]bool{}
		for _, value := range before[recipe] {
			previous[value] = true
		}
		for _, value := range after[recipe] {
			if previous[value] {
				delete(previous, value)
				continue
			}
			parts := strings.SplitN(value, "|", 4)
			// Only catalog category/name, never function bodies or runtime data.
			label := parts[0]
			if len(parts) > 1 && parts[0] == "function" {
				label += ":" + parts[1]
				if len(parts) > 2 {
					label += ":" + parts[2]
				}
			}
			messages = append(messages, fmt.Sprintf("ordered installer changed recipe=%s category=%s", recipe, label))
		}
		if len(previous) > 0 {
			messages = append(messages, fmt.Sprintf("ordered installer removed recipe=%s count=%d", recipe, len(previous)))
		}
	}
	return append(messages, fmt.Sprintf("ordered installer recipes compared=%d", len(recipes)))
}

func TestOrderedWriterRecipeDiagnosticCoverage(t *testing.T) {
	before := map[string][]string{"base": {"predecessor|old"}, "inherited": {"function|public|fixed_name|old_body"}, "unchanged": {"table|fixed_table|owner"}}
	after := map[string][]string{"base": {"predecessor|new"}, "inherited": {"function|public|fixed_name|never_log_this_body"}, "unchanged": {"table|fixed_table|owner"}}
	messages := orderedWriterRecipeChanges(before, after)
	joined := strings.Join(messages, "\n")
	if len(messages) != 5 || !strings.Contains(joined, "recipe=inherited category=function:public:fixed_name") || !strings.Contains(joined, "recipes compared=3") || strings.Contains(joined, "never_log") || strings.Contains(joined, "old_body") || strings.Contains(joined, "recipe=unchanged") {
		t.Fatal("diagnostic coverage or redaction differs", messages)
	}
}

func assertOrderedWriterCatalogControls(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	for _, mutation := range []struct{ name, signature, kind string }{
		{"fingerprint-same-result-body", "public.zasp_policy_deployment_execution_live_fingerprint()", "body"},
		{"fingerprint-acl", "public.zasp_policy_deployment_execution_live_fingerprint()", "acl"},
		{"fingerprint-owner", "public.zasp_policy_deployment_execution_live_fingerprint()", "owner"},
		{"projection-same-result-body", "zasp_authorization80_worker.ordered_projected28()", "body"},
		{"temporary-source-body", "public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)", "body"},
		{"temporary-store-body", "public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)", "body"},
		{"session-store-body", "public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)", "body"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := tx.Rollback(cleanup); err != nil {
					t.Error("catalog control rollback", err)
				}
			}()
			var ready bool
			if err := tx.QueryRow(ctx, `SELECT zasp_authorization80_worker.catalog_ready() AND zasp_authorization80_temporal.ready()`).Scan(&ready); err != nil || !ready {
				t.Fatal("unchanged installed catalog", err)
			}
			statement := "GRANT EXECUTE ON FUNCTION " + mutation.signature + " TO PUBLIC"
			if mutation.kind == "owner" {
				statement = "ALTER FUNCTION " + mutation.signature + " OWNER TO " + pgx.Identifier{owner.Config().User}.Sanitize()
			} else if mutation.kind == "body" {
				var definition string
				if err := tx.QueryRow(ctx, `SELECT pg_get_functiondef(to_regprocedure($1::text))`, mutation.signature).Scan(&definition); err != nil {
					t.Fatal(err)
				}
				const header = "AS $function$"
				if strings.Count(definition, header) != 1 {
					t.Fatal("catalog control body anchor changed")
				}
				statement = strings.Replace(definition, header, header+"\n-- same-result owned catalog mutation\n", 1)
			}
			if _, err := tx.Exec(ctx, statement); err != nil {
				t.Fatal("catalog mutation", err)
			}
			if err := tx.QueryRow(ctx, `SELECT zasp_authorization80_worker.catalog_ready() OR zasp_authorization80_temporal.ready()`).Scan(&ready); err != nil || ready {
				t.Fatal("changed live identity remained ready", err)
			}
		})
	}
}

func orderedWriterIdentityRows(t *testing.T, ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) map[string][]string {
	t.Helper()
	result := map[string][]string{}
	// Enumerate the retained lower recipes once per boundary, including private
	// copies inherited by60. The four public wrappers are compared using their
	// exact live projection recipes after installation, not historical pins.
	var encodedRecipes json.RawMessage
	if err := db.QueryRow(ctx, `SELECT jsonb_agg(signature ORDER BY signature) FROM (
 SELECT p.oid::regprocedure::text signature FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE p.pronargs=0 AND p.prorettype='text'::regtype AND p.proname LIKE '%fingerprint%'
 AND n.nspname NOT LIKE 'zasp_authorization%' AND p.prosrc LIKE '%FROM identities%'
 UNION SELECT unnest(ARRAY['zasp_security_agent_live_fingerprint()','zasp_security_agent_temporary_policy_live_fingerprint()','zasp_security_agent_session_isolation_live_fingerprint()','zasp_recovery_execution_live_fingerprint()','zasp_policy_deployment_execution_live_fingerprint()'])
 ) recipes`).Scan(&encodedRecipes); err != nil {
		t.Fatal("catalog recipe inventory", err)
	}
	var recipes []string
	if json.Unmarshal(encodedRecipes, &recipes) != nil || len(recipes) == 0 {
		t.Fatal("catalog recipe inventory decode")
	}
	aggregate := regexp.MustCompile(`(?is)\)\s*SELECT\s+encode\(digest\(convert_to\(string_agg\(value`)
	for _, recipe := range recipes {
		var source string
		if err := db.QueryRow(ctx, `SELECT prosrc FROM pg_proc WHERE oid=CASE WHEN to_regnamespace('zasp_authorization80_worker') IS NULL THEN to_regprocedure($1::text) ELSE COALESCE(to_regprocedure(CASE $1::text
 WHEN 'zasp_security_agent_live_fingerprint()' THEN 'zasp_authorization80_worker.gateway_projected18()'
 WHEN 'zasp_security_agent_temporary_policy_live_fingerprint()' THEN 'zasp_authorization80_worker.ordered_projected22()'
 WHEN 'zasp_security_agent_session_isolation_live_fingerprint()' THEN 'zasp_authorization80_worker.gateway_projected24()'
 WHEN 'zasp_recovery_execution_live_fingerprint()' THEN 'zasp_authorization80_worker.gateway_projected27()'
 WHEN 'zasp_policy_deployment_execution_live_fingerprint()' THEN 'zasp_authorization80_worker.ordered_projected28()' END),to_regprocedure($1::text)) END`, recipe).Scan(&source); err != nil {
			t.Fatal("catalog recipe source", err)
		}
		matches := aggregate.FindAllStringIndex(source, -1)
		if len(matches) != 1 {
			t.Fatal("catalog recipe aggregate changed", recipe)
		}
		query := source[:matches[0][0]] + ") SELECT jsonb_agg(value ORDER BY value) FROM identities"
		var raw json.RawMessage
		if err := db.QueryRow(ctx, query).Scan(&raw); err != nil {
			t.Fatal("catalog recipe rows", err)
		}
		var rows []string
		if json.Unmarshal(raw, &rows) != nil {
			t.Fatal("catalog recipe row decode")
		}
		result[recipe] = rows
	}
	return result
}

func assertOrderedLegacyOrganizationWait(t *testing.T, ctx context.Context, owner, action *pgx.Conn, organization, run, barrier string, invoke func(context.Context, pgx.Tx) error) {
	t.Helper()
	before := orderedActionFenceSnapshot(t, ctx, owner, run)
	lock, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = lock.Rollback(cleanup)
	}()
	if barrier == "schema" {
		if _, err = lock.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0))`); err != nil {
			t.Fatal(err)
		}
	} else {
		var locked string
		if err = lock.QueryRow(ctx, `SELECT organization_id FROM zasp_authorization79.organizations WHERE organization_id=$1 FOR UPDATE`, organization).Scan(&locked); err != nil {
			t.Fatal("organization fixture", err)
		}
	}
	call, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tx, err := action.Begin(call)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, release := context.WithTimeout(context.Background(), 5*time.Second)
		defer release()
		_ = tx.Rollback(cleanup)
	}()
	done := make(chan error, 1)
	go func() { done <- invoke(call, tx) }()
	joined, waiting := false, false
	var result error
	defer func() {
		cancel()
		if !joined {
			<-done
		}
	}()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		select {
		case result = <-done:
			joined = true
		default:
		}
		if joined {
			break
		}
		if err = lock.QueryRow(ctx, `SELECT $2=ANY(pg_blocking_pids($1))`, action.PgConn().PID(), owner.PgConn().PID()).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
	}
	if joined {
		t.Errorf("retained writer completed before %s release: %v", barrier, result)
	} else if !waiting {
		t.Errorf("retained writer did not reach held %s", barrier)
	}
	if waiting {
		// A trigger reached only after effect acquisition is too late. The exact
		// application row must still be free while the organization is held.
		if _, err = lock.Exec(ctx, `SAVEPOINT effect_probe`); err != nil {
			t.Fatal(err)
		}
		if barrier == "schema" {
			_, err = lock.Exec(ctx, `SELECT 1 FROM zasp_authorization79.organizations WHERE organization_id=$1 FOR UPDATE NOWAIT`, organization)
		} else {
			_, err = lock.Exec(ctx, `SELECT 1 FROM zasp_security_agent_effects WHERE run_id=$1 FOR UPDATE NOWAIT`, run)
		}
		var pgerr *pgconn.PgError
		if errors.As(err, &pgerr) && pgerr.Code == "55P03" {
			t.Errorf("retained writer locked downstream row before %s", barrier)
		} else if err != nil {
			t.Errorf("effect lock probe: %v", err)
		}
		if _, err = lock.Exec(ctx, `ROLLBACK TO SAVEPOINT effect_probe`); err != nil {
			t.Fatal(err)
		}
	}
	if barrier == "principal-revoked" {
		// Keep the login, membership and socket intact. Only the exact native
		// registration changes while its organization serialization is held.
		if _, err = lock.Exec(ctx, `UPDATE zasp_security_agent_action_principal_bindings SET principal_name='ordered_revoked_login' WHERE principal_name=$1`, action.Config().User); err != nil {
			t.Fatal(err)
		}
		if err = lock.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		defer func() {
			cleanup, release := context.WithTimeout(context.Background(), 5*time.Second)
			defer release()
			if _, err := owner.Exec(cleanup, `UPDATE zasp_security_agent_action_principal_bindings SET principal_name=$1 WHERE principal_name='ordered_revoked_login'`, action.Config().User); err != nil {
				t.Error("restore exact action registration", err)
			}
		}()
	} else if err = lock.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if !joined {
		result = <-done
		joined = true
	}
	if barrier == "principal-revoked" {
		var native *pgconn.PgError
		if !errors.As(result, &native) || native.Code != "42501" {
			t.Errorf("changed registration must refuse after wait: %v", result)
		}
	} else if result != nil {
		t.Errorf("unchanged retained call after organization release: %v", result)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if after := orderedActionFenceSnapshot(t, ctx, owner, run); after != before {
		t.Error("rolled-back retained writer changed authority or accounting")
	}
}
