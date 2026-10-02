package migrations

import (
	"context"
	"strings"
	"testing"
)

func TestSingleTestRecoveryAssembly(t *testing.T) {
	source, checksum := ProductionTemporalSingleRecoverySource()
	again, other := ProductionTemporalSingleRecoverySource()
	if source != again || checksum != other || len(checksum) != 64 || len(source) < 1000 {
		t.Fatal("non-deterministic or missing source")
	}
	// The consumer is the installer. A failed composed postcondition must
	// roll back its DDL, never commit a dormant-but-reported-ready profile.
	for _, post := range []bool{false, true} {
		events := []string{}
		tx := &fakeTransaction{events: &events, rows: []Row{fakeRow{values: []any{true}}, fakeRow{values: []any{false}}, fakeRow{values: []any{true}}, fakeRow{values: []any{post}}}}
		db := &singleRecoveryInstallDB{tx: tx}
		r, _ := NewRunner(db)
		err := r.UpProductionTemporalSingleRecovery(context.Background())
		joined := strings.Join(events, "\n")
		if (err == nil) != post || strings.Contains(joined, "\ncommit") != post || strings.Contains(joined, "rollback") == post {
			t.Fatal("installer transaction boundary", post, err)
		}
	}
	// A present namespace is not adoptable if its readiness implementation has
	// changed. The install consumer must stop before calling the changed body.
	events := []string{}
	tx := &fakeTransaction{events: &events, rows: []Row{fakeRow{values: []any{true}}, fakeRow{values: []any{true}}, fakeRow{values: []any{false}}}}
	r, _ := NewRunner(&singleRecoveryInstallDB{tx: tx})
	if err := r.UpProductionTemporalSingleRecovery(context.Background()); err == nil || strings.Contains(strings.Join(events, "\n"), "SELECT zasp_temporal_single_recovery.ready($1)") {
		t.Fatal("adopted altered readiness source")
	}
	for _, recipe := range []string{"cancel_core(text,text,text,text,text,text,bigint,text,text,text)", "planning_terminal_valid(text,text,text,text)", "decision_owner(zasp_temporal74.control_intents)"} {
		found := false
		for _, f := range recoveryNativeSources() {
			if strings.HasSuffix(f.signature, recipe) {
				found = true
				if !strings.Contains(source, recoverySHA(f.body)) {
					t.Fatal("source descriptor omitted")
				}
			}
		}
		if !found {
			t.Fatal("fixed predecessor recipe missing", recipe)
		}
	}
	t.Run("source recipe drift refuses", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("unknown source recipe accepted")
			}
		}()
		recoveryReplace("changed body", "exact old body", "replacement", 1)
	})
}

func TestSingleTestRecoveryBindsInstalledPortablePlanningTerminal(t *testing.T) {
	baseline := recoveryFindBody(ProductionTemporalExecutor().UpSQL(), "zasp_temporal68.planning_terminal_valid(text,text,text,text)")
	baseline.body = strings.NewReplacer(
		"zasp_temporal68.", "zasp_temporal74.",
		"zasp_temporal66.is_temporal(", "zasp_temporal74.is_owned(",
		"zasp_sa_multistep_prior.context(", "zasp_temporal74.context(",
		"zasp_sa_multistep_prior.planning_body(", "zasp_temporal74.planning_body(",
		"zasp_sa_multistep_prior.planning_result(", "zasp_temporal74.planning_result(",
	).Replace(baseline.body)
	baseline.body = strings.NewReplacer(
		"zasp_temporal74.principal_ready(", "zasp_temporal68.principal_ready(",
		"zasp_temporal74.active_count(", "zasp_temporal68.active_count(",
	).Replace(baseline.body)

	expected := baseline.body
	for _, replacement := range []struct {
		needle, assignment, tag string
	}{
		{"to_jsonb(j)", "needle:='to_jsonb(j)';", "job"},
		{"to_jsonb(p)", "needle:='to_jsonb(p)';", "reservation"},
		{" AND a.body=jsonb_build_object(", "needle:=' AND a.body=jsonb_build_object(';", "guard"},
	} {
		start := strings.Index(authorizationWorkerPlannerPortabilitySQL, replacement.assignment)
		if start < 0 {
			t.Fatal("worker portability needle changed", replacement.tag)
		}
		prefix := "d:=replace(d,needle,$" + replacement.tag + "$"
		start = strings.Index(authorizationWorkerPlannerPortabilitySQL[start:], prefix)
		if start < 0 {
			t.Fatal("worker portability replacement changed", replacement.tag)
		}
		start += strings.Index(authorizationWorkerPlannerPortabilitySQL, replacement.assignment) + len(prefix)
		end := strings.Index(authorizationWorkerPlannerPortabilitySQL[start:], "$"+replacement.tag+"$);")
		if end < 0 {
			t.Fatal("worker portability replacement terminator changed", replacement.tag)
		}
		value := authorizationWorkerPlannerPortabilitySQL[start : start+end]
		if strings.Count(expected, replacement.needle) != 1 {
			t.Fatal("test predecessor recipe changed", replacement.tag)
		}
		expected = strings.Replace(expected, replacement.needle, value, 1)
	}

	var installed recoveryFunctionSource
	for _, source := range recoveryNativeSources() {
		if source.signature == "zasp_temporal74.planning_terminal_valid(text,text,text,text)" {
			installed = source
		}
	}
	if installed.signature == "" {
		t.Fatal("portable planning terminal descriptor missing")
	}
	if installed.body != expected {
		t.Fatalf("recovery bound pre-worker planning terminal: got %s want %s", recoverySHA(installed.body), recoverySHA(expected))
	}
	if installed.language != baseline.language || installed.volatility != baseline.volatility || installed.definer != baseline.definer {
		t.Fatal("portable planning terminal metadata changed")
	}
	source, _ := ProductionTemporalSingleRecoverySource()
	if !strings.Contains(source, recoverySHA(expected)) {
		t.Fatal("recovery readiness omitted installed portable planning terminal")
	}
}

func TestSingleTestRecoveryObservationAllowsOnlyNullableRunID(t *testing.T) {
	source, _ := ProductionTemporalSingleRecoverySource()
	admit := recoveryFindBody(source, "zasp_temporal_single_recovery.admit(jsonb)").body
	narrow := "ob?'run_id' AND zasp_sa_multistep_prior.closed(ob-'run_id',ARRAY['workflow_id','status','observed_at'])"
	if !strings.Contains(admit, narrow) {
		t.Fatal("recovery observation does not isolate nullable run_id")
	}
	if strings.Contains(admit, "zasp_sa_multistep_prior.closed(ob,ARRAY['workflow_id','run_id','status','observed_at'])") {
		t.Fatal("recovery observation still rejects its declared nullable run_id")
	}
}

func TestSingleTestRecoveryRetainedBindingAllowsOnlyNullableReceipts(t *testing.T) {
	source, _ := ProductionTemporalSingleRecoverySource()
	body := recoveryFindBody(source, "zasp_temporal_single_recovery.checked(jsonb)").body
	retained := "IF NOT zasp_sa_multistep_prior.closed(b-ARRAY['receipt_id','audit_id'],ARRAY['kind','digest'])"
	if !strings.Contains(body, retained) {
		t.Fatal("retained recovery proof does not validate only its non-null fields")
	}
	for _, required := range []string{
		"OR NOT b ?& ARRAY['receipt_id','audit_id']",
		"OR b->'receipt_id' IS DISTINCT FROM 'null'::jsonb",
		"OR b->'audit_id' IS DISTINCT FROM 'null'::jsonb",
	} {
		if !strings.Contains(body, required) {
			t.Fatal("retained recovery proof nullable-field guard missing", required)
		}
	}
	cancel := "IF b->>'kind'='cancel' THEN\n  IF NOT zasp_sa_multistep_prior.closed(b,ARRAY['kind','receipt_id','audit_id','digest'])"
	if !strings.Contains(body, cancel) {
		t.Fatal("cancellation binding no longer requires all non-null fields")
	}
	for _, required := range []string{
		"FROM zasp_temporal74.control_intents WHERE(organization_id,workspace_id,environment_id,run_id,operation,receipt_id,audit_id)",
		"verified:=zasp_temporal74.decision_owner(ci)",
		"b->>'digest' IS DISTINCT FROM encode(ci.response_digest,'hex')",
	} {
		if !strings.Contains(body, required) {
			t.Fatal("cancellation control proof changed", required)
		}
	}
}

type singleRecoveryInstallDB struct{ tx Transaction }

func (d *singleRecoveryInstallDB) Begin(context.Context) (Transaction, error) { return d.tx, nil }
func (d *singleRecoveryInstallDB) QueryRow(context.Context, string, ...any) Row {
	panic("untransactional install")
}
