package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// One changed-profile producer consumes the accepted happy/settled contract,
// all four actual raw denials, then this transition's live catalog controls.
func TestP7Ordered69RetirementSecurity(t *testing.T) {
	runOrderedActualRunnerWithSettledConsumer(t, "", func(c ordered68ApprovedTestContext, directory string) {
		assertOrdered69SettledRetirement(c, directory)
		assertOrdered69RetirementDrift(c, directory)
		if !t.Failed() {
			captureReadinessSourceAttribution(t, c.ctx, c.owner)
		}
	})
}

type retirementCatalogCommand struct {
	sql  string
	args []any
	one  bool
}

func retirementCatalogCommit(ctx context.Context, owner *pgx.Conn, commands []retirementCatalogCommand) error {
	tx, err := owner.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		clean, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = tx.Rollback(clean)
	}()
	for _, command := range commands {
		tag, err := tx.Exec(ctx, command.sql, command.args...)
		if err != nil {
			return err
		}
		if command.one && tag.RowsAffected() != 1 {
			return errors.New("retirement exact saved-row count")
		}
	}
	return tx.Commit(ctx)
}

func assertOrdered69RetirementDrift(c ordered68ApprovedTestContext, directory string) {
	t, ctx := c.t, c.ctx
	t.Helper()
	before := orderedPostRecoveryEvidence(c, directory)
	cfg := c.owner.Config().Copy()
	cfg.User = "temporal_compensation_test_login"
	comp, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal("retirement compensation connection", ordered68ErrorClass(err))
	}
	defer func() {
		clean, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		if err := comp.Close(clean); err != nil {
			t.Error("retirement close", ordered68ErrorClass(err))
		}
	}()
	var exposed bool
	probe, cancelProbe := context.WithTimeout(ctx, 10*time.Second)
	defer cancelProbe()
	if err := comp.QueryRow(probe, `SELECT has_function_privilege(session_user,'zasp_authorization80_worker.projected69()','EXECUTE')`).Scan(&exposed); err != nil || exposed {
		t.Fatal("retirement projection exposed", ordered68ErrorClass(err))
	}
	var privateValue string
	privateErr := comp.QueryRow(probe, `SELECT zasp_authorization80_worker.projected69()`).Scan(&privateValue)
	var native *pgconn.PgError
	if probe.Err() != nil || !errors.As(privateErr, &native) || native.Code != "42501" {
		t.Fatal("retirement projection callable", ordered68ErrorClass(privateErr))
	}
	cancelProbe()
	signatures := []string{"zasp_temporal69.inspect(jsonb)", "zasp_temporal69.inspect_message(jsonb)", "zasp_temporal69.stop(jsonb)", "zasp_temporal69.fingerprint()", "zasp_authorization80_worker.projected69()"}
	definitions := map[string]string{}
	for _, sig := range signatures {
		var definition string
		if err := c.owner.QueryRow(ctx, `SELECT pg_get_functiondef($1::regprocedure)`, sig).Scan(&definition); err != nil {
			t.Fatal("retirement definition capture", ordered68ErrorClass(err))
		}
		definitions[sig] = definition
	}
	var ownerLogin string
	if err := c.owner.QueryRow(ctx, `SELECT session_user`).Scan(&ownerLogin); err != nil || ownerLogin == "zasp_discovery_authority" {
		t.Fatal("retirement owner mutation fixture unavailable")
	}
	type mutation struct {
		name           string
		apply, restore []retirementCatalogCommand
	}
	command := func(sql string) []retirementCatalogCommand { return []retirementCatalogCommand{{sql: sql}} }
	var cases []mutation
	for _, edge := range []struct{ signature, role string }{
		{signatures[0], "zasp_temporal_executor"}, {signatures[0], "zasp_temporal_compensation"}, {signatures[1], "zasp_temporal_executor"}, {signatures[2], "zasp_temporal_compensation"},
	} {
		cases = append(cases, mutation{"regrant-" + edge.signature + "-" + edge.role, command("GRANT EXECUTE ON FUNCTION " + edge.signature + " TO " + edge.role), command("REVOKE EXECUTE ON FUNCTION " + edge.signature + " FROM " + edge.role)})
	}
	for _, role := range []string{"PUBLIC", "zasp_red_team_adapter"} {
		cases = append(cases, mutation{"foreign-grant-" + role, command("GRANT EXECUTE ON FUNCTION " + signatures[0] + " TO " + role), command("REVOKE EXECUTE ON FUNCTION " + signatures[0] + " FROM " + role)})
	}
	for _, sig := range signatures[:3] {
		cases = append(cases, mutation{"owner-" + sig, command("ALTER FUNCTION " + sig + " OWNER TO " + pgx.Identifier{ownerLogin}.Sanitize()), command("ALTER FUNCTION " + sig + " OWNER TO zasp_discovery_authority")})
	}
	for _, sig := range signatures {
		definition := definitions[sig]
		const anchor = "AS $function$\n"
		if strings.Count(definition, anchor) != 1 {
			t.Fatal("retirement same-result body anchor changed")
		}
		cases = append(cases, mutation{"same-result-body-" + sig, command(strings.Replace(definition, anchor, anchor+"-- retirement catalog drift\n", 1)), command(definition)})
	}
	cases = append(cases, mutation{"projection-acl", command("GRANT EXECUTE ON FUNCTION " + signatures[4] + " TO zasp_temporal_compensation"), command("REVOKE EXECUTE ON FUNCTION " + signatures[4] + " FROM zasp_temporal_compensation")})
	cases = append(cases, mutation{"forged-same-fingerprint", command("CREATE OR REPLACE FUNCTION zasp_temporal69.fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path=pg_catalog,public AS 'SELECT ''" + migrations.TemporalWorkflowFingerprint() + "''::text'"), command(definitions[signatures[3]])})
	var saved string
	if err := c.owner.QueryRow(ctx, `SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE to_regprocedure(signature)='zasp_temporal69.fingerprint()'::regprocedure`).Scan(&saved); err != nil {
		t.Fatal("retirement saved recipe", ordered68ErrorClass(err))
	}
	savedCommands := func(value string) []retirementCatalogCommand {
		return []retirementCatalogCommand{
			{sql: `ALTER TABLE zasp_authorization80_worker.predecessor_functions DISABLE TRIGGER immutable`},
			{sql: `UPDATE zasp_authorization80_worker.predecessor_functions SET definition=$1 WHERE to_regprocedure(signature)='zasp_temporal69.fingerprint()'::regprocedure`, args: []any{value}, one: true},
			{sql: `ALTER TABLE zasp_authorization80_worker.predecessor_functions ENABLE TRIGGER immutable`},
		}
	}
	cases = append(cases, mutation{"saved-recipe", savedCommands(saved + "\n-- saved retirement drift"), savedCommands(saved)})
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			decision, err := c.compensation.Authorize(bounded, "ordered69.inspect", c.identity)
			if err != nil {
				t.Fatal("retirement before-mutation proof", ordered68ErrorClass(err))
			}
			// Commit the isolated catalog change before the real registered service
			// consumes its proof. An owner-only uncommitted change would be invisible.
			restored := false
			restore := func() {
				if restored {
					return
				}
				clean, done := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
				defer done()
				if err := retirementCatalogCommit(clean, c.owner, item.restore); err != nil {
					t.Error("retirement restoration", ordered68ErrorClass(err))
					return
				}
				restored = true
			}
			defer restore()
			if err := retirementCatalogCommit(bounded, c.owner, item.apply); err != nil {
				t.Fatal("retirement catalog mutation", ordered68ErrorClass(err))
			}
			var catalog, ready bool
			if err := c.owner.QueryRow(bounded, `SELECT zasp_authorization80_worker.catalog_ready(),zasp_temporal69.current_ready()`).Scan(&catalog, &ready); err != nil || catalog || ready {
				t.Fatal("retirement catalog drift accepted", catalog, ready, ordered68ErrorClass(err))
			}
			value, err := c.compensation.Execute(bounded, decision)
			live := bounded.Err() == nil
			restore()
			if !live || !errors.Is(err, authorization.ErrDenied) || len(value) != 0 {
				t.Fatalf("retirement named proof accepted drift: live=%t class=%s", live, ordered68ErrorClass(err))
			}
			if err := c.owner.QueryRow(ctx, `SELECT zasp_authorization80_worker.catalog_ready(),zasp_temporal69.current_ready()`).Scan(&catalog, &ready); err != nil || !catalog || !ready {
				t.Fatal("retirement restored readiness", ordered68ErrorClass(err))
			}
			if !bytes.Equal(before, orderedPostRecoveryEvidence(c, directory)) {
				t.Fatal("retirement drift changed durable evidence")
			}
		})
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	decision, err := c.compensation.Authorize(bounded, "ordered69.inspect", c.identity)
	if err != nil {
		t.Fatal("retirement final named authorize", ordered68ErrorClass(err))
	}
	if _, err := c.compensation.Execute(bounded, decision); err != nil {
		t.Fatal("retirement final named inspect", ordered68ErrorClass(err))
	}
	if !bytes.Equal(before, orderedPostRecoveryEvidence(c, directory)) {
		t.Fatal("retirement final evidence changed")
	}
}

// Historical0069 stays usable without the worker profile. This stops before
// model planning or any Test engine; the queued run is admitted by the real API.
func TestP7Ordered69RetirementHistoricalCompatibility(t *testing.T) {
	consumed := false
	runTemporalExecutorPlanningFixtureWithHook(t, func(ctx context.Context, owner, executor, api *pgx.Conn, o, w, e, run, test string) bool {
		consumed = true
		if err := precisionMigrationRunner(t, owner).UpProductionTemporalWorkflow(ctx); err != nil {
			t.Fatal("historical69 install", err)
		}
		var absent bool
		if err := owner.QueryRow(ctx, `SELECT to_regnamespace('zasp_authorization80_worker') IS NULL`).Scan(&absent); err != nil || !absent {
			t.Fatal("historical fixture has worker profile")
		}
		cfg := owner.Config().Copy()
		cfg.User = "temporal_compensation_test_login"
		comp, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			clean, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer cancel()
			if err := comp.Close(clean); err != nil {
				t.Error("historical compensation close", ordered68ErrorClass(err))
			}
		}()
		for _, p := range []struct {
			conn         *pgx.Conn
			role, second string
		}{{executor, "zasp_temporal_executor", "zasp_temporal69.inspect_message(jsonb)"}, {comp, "zasp_temporal_compensation", "zasp_temporal69.stop(jsonb)"}} {
			bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
			var retained bool
			err := p.conn.QueryRow(bounded, `SELECT session_user=$1 AND current_user=session_user AND has_schema_privilege(session_user,'zasp_temporal69','USAGE') AND has_function_privilege(session_user,'zasp_temporal69.inspect(jsonb)','EXECUTE') AND has_function_privilege(session_user,$2,'EXECUTE') AND zasp_temporal69.ready($3,$4) AND zasp_temporal69.principal_ready($5)`, p.conn.Config().User, p.second, migrations.ProductionTemporalWorkflow().Checksum(), migrations.TemporalWorkflowFingerprint(), p.role).Scan(&retained)
			cancel()
			if err != nil || !retained {
				t.Fatal("historical original grants/metadata changed", p.role, ordered68ErrorClass(err))
			}
		}
		var identity json.RawMessage
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'run_id',run_id,'definition_version',definition_version,'input_digest',input_digest) FROM zasp_temporal66.run_owners WHERE run_id=$1`, run).Scan(&identity); err != nil {
			t.Fatal(err)
		}
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		var view json.RawMessage
		if err := executor.QueryRow(bounded, `SELECT zasp_temporal69.inspect($1::jsonb)`, identity).Scan(&view); err != nil || !json.Valid(view) {
			t.Fatal("historical raw inspect unavailable", ordered68ErrorClass(err))
		}
		return true
	}, nil, nil)
	if !t.Failed() && !consumed {
		t.Fatal("historical retirement fixture not consumed")
	}
}
