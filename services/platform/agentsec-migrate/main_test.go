package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestLoadMigrationTimeoutRequiresFiniteBound(t *testing.T) {
	if got, err := loadMigrationTimeout(func(string) string { return "2m" }); err != nil || got != 2*time.Minute {
		t.Fatalf("timeout = (%v, %v)", got, err)
	}
	for _, value := range []string{"", "0s", "31m", "forever"} {
		if _, err := loadMigrationTimeout(func(string) string { return value }); err == nil {
			t.Fatalf("timeout %q accepted", value)
		}
	}
}

type scriptedMigrationRunner struct {
	events  []string
	errAt   string
	version int64
}

func (runner *scriptedMigrationRunner) Version(context.Context) (int64, error) {
	runner.events = append(runner.events, "version")
	if runner.errAt == "version" {
		return 0, errors.New("detail")
	}
	return runner.version, nil
}

func (runner *scriptedMigrationRunner) Up(context.Context) error {
	runner.events = append(runner.events, "up-baseline")
	if runner.errAt == "up-baseline" {
		return errors.New("detail")
	}
	runner.version = 1
	return nil
}

func (runner *scriptedMigrationRunner) UpCore(context.Context) error {
	runner.events = append(runner.events, "up-core")
	if runner.errAt == "up-core" {
		return errors.New("detail")
	}
	runner.version = 2
	return nil
}

func (runner *scriptedMigrationRunner) UpWorkflows(context.Context) error {
	runner.events = append(runner.events, "up-workflows")
	if runner.errAt == "up-workflows" {
		return errors.New("detail")
	}
	runner.version = 3
	return nil
}

func (runner *scriptedMigrationRunner) UpWorkflowReceipts(context.Context) error {
	runner.events = append(runner.events, "up-receipts")
	if runner.errAt == "up-receipts" {
		return errors.New("detail")
	}
	runner.version = 4
	return nil
}

func (runner *scriptedMigrationRunner) UpWorkflowReceiptSafety(context.Context) error {
	runner.events = append(runner.events, "up-receipt-safety")
	if runner.errAt == "up-receipt-safety" {
		return errors.New("detail")
	}
	runner.version = 5
	return nil
}

func (runner *scriptedMigrationRunner) UpWorkflowReceiptProvenance(context.Context) error {
	runner.events = append(runner.events, "up-receipt-provenance")
	if runner.errAt == "up-receipt-provenance" {
		return errors.New("detail")
	}
	runner.version = 6
	return nil
}

func (runner *scriptedMigrationRunner) DownWorkflowReceiptProvenance(context.Context) error {
	runner.events = append(runner.events, "down-receipt-provenance")
	if runner.errAt == "down-receipt-provenance" {
		return errors.New("detail")
	}
	runner.version = 5
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionAdministration(context.Context) error {
	runner.events = append(runner.events, "up-production-administration")
	if runner.errAt == "up-production-administration" {
		return errors.New("detail")
	}
	runner.version = 7
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionAdministration(context.Context) error {
	runner.events = append(runner.events, "down-production-administration")
	if runner.errAt == "down-production-administration" {
		return errors.New("detail")
	}
	runner.version = 6
	return nil
}

func (runner *scriptedMigrationRunner) UpAPITokenRevealGrants(context.Context) error {
	runner.events = append(runner.events, "up-api-token-reveal-grants")
	if runner.errAt == "up-api-token-reveal-grants" {
		return errors.New("detail")
	}
	runner.version = 8
	return nil
}

func (runner *scriptedMigrationRunner) DownAPITokenRevealGrants(context.Context) error {
	runner.events = append(runner.events, "down-api-token-reveal-grants")
	if runner.errAt == "down-api-token-reveal-grants" {
		return errors.New("detail")
	}
	runner.version = 7
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionRiskProjection(context.Context) error {
	runner.events = append(runner.events, "up-production-risk-projection")
	if runner.errAt == "up-production-risk-projection" {
		return errors.New("detail")
	}
	runner.version = 9
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionRiskProjection(context.Context) error {
	runner.events = append(runner.events, "down-production-risk-projection")
	if runner.errAt == "down-production-risk-projection" {
		return errors.New("detail")
	}
	runner.version = 8
	return nil
}

func (runner *scriptedMigrationRunner) DownWorkflowReceiptSafety(context.Context) error {
	runner.events = append(runner.events, "down-receipt-safety")
	if runner.errAt == "down-receipt-safety" {
		return errors.New("detail")
	}
	runner.version = 4
	return nil
}

func (runner *scriptedMigrationRunner) DownWorkflowReceipts(context.Context) error {
	runner.events = append(runner.events, "down-receipts")
	if runner.errAt == "down-receipts" {
		return errors.New("detail")
	}
	runner.version = 3
	return nil
}

func (runner *scriptedMigrationRunner) DownWorkflows(context.Context) error {
	runner.events = append(runner.events, "down-workflows")
	if runner.errAt == "down-workflows" {
		return errors.New("detail")
	}
	runner.version = 2
	return nil
}

func (runner *scriptedMigrationRunner) DownCore(context.Context) error {
	runner.events = append(runner.events, "down-core")
	if runner.errAt == "down-core" {
		return errors.New("detail")
	}
	runner.version = 1
	return nil
}

func (runner *scriptedMigrationRunner) Down(context.Context) error {
	runner.events = append(runner.events, "down-baseline")
	if runner.errAt == "down-baseline" {
		return errors.New("detail")
	}
	runner.version = 0
	return nil
}

func TestRunReleaseMigrationReachesExactTargetStateIdempotently(t *testing.T) {
	for _, test := range []struct {
		direction string
		version   int64
		want      []string
	}{
		{direction: "up", version: 0, want: []string{"version", "up-baseline", "up-core", "up-workflows", "up-receipts", "up-receipt-safety", "up-receipt-provenance", "up-production-administration", "up-api-token-reveal-grants", "up-production-risk-projection", "version"}},
		{direction: "up", version: 1, want: []string{"version", "up-core", "up-workflows", "up-receipts", "up-receipt-safety", "up-receipt-provenance", "up-production-administration", "up-api-token-reveal-grants", "up-production-risk-projection", "version"}},
		{direction: "up", version: 2, want: []string{"version", "up-workflows", "up-receipts", "up-receipt-safety", "up-receipt-provenance", "up-production-administration", "up-api-token-reveal-grants", "up-production-risk-projection", "version"}},
		{direction: "up", version: 3, want: []string{"version", "up-receipts", "up-receipt-safety", "up-receipt-provenance", "up-production-administration", "up-api-token-reveal-grants", "up-production-risk-projection", "version"}},
		{direction: "up", version: 4, want: []string{"version", "up-receipt-safety", "up-receipt-provenance", "up-production-administration", "up-api-token-reveal-grants", "up-production-risk-projection", "version"}},
		{direction: "up", version: 5, want: []string{"version", "up-receipt-provenance", "up-production-administration", "up-api-token-reveal-grants", "up-production-risk-projection", "version"}},
		{direction: "up", version: 6, want: []string{"version", "up-production-administration", "up-api-token-reveal-grants", "up-production-risk-projection", "version"}},
		{direction: "up", version: 7, want: []string{"version", "up-api-token-reveal-grants", "up-production-risk-projection", "version"}},
		{direction: "up", version: 8, want: []string{"version", "up-production-risk-projection", "version"}},
		{direction: "up", version: 9, want: []string{"version", "version"}},
		{direction: "down", version: 9, want: []string{"version", "down-production-risk-projection", "down-api-token-reveal-grants", "down-production-administration", "down-receipt-provenance", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 8, want: []string{"version", "down-api-token-reveal-grants", "down-production-administration", "down-receipt-provenance", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 7, want: []string{"version", "down-production-administration", "down-receipt-provenance", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 6, want: []string{"version", "down-receipt-provenance", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 5, want: []string{"version", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 4, want: []string{"version", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 3, want: []string{"version", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 2, want: []string{"version", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 1, want: []string{"version", "down-baseline", "version"}},
		{direction: "down", version: 0, want: []string{"version", "version"}},
	} {
		t.Run(test.direction+string(rune('0'+test.version)), func(t *testing.T) {
			runner := &scriptedMigrationRunner{version: test.version}
			if err := runReleaseMigration(context.Background(), runner, []string{test.direction}); err != nil {
				t.Fatal(err)
			}
			if len(runner.events) != len(test.want) {
				t.Fatalf("events = %#v", runner.events)
			}
			for index := range test.want {
				if runner.events[index] != test.want[index] {
					t.Fatalf("events = %#v, want %#v", runner.events, test.want)
				}
			}
		})
	}
}

func TestRunReleaseMigrationRejectsDriftAndHonorsDeadline(t *testing.T) {
	if err := runReleaseMigration(context.Background(), &scriptedMigrationRunner{version: 10}, []string{"up"}); !errors.Is(err, migrations.ErrInvalidState) {
		t.Fatalf("drift error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runReleaseMigration(ctx, &scriptedMigrationRunner{}, []string{"up"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("deadline error = %v", err)
	}
}

func TestRunReleaseMigrationRejectsAmbiguousInputsAndStopsOnFailure(t *testing.T) {
	for _, arguments := range [][]string{nil, {}, {"status"}, {"up", "extra"}} {
		if err := runReleaseMigration(context.Background(), &scriptedMigrationRunner{}, arguments); err == nil {
			t.Fatalf("arguments %#v accepted", arguments)
		}
	}
	runner := &scriptedMigrationRunner{errAt: "up-baseline"}
	if err := runReleaseMigration(context.Background(), runner, []string{"up"}); err == nil || len(runner.events) != 2 {
		t.Fatalf("failure = %v, events = %#v", err, runner.events)
	}
}

func TestReleaseMigrationReachesExactPostgresTargetFromEmptyV1AndV2AndRejectsDrift(t *testing.T) {
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close(context.Background()) }()
	runner, err := migrations.NewRunner(&migrationDatabase{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	if err := runReleaseMigration(ctx, runner, []string{"up"}); err != nil {
		t.Fatalf("empty to v7: %v", err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 9 {
		t.Fatalf("v9 = (%d, %v)", version, err)
	}
	if err := runReleaseMigration(ctx, runner, []string{"up"}); err != nil {
		t.Fatalf("v7 retry: %v", err)
	}
	if err := runReleaseMigration(ctx, runner, []string{"down"}); err != nil {
		t.Fatalf("v7 to empty: %v", err)
	}
	if err := runner.Up(ctx); err != nil {
		t.Fatalf("create v1: %v", err)
	}
	if err := runReleaseMigration(ctx, runner, []string{"up"}); err != nil {
		t.Fatalf("v1 to v7: %v", err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_schema_versions SET checksum = repeat('0', 64) WHERE version = 2`); err != nil {
		t.Fatal(err)
	}
	if err := runReleaseMigration(ctx, runner, []string{"up"}); !errors.Is(err, migrations.ErrInvalidState) {
		t.Fatalf("drift error = %v", err)
	}
}

func TestV6ReceiptlessPATReplayUsesDurableMarkerAndBlocksEveryRollbackWithoutPartialMigration(t *testing.T) {
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close(context.Background()) }()
	runner, err := migrations.NewRunner(&migrationDatabase{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	if err := runReleaseMigration(ctx, runner, []string{"up"}); err != nil {
		t.Fatalf("empty to v7: %v", err)
	}
	if err := runner.DownProductionRiskProjection(ctx); err != nil {
		t.Fatalf("v9 to v8 fixture: %v", err)
	}
	if err := runner.DownAPITokenRevealGrants(ctx); err != nil {
		t.Fatalf("v8 to v7 fixture: %v", err)
	}
	if err := runner.DownProductionAdministration(ctx); err != nil {
		t.Fatalf("v7 to v6 fixture: %v", err)
	}
	organization := "pid_71000001-0000-4000-8000-000000000001"
	workspace := "pid_71000002-0000-4000-8000-000000000002"
	environment := "pid_71000003-0000-4000-8000-000000000003"
	principal := "pid_71000004-0000-4000-8000-000000000004"
	createReplay := func(id, key, auditID, correlationID string, receiptID any) string {
		t.Helper()
		body := fmt.Sprintf(`{"id":%q,"name":"Rollback replay","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"read"}],"action":"monitor","rollout":"draft","failure_mode":"open"}`, id)
		intent := fmt.Sprintf(`{"body":%s,"expected_version":0,"resource_id":""}`, body)
		if _, err := connection.Exec(ctx, `SELECT public.zasp_workflow_mutate(
			'create','policy',$1,$2,$3,$4,$5,'createPolicy',$6,0,$7::jsonb,$8::jsonb,$9,$10,$11)`,
			id, organization, workspace, environment, principal, key, intent, body, auditID, correlationID, receiptID); err != nil {
			t.Fatalf("create replay %s: %v", key, err)
		}
		return intent
	}
	const patID = "policy-rollback-pat"
	const patKey = "idem-rollback-pat-0001"
	createReplay(patID, patKey, "pid_72000001-0000-4000-8000-000000000001", "pid_72000002-0000-4000-8000-000000000002", nil)
	const browserKey = "idem-rollback-browser-0001"
	const browserReceiptID = "pid_72000003-0000-4000-8000-000000000003"
	browserIntent := createReplay("policy-rollback-browser", browserKey, "pid_72000004-0000-4000-8000-000000000004", "pid_72000005-0000-4000-8000-000000000005", browserReceiptID)

	type rollbackSnapshot struct {
		Version             int64
		VersionRows         int
		ProvenanceChecksum  string
		Release             string
		Fingerprint         string
		MutationFunction    string
		IdempotencyRowCount int
		IncompatibleCount   int
	}
	snapshot := func() rollbackSnapshot {
		t.Helper()
		value := rollbackSnapshot{}
		value.Version, err = runner.Version(ctx)
		if err != nil {
			t.Fatalf("snapshot version: %v", err)
		}
		if err := connection.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM zasp_schema_versions),
			(SELECT checksum FROM zasp_schema_versions WHERE version=6),
			(SELECT value FROM zasp_schema_metadata WHERE key='production_core_schema'),
			(SELECT value FROM zasp_schema_metadata WHERE key='production_workflow_receipt_provenance_fingerprint'),
			pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure),
			(SELECT count(*) FROM zasp_workflow_idempotency),
			(SELECT count(*) FROM zasp_workflow_idempotency WHERE receipt_semantics='receiptless_incompatible')`).Scan(
			&value.VersionRows, &value.ProvenanceChecksum, &value.Release, &value.Fingerprint, &value.MutationFunction, &value.IdempotencyRowCount, &value.IncompatibleCount); err != nil {
			t.Fatalf("snapshot state: %v", err)
		}
		return value
	}
	before := snapshot()
	if before.Version != 6 || before.VersionRows != 6 || before.Release != "production-workflow-receipt-provenance-v3" || before.IdempotencyRowCount != 2 || before.IncompatibleCount != 1 {
		t.Fatalf("initial v6 snapshot = %#v", before)
	}
	for _, rollback := range []struct {
		name string
		run  func(context.Context) error
	}{
		{name: "DownCore", run: runner.DownCore},
		{name: "Down", run: runner.Down},
	} {
		if err := rollback.run(ctx); !errors.Is(err, migrations.ErrInvalidState) {
			t.Fatalf("%s v6 precondition = %v", rollback.name, err)
		}
		if after := snapshot(); after != before {
			t.Fatalf("%s changed v6 state: before=%#v after=%#v", rollback.name, before, after)
		}
	}
	for _, rollback := range []struct {
		name string
		run  func() error
	}{
		{name: "DownWorkflowReceiptProvenance", run: func() error { return runner.DownWorkflowReceiptProvenance(ctx) }},
		{name: "release down", run: func() error { return runReleaseMigration(ctx, runner, []string{"down"}) }},
	} {
		err := rollback.run()
		if !errors.Is(err, migrations.ErrDatabase) || err.Error() != migrations.ErrDatabase.Error() {
			t.Fatalf("%s unsanitized error = %v", rollback.name, err)
		}
		if after := snapshot(); after != before {
			t.Fatalf("%s partially changed v6 state: before=%#v after=%#v", rollback.name, before, after)
		}
	}
	command := exec.CommandContext(ctx, "go", "run", ".", "down")
	command.Env = append(os.Environ(), "ZASP_POSTGRES_DSN="+dsn, "ZASP_MIGRATION_TIMEOUT=10s")
	output, commandErr := command.CombinedOutput()
	if commandErr == nil || !strings.Contains(string(output), "release migration failed") || strings.Contains(string(output), "workflow receipt safety rollback blocked") || strings.Contains(string(output), patKey) {
		t.Fatalf("migrator CLI error = %v output=%q", commandErr, output)
	}
	if after := snapshot(); after != before {
		t.Fatalf("migrator CLI partially changed v6 state: before=%#v after=%#v", before, after)
	}

	cleanup, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, deletion := range []struct {
		name      string
		statement string
		args      []any
	}{
		{name: "idempotency", statement: `DELETE FROM zasp_workflow_idempotency WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND principal_id=$4 AND operation='createPolicy' AND idempotency_key=$5`, args: []any{organization, workspace, environment, principal, patKey}},
		{name: "audit", statement: `DELETE FROM zasp_workflow_audit WHERE organization_id=$1 AND audit_id=$2`, args: []any{organization, "pid_72000001-0000-4000-8000-000000000001"}},
		{name: "record", statement: `DELETE FROM zasp_workflow_records WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND kind='policy' AND id=$4`, args: []any{organization, workspace, environment, patID}},
	} {
		result, err := cleanup.Exec(ctx, deletion.statement, deletion.args...)
		if err != nil || result.RowsAffected() != 1 {
			_ = cleanup.Rollback(ctx)
			t.Fatalf("exact %s cleanup = rows %d error %v", deletion.name, result.RowsAffected(), err)
		}
	}
	if err := cleanup.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownWorkflowReceiptProvenance(ctx); err != nil {
		t.Fatalf("clean v6 to v5: %v", err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 5 {
		t.Fatalf("intermediate rollback target = (%d, %v)", version, err)
	}
	blocked := concurrentPATMutation("intermediate-v5", "pid_72000006-0000-4000-8000-000000000006", "pid_72000007-0000-4000-8000-000000000007")
	var blockedPayload []byte
	if err := connection.QueryRow(ctx, concurrentPATMutationSQL, blocked.arguments()...).Scan(&blockedPayload); err == nil || !strings.Contains(err.Error(), "workflow mutations unavailable at intermediate receipt provenance downgrade") {
		t.Fatalf("intermediate v5 mutation = %v", err)
	}
	if err := runner.DownWorkflowReceiptSafety(ctx); err != nil {
		t.Fatalf("safe v5 to v4: %v", err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 4 {
		t.Fatalf("rollback target = (%d, %v)", version, err)
	}
	var replayJSON []byte
	if err := connection.QueryRow(ctx, `SELECT public.zasp_workflow_replay($1,$2,$3,$4,'createPolicy',$5,$6::jsonb)`, organization, workspace, environment, principal, browserKey, browserIntent).Scan(&replayJSON); err != nil {
		t.Fatal(err)
	}
	var replay struct {
		Found  bool `json:"found"`
		Result struct {
			Replayed  bool   `json:"replayed"`
			ReceiptID string `json:"receipt_id"`
		} `json:"result"`
	}
	if json.Unmarshal(replayJSON, &replay) != nil || !replay.Found || !replay.Result.Replayed || replay.Result.ReceiptID != browserReceiptID {
		t.Fatalf("v4 replay semantics = %s", replayJSON)
	}
	if err := runReleaseMigration(ctx, runner, []string{"down"}); err != nil {
		t.Fatalf("clean release down: %v", err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 0 {
		t.Fatalf("clean release target = (%d, %v)", version, err)
	}
}

func TestV6BackfillsConservativelyAndMarksMutationFromOlderTransaction(t *testing.T) {
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	migrationConnection := connectMigrationPostgres(t, ctx, dsn)
	defer func() { _ = migrationConnection.Close(context.Background()) }()
	writer := connectMigrationPostgres(t, ctx, dsn)
	defer func() { _ = writer.Close(context.Background()) }()
	runner := migrateToV5(t, ctx, migrationConnection)

	prePAT := concurrentPATMutation("pre-v6-pat", "pid_74000001-0000-4000-8000-000000000001", "pid_74000002-0000-4000-8000-000000000002")
	var payload []byte
	if err := migrationConnection.QueryRow(ctx, concurrentPATMutationSQL, prePAT.arguments()...).Scan(&payload); err != nil {
		t.Fatalf("pre-v6 PAT mutation: %v", err)
	}
	preBrowser := concurrentPATMutation("pre-v6-browser", "pid_74000003-0000-4000-8000-000000000003", "pid_74000004-0000-4000-8000-000000000004")
	browserArguments := append(preBrowser.arguments(), "pid_74000005-0000-4000-8000-000000000005")
	if err := migrationConnection.QueryRow(ctx, concurrentBrowserMutationSQL, browserArguments...).Scan(&payload); err != nil {
		t.Fatalf("pre-v6 browser mutation: %v", err)
	}

	writerTx, err := writer.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writerTx.Rollback(context.Background()) }()
	if err := runner.UpWorkflowReceiptProvenance(ctx); err != nil {
		t.Fatalf("v5 to v6 with older transaction: %v", err)
	}
	latePAT := concurrentPATMutation("older-transaction", "pid_74000006-0000-4000-8000-000000000006", "pid_74000007-0000-4000-8000-000000000007")
	if err := writerTx.QueryRow(ctx, concurrentPATMutationSQL, latePAT.arguments()...).Scan(&payload); err != nil {
		t.Fatalf("older transaction mutation after v6: %v", err)
	}
	if err := writerTx.QueryRow(ctx, concurrentPATMutationSQL, latePAT.arguments()...).Scan(&payload); err != nil {
		t.Fatalf("older transaction replay after v6: %v", err)
	}
	if err := writerTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	var prePATMarker, preBrowserMarker, latePATMarker string
	var latePredatesMigration bool
	if err := migrationConnection.QueryRow(ctx, `SELECT
		(SELECT receipt_semantics FROM zasp_workflow_idempotency WHERE idempotency_key=$1),
		(SELECT receipt_semantics FROM zasp_workflow_idempotency WHERE idempotency_key=$2),
		(SELECT receipt_semantics FROM zasp_workflow_idempotency WHERE idempotency_key=$3),
		(SELECT replay.created_at < marker.applied_at
		   FROM zasp_workflow_idempotency AS replay
		   JOIN zasp_schema_metadata AS marker ON marker.key='production_core_schema'
		  WHERE replay.idempotency_key=$3)`, prePAT.key, preBrowser.key, latePAT.key).Scan(
		&prePATMarker, &preBrowserMarker, &latePATMarker, &latePredatesMigration); err != nil {
		t.Fatal(err)
	}
	if prePATMarker != "receiptless_incompatible" || preBrowserMarker != "receipt_backed" || latePATMarker != "receiptless_incompatible" || !latePredatesMigration {
		t.Fatalf("provenance markers = prePAT %q browser %q latePAT %q predates=%t", prePATMarker, preBrowserMarker, latePATMarker, latePredatesMigration)
	}
	if err := runner.DownWorkflowReceiptProvenance(ctx); !errors.Is(err, migrations.ErrDatabase) {
		t.Fatalf("older transaction provenance rollback = %v", err)
	}
}

func TestV6DownRejectsMarkerDriftBeforeAnyDDL(t *testing.T) {
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	connection := connectMigrationPostgres(t, ctx, dsn)
	defer func() { _ = connection.Close(context.Background()) }()
	runner := migrateToV6(t, ctx, connection)
	if _, err := connection.Exec(ctx, `ALTER TABLE zasp_workflow_idempotency ALTER COLUMN receipt_semantics SET DEFAULT 'receipt_backed'`); err != nil {
		t.Fatal(err)
	}
	var functionBefore string
	if err := connection.QueryRow(ctx, `SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure)`).Scan(&functionBefore); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownWorkflowReceiptProvenance(ctx); !errors.Is(err, migrations.ErrDatabase) || err.Error() != migrations.ErrDatabase.Error() {
		t.Fatalf("marker drift down error = %v", err)
	}
	var functionAfter, markerDefault, markerRelease string
	if err := connection.QueryRow(ctx, `SELECT
		pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure),
		pg_get_expr(default_value.adbin, default_value.adrelid, true),
		(SELECT value FROM zasp_schema_metadata WHERE key='production_core_schema')
	 FROM pg_attribute AS attribute
	 JOIN pg_attrdef AS default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum
	 WHERE attribute.attrelid='public.zasp_workflow_idempotency'::regclass AND attribute.attname='receipt_semantics'`).Scan(
		&functionAfter, &markerDefault, &markerRelease); err != nil {
		t.Fatal(err)
	}
	if functionAfter != functionBefore || markerDefault != "'receipt_backed'::text" || markerRelease != "production-workflow-receipt-provenance-v3" {
		t.Fatalf("partial marker drift down: function_changed=%t default=%q release=%q", functionAfter != functionBefore, markerDefault, markerRelease)
	}
	if version, err := runner.Version(ctx); err != nil || version != 6 {
		t.Fatalf("marker drift version = (%d, %v)", version, err)
	}
}

func TestV6RollbackSerializesConcurrentWorkflowMutations(t *testing.T) {
	t.Run("writer before down blocks rollback then rejects it", func(t *testing.T) {
		dsn := startMigrationPostgres(t)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		writer := connectMigrationPostgres(t, ctx, dsn)
		defer func() { _ = writer.Close(context.Background()) }()
		down := connectMigrationPostgres(t, ctx, dsn)
		defer func() { _ = down.Close(context.Background()) }()
		observer := connectMigrationPostgres(t, ctx, dsn)
		defer func() { _ = observer.Close(context.Background()) }()
		runner := migrateToV6(t, ctx, down)

		writerTx, err := writer.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = writerTx.Rollback(context.Background()) }()
		fixture := concurrentPATMutation("writer-first", "pid_73000001-0000-4000-8000-000000000001", "pid_73000002-0000-4000-8000-000000000002")
		if _, err := writerTx.Exec(ctx, concurrentPATMutationSQL, fixture.arguments()...); err != nil {
			t.Fatalf("writer mutation: %v", err)
		}
		downPID := postgresBackendPID(t, ctx, down)
		downDone := make(chan error, 1)
		go func() {
			downCtx, downCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer downCancel()
			downDone <- runner.DownWorkflowReceiptProvenance(downCtx)
		}()
		awaitPostgresLockWait(t, ctx, observer, downPID, downDone)

		if err := writerTx.Commit(ctx); err != nil {
			t.Fatalf("writer commit: %v", err)
		}
		if err := awaitMigrationResult(t, downDone); !errors.Is(err, migrations.ErrDatabase) {
			t.Fatalf("down after committed receipt-less writer = %v", err)
		}
		if version, err := runner.Version(ctx); err != nil || version != 6 {
			t.Fatalf("guarded concurrent rollback state = (%d, %v)", version, err)
		}
		assertConcurrentMutationCounts(t, ctx, observer, fixture, 1, 1, 1)
	})

	t.Run("down before queued old v6 writer commits v5 and writer aborts", func(t *testing.T) {
		dsn := startMigrationPostgres(t)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		barrier := connectMigrationPostgres(t, ctx, dsn)
		defer func() { _ = barrier.Close(context.Background()) }()
		down := connectMigrationPostgres(t, ctx, dsn)
		defer func() { _ = down.Close(context.Background()) }()
		writer := connectMigrationPostgres(t, ctx, dsn)
		defer func() { _ = writer.Close(context.Background()) }()
		observer := connectMigrationPostgres(t, ctx, dsn)
		defer func() { _ = observer.Close(context.Background()) }()
		runner := migrateToV6(t, ctx, down)

		barrierTx, err := barrier.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = barrierTx.Rollback(context.Background()) }()
		if _, err := barrierTx.Exec(ctx, `LOCK TABLE public.zasp_workflow_idempotency IN ROW EXCLUSIVE MODE`); err != nil {
			t.Fatalf("barrier lock: %v", err)
		}
		downPID := postgresBackendPID(t, ctx, down)
		downDone := make(chan error, 1)
		go func() {
			downCtx, downCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer downCancel()
			downDone <- runner.DownWorkflowReceiptProvenance(downCtx)
		}()
		awaitPostgresLockWait(t, ctx, observer, downPID, downDone)

		fixture := concurrentPATMutation("down-first", "pid_73000003-0000-4000-8000-000000000003", "pid_73000004-0000-4000-8000-000000000004")
		writerPID := postgresBackendPID(t, ctx, writer)
		writerDone := make(chan error, 1)
		go func() {
			writerCtx, writerCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer writerCancel()
			var payload []byte
			writerDone <- writer.QueryRow(writerCtx, concurrentPATMutationSQL, fixture.arguments()...).Scan(&payload)
		}()
		awaitPostgresLockWait(t, ctx, observer, writerPID, writerDone)

		if err := barrierTx.Commit(ctx); err != nil {
			t.Fatalf("barrier commit: %v", err)
		}
		if err := awaitMigrationResult(t, downDone); err != nil {
			t.Fatalf("down with queued old-v5 writer: %v", err)
		}
		if version, err := runner.Version(ctx); err != nil || version != 5 {
			t.Fatalf("concurrent rollback target = (%d, %v)", version, err)
		}
		if err := awaitMigrationResult(t, writerDone); err == nil || !strings.Contains(err.Error(), "workflow receipt provenance release unavailable") {
			t.Fatalf("queued old-v6 writer after v5 = %v", err)
		}
		assertConcurrentMutationCounts(t, ctx, observer, fixture, 0, 0, 0)
	})
}

const concurrentPATMutationSQL = `SELECT public.zasp_workflow_mutate(
	'create','policy',$1,$2,$3,$4,$5,'createPolicy',$6,0,$7::jsonb,$8::jsonb,$9,$10,NULL)`

const concurrentBrowserMutationSQL = `SELECT public.zasp_workflow_mutate(
	'create','policy',$1,$2,$3,$4,$5,'createPolicy',$6,0,$7::jsonb,$8::jsonb,$9,$10,$11)`

type concurrentMutationFixture struct {
	id            string
	organization  string
	workspace     string
	environment   string
	principal     string
	key           string
	intent        string
	body          string
	auditID       string
	correlationID string
}

func concurrentPATMutation(suffix, auditID, correlationID string) concurrentMutationFixture {
	id := "policy-concurrent-" + suffix
	body := fmt.Sprintf(`{"id":%q,"name":"Concurrent rollback","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"read"}],"action":"monitor","rollout":"draft","failure_mode":"open"}`, id)
	return concurrentMutationFixture{
		id: id, organization: "pid_73000011-0000-4000-8000-000000000011", workspace: "pid_73000012-0000-4000-8000-000000000012",
		environment: "pid_73000013-0000-4000-8000-000000000013", principal: "pid_73000014-0000-4000-8000-000000000014",
		key: "idem-concurrent-" + suffix + "-0001", intent: fmt.Sprintf(`{"body":%s,"expected_version":0,"resource_id":""}`, body), body: body,
		auditID: auditID, correlationID: correlationID,
	}
}

func (fixture concurrentMutationFixture) arguments() []any {
	return []any{fixture.id, fixture.organization, fixture.workspace, fixture.environment, fixture.principal, fixture.key, fixture.intent, fixture.body, fixture.auditID, fixture.correlationID}
}

func connectMigrationPostgres(t *testing.T, ctx context.Context, dsn string) *pgx.Conn {
	t.Helper()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func migrateToV6(t *testing.T, ctx context.Context, connection *pgx.Conn) *migrations.Runner {
	t.Helper()
	runner, err := migrations.NewRunner(&migrationDatabase{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	if err := runReleaseMigration(ctx, runner, []string{"up"}); err != nil {
		t.Fatalf("migrate to v6: %v", err)
	}
	if err := runner.DownProductionRiskProjection(ctx); err != nil {
		t.Fatalf("down risk projection: %v", err)
	}
	if err := runner.DownAPITokenRevealGrants(ctx); err != nil {
		t.Fatalf("migrate v8 to v7 fixture: %v", err)
	}
	if err := runner.DownProductionAdministration(ctx); err != nil {
		t.Fatalf("migrate v7 to v6 fixture: %v", err)
	}
	return runner
}

func migrateToV5(t *testing.T, ctx context.Context, connection *pgx.Conn) *migrations.Runner {
	t.Helper()
	runner, err := migrations.NewRunner(&migrationDatabase{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range []struct {
		name string
		run  func(context.Context) error
	}{
		{name: "baseline", run: runner.Up}, {name: "core", run: runner.UpCore}, {name: "workflows", run: runner.UpWorkflows},
		{name: "receipts", run: runner.UpWorkflowReceipts}, {name: "safety", run: runner.UpWorkflowReceiptSafety},
	} {
		if err := migration.run(ctx); err != nil {
			t.Fatalf("migrate %s to v5: %v", migration.name, err)
		}
	}
	return runner
}

func postgresBackendPID(t *testing.T, ctx context.Context, connection *pgx.Conn) int32 {
	t.Helper()
	var pid int32
	if err := connection.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	return pid
}

func awaitPostgresLockWait(t *testing.T, ctx context.Context, observer *pgx.Conn, pid int32, completed <-chan error) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-completed:
			t.Fatalf("operation completed before required lock wait: %v", err)
		default:
		}
		var waiting bool
		if err := observer.QueryRow(ctx, `SELECT COALESCE(wait_event_type = 'Lock', false) FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&waiting); err != nil {
			t.Fatalf("observe lock wait: %v", err)
		}
		if waiting {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("backend %d did not enter a bounded lock wait", pid)
}

func awaitMigrationResult(t *testing.T, completed <-chan error) error {
	t.Helper()
	select {
	case err := <-completed:
		return err
	case <-time.After(6 * time.Second):
		t.Fatal("concurrent migration operation exceeded bounded wait")
		return nil
	}
}

func assertConcurrentMutationCounts(t *testing.T, ctx context.Context, connection *pgx.Conn, fixture concurrentMutationFixture, records, audits, idempotency int) {
	t.Helper()
	var gotRecords, gotAudits, gotIdempotency int
	if err := connection.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM zasp_workflow_records WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND kind='policy' AND id=$4),
		(SELECT count(*) FROM zasp_workflow_audit WHERE organization_id=$1 AND audit_id=$5),
		(SELECT count(*) FROM zasp_workflow_idempotency WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND principal_id=$6 AND operation='createPolicy' AND idempotency_key=$7)`,
		fixture.organization, fixture.workspace, fixture.environment, fixture.id, fixture.auditID, fixture.principal, fixture.key).Scan(&gotRecords, &gotAudits, &gotIdempotency); err != nil {
		t.Fatalf("mutation counts: %v", err)
	}
	if gotRecords != records || gotAudits != audits || gotIdempotency != idempotency {
		t.Fatalf("mutation counts = (%d,%d,%d), want (%d,%d,%d)", gotRecords, gotAudits, gotIdempotency, records, audits, idempotency)
	}
}

func startMigrationPostgres(t *testing.T) string {
	t.Helper()
	initdb, initErr := exec.LookPath("initdb")
	postgres, postgresErr := exec.LookPath("postgres")
	ready, readyErr := exec.LookPath("pg_isready")
	ctl, ctlErr := exec.LookPath("pg_ctl")
	if initErr != nil || postgresErr != nil || readyErr != nil || ctlErr != nil {
		t.Skip("local PostgreSQL binaries unavailable")
	}
	root := t.TempDir()
	data := filepath.Join(root, "data")
	if err := exec.Command(initdb, "--no-locale", "--encoding=UTF8", "--auth-local=trust", "--auth-host=trust", "--username=zasp_test", "-D", data).Run(); err != nil {
		t.Fatalf("initdb: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	var stderr bytes.Buffer
	command := exec.Command(postgres, "-D", data, "-h", "127.0.0.1", "-p", strconv.Itoa(port), "-k", "")
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop := exec.Command(ctl, "-D", data, "-m", "fast", "-w", "stop")
		if stop.Run() != nil && command.Process != nil {
			_ = command.Process.Kill()
		}
		_ = command.Wait()
	})
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(25 * time.Millisecond) {
		if exec.Command(ready, "-h", "127.0.0.1", "-p", strconv.Itoa(port), "-U", "zasp_test", "-d", "postgres").Run() == nil {
			return fmt.Sprintf("postgres://zasp_test@127.0.0.1:%d/postgres?sslmode=disable", port)
		}
	}
	t.Fatalf("postgres did not become ready: %s", stderr.String())
	return ""
}
