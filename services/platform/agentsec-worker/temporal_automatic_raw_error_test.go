package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"go.temporal.io/sdk/activity"
)

type automaticRawRecord struct{ Operation, Error, SQLState, Function, Context, Phase, State, SendPermit, InputPresent, ChildPresent string }
type automaticRawObserver func(context.Context, automaticRawRecord)

func automaticRawDriver(delegate apiserver.PostgresDriver, observer automaticRawObserver) apiserver.PostgresDriver {
	if observer == nil {
		return delegate
	}
	d := &automaticRawObservedDriver{PostgresDriver: delegate, observer: observer}
	if begin, ok := delegate.(apiserver.AuthorizationTransactionDriver); ok {
		return &automaticRawObservedBeginner{automaticRawObservedDriver: d, begin: begin}
	}
	return d
}

type automaticRawObservedDriver struct {
	apiserver.PostgresDriver
	observer automaticRawObserver
}

func (d *automaticRawObservedDriver) QueryRow(ctx context.Context, statement string, args ...any) apiserver.PostgresRow {
	operation := "other_sql"
	for _, name := range []string{"inspect", "test_state", "effect", "linked", "test_settle", "client_ready", "ready"} {
		if strings.HasPrefix(statement, "SELECT zasp_temporal74."+name+"(") {
			operation = name
			break
		}
	}
	return automaticRawObservedRow{row: d.PostgresDriver.QueryRow(ctx, statement, args...), ctx: ctx, operation: operation, observer: d.observer}
}

type automaticRawObservedRow struct {
	row       apiserver.PostgresRow
	ctx       context.Context
	operation string
	observer  automaticRawObserver
}

func (r automaticRawObservedRow) Scan(dest ...any) error {
	err := r.row.Scan(dest...)
	r.observer(r.ctx, automaticRawObservation(r.ctx, r.operation, err, dest))
	return err
}

type automaticRawObservedBeginner struct {
	*automaticRawObservedDriver
	begin apiserver.AuthorizationTransactionDriver
}

func (d *automaticRawObservedBeginner) Begin(ctx context.Context) (pgx.Tx, error) {
	// Preserve the original transaction object and its commit/rollback behavior.
	// Worker drivers currently do not expose Begin; never invent the capability.
	return d.begin.Begin(ctx)
}

var automaticRawSQLState = regexp.MustCompile(`^[0-9A-Z]{5}$`)

// Only static labels and booleans leave this formatter. No new SQL reads are
// issued, even when Scan failed or a delegate still owns a transaction.
func automaticRawObservation(ctx context.Context, operation string, err error, dest []any) automaticRawRecord {
	v := automaticRawRecord{Operation: "other_sql", Error: automaticFirstErrorClass(err), SQLState: "none", Function: "none", Context: automaticFirstErrorClass(ctx.Err()), Phase: "unknown", State: "unknown", SendPermit: "unknown", InputPresent: "unknown", ChildPresent: "unknown"}
	if stringInWorker(operation, "inspect", "test_state", "effect", "linked", "test_settle", "client_ready", "ready", "command/enter", "command/exit", "child/enter", "child/exit") {
		v.Operation = operation
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		v.Error = "postgres"
		if automaticRawSQLState.MatchString(pg.Code) {
			v.SQLState = pg.Code
		}
		for _, name := range []string{"zasp_temporal74.linked", "zasp_temporal74.effect", "zasp_temporal74.test_state", "zasp_temporal74.inspect", "zasp_temporal74.authorize", "zasp_temporal74.current_ready", "zasp_temporal74.require_executor", "zasp_temporal74.test_settle"} {
			if strings.Contains(pg.Where, name+"(") {
				v.Function = name
				break
			}
		}
	}
	if err != nil || len(dest) != 1 {
		return v
	}
	var raw []byte
	switch value := dest[0].(type) {
	case *[]byte:
		raw = *value
	case *json.RawMessage:
		raw = *value
	}
	if len(raw) > 131072 {
		return v
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(raw, &body) != nil {
		return v
	}
	var value string
	if json.Unmarshal(body["phase"], &value) == nil && stringInWorker(value, "planning", "test", "settling", "terminal", "waiting_approval", "pending", "permission_lost", "stopping") {
		v.Phase = value
	}
	if json.Unmarshal(body["state"], &value) == nil && stringInWorker(value, "absent", "reserved", "started", "unknown", "stopped", "child", "verified") {
		v.State = value
	}
	if permit := string(body["send_permit"]); permit == "true" || permit == "false" {
		v.SendPermit = permit
	}
	if manifest, ok := body["input_manifest"]; ok {
		v.InputPresent = fmt.Sprint(string(manifest) != "null")
	}
	if v.State == "child" || v.State == "verified" {
		v.ChildPresent = "true"
	}
	return v
}
func automaticRawLog(t *testing.T, ctx context.Context, v automaticRawRecord) {
	if !activity.IsActivity(ctx) {
		return
	}
	i := activity.GetInfo(ctx)
	if i.ActivityType.Name != "SingleTest" {
		return
	}
	t.Logf("automatic77-raw workflow=%s execution=%s activity=SingleTest attempt=%d operation=%s error=%s sqlstate=%s function=%s context=%s phase=%s state=%s send_permit=%s input_present=%s child_present=%s invocation_present=unknown", i.WorkflowExecution.ID, i.WorkflowExecution.RunID, i.Attempt, v.Operation, v.Error, v.SQLState, v.Function, v.Context, v.Phase, v.State, v.SendPermit, v.InputPresent, v.ChildPresent)
}
func automaticRawCommandMarker(t *testing.T, ctx context.Context, operation string, err error) {
	automaticRawLog(t, ctx, automaticRawObservation(ctx, operation, err, nil))
}

type automaticRawFixtureRow struct {
	calls       int
	destination any
	value       []byte
	err         error
}

func (r *automaticRawFixtureRow) Scan(dest ...any) error {
	r.calls++
	r.destination = dest[0]
	if r.err == nil {
		*dest[0].(*[]byte) = append([]byte(nil), r.value...)
	}
	return r.err
}

type automaticRawFixtureDriver struct {
	row                    *automaticRawFixtureRow
	queries, execs, closes int
	ctx                    context.Context
	statement              string
	args                   []any
	execErr, closeErr      error
}

func (d *automaticRawFixtureDriver) QueryRow(ctx context.Context, q string, args ...any) apiserver.PostgresRow {
	d.queries++
	d.ctx = ctx
	d.statement = q
	d.args = args
	return d.row
}
func (d *automaticRawFixtureDriver) Exec(ctx context.Context, q string, args ...any) error {
	d.execs++
	d.ctx = ctx
	d.statement = q
	d.args = args
	return d.execErr
}
func (d *automaticRawFixtureDriver) Close() error { d.closes++; return d.closeErr }

type automaticRawFixtureTransaction struct{ pgx.Tx }
type automaticRawFixtureBeginner struct {
	*automaticRawFixtureDriver
	begins   int
	tx       pgx.Tx
	beginErr error
}

func (d *automaticRawFixtureBeginner) Begin(ctx context.Context) (pgx.Tx, error) {
	d.begins++
	d.ctx = ctx
	return d.tx, d.beginErr
}

func TestAutomaticRawScanBeforeClassification(t *testing.T) {
	secret := "private-dsn-token-payload-marker"
	for _, code := range []string{"23505", "40001", "40P01", "22023", "P0002", "42501"} {
		t.Run(code, func(t *testing.T) {
			original := &pgconn.PgError{Code: code, Message: secret, Detail: secret, Where: "PL/pgSQL function zasp_temporal74.linked(jsonb) " + secret}
			row := &automaticRawFixtureRow{err: original}
			driver := &automaticRawFixtureDriver{row: row}
			var records []automaticRawRecord
			observed := automaticRawDriver(driver, func(_ context.Context, v automaticRawRecord) { records = append(records, v) })
			ctx := context.Background()
			q := "SELECT zasp_temporal74.linked($1::jsonb)"
			arg := json.RawMessage("{\"secret\":\"" + secret + "\"}")
			var destination []byte
			err := observed.QueryRow(ctx, q, arg).Scan(&destination)
			if err != original || driver.queries != 1 || row.calls != 1 || row.destination != &destination || driver.ctx != ctx || driver.statement != q || string(driver.args[0].(json.RawMessage)) != string(arg) {
				t.Fatal("observer changed original Scan/delegation")
			}
			if len(records) != 1 || records[0].SQLState != code || records[0].Operation != "linked" || records[0].Function != "zasp_temporal74.linked" {
				t.Fatalf("missing original pre-classification observation: count=%d", len(records))
			}
			encoded, _ := json.Marshal(records)
			if strings.Contains(string(encoded), secret) || strings.Contains(string(encoded), q) {
				t.Fatal("raw error/query payload disclosed")
			}
			db, err := apiserver.NewPostgresJSONDatabase(observed)
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.QueryJSON(ctx, q, arg)
			if err == nil || driver.queries != 2 || row.calls != 2 || len(records) != 2 || records[1].SQLState != code {
				t.Fatal("classified application query lost raw observation or delegated twice")
			}
		})
	}
}
func TestAutomaticRawSuccessAndDelegation(t *testing.T) {
	row := &automaticRawFixtureRow{value: []byte(`{"state":"reserved","send_permit":false,"input_manifest":null,"secret":"private-body-marker"}`)}
	driver := &automaticRawFixtureDriver{row: row, execErr: errors.New("private-exec-marker"), closeErr: errors.New("private-close-marker")}
	var records []automaticRawRecord
	observed := automaticRawDriver(driver, func(_ context.Context, v automaticRawRecord) { records = append(records, v) })
	if _, ok := observed.(apiserver.AuthorizationTransactionDriver); ok {
		t.Fatal("observer invented Begin capability")
	}
	var got []byte
	if err := observed.QueryRow(context.Background(), "SELECT zasp_temporal74.effect($1::jsonb)").Scan(&got); err != nil || string(got) != string(row.value) {
		t.Fatal("observer changed successful scan")
	}
	if len(records) != 1 || records[0].State != "reserved" || records[0].SendPermit != "false" || records[0].InputPresent != "false" || records[0].ChildPresent != "unknown" {
		t.Fatal("missing safe success state")
	}
	if err := observed.Exec(context.Background(), "private-query", "private-argument"); err != driver.execErr || driver.execs != 1 {
		t.Fatal("Exec did not preserve error/one delegation")
	}
	if err := observed.Close(); err != driver.closeErr || driver.closes != 1 {
		t.Fatal("Close did not preserve error/one delegation")
	}
	encoded, _ := json.Marshal(records)
	if strings.Contains(string(encoded), "private-") {
		t.Fatal("observer leaked delegate material")
	}
	for _, beginErr := range []error{nil, errors.New("private-begin-marker")} {
		tx := &automaticRawFixtureTransaction{}
		beginner := &automaticRawFixtureBeginner{automaticRawFixtureDriver: driver, tx: tx, beginErr: beginErr}
		wrapped := automaticRawDriver(beginner, func(context.Context, automaticRawRecord) {})
		capable, ok := wrapped.(apiserver.AuthorizationTransactionDriver)
		if !ok {
			t.Fatal("observer hid Begin capability")
		}
		result, err := capable.Begin(context.Background())
		if result != tx || err != beginErr || beginner.begins != 1 {
			t.Fatal("Begin/transaction identity changed")
		}
	}
}
func TestAutomaticRawUnknownAndCancellationSafe(t *testing.T) {
	for _, original := range []error{errors.New("private-error-marker"), &pgconn.PgError{Code: "x\nsec", Message: "private-error-marker", Where: "private-function"}, context.Canceled, context.DeadlineExceeded} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		driver := &automaticRawFixtureDriver{row: &automaticRawFixtureRow{err: original}}
		var records []automaticRawRecord
		wrapped := automaticRawDriver(driver, func(_ context.Context, v automaticRawRecord) { records = append(records, v) })
		var out []byte
		if err := wrapped.QueryRow(ctx, "private-SQL", "private-parameter").Scan(&out); err != original || driver.queries != 1 {
			t.Fatal("observer suppressed canceled delegate")
		}
		if len(records) != 1 || records[0].Operation != "other_sql" || records[0].SQLState != "none" || records[0].Function != "none" || records[0].Context != "cancelled" || records[0].Phase != "unknown" {
			t.Fatal("unknown/cancelled observation missing")
		}
		raw, _ := json.Marshal(records)
		if strings.Contains(string(raw), "private-") || strings.Contains(string(raw), "x\\nsec") {
			t.Fatal("observer leaked untrusted fields")
		}
	}
}
func TestAutomaticRawProductionDefaultDisabled(t *testing.T) {
	if productionWorkerIO().temporalDiagnostic != nil {
		t.Fatal("production enabled test diagnostics")
	}
}

func TestAutomaticRawUnknownMetadataAndCommandLabels(t *testing.T) {
	ctx := context.Background()
	raw := []byte(`{"phase":"private-phase","state":"private-state","send_permit":null,"input_manifest":null}`)
	v := automaticRawObservation(ctx, "private-operation", nil, []any{&raw})
	if v.Operation != "other_sql" || v.Phase != "unknown" || v.State != "unknown" || v.SendPermit != "unknown" || v.ChildPresent != "unknown" {
		t.Fatal("unavailable metadata fabricated or reflected")
	}
	for _, op := range []string{"command/enter", "command/exit", "child/enter", "child/exit"} {
		v := automaticRawObservation(ctx, op, errors.New("private-command-error"), nil)
		if v.Operation != op || v.Error != "other" || v.InputPresent != "unknown" {
			t.Fatal("command marker lost safe phase or fabricated state")
		}
		encoded, _ := json.Marshal(v)
		if strings.Contains(string(encoded), "private-") {
			t.Fatal("command marker disclosed error")
		}
	}
	driver := &automaticRawFixtureDriver{}
	if automaticRawDriver(driver, nil) != driver {
		t.Fatal("nil observer changed driver identity")
	}
}
