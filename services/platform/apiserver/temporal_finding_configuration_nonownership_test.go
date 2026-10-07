package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

const nonownerRawWrite = `SELECT zasp_temporal78.configuration_write($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14)`
const nonownerJSONWrite = `SELECT COALESCE((SELECT zasp_temporal78.configuration_write($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14)),'null'::jsonb)`

// SQL NULL is deliberately distinct from a PostgreSQL P0002 error. This
// driver models only the fixed scalar boundary; the genuine native fixture
// separately exercises the installed78 function and real74 typed writer.
type nonownerWriteDriver struct {
	PostgresDriver
	failure   error
	owned     []byte
	writeArgs []any
}

func (d *nonownerWriteDriver) QueryRow(_ context.Context, q string, args ...any) PostgresRow {
	switch q {
	case `SELECT to_jsonb(to_regnamespace('zasp_temporal78') IS NOT NULL)`, `SELECT to_jsonb(zasp_temporal78.api_ready($1,$2))`:
		return databaseRow{value: []byte("true")}
	case nonownerRawWrite, nonownerJSONWrite:
		d.writeArgs = append([]any(nil), args...)
		if d.failure != nil {
			return databaseRow{err: d.failure}
		}
		if d.owned != nil {
			return databaseRow{value: d.owned}
		}
		if q == nonownerJSONWrite {
			return databaseRow{value: []byte("null")}
		}
		return databaseRow{} // Actual nil Scan destination for SQL NULL.
	default:
		for _, fixed := range []string{`SELECT zasp_temporal78.configuration_write($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14)`, `SELECT zasp_temporal78.configuration_replay($1,$2,$3,$4,$5,$6,$7::jsonb)`, `SELECT to_jsonb(zasp_temporal78.family($1,$2,$3,$4,$5))`, `SELECT zasp_temporal78.resource($1::jsonb)`, `SELECT zasp_temporal78.definition($1,$2,$3,$4,$5)`, `SELECT zasp_temporal78.activate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, `SELECT zasp_temporal78.run_context($1,$2,$3,$4)`, `SELECT zasp_temporal78.approval_page($1,$2,$3,NULLIF($4,''),NULLIF($5,''),$6,NULLIF($7,''),$8,$9)`, `SELECT zasp_temporal78.approval($1,$2,$3,$4,$5)`, `SELECT zasp_temporal78.decide_approval($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`} {
			if q == fixed {
				return databaseRow{}
			}
			if q == `SELECT COALESCE((`+fixed+`),'null'::jsonb)` {
				return databaseRow{value: []byte("null")}
			}
		}
		return databaseRow{err: errors.New("unexpected statement")}
	}
}

type nonownerTypedDatabase struct {
	*PostgresJSONDatabase
	typedCalls int
	typedArgs  []any
	response   json.RawMessage
}

func (d *nonownerTypedDatabase) MutateTemporalTestDefinition(_ context.Context, args ...any) (json.RawMessage, bool, error) {
	d.typedCalls++
	d.typedArgs = append([]any(nil), args...)
	return d.response, true, nil
}
func nonownerMutationFixture(t *testing.T, driver *nonownerWriteDriver) (*PostgresRepository, *nonownerTypedDatabase, WorkflowMutation, RequestIdentity) {
	t.Helper()
	base, err := NewPostgresJSONDatabase(driver)
	if err != nil {
		t.Fatal(err)
	}
	q := WorkflowMutation{Action: "create", Kind: "security_agent", ID: "pid_f0740000-0000-4000-8000-000000000101", Operation: "createSecurityAgent", IdempotencyKey: "test74-full-create", Intent: json.RawMessage(`{"resource_id":"","expected_version":0}`), Body: json.RawMessage(`{"enabled":false,"allowed_actions":["run_test"]}`), AuditID: "pid_f0740000-0000-4000-8000-000000000102", CorrelationID: "pid_f0740000-0000-4000-8000-000000000103", ReceiptID: "pid_f0740000-0000-4000-8000-000000000104"}
	payload, err := json.Marshal(WorkflowMutationResult{WorkflowValue: WorkflowValue{Body: q.Body, Version: 1}, AuditID: q.AuditID, CorrelationID: q.CorrelationID, ReceiptID: q.ReceiptID})
	if err != nil {
		t.Fatal(err)
	}
	db := &nonownerTypedDatabase{PostgresJSONDatabase: base, response: payload}
	return &PostgresRepository{database: db, securityAgentExecution: true}, db, q, fixtureRequestIdentity(t)
}
func TestTemporalFindingSQLNullRemainsMissingAtGeneralDatabaseBoundary(t *testing.T) {
	db, err := NewPostgresJSONDatabase(&nonownerWriteDriver{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.QueryJSON(context.Background(), nonownerRawWrite); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatal("general SQL NULL admission changed", err)
	}
}
func TestTemporalFindingConfigurationNonownerReachesTyped74(t *testing.T) {
	driver := &nonownerWriteDriver{}
	repo, db, q, id := nonownerMutationFixture(t, driver)
	result, err := repo.MutateWorkflow(context.Background(), id, q)
	if err != nil || result.Version != 1 || result.ReceiptID != q.ReceiptID || db.typedCalls != 1 {
		t.Fatalf("native78 nonowner must reach typed74: version=%d calls=%d err=%v", result.Version, db.typedCalls, err)
	}
	if !reflect.DeepEqual(driver.writeArgs, db.typedArgs) || len(db.typedArgs) != 14 {
		t.Fatal("fallback changed native positional arguments")
	}
}
func TestTemporalFindingConfigurationErrorsNeverDowngrade(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		want       error
	}{{"missing owned record", "P0002", ErrRepositoryNotFound}, {"permission refused", "42501", ErrRepositoryUnavailable}} {
		t.Run(tc.name, func(t *testing.T) {
			driver := &nonownerWriteDriver{failure: &pgconn.PgError{Code: tc.code}}
			repo, db, q, id := nonownerMutationFixture(t, driver)
			_, err := repo.MutateWorkflow(context.Background(), id, q)
			if !errors.Is(err, tc.want) || db.typedCalls != 0 {
				t.Fatalf("real failure downgraded: typed=%d err=%v", db.typedCalls, err)
			}
		})
	}
	t.Run("owned response remains handled", func(t *testing.T) {
		driver := &nonownerWriteDriver{}
		repo, db, q, id := nonownerMutationFixture(t, driver)
		driver.owned = db.response
		got, err := repo.MutateWorkflow(context.Background(), id, q)
		if err != nil || got.Version != 1 || db.typedCalls != 0 {
			t.Fatalf("owned response changed: typed=%d err=%v", db.typedCalls, err)
		}
	})
}

func TestTemporalFindingResponseSQLNullNonownershipAllFixedCalls(t *testing.T) {
	for _, q := range []string{`SELECT zasp_temporal78.configuration_write($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14)`, `SELECT zasp_temporal78.configuration_replay($1,$2,$3,$4,$5,$6,$7::jsonb)`, `SELECT to_jsonb(zasp_temporal78.family($1,$2,$3,$4,$5))`, `SELECT zasp_temporal78.resource($1::jsonb)`, `SELECT zasp_temporal78.definition($1,$2,$3,$4,$5)`, `SELECT zasp_temporal78.activate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, `SELECT zasp_temporal78.run_context($1,$2,$3,$4)`, `SELECT zasp_temporal78.approval_page($1,$2,$3,NULLIF($4,''),NULLIF($5,''),$6,NULLIF($7,''),$8,$9)`, `SELECT zasp_temporal78.approval($1,$2,$3,$4,$5)`, `SELECT zasp_temporal78.decide_approval($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`} {
		name := strings.Split(strings.Split(q, "zasp_temporal78.")[1], "(")[0]
		t.Run(name, func(t *testing.T) {
			db, err := NewPostgresJSONDatabase(&nonownerWriteDriver{})
			if err != nil {
				t.Fatal(err)
			}
			raw, handled, err := queryTemporalFindingResponse(context.Background(), db, q)
			if err != nil || handled || string(raw) != "null" {
				t.Fatalf("explicit SQL nonowner lost: handled=%t raw=%q err=%v", handled, raw, err)
			}
		})
	}
}
