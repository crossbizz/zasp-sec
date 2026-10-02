package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

type singleRecoveryRequestDiagnosticObservation struct {
	stage, class, reason, sqlstate string
	wireValid, observationValid    bool
	deadline, canceled             bool
}

type singleRecoveryRequestDiagnostic struct {
	mu   sync.Mutex
	last singleRecoveryRequestDiagnosticObservation
}

type singleRecoveryRequestDiagnosticDriver struct {
	driver     PostgresDriver
	diagnostic *singleRecoveryRequestDiagnostic
}

type singleRecoveryRequestDiagnosticTransactionDriver struct {
	*singleRecoveryRequestDiagnosticDriver
	transactions AuthorizationTransactionDriver
}

func wrapSingleRecoveryRequestDiagnosticDriver(driver PostgresDriver) (PostgresDriver, *singleRecoveryRequestDiagnostic) {
	diagnostic := &singleRecoveryRequestDiagnostic{}
	wrapped := &singleRecoveryRequestDiagnosticDriver{driver: driver, diagnostic: diagnostic}
	if transactions, ok := driver.(AuthorizationTransactionDriver); ok {
		return &singleRecoveryRequestDiagnosticTransactionDriver{singleRecoveryRequestDiagnosticDriver: wrapped, transactions: transactions}, diagnostic
	}
	return wrapped, diagnostic
}

func (diagnostic *singleRecoveryRequestDiagnostic) reset() {
	diagnostic.mu.Lock()
	diagnostic.last = singleRecoveryRequestDiagnosticObservation{}
	diagnostic.mu.Unlock()
}

func (diagnostic *singleRecoveryRequestDiagnostic) summary(status int) string {
	diagnostic.mu.Lock()
	observation := diagnostic.last
	diagnostic.mu.Unlock()
	if observation.stage == "" {
		observation.stage = "handler"
		observation.class = singleRecoveryRequestDiagnosticHTTPClass(status)
	} else if observation.class == "ok" && status >= 400 {
		observation.class = singleRecoveryRequestDiagnosticHTTPClass(status)
	}
	if observation.reason == "" {
		observation.reason = "unknown"
	}
	return fmt.Sprintf("stage=%s class=%s reason=%s status=%d wire=%t observation=%t deadline=%t canceled=%t sqlstate=%s", observation.stage, observation.class, observation.reason, status, observation.wireValid, observation.observationValid, observation.deadline, observation.canceled, observation.sqlstate)
}

func singleRecoveryRequestDiagnosticHTTPClass(status int) string {
	switch status {
	case 400:
		return "operation"
	case 401, 403:
		return "authentication"
	case 404:
		return "not_found"
	case 409:
		return "conflict"
	case 503:
		return "unavailable"
	default:
		return "unknown"
	}
}

func singleRecoveryRequestDiagnosticError(err error, ctx context.Context) (class, sqlstate string, deadline, canceled bool) {
	deadline = errors.Is(err, context.DeadlineExceeded) || ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded)
	canceled = errors.Is(err, context.Canceled) || ctx != nil && errors.Is(ctx.Err(), context.Canceled)
	if err == nil && !deadline && !canceled {
		return "ok", "", false, false
	}
	if deadline {
		return "deadline", "", true, canceled
	}
	if canceled {
		return "canceled", "", false, true
	}
	var postgres *pgconn.PgError
	if errors.As(err, &postgres) {
		if singleRecoveryRequestDiagnosticSQLState(postgres.Code) {
			sqlstate = postgres.Code
		}
		switch postgres.Code {
		case "22023", "22P02", "23514":
			return "operation", sqlstate, false, false
		case "23505", "40001", "40P01", "55P03":
			return "conflict", sqlstate, false, false
		case "P0002":
			return "not_found", sqlstate, false, false
		case "42501":
			return "authentication", sqlstate, false, false
		case "54000", "55000":
			return "unavailable", sqlstate, false, false
		default:
			return "unknown", "", false, false
		}
	}
	switch {
	case errors.Is(err, ErrRepositoryOperation):
		return "operation", "", false, false
	case errors.Is(err, ErrRepositoryAuthentication), errors.Is(err, ErrAuthorizationDenied):
		return "authentication", "", false, false
	case errors.Is(err, ErrRepositoryNotFound):
		return "not_found", "", false, false
	case errors.Is(err, ErrRepositoryConflict):
		return "conflict", "", false, false
	case errors.Is(err, ErrRepositoryUnavailable):
		return "unavailable", "", false, false
	default:
		return "unknown", "", false, false
	}
}

func singleRecoveryRequestDiagnosticSQLState(value string) bool {
	switch value {
	case "22023", "22P02", "23514", "23505", "40001", "40P01", "55P03", "P0002", "42501", "54000", "55000":
		return true
	default:
		return false
	}
}

func singleRecoveryRequestDiagnosticReason(err error) string {
	var postgres *pgconn.PgError
	if !errors.As(err, &postgres) {
		return "unknown"
	}
	if postgres.Code == "22023" {
		switch postgres.Message {
		case "recovery request shape rejected":
			return "request_shape"
		case "recovery identity rejected":
			return "request_identity"
		case "recovery intent rejected":
			return "request_intent"
		case "recovery admission shape rejected":
			return "admission_shape"
		case "recovery observation rejected":
			return "observation_shape"
		case "recovery reference rejected":
			return "reference_shape"
		case "security agent cancellation rejected":
			return "cancellation_input"
		case "single-test start rejected":
			return "start_shape"
		case "single-test start scope rejected":
			return "start_scope"
		}
	}
	if postgres.Code == "40001" {
		switch postgres.Message {
		case "recovery authorization revision changed":
			return "authorization_revision"
		case "recovery idempotency conflict":
			return "idempotency"
		case "recovery receipt changed":
			return "receipt"
		case "recovery parent changed":
			return "parent"
		case "recovery version or ownership changed":
			return "version_or_ownership"
		case "recovery observation expired":
			return "observation_expired"
		case "native cancellation proof rejected":
			return "cancellation_proof"
		case "native stop owner changed":
			return "stop_owner"
		case "native stop proof required":
			return "stop_proof"
		case "recovery ancestry changed":
			return "ancestry"
		case "recovery planning proof changed":
			return "planning_proof"
		case "security agent cancellation conflict":
			return "cancellation_conflict"
		case "single-test decision receipt rejected":
			return "decision_receipt"
		case "single-test decision replay changed":
			return "decision_replay"
		case "single-test control proof unavailable":
			return "control_proof"
		case "single-test durable start changed":
			return "durable_start"
		case "recovery completion source changed":
			return "completion_source"
		case "recovery not accepted":
			return "not_accepted"
		case "recovery command changed":
			return "command"
		case "recovery obligations changed":
			return "obligations"
		case "recovery stop binding rejected":
			return "stop_binding"
		case "recovery cancellation changed":
			return "cancellation_changed"
		case "recovery stop kind rejected":
			return "stop_kind"
		case "recovery retained proof changed":
			return "retained_proof"
		}
	}
	return "unknown"
}

func (diagnostic *singleRecoveryRequestDiagnostic) record(stage string, err error, ctx context.Context) {
	class, sqlstate, deadline, canceled := singleRecoveryRequestDiagnosticError(err, ctx)
	reason := singleRecoveryRequestDiagnosticReason(err)
	diagnostic.mu.Lock()
	defer diagnostic.mu.Unlock()
	if diagnostic.last.class != "" && diagnostic.last.class != "ok" {
		return
	}
	diagnostic.last.stage = stage
	diagnostic.last.class = class
	diagnostic.last.reason = reason
	diagnostic.last.sqlstate = sqlstate
	diagnostic.last.deadline = deadline
	diagnostic.last.canceled = canceled
}

func (diagnostic *singleRecoveryRequestDiagnostic) recordWire(valid bool) {
	diagnostic.mu.Lock()
	defer diagnostic.mu.Unlock()
	diagnostic.last = singleRecoveryRequestDiagnosticObservation{stage: "wire", class: map[bool]string{true: "ok", false: "operation"}[valid], wireValid: valid}
}

func (diagnostic *singleRecoveryRequestDiagnostic) recordObserver(valid bool, err error, ctx context.Context) {
	class, sqlstate, deadline, canceled := singleRecoveryRequestDiagnosticError(err, ctx)
	reason := singleRecoveryRequestDiagnosticReason(err)
	if err == nil && !valid {
		class = "unavailable"
	}
	diagnostic.mu.Lock()
	defer diagnostic.mu.Unlock()
	if diagnostic.last.class != "" && diagnostic.last.class != "ok" {
		return
	}
	diagnostic.last.stage = "observer"
	diagnostic.last.class = class
	diagnostic.last.reason = reason
	diagnostic.last.sqlstate = sqlstate
	diagnostic.last.deadline = deadline
	diagnostic.last.canceled = canceled
	diagnostic.last.observationValid = valid
	// A later stage cannot be reached unless the reconstructed wire was valid.
	diagnostic.last.wireValid = true
}

func (diagnostic *singleRecoveryRequestDiagnostic) recordResult(err error, ctx context.Context) {
	if err == nil {
		return
	}
	class, sqlstate, deadline, canceled := singleRecoveryRequestDiagnosticError(err, ctx)
	reason := singleRecoveryRequestDiagnosticReason(err)
	diagnostic.mu.Lock()
	defer diagnostic.mu.Unlock()
	if diagnostic.last.class != "ok" {
		return
	}
	diagnostic.last.class = class
	diagnostic.last.reason = reason
	diagnostic.last.sqlstate = sqlstate
	diagnostic.last.deadline = deadline
	diagnostic.last.canceled = canceled
}

type singleRecoveryDiagnosticAuthority struct {
	delegate   singleTestRecoveryAuthority
	diagnostic *singleRecoveryRequestDiagnostic
}

func (authority *singleRecoveryDiagnosticAuthority) Request(ctx context.Context, identity RequestIdentity, input SingleTestRecoveryMutation) (SingleTestRecoveryMutationResult, error) {
	valid := recoveryWire(identity, input).valid()
	authority.diagnostic.recordWire(valid)
	result, err := authority.delegate.Request(ctx, identity, input)
	authority.diagnostic.recordResult(err, ctx)
	return result, err
}

func (authority *singleRecoveryDiagnosticAuthority) Get(ctx context.Context, identity RequestIdentity, run string) (SingleTestRecoveryView, error) {
	return authority.delegate.Get(ctx, identity, run)
}

type singleRecoveryDiagnosticObserver struct {
	delegate   orchestration.SingleTestOriginalObserver
	diagnostic *singleRecoveryRequestDiagnostic
}

func (observer *singleRecoveryDiagnosticObserver) ObserveOriginal(ctx context.Context, request orchestration.StartRequest) (orchestration.SingleTestOriginalObservation, error) {
	observation, err := observer.delegate.ObserveOriginal(ctx, request)
	workflowID, _ := orchestration.SingleTestWorkflowID(request.Ref)
	observer.diagnostic.recordObserver(err == nil && recoveryObservationValid(observation, workflowID, time.Now()), err, ctx)
	return observation, err
}

func (driver *singleRecoveryRequestDiagnosticDriver) QueryRow(ctx context.Context, query string, arguments ...any) PostgresRow {
	return driver.driver.QueryRow(ctx, query, arguments...)
}

func (driver *singleRecoveryRequestDiagnosticDriver) Exec(ctx context.Context, query string, arguments ...any) error {
	return driver.driver.Exec(ctx, query, arguments...)
}

func (driver *singleRecoveryRequestDiagnosticDriver) Close() error { return driver.driver.Close() }

func (driver *singleRecoveryRequestDiagnosticTransactionDriver) Begin(ctx context.Context) (pgx.Tx, error) {
	transaction, err := driver.transactions.Begin(ctx)
	if err != nil {
		driver.diagnostic.record("begin", err, ctx)
		return transaction, err
	}
	return &singleRecoveryRequestDiagnosticTransaction{Tx: transaction, diagnostic: driver.diagnostic}, nil
}

type singleRecoveryRequestDiagnosticTransaction struct {
	pgx.Tx
	diagnostic *singleRecoveryRequestDiagnostic
}

func (transaction *singleRecoveryRequestDiagnosticTransaction) Exec(ctx context.Context, query string, arguments ...any) (pgconn.CommandTag, error) {
	tag, err := transaction.Tx.Exec(ctx, query, arguments...)
	if query == `SELECT zasp_authorization80.fence($1::text)` {
		transaction.diagnostic.record("fence", err, ctx)
	}
	return tag, err
}

func singleRecoveryRequestDiagnosticQueryStage(query string) string {
	switch query {
	case singleTestRecoveryPreflightSQL:
		return "preflight"
	case singleTestRecoveryAdmitSQL:
		return "admit"
	case singleTestRecoveryGetSQL:
		return "get"
	default:
		return ""
	}
}

func (transaction *singleRecoveryRequestDiagnosticTransaction) QueryRow(ctx context.Context, query string, arguments ...any) pgx.Row {
	row := transaction.Tx.QueryRow(ctx, query, arguments...)
	stage := singleRecoveryRequestDiagnosticQueryStage(query)
	if stage == "" {
		return row
	}
	return singleRecoveryRequestDiagnosticRow(func(values ...any) error {
		err := row.Scan(values...)
		transaction.diagnostic.record(stage, err, ctx)
		return err
	})
}

func (transaction *singleRecoveryRequestDiagnosticTransaction) Commit(ctx context.Context) error {
	err := transaction.Tx.Commit(ctx)
	if err != nil {
		transaction.diagnostic.record("commit", err, ctx)
	}
	return err
}

func (transaction *singleRecoveryRequestDiagnosticTransaction) Rollback(ctx context.Context) error {
	err := transaction.Tx.Rollback(ctx)
	if err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		transaction.diagnostic.record("rollback", err, ctx)
	}
	return err
}

type singleRecoveryRequestDiagnosticRow func(...any) error

func (row singleRecoveryRequestDiagnosticRow) Scan(values ...any) error { return row(values...) }

type singleRecoveryRequestDiagnosticTx struct {
	pgx.Tx
	execContext, queryContext, commitContext, rollbackContext context.Context
	execSQL, querySQL                                         string
	execArguments, queryArguments                             []any
	queryErr                                                  error
	commits, rollbacks                                        int
}

func (tx *singleRecoveryRequestDiagnosticTx) Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
	tx.execContext, tx.execSQL, tx.execArguments = ctx, sql, append([]any(nil), arguments...)
	return pgconn.CommandTag{}, nil
}

func (tx *singleRecoveryRequestDiagnosticTx) QueryRow(ctx context.Context, sql string, arguments ...any) pgx.Row {
	tx.queryContext, tx.querySQL, tx.queryArguments = ctx, sql, append([]any(nil), arguments...)
	return singleRecoveryRequestDiagnosticRow(func(...any) error { return tx.queryErr })
}

func (tx *singleRecoveryRequestDiagnosticTx) Commit(ctx context.Context) error {
	tx.commitContext, tx.commits = ctx, tx.commits+1
	return nil
}

func (tx *singleRecoveryRequestDiagnosticTx) Rollback(ctx context.Context) error {
	tx.rollbackContext, tx.rollbacks = ctx, tx.rollbacks+1
	return nil
}

type singleRecoveryRequestDiagnosticDriverFixture struct {
	tx       *singleRecoveryRequestDiagnosticTx
	beginCtx context.Context
}

func (driver *singleRecoveryRequestDiagnosticDriverFixture) Begin(ctx context.Context) (pgx.Tx, error) {
	driver.beginCtx = ctx
	return driver.tx, nil
}

func (*singleRecoveryRequestDiagnosticDriverFixture) QueryRow(context.Context, string, ...any) PostgresRow {
	return singleRecoveryRequestDiagnosticRow(func(...any) error { return nil })
}

func (*singleRecoveryRequestDiagnosticDriverFixture) Exec(context.Context, string, ...any) error {
	return nil
}
func (*singleRecoveryRequestDiagnosticDriverFixture) Close() error { return nil }

func TestSingleRecoveryRequestDiagnosticPreservesTransactionAndClassifiesStage(t *testing.T) {
	secret := "credential=do-not-print"
	sourceTx := &singleRecoveryRequestDiagnosticTx{queryErr: &pgconn.PgError{Code: "22023", Message: secret}}
	source := &singleRecoveryRequestDiagnosticDriverFixture{tx: sourceTx}
	wrapped, diagnostic := wrapSingleRecoveryRequestDiagnosticDriver(source)
	transactions, ok := wrapped.(AuthorizationTransactionDriver)
	if !ok {
		t.Fatal("diagnostic hid transaction capability")
	}
	ctx := context.WithValue(context.Background(), struct{ key string }{"request"}, "preserved")
	tx, err := transactions.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `SELECT zasp_authorization80.fence($1::text)`, "fixed-proof"); err != nil {
		t.Fatal(err)
	}
	argument := json.RawMessage(`{"fixed":true}`)
	var payload []byte
	err = tx.QueryRow(ctx, singleTestRecoveryPreflightSQL, argument).Scan(&payload)
	if err == nil {
		t.Fatal("fixture error was lost")
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if source.beginCtx != ctx || sourceTx.execContext != ctx || sourceTx.queryContext != ctx || sourceTx.commitContext != ctx || sourceTx.rollbackContext != ctx || sourceTx.execSQL != `SELECT zasp_authorization80.fence($1::text)` || sourceTx.querySQL != singleTestRecoveryPreflightSQL || len(sourceTx.execArguments) != 1 || sourceTx.execArguments[0] != "fixed-proof" || len(sourceTx.queryArguments) != 1 || string(sourceTx.queryArguments[0].(json.RawMessage)) != string(argument) || sourceTx.commits != 1 || sourceTx.rollbacks != 1 {
		t.Fatal("diagnostic changed transaction context, arguments, or lifecycle")
	}
	want := "stage=preflight class=operation reason=unknown status=400 wire=false observation=false deadline=false canceled=false sqlstate=22023"
	if got := diagnostic.summary(400); got != want || strings.Contains(got, secret) {
		t.Fatalf("summary=%q want=%q", got, want)
	}

	diagnostic.reset()
	sourceTx.queryErr = &pgconn.PgError{Code: "ZZ999", Message: secret}
	var ignored []byte
	_ = tx.QueryRow(ctx, singleTestRecoveryAdmitSQL, argument).Scan(&ignored)
	if got := diagnostic.summary(503); !strings.Contains(got, "stage=admit class=unknown") || !strings.HasSuffix(got, "sqlstate=") || strings.Contains(got, "ZZ999") || strings.Contains(got, secret) {
		t.Fatalf("unapproved SQLSTATE or message escaped: %q", got)
	}
}

type singleRecoveryRequestDiagnosticAuthorityFixture struct {
	requestErr error
}

func (fixture *singleRecoveryRequestDiagnosticAuthorityFixture) Request(context.Context, RequestIdentity, SingleTestRecoveryMutation) (SingleTestRecoveryMutationResult, error) {
	return SingleTestRecoveryMutationResult{}, fixture.requestErr
}

func (*singleRecoveryRequestDiagnosticAuthorityFixture) Get(context.Context, RequestIdentity, string) (SingleTestRecoveryView, error) {
	return SingleTestRecoveryView{}, nil
}

func TestSingleRecoveryRequestDiagnosticSeparatesHandlerWireObserverAndUnknown(t *testing.T) {
	identity := orderedPublicIdentity()
	validInput := SingleTestRecoveryMutation{
		RunID:             public62Finding,
		DefinitionVersion: 2,
		InputDigest:       strings.Repeat("a", 64),
		ExpectedVersion:   3,
		IdempotencyKey:    "single-recovery-diagnostic-1",
		AuditID:           "pid_98000001-0000-4000-8000-000000000001",
		CorrelationID:     "pid_98000002-0000-4000-8000-000000000002",
		ReceiptID:         "pid_98000003-0000-4000-8000-000000000003",
	}
	diagnostic := &singleRecoveryRequestDiagnostic{}
	authority := &singleRecoveryDiagnosticAuthority{delegate: &singleRecoveryRequestDiagnosticAuthorityFixture{requestErr: ErrRepositoryOperation}, diagnostic: diagnostic}

	if _, err := authority.Request(context.Background(), identity, validInput); !errors.Is(err, ErrRepositoryOperation) {
		t.Fatal(err)
	}
	if got := diagnostic.summary(400); !strings.Contains(got, "stage=wire") || !strings.Contains(got, "wire=true") || !strings.Contains(got, "class=operation") {
		t.Fatalf("valid wire stage missing: %q", got)
	}

	diagnostic.reset()
	invalidInput := validInput
	invalidInput.ExpectedVersion = 0
	if _, err := authority.Request(context.Background(), identity, invalidInput); !errors.Is(err, ErrRepositoryOperation) {
		t.Fatal(err)
	}
	if got := diagnostic.summary(400); !strings.Contains(got, "stage=wire") || !strings.Contains(got, "wire=false") {
		t.Fatalf("invalid wire stage missing: %q", got)
	}

	diagnostic.reset()
	workflowID, _ := orchestration.SingleTestWorkflowID(orchestration.RunRef{OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(), RunID: validInput.RunID})
	observer := &singleRecoveryDiagnosticObserver{delegate: recoveryObserverFunc(func(context.Context, orchestration.StartRequest) (orchestration.SingleTestOriginalObservation, error) {
		return orchestration.SingleTestOriginalObservation{WorkflowID: workflowID, Status: "absent", ObservedAt: time.Now().UTC()}, nil
	}), diagnostic: diagnostic}
	request := orchestration.StartRequest{Ref: orchestration.RunRef{OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(), RunID: validInput.RunID}, DefinitionVersion: validInput.DefinitionVersion, InputDigest: validInput.InputDigest}
	observation, err := observer.ObserveOriginal(context.Background(), request)
	if err != nil || observation.WorkflowID != workflowID {
		t.Fatal("observer delegate changed", err)
	}
	if got := diagnostic.summary(500); !strings.Contains(got, "stage=observer") || !strings.Contains(got, "observation=true") {
		t.Fatalf("observer stage missing: %q", got)
	}

	diagnostic.reset()
	if got := diagnostic.summary(400); got != "stage=handler class=operation reason=unknown status=400 wire=false observation=false deadline=false canceled=false sqlstate=" {
		t.Fatalf("handler refusal not isolated: %q", got)
	}

	diagnostic.reset()
	secret := "password=raw-secret"
	authority.delegate = &singleRecoveryRequestDiagnosticAuthorityFixture{requestErr: errors.New(secret)}
	_, _ = authority.Request(context.Background(), identity, validInput)
	if got := diagnostic.summary(503); !strings.Contains(got, "class=unknown") || strings.Contains(got, secret) {
		t.Fatalf("unknown error was disclosed: %q", got)
	}
}

func TestSingleRecoveryRequestDiagnosticClassifiesOnlyExactStaticReason(t *testing.T) {
	tests := []struct {
		name, code, message, want string
	}{
		{"conflict", "40001", "native cancellation proof rejected", "cancellation_proof"},
		{"operation", "22023", "recovery observation rejected", "observation_shape"},
		{"wrong code", "22023", "native cancellation proof rejected", "unknown"},
		{"unknown message", "40001", "credential=raw-secret", "unknown"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			diagnostic := &singleRecoveryRequestDiagnostic{}
			err := error(&pgconn.PgError{Code: test.code, Message: test.message})
			if test.name == "conflict" {
				err = errors.Join(errors.New("outer secret"), err)
			}
			diagnostic.record("admit", err, context.Background())
			got := diagnostic.summary(409)
			if !strings.Contains(got, "reason="+test.want) || strings.Contains(got, test.message) || strings.Contains(got, "outer secret") || strings.Contains(got, "raw-secret") {
				t.Fatalf("unsafe or incorrect reason summary: %q", got)
			}
		})
	}
}
