package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type orderedProductionDB struct {
	*orderedPublicDB
	readyCalls int
	readyErr   error
}

func (d *orderedProductionDB) VerifySecurityAgentOrderedHTTPRelease(ctx context.Context) error {
	d.readyCalls++
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("unbounded readiness")
	}
	return d.readyErr
}

func orderedRolloutCookie(t *testing.T, enabled bool) CookiePolicy {
	t.Helper()
	c := fixtureCookiePolicy()
	c.SecurityAgentOrderedHTTPEnabled = enabled
	return c
}

func orderedProductionHandlers(t *testing.T, db JSONDatabase, c CookiePolicy) (Dependencies, error) {
	t.Helper()
	main := &PostgresRepository{database: &discoveryCallDatabase{schema: SecurityAgentExecutionSchemaVersion, responses: map[string]json.RawMessage{postgresSecurityAgentExecutionReadinessSQL: json.RawMessage(`true`), postgresDiscoveryPrincipalReadySQL: json.RawMessage(`true`)}}, schema: SecurityAgentExecutionSchemaVersion}
	sa := &PostgresRepository{database: db, schema: SecurityAgentExecutionSchemaVersion, securityAgentExecution: true}
	h, _, err := NewProductionHandlersWithSecurityAgent(main, sa, CallbackProviderFunc(func(context.Context, string, string) (SessionGrant, error) { return SessionGrant{}, nil }), http.NotFoundHandler(), c)
	return h, err
}

func TestSecurityAgentOrderedProductionGate(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, readyErr := range []error{nil, errors.New("private database detail"), context.Canceled, context.DeadlineExceeded} {
			db := &orderedProductionDB{orderedPublicDB: &orderedPublicDB{}, readyErr: readyErr}
			h, err := orderedProductionHandlers(t, db, orderedRolloutCookie(t, enabled))
			if enabled && readyErr != nil {
				if err != ErrRepositoryUnavailable || h.Workflow != nil {
					t.Fatalf("enabled downgrade: %v %T", err, h.Workflow)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			want := 0
			if enabled {
				want = 1
			}
			if db.readyCalls != want || db.calls != 0 {
				t.Fatalf("readiness=%d queries=%d", db.readyCalls, db.calls)
			}
		}
	}
	if _, err := orderedProductionHandlers(t, &orderedPublicDB{}, orderedRolloutCookie(t, true)); err != ErrRepositoryConfiguration {
		t.Fatal("missing verifier", err)
	}
	if _, err := orderedProductionHandlers(t, &orderedPublicDB{}, orderedRolloutCookie(t, false)); err != nil {
		t.Fatal("rollback requires extension", err)
	}
}

func TestSecurityAgentOrderedProductionReadAndPassthrough(t *testing.T) {
	id := orderedPublicIdentity()
	a, db := orderedHTTPAuthority(t, "ordered_release61", orderedResourceFixture(id, public62Definition, false), nil)
	_ = a
	orderedQuery := db.query
	db.query = func(ctx context.Context, statement string, args ...any) (json.RawMessage, error) {
		if statement != securityAgentPublicSQL {
			return nil, ErrRepositoryUnavailable
		}
		return orderedQuery(ctx, statement, args...)
	}
	h, err := orderedProductionHandlers(t, &orderedProductionDB{orderedPublicDB: db}, orderedRolloutCookie(t, true))
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.Workflow.ServeHTTP(w, orderedHTTPRequest(id, "getSecurityAgentRun", "GET", public62Definition, ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"contract_version":62`) {
		t.Fatal(w.Code, w.Body.String())
	}
	// Unintercepted operations keep the established handler and its response bytes.
	for _, op := range []string{"getSecurityAgent", "getSecurityAgentExecutionControls", "simulateSecurityAgent"} {
		legacy, err := orderedProductionHandlers(t, &securityAgentRepositoryDatabase{}, orderedRolloutCookie(t, false))
		if err != nil {
			t.Fatal(err)
		}
		before, after := httptest.NewRecorder(), httptest.NewRecorder()
		legacy.Workflow.ServeHTTP(before, orderedHTTPRequest(id, op, "GET", public62Definition, ""))
		h.Workflow.ServeHTTP(after, orderedHTTPRequest(id, op, "GET", public62Definition, ""))
		if before.Code != after.Code || before.Body.String() != after.Body.String() {
			t.Fatalf("%s changed: %d %s / %d %s", op, before.Code, before.Body.String(), after.Code, after.Body.String())
		}
	}
}

func TestSecurityAgentOrderedDeploymentVerifier(t *testing.T) {
	for _, body := range []string{`{"contract_version":62,"ready":true}`, `{"contract_version":62,"ready":false}`, `{"contract_version":61,"ready":true}`, `{"ready":true}`, `{"contract_version":62,"ready":null}`, `{"contract_version":62,"ready":true,"actor_id":"secret"}`, `{"contract_version":62,"ready":true,"ready":false}`, `null`} {
		driver := &databaseDriver{responses: map[string][]byte{securityAgentPublicSQL: []byte(body)}}
		db, err := NewPostgresJSONDatabase(driver)
		if err != nil {
			t.Fatal(err)
		}
		verifier, ok := any(db).(interface{ VerifySecurityAgentOrderedHTTPRelease(context.Context) error })
		if !ok {
			t.Fatal("typed deployment verifier absent")
		}
		err = verifier.VerifySecurityAgentOrderedHTTPRelease(context.Background())
		if (err == nil) != (body == `{"contract_version":62,"ready":true}`) {
			t.Fatalf("%s: %v", body, err)
		}
		args := driver.queryArguments
		if len(args) != 3 || args[0] != migrations.ProductionSecurityAgentPublic().Checksum() || args[1] != migrations.SecurityAgentPublicFingerprint() || string(args[2].(json.RawMessage)) != `{"operation":"deployment_ready"}` {
			t.Fatal(args)
		}
		for _, ctx := range []context.Context{nil, canceledOrderedContext()} {
			if err := verifier.VerifySecurityAgentOrderedHTTPRelease(ctx); err != ErrRepositoryUnavailable {
				t.Fatal("invalid context", err)
			}
		}
		driver.rowErr = errors.New("private SQL detail")
		if err := verifier.VerifySecurityAgentOrderedHTTPRelease(context.Background()); err != ErrRepositoryUnavailable {
			t.Fatal(err)
		}
	}
}

func TestSecurityAgentOrderedProductionConstructionFailures(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, length := range []int{0, 31, 4097} {
			db := &orderedProductionDB{orderedPublicDB: &orderedPublicDB{}}
			config := SecurityAgentPublicHandlerConfig{Clock: time.Now, NewProductID: newWorkflowProductID, SigningKey: make([]byte, length)}
			h, err := newSecurityAgentProductionHTTPHandler(context.Background(), &PostgresRepository{database: db}, http.NotFoundHandler(), config, enabled)
			if h != nil || err != ErrRepositoryConfiguration || db.readyCalls != 0 {
				t.Fatal(length, h, err, db.readyCalls)
			}
		}
	}
	config := SecurityAgentPublicHandlerConfig{Clock: time.Now, NewProductID: newWorkflowProductID, SigningKey: securityAgentTestSigningKey}
	for _, repo := range []*PostgresRepository{nil, {}, {database: (*orderedProductionDB)(nil)}} {
		if h, err := newSecurityAgentProductionHTTPHandler(context.Background(), repo, http.NotFoundHandler(), config, true); h != nil || err != ErrRepositoryConfiguration {
			t.Fatal(h, err)
		}
	}
	db := &orderedProductionDB{orderedPublicDB: &orderedPublicDB{}}
	repo := &PostgresRepository{database: db}
	for _, ctx := range []context.Context{nil, canceledOrderedContext()} {
		if h, err := newSecurityAgentProductionHTTPHandler(ctx, repo, http.NotFoundHandler(), config, true); h != nil || err != ErrRepositoryUnavailable || db.readyCalls != 0 {
			t.Fatal(h, err, db.readyCalls)
		}
	}
	if h, err := newSecurityAgentProductionHTTPHandler(context.Background(), repo, http.HandlerFunc(nil), config, true); h != nil || err != ErrRepositoryConfiguration || db.readyCalls != 0 {
		t.Fatal(h, err, db.readyCalls)
	}
}

func canceledOrderedContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
