package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type orderedPublicDB struct {
	calls int
	query func(context.Context, string, ...any) (json.RawMessage, error)
}

func (d *orderedPublicDB) SchemaVersion(context.Context) (string, error) {
	panic("unexpected schema fallback")
}
func (d *orderedPublicDB) Exec(context.Context, string, ...any) error {
	panic("unexpected write fallback")
}
func (d *orderedPublicDB) QueryJSON(ctx context.Context, q string, a ...any) (json.RawMessage, error) {
	d.calls++
	return d.query(ctx, q, a...)
}

func orderedPublicIdentity() RequestIdentity {
	p, _ := domain.ParseProductID("pid_10000000-0000-4000-8000-000000000004")
	o, _ := domain.ParseProductID("pid_10000000-0000-4000-8000-000000000001")
	w, _ := domain.ParseProductID("pid_10000000-0000-4000-8000-000000000002")
	e, _ := domain.ParseProductID("pid_10000000-0000-4000-8000-000000000003")
	s, _ := domain.NewScope(o, w, e)
	return RequestIdentity{PrincipalID: p, Scope: s, Permissions: []string{"view", "manage_workflows", "run_tests"}, CredentialKind: CredentialBrowserSession, CSRFToken: strings.Repeat("c", 32)}
}

func TestSecurityAgentPublic62RepositoryCalls(t *testing.T) {
	id := orderedPublicIdentity()
	db := &orderedPublicDB{}
	repo, err := NewSecurityAgentPublicRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	trigger := SecurityAgentPublicTrigger{DefinitionID: public62Definition, DefinitionVersion: 2, TriggerID: public62Finding, TriggerVersion: 1, IdempotencyKey: "public62-go-test-0001"}
	run, _ := CanonicalDiscoveryID(id.Scope, "security_agent_run", public62Definition+"\x1f"+public62Finding+"\x1f1")
	for _, op := range []string{"ready", "ready", "activate", "trigger", "trigger", "detail", "list"} {
		db.query = func(ctx context.Context, q string, a ...any) (json.RawMessage, error) {
			if q != "SELECT zasp_ordered_public62.api($1,$2,$3::jsonb)" || len(a) != 3 || a[0] != migrations.ProductionSecurityAgentPublic().Checksum() || a[1] != migrations.SecurityAgentPublicFingerprint() {
				t.Fatalf("unsafe query %s %#v", q, a)
			}
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > 5*time.Second || time.Until(deadline) <= 0 {
				t.Fatal("missing bounded deadline")
			}
			raw, ok := a[2].(json.RawMessage)
			if !ok {
				t.Fatal("request is not marshalled JSON")
			}
			var got map[string]any
			if json.Unmarshal(raw, &got) != nil {
				t.Fatal("bad request")
			}
			want := map[string]any{"organization_id": id.Scope.OrganizationID().String(), "workspace_id": id.Scope.WorkspaceID().String(), "environment_id": id.Scope.EnvironmentID().String(), "actor_id": id.PrincipalID.String(), "operation": op}
			var response any
			switch op {
			case "ready":
				response = map[string]any{"contract_version": 62, "ready": true}
			case "activate":
				want["definition_id"], want["definition_version"] = public62Definition, float64(1)
				response = map[string]any{"contract_version": 62, "definition_id": public62Definition, "definition_version": 2, "activation": "supervised"}
			case "trigger":
				want["definition_id"], want["definition_version"], want["trigger_id"], want["trigger_version"], want["idempotency_key"] = public62Definition, float64(2), public62Finding, float64(1), trigger.IdempotencyKey
				response = map[string]any{"contract_version": 62, "run_id": run, "definition_id": public62Definition, "definition_version": 2, "state": "queued", "version": 1}
			case "detail":
				want["run_id"] = run
				response = orderedPublicRunFixture(id, run, false)
			case "list":
				want["after_run_id"], want["limit"] = "", float64(1)
				response = map[string]any{"contract_version": 62, "items": []any{orderedPublicRunFixture(id, run, false)}, "next_after_run_id": nil}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("scope/request mismatch got=%v want=%v", got, want)
			}
			return json.Marshal(response)
		}
		switch op {
		case "ready":
			err = repo.Ready(context.Background(), id)
		case "activate":
			var v SecurityAgentPublicActivation
			v, err = repo.Activate(context.Background(), id, public62Definition, 1)
			if err == nil && v.DefinitionVersion != 2 {
				t.Fatal(v)
			}
		case "trigger":
			var v SecurityAgentPublicTriggerResult
			v, err = repo.Trigger(context.Background(), id, trigger)
			if err == nil && v.RunID != run {
				t.Fatal(v)
			}
		case "detail":
			var v SecurityAgentPublicRun
			v, err = repo.Run(context.Background(), id, run)
			if err == nil && v.Admitted {
				t.Fatal(v)
			}
		case "list":
			var v SecurityAgentPublicPage
			v, err = repo.Runs(context.Background(), id, "", 1)
			if err == nil && len(v.Items) != 1 {
				t.Fatal(v)
			}
		}
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
	}
	if db.calls != 7 {
		t.Fatalf("cached readiness or fallback: %d", db.calls)
	}
}

func TestSecurityAgentPublic62LocalValidation(t *testing.T) {
	db := &orderedPublicDB{query: func(context.Context, string, ...any) (json.RawMessage, error) {
		t.Error("invalid input reached database")
		return nil, nil
	}}
	repo, _ := NewSecurityAgentPublicRepository(db)
	id := orderedPublicIdentity()
	ctx := context.Background()
	if _, err := NewSecurityAgentPublicRepository(nil); err != ErrRepositoryOperation {
		t.Fatal(err)
	}
	var typedNil *orderedPublicDB
	if _, err := NewSecurityAgentPublicRepository(typedNil); err != ErrRepositoryOperation {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	for _, badCtx := range []context.Context{nil, canceled} {
		if err := repo.Ready(badCtx, id); err != ErrRepositoryOperation {
			t.Fatal(err)
		}
	}
	for _, broken := range []func(*RequestIdentity){func(i *RequestIdentity) { i.CredentialKind = CredentialBearerToken }, func(i *RequestIdentity) { i.CredentialKind = 0 }, func(i *RequestIdentity) { i.PrincipalID = domain.ProductID{} }, func(i *RequestIdentity) { i.Scope = domain.Scope{} }, func(i *RequestIdentity) { i.CSRFToken = "" }, func(i *RequestIdentity) { i.Permissions = []string{"unknown"} }, func(i *RequestIdentity) { i.Permissions = []string{"view", "view"} }} {
		bad := id
		broken(&bad)
		for _, call := range []func() error{func() error { return repo.Ready(ctx, bad) }, func() error { _, e := repo.Activate(ctx, bad, public62Definition, 1); return e }, func() error { _, e := repo.Trigger(ctx, bad, SecurityAgentPublicTrigger{}); return e }, func() error { _, e := repo.Run(ctx, bad, public62Finding); return e }, func() error { _, e := repo.Runs(ctx, bad, "", 1); return e }} {
			if err := call(); err != ErrRepositoryOperation {
				t.Fatal(err)
			}
		}
	}
	for _, bad := range []string{"", strings.ToUpper(public62Definition), "pid_bad", public62Definition + " ", strings.Repeat("x", 10000)} {
		if _, err := repo.Activate(ctx, id, bad, 1); err != ErrRepositoryOperation {
			t.Fatal(err)
		}
		if _, err := repo.Run(ctx, id, bad); err != ErrRepositoryOperation {
			t.Fatal(err)
		}
		if bad != "" {
			if _, err := repo.Runs(ctx, id, bad, 1); err != ErrRepositoryOperation {
				t.Fatal(err)
			}
		}
	}
	for _, v := range []int64{-1, 0, 1000001} {
		if _, err := repo.Activate(ctx, id, public62Definition, v); err != ErrRepositoryOperation {
			t.Fatal(err)
		}
	}
	for _, limit := range []int{-1, 0, 11} {
		if _, err := repo.Runs(ctx, id, "", limit); err != ErrRepositoryOperation {
			t.Fatal(err)
		}
	}
	valid := SecurityAgentPublicTrigger{DefinitionID: public62Definition, DefinitionVersion: 2, TriggerID: public62Finding, TriggerVersion: 1, IdempotencyKey: "public62-go-test-0001"}
	for _, mutate := range []func(*SecurityAgentPublicTrigger){func(v *SecurityAgentPublicTrigger) { v.DefinitionID = "bad" }, func(v *SecurityAgentPublicTrigger) { v.TriggerID = "bad" }, func(v *SecurityAgentPublicTrigger) { v.DefinitionVersion = 0 }, func(v *SecurityAgentPublicTrigger) { v.DefinitionVersion = 1000001 }, func(v *SecurityAgentPublicTrigger) { v.TriggerVersion = 0 }, func(v *SecurityAgentPublicTrigger) { v.TriggerVersion = 1000001 }, func(v *SecurityAgentPublicTrigger) { v.IdempotencyKey = "short" }, func(v *SecurityAgentPublicTrigger) { v.IdempotencyKey = strings.Repeat("x", 129) }, func(v *SecurityAgentPublicTrigger) { v.IdempotencyKey = "_public62-test-key" }, func(v *SecurityAgentPublicTrigger) { v.IdempotencyKey = "public62 test key" }} {
		v := valid
		mutate(&v)
		if _, err := repo.Trigger(ctx, id, v); err != ErrRepositoryOperation {
			t.Fatal(err)
		}
	}
	var nilRepo *SecurityAgentPublicRepository
	if nilRepo.Ready(ctx, id) != ErrRepositoryOperation {
		t.Fatal("nil repository")
	}
	if (&SecurityAgentPublicRepository{}).Ready(ctx, id) != ErrRepositoryOperation {
		t.Fatal("nil database")
	}
	if db.calls != 0 {
		t.Fatal(db.calls)
	}
}

func TestSecurityAgentPublic62SafeErrorsAndCancellation(t *testing.T) {
	id := orderedPublicIdentity()
	for _, tc := range []struct{ err, want error }{
		{errors.New("secret sql credential_reference"), ErrRepositoryUnavailable},
		{&pgconn.PgError{Code: "42501", Message: "secret sql"}, ErrRepositoryUnavailable},
		{&pgconn.PgError{Code: "40001", Message: "secret sql"}, ErrRepositoryUnavailable},
		{&pgconn.PgError{Code: "23505", Message: "secret sql"}, ErrRepositoryUnavailable},
		{ErrRepositoryConflict, ErrRepositoryUnavailable}, {ErrRepositoryNotFound, ErrRepositoryNotFound}, {ErrRepositoryOperation, ErrRepositoryOperation},
		{context.Canceled, ErrRepositoryUnavailable}, {context.DeadlineExceeded, ErrRepositoryUnavailable},
	} {
		db := &orderedPublicDB{query: func(context.Context, string, ...any) (json.RawMessage, error) { return nil, tc.err }}
		repo, _ := NewSecurityAgentPublicRepository(db)
		if err := repo.Ready(context.Background(), id); err != tc.want || strings.Contains(err.Error(), "secret") {
			t.Fatalf("unsafe error: %v want %v", err, tc.want)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	db := &orderedPublicDB{query: func(c context.Context, _ string, _ ...any) (json.RawMessage, error) {
		cancel()
		<-c.Done()
		return nil, c.Err()
	}}
	repo, _ := NewSecurityAgentPublicRepository(db)
	if err := repo.Ready(ctx, id); err != ErrRepositoryUnavailable {
		t.Fatal(err)
	}
	db.query = func(c context.Context, _ string, _ ...any) (json.RawMessage, error) { <-c.Done(); return nil, c.Err() }
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer stop()
	if err := repo.Ready(ctx, id); err != ErrRepositoryUnavailable {
		t.Fatal(err)
	}
}

func TestSecurityAgentPublic62OperationSpecificConflicts(t *testing.T) {
	id := orderedPublicIdentity()
	ctx := context.Background()
	for _, provider := range []error{ErrRepositoryConflict, &pgconn.PgError{Code: "40001", Message: "private"}, &pgconn.PgError{Code: "23505", Message: "private"}} {
		db := &orderedPublicDB{query: func(context.Context, string, ...any) (json.RawMessage, error) { return nil, provider }}
		repo, _ := NewSecurityAgentPublicRepository(db)
		if err := repo.Ready(ctx, id); err != ErrRepositoryUnavailable {
			t.Fatal(err)
		}
		if _, err := repo.Run(ctx, id, public62Finding); err != ErrRepositoryUnavailable {
			t.Fatal(err)
		}
		if _, err := repo.Runs(ctx, id, "", 1); err != ErrRepositoryUnavailable {
			t.Fatal(err)
		}
		if _, err := repo.Activate(ctx, id, public62Definition, 1); err != ErrRepositoryConflict {
			t.Fatal(err)
		}
		if _, err := repo.Trigger(ctx, id, SecurityAgentPublicTrigger{DefinitionID: public62Definition, DefinitionVersion: 2, TriggerID: public62Finding, TriggerVersion: 1, IdempotencyKey: "public62-go-test-0001"}); err != ErrRepositoryConflict {
			t.Fatal(err)
		}
	}
}
