package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"go.temporal.io/sdk/activity"
)

// All diagnostic values are explicit static labels or existing public IDs.
// SQL text, arguments, provider errors, artifact contents and URLs never print.
func automaticFirstErrorClass(err error) string {
	if err == nil {
		return "none"
	}
	for _, pair := range []struct {
		err  error
		name string
	}{{context.DeadlineExceeded, "deadline"}, {context.Canceled, "cancelled"}, {apiserver.ErrRepositoryUnavailable, "repository_unavailable"}, {apiserver.ErrRepositoryConflict, "repository_conflict"}, {apiserver.ErrRepositoryOperation, "repository_operation"}, {errRuntimeUnavailable, "runtime_unavailable"}, {errWorkerExecution, "worker_execution"}, {artifactstore.ErrIntegrity, "artifact_integrity"}, {artifactstore.ErrGet, "artifact_get"}, {artifactstore.ErrPut, "artifact_put"}} {
		if errors.Is(err, pair.err) {
			return pair.name
		}
	}
	return "other"
}
func automaticFirstErrorLog(t *testing.T, ctx context.Context, operation string, started time.Time, err error, details string) {
	if !activity.IsActivity(ctx) {
		return
	}
	i := activity.GetInfo(ctx)
	if i.ActivityType.Name != "SingleTest" {
		return
	}
	code, identifier := "none", "none"
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		if len(pg.Code) == 5 {
			code = pg.Code
		}
		for _, name := range []string{"zasp_temporal74.linked", "zasp_temporal74.effect", "zasp_temporal74.test_state", "zasp_temporal74.inspect", "zasp_temporal74.authorize", "zasp_temporal74.current_ready", "zasp_temporal74.require_executor"} {
			if strings.Contains(pg.Where, name+"(") {
				identifier = name
				break
			}
		}
	}
	t.Logf("first-error workflow=%s execution=%s activity=%s attempt=%d operation=%s elapsed_ms=%d error=%s sqlstate=%s function=%s context=%s %s", i.WorkflowExecution.ID, i.WorkflowExecution.RunID, i.ActivityType.Name, i.Attempt, operation, time.Since(started).Milliseconds(), automaticFirstErrorClass(err), code, identifier, automaticFirstErrorClass(ctx.Err()), details)
}

type automaticFirstErrorDatabase struct {
	apiserver.JSONDatabase
	t *testing.T
}

func (d automaticFirstErrorDatabase) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	started := time.Now()
	raw, err := d.JSONDatabase.QueryJSON(ctx, q, args...)
	operation := "other_sql"
	for _, name := range []string{"inspect", "test_state", "effect", "linked", "test_settle", "client_ready", "ready"} {
		if strings.Contains(q, "zasp_temporal74."+name+"(") {
			operation = name
			break
		}
	}
	if operation == "other_sql" {
		return raw, err
	}
	if len(args) == 1 {
		var request struct {
			Operation string `json:"operation"`
		}
		var encoded []byte
		switch v := args[0].(type) {
		case json.RawMessage:
			encoded = v
		case string:
			encoded = []byte(v)
		}
		if json.Unmarshal(encoded, &request) == nil && stringInWorker(request.Operation, "read", "reserve", "input", "dispatch", "child", "snapshot", "complete") {
			operation += "/" + request.Operation
		}
	}
	var response map[string]json.RawMessage
	json.Unmarshal(raw, &response)
	details := ""
	for _, field := range []string{"state", "phase"} {
		var value string
		if json.Unmarshal(response[field], &value) == nil && stringInWorker(value, "absent", "reserved", "started", "unknown", "stopped", "child", "verified", "planning", "test", "settling", "terminal") {
			details += field + "=" + value + " "
		}
	}
	var permit bool
	if json.Unmarshal(response["send_permit"], &permit) == nil {
		if permit {
			details += "send_permit=true "
		} else {
			details += "send_permit=false "
		}
	}
	automaticFirstErrorLog(d.t, ctx, operation, started, err, details)
	return raw, err
}

type automaticFirstErrorProduct struct {
	orchestration.SingleTestProduct
	t *testing.T
}

func (p automaticFirstErrorProduct) Test(ctx context.Context, q orchestration.StartRequest) error {
	started := time.Now()
	err := p.SingleTestProduct.Test(ctx, q)
	automaticFirstErrorLog(p.t, ctx, "product.Test", started, err, "")
	return err
}

type automaticFirstErrorStore struct {
	artifactstore.ObjectReferencingArtifactStore
	t *testing.T
}

func (s automaticFirstErrorStore) Get(ctx context.Context, q artifactstore.Locator) (artifactstore.Artifact, error) {
	started := time.Now()
	v, e := s.ObjectReferencingArtifactStore.Get(ctx, q)
	automaticFirstErrorLog(s.t, ctx, "artifact.Get", started, e, "")
	return v, e
}
func (s automaticFirstErrorStore) Put(ctx context.Context, q artifactstore.PutRequest) (artifactstore.Artifact, error) {
	started := time.Now()
	v, e := s.ObjectReferencingArtifactStore.Put(ctx, q)
	automaticFirstErrorLog(s.t, ctx, "artifact.Put", started, e, "")
	return v, e
}

func TestAutomaticDiagnosticPreservesDefaultProduct(t *testing.T) {
	p := &temporalSecurityAgentProduct{}
	defaultProduct, ok := p.SingleTestProduct().(*temporalSingleTestProduct)
	if !ok || defaultProduct.shared != p {
		t.Fatal("default product changed")
	}
	var original orchestration.SingleTestProduct
	p.singleTestDiagnostic = func(v orchestration.SingleTestProduct) orchestration.SingleTestProduct {
		original = v
		return automaticFirstErrorProduct{SingleTestProduct: v, t: t}
	}
	decorated, ok := p.SingleTestProduct().(automaticFirstErrorProduct)
	if !ok || decorated.SingleTestProduct != original || original.(*temporalSingleTestProduct).shared != p {
		t.Fatal("decorator replaced actual product")
	}
}
