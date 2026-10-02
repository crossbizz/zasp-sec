package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

// A scope mismatch or omitted immutable start must fail before planner/provider
// access, even if the remaining projection claims the step is authorized.
func TestTemporalProductRefusesUnboundStart(t *testing.T) {
	ref := orchestration.RunRef{OrganizationID: "pid_6a000001-0000-4000-8000-000000000001", WorkspaceID: "pid_6a000002-0000-4000-8000-000000000002", EnvironmentID: "pid_6a000003-0000-4000-8000-000000000003", RunID: "pid_8e190001-0000-4000-8000-000000000001"}
	q := orchestration.StartRequest{Ref: ref, DefinitionVersion: 2, InputDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	for _, raw := range []string{`{}`, `{"run_state":"planning","admitted":false,"terminal":false,"start":{"organization_id":"pid_6a000001-0000-4000-8000-000000000001","workspace_id":"pid_6a000002-0000-4000-8000-000000000002","environment_id":"pid_6a000003-0000-4000-8000-000000000003","run_id":"pid_8e190001-0000-4000-8000-000000000001","definition_version":2,"input_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}`} {
		product := &temporalSecurityAgentProduct{executor: &temporalProductDatabase{raw: json.RawMessage(raw)}}
		if _, err := product.Observe(context.Background(), q); err == nil {
			t.Fatal("unbound start trusted")
		}
		if err := product.Plan(context.Background(), q); err == nil {
			t.Fatal("unbound start planned")
		}
	}
}

func TestTemporalProductClassifiesPermanentValidation(t *testing.T) {
	for _, err := range []error{apiserver.ErrRepositoryOperation, apiserver.ErrRepositoryNotFound} {
		if !errors.Is(temporalProductError(context.Background(), err), orchestration.ErrInvalid) {
			t.Fatal("permanent validation retried")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(temporalProductError(ctx, apiserver.ErrRepositoryOperation), context.Canceled) {
		t.Fatal("cancellation misclassified")
	}
	if !errors.Is(temporalProductError(context.Background(), apiserver.ErrRepositoryConflict), apiserver.ErrRepositoryConflict) {
		t.Fatal("retryable CAS lost")
	}
}

type temporalProductDatabase struct {
	apiserver.JSONDatabase
	raw json.RawMessage
}

func (d *temporalProductDatabase) QueryJSON(context.Context, string, ...any) (json.RawMessage, error) {
	return d.raw, nil
}
func (d *temporalProductDatabase) Close() error { return nil }

func TestTemporalProductRevokedWaitDoesNotRetainPolicy(t *testing.T) {
	for _, index := range []int{0, 1} {
		raw := `{"admitted":true,"projection":{"steps":[{"index":0,"action":"create_temporary_policy","state":"waiting_approval","dependency":{"ready":false}},{"index":1,"action":"run_test","state":"blocked"}]}}`
		if index == 1 {
			raw = `{"admitted":true,"projection":{"steps":[{"index":0,"action":"create_temporary_policy","state":"succeeded","receipt":{"kind":"temporary_policy_applied.v1"}},{"index":1,"action":"run_test","state":"waiting_approval","dependency":{"satisfied":true,"ready":false}}]}}`
		}
		var state temporalProductState
		if json.Unmarshal([]byte(raw), &state) != nil {
			t.Fatal("fixture")
		}
		phase, err := temporalPhase(state)
		if err != nil || phase != "permission_lost" {
			t.Fatal("revoked wait did not request compensation", phase, err)
		}
	}
}
