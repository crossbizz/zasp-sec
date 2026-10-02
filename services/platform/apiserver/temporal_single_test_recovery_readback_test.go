package apiserver

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"strings"
	"testing"
)

func TestSingleTestRecoveryReadbackContracts(t *testing.T) {
	id := orderedPublicIdentity()
	raw := json.RawMessage(`{"run_id":"` + public62Finding + `","request_identity":{"definition_version":2,"input_digest":"` + strings.Repeat("a", 64) + `"},"status":"not_requested","reason":"not_requested","parent_version":3,"command":null,"accepted_at":null,"completion":null}`)
	for _, mode := range []string{"valid", "revoked", "foreign", "child_digest_shape", "forged_complete"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			db := &orderedPublicDB{query: func(_ context.Context, sql string, args ...any) (json.RawMessage, error) {
				calls++
				if sql != singleTestRecoveryGetSQL || len(args) != 5 || args[3] != public62Finding {
					t.Fatal("not exact scoped read")
				}
				if mode == "revoked" {
					return nil, ErrRepositoryAuthentication
				}
				v := string(raw)
				if mode == "foreign" {
					v = strings.Replace(v, public62Finding, public62Definition, 1)
				}
				if mode == "child_digest_shape" {
					v = strings.Replace(v, "input_digest", "child_input_digest", 1)
				}
				if mode == "forged_complete" {
					v = strings.Replace(v, "not_requested", "complete", 1)
				}
				return json.RawMessage(v), nil
			}}
			repo, _ := NewSingleTestRecoveryRepository(db, recoveryObserverFunc(func(context.Context, orchestration.StartRequest) (orchestration.SingleTestOriginalObservation, error) {
				t.Fatal("GET called Temporal")
				return orchestration.SingleTestOriginalObservation{}, nil
			}))
			v, err := repo.Get(context.Background(), id, public62Finding)
			if mode == "valid" {
				if err != nil || v.Status != "not_requested" {
					t.Fatal("pre-command identity missing", err)
				}
			} else if err == nil {
				t.Fatal("invalid identity exposed")
			}
			if calls != 1 {
				t.Fatal("GET not single read")
			}
		})
	}
}
