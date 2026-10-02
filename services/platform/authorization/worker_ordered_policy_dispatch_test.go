package authorization

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Exercise the consumer dispatcher, not just the already-tested policy helper.
// Missing dispatch, a generic three-check fallback, or an ordinary SQL route
// would otherwise strand signing or authorize an incomplete composition.
func TestOrderedPolicyDispatch(t *testing.T) {
	for _, tc := range []struct {
		op      WorkerOperation
		purpose WorkerPurpose
		current bool
	}{
		{"ordered68.application.source", WorkerForward, true},
		{"ordered68.delivery.apply.store", WorkerForward, true},
		{"ordered68.cleanup.source", CapturedCompensation, false},
		{"ordered68.cleanup.renew", CapturedCompensation, false},
		{"ordered68.delivery.cleanup.store", CapturedCompensation, false},
	} {
		t.Run(string(tc.op), func(t *testing.T) {
			spec, ok := workerOperation(tc.op)
			if !ok || !spec.orderedSigning || spec.purpose != tc.purpose || spec.current != tc.current || spec.phase != string(tc.op) ||
				spec.source != `SELECT zasp_authorization80_worker.ordered68_policy_source($1,$2::jsonb)` || spec.statement != "" || spec.limit != 32768 ||
				spec.adapter || spec.discovery || spec.bindRequest || spec.orderedExecution || spec.orderedPlanning || spec.testPlanning || spec.testExecution {
				t.Fatal("signing operation missing or crossed execution boundary")
			}
			key, err := NewWorkerKey(tc.purpose, bytes.Repeat([]byte{71}, 32))
			if err != nil {
				t.Fatal(err)
			}
			// This pool panics on use: ordinary execution must refuse before IO.
			e := &WorkerExecutor{key: key, pool: &pgxpool.Pool{}}
			decision := WorkerDecision{operation: tc.op, request: json.RawMessage(`{}`), envelope: []byte(`{"proof":"opaque"}`)}
			if _, err := e.Execute(context.Background(), decision); err != ErrInvalid {
				t.Fatal("ordinary execution accepted signing")
			}
			for _, mode := range []string{"adapter", "discovery", "other-purpose"} {
				crossed := *e
				switch mode {
				case "adapter":
					crossed.adapter = true
				case "discovery":
					crossed.discovery = true
				case "other-purpose":
					other := WorkerForward
					if tc.purpose == WorkerForward {
						other = CapturedCompensation
					}
					crossed.key, _ = NewWorkerKey(other, bytes.Repeat([]byte{72}, 32))
				}
				if err := crossed.ReadyFor(context.Background(), tc.op); err != ErrInvalid {
					t.Fatal("crossed signing mode reached database", mode)
				}
			}
		})
	}
	for _, op := range []WorkerOperation{"ordered68.delivery.store", "ordered68.application.source.extra", "ordered68.cleanup.apply", "ordered68.delivery.cleanup.store.sql"} {
		if _, ok := workerOperation(op); ok {
			t.Fatal("unrecognized signing route accepted", op)
		}
	}
}

func TestOrderedPolicyDispatchedCheckShape(t *testing.T) {
	for _, tc := range []struct {
		op    WorkerOperation
		count int
	}{
		{"ordered68.application.source", 0},
		{"ordered68.delivery.apply.store", 1},
		{"ordered68.delivery.apply.store", 100},
	} {
		t.Run(string(tc.op)+"/"+strconv.Itoa(tc.count), func(t *testing.T) {
			// The existing operation helper supplies its production spec. This
			// independently catches the generic shape fallback even before the
			// main operation dispatcher is connected.
			spec, ok := orderedPolicyWorkerOperation(tc.op)
			if !ok {
				t.Fatal("policy spec unavailable")
			}
			facts := orderedPolicyShapeFixture(tc.count)
			if !workerCheckShape(spec, facts) {
				t.Fatal("complete policy composition rejected by dispatch")
			}
			facts.Checks[2].Permission = "view"
			if workerCheckShape(spec, facts) {
				t.Fatal("weaker destination permission accepted by dispatch")
			}
			facts = orderedPolicyShapeFixture(tc.count)
			facts.OrderedPolicyDeviceID = facts.DefinitionID
			if workerCheckShape(spec, facts) {
				t.Fatal("different destination accepted by dispatch")
			}
			if tc.count > 0 {
				facts = orderedPolicyShapeFixture(tc.count)
				facts.Checks = facts.Checks[:3]
				if workerCheckShape(spec, facts) {
					t.Fatal("composition checks dropped by generic fallback")
				}
			}
		})
	}
}
