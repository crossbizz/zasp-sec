package runtimeindex

import (
	"context"
	"fmt"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type eventVisibilityFunc func(context.Context, domain.Scope, []string) (map[string]bool, error)

func (f eventVisibilityFunc) VisibleEvents(ctx context.Context, s domain.Scope, ids []string) (map[string]bool, error) {
	return f(ctx, s, ids)
}

func TestEventVisibilityBatchesCompleteAuthorityWithoutDefaultAllow(t *testing.T) {
	scope := testScope(t, 1)
	ids := make([]string, 1001)
	for i := range ids {
		ids[i] = fmt.Sprintf("pid_70000001-0000-4000-8000-%012d", i+1)
	}
	ids = append(ids, ids[0])
	for _, mode := range []string{"complete", "missing", "extra", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			states, err := CheckEventVisibility(ctx, eventVisibilityFunc(func(_ context.Context, got domain.Scope, batch []string) (map[string]bool, error) {
				calls++
				if got != scope || len(batch) > 1000 {
					t.Fatal("scope/bound changed")
				}
				state := map[string]bool{}
				for _, id := range batch {
					state[id] = false
				}
				switch mode {
				case "missing":
					delete(state, batch[0])
				case "extra":
					state["foreign"] = true
				case "canceled":
					cancel()
				}
				return state, nil
			}), scope, ids)
			if mode != "complete" {
				if err == nil || states != nil {
					t.Fatalf("incomplete authority accepted: %v %v", states, err)
				}
				return
			}
			if err != nil || len(states) != 1001 || calls != 2 {
				t.Fatalf("bounded dedup/complete result failed: states=%d calls=%d err=%v", len(states), calls, err)
			}
			for _, live := range states {
				if live {
					t.Fatal("expired event defaulted live")
				}
			}
		})
	}
}
