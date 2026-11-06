package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Successor coverage added after the original grouped behavior RED. These are
// controlled Kubernetes dependencies, not native custody or permission evidence.
func TestRetainedCoordinatorStorageCustodyAndEpoch(t *testing.T) {
	for _, mode := range []string{"newer_epoch", "foreign_owner", "recreated_slot", "replaced_anchor"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
			c, api, _, sink := retainedCoordinatorFixture(t, 2, func() time.Time { return now })
			if _, e := c.pendingOrPrepare(context.Background(), now); e != nil {
				t.Fatal(e)
			}
			anchor, state, e := c.loadRetainedState(context.Background(), false)
			if e != nil {
				t.Fatal(e)
			}
			ref := state.Manifest.Chunks[0]
			slot := api.leases[ref.Name]
			switch mode {
			case "newer_epoch":
				var payload retainedSlot
				if json.Unmarshal([]byte(slot.Annotations[retainedSlotAnnotation]), &payload) != nil {
					t.Fatal("slot fixture")
				}
				payload.StorageEpoch++
				raw, _ := json.Marshal(payload)
				slot.Annotations[retainedSlotAnnotation] = string(raw)
				_, body, ok := decodeRetainedSlot(string(raw))
				if !ok {
					t.Fatal("newer slot fixture")
				}
				before := slot.DeepCopy()
				if _, e := c.writeRetainedSlot(context.Background(), anchor, state.StorageEpoch, ref, body); e == nil {
					t.Fatal("old epoch overwrote newer slot")
				}
				if api.leases[ref.Name].Annotations[retainedSlotAnnotation] != before.Annotations[retainedSlotAnnotation] || api.leases[ref.Name].ResourceVersion != before.ResourceVersion {
					t.Fatal("stale publisher mutated slot")
				}
			case "foreign_owner":
				slot.OwnerReferences[0].UID = types.UID("44444444-4444-4444-8444-444444444444")
			case "recreated_slot":
				slot.UID = types.UID("44444444-4444-4444-8444-444444444444")
			case "replaced_anchor":
				api.leases[clusterStateLeaseName].UID = types.UID("44444444-4444-4444-8444-444444444444")
			}
			if e := c.Tick(context.Background(), fixtureNodeReport("node-0000", now)); e == nil || len(sink.bodies) != 0 {
				t.Fatal("invalid durable custody acquired send authority")
			}
		})
	}
}

func TestRetainedCoordinatorAbortsUnsentPrepareWithoutEpochReuse(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	c, api, _, sink := retainedCoordinatorFixture(t, 2, func() time.Time { return now })
	if _, e := c.pendingOrPrepare(context.Background(), now); e != nil {
		t.Fatal(e)
	}
	anchor, state, e := c.loadRetainedState(context.Background(), false)
	if e != nil {
		t.Fatal(e)
	}
	state.Phase = "preparing"
	for i := range state.Manifest.Chunks {
		state.Manifest.Chunks[i].UID = nil
	}
	state.Manifest.MarkerSHA256 = c.retainedMarker(state.Manifest)
	if _, e = c.storeRetainedState(context.Background(), anchor, state); e != nil {
		t.Fatal(e)
	}
	delete(api.leases, state.Manifest.Chunks[0].Name) // Never-sent incomplete prepare.
	if _, e = c.pendingOrPrepare(context.Background(), now); e == nil {
		t.Fatal("incomplete prepare was sent")
	}
	_, aborted, e := c.loadRetainedState(context.Background(), false)
	if e != nil || aborted.Phase != "idle" || aborted.StorageEpoch != 1 || aborted.ResolvedAttemptSequence != 0 || len(sink.bodies) != 0 {
		t.Fatal("abort lost epoch or advanced attempt")
	}
	if _, e = c.pendingOrPrepare(context.Background(), now); e != nil {
		t.Fatal(e)
	}
	_, next, e := c.loadRetainedState(context.Background(), false)
	if e != nil || next.Phase != "pending" || next.StorageEpoch != 2 || next.Manifest.Sequence != 1 {
		t.Fatal("abandoned storage epoch reused")
	}
}

func TestRetainedCoordinatorStateCASDoesNotEraseSealedPending(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	c, api, _, _ := retainedCoordinatorFixture(t, 2, func() time.Time { return now })
	stale, initial, e := c.loadRetainedState(context.Background(), true)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.pendingOrPrepare(context.Background(), now); e != nil {
		t.Fatal(e)
	}
	before := api.leases[clusterStateLeaseName].DeepCopy()
	if _, e = c.storeRetainedState(context.Background(), stale, initial); e == nil {
		t.Fatal("stale idle state erased sealed pending")
	}
	after, e := api.Get(context.Background(), clusterStateLeaseName, metav1.GetOptions{})
	if e != nil || after.ResourceVersion != before.ResourceVersion || after.Annotations[retainedStateAnnotation] != before.Annotations[retainedStateAnnotation] {
		t.Fatal("state CAS lost unknown pending")
	}
}

func TestRetainedCoordinatorRequiresExactSensorReceipt(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	c, api, _, sink := retainedCoordinatorFixture(t, 1, func() time.Time { return now })
	for _, id := range []string{"", "pid_00000000-0000-0000-0000-000000000000", "pid_10000001-0000-4000-8000-000000000001 "} {
		cfg := c.config
		cfg.SensorID = id
		if _, err := NewClusterCoordinator(cfg); err == nil {
			t.Fatal("retention accepted missing or malformed expected sensor")
		}
	}
	if _, err := c.pendingOrPrepare(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	body, _ := retainedCoordinatorStoredBody(t, api)
	receipt, err := sink.SendRetainedHeartbeat(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	receipt.SensorID = "pid_20000002-0000-4000-8000-000000000002"
	before := api.leases[clusterStateLeaseName].DeepCopy()
	if err := c.commitRetainedReceipt(context.Background(), body, receipt); err == nil {
		t.Fatal("foreign valid sensor receipt resolved pending")
	}
	if api.leases[clusterStateLeaseName].ResourceVersion != before.ResourceVersion || api.leases[clusterStateLeaseName].Annotations[retainedStateAnnotation] != before.Annotations[retainedStateAnnotation] {
		t.Fatal("foreign receipt changed pending")
	}
	cfg := c.config
	cfg.NodeCoverageRetention = false
	cfg.SensorID = ""
	if _, err := NewClusterCoordinator(cfg); err != nil {
		t.Fatal("legacy mode acquired new sensor-ID requirement", err)
	}
}
