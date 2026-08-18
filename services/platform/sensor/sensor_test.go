package sensor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestSensorEnrollmentRotationHeartbeatAndScope(t *testing.T) {
	ids := []domain.ProductID{fixtureID(7)}
	tokens := []string{"sensor_token_abcdefghijklmnopqrstuvwxyz012345", "sensor_token_abcdefghijklmnopqrstuvwxyz067890"}
	store := NewMemoryStore(func() (domain.ProductID, error) { id := ids[0]; return id, nil }, func() (string, error) { token := tokens[0]; tokens = tokens[1:]; return token, nil }, func() time.Time { return time.Date(2026, 8, 18, 9, 0, 0, 0, time.UTC) })
	scope := fixtureScope(1)
	enrollment, err := store.Create(context.Background(), scope, Input{Name: "cluster-a", Mode: "metadata_only"})
	if err != nil || enrollment.Token == "" || enrollment.Sensor.TokenHash == "" {
		t.Fatalf("%+v %v", enrollment, err)
	}
	listed, err := store.List(context.Background(), scope)
	if err != nil || len(listed) != 1 || listed[0].TokenHash == enrollment.Token {
		t.Fatalf("%+v %v", listed, err)
	}
	rotated, err := store.Rotate(context.Background(), scope, enrollment.Sensor.ID)
	if err != nil || rotated.Token == "" || rotated.Token == enrollment.Token {
		t.Fatalf("%+v %v", rotated, err)
	}
	if _, err := store.Heartbeat(context.Background(), scope, enrollment.Sensor.ID, enrollment.Token, Heartbeat{Capabilities: []string{"process", "network"}, Kernel: "6.8", BTF: true, EventRate: 4, Drops: 1}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("old token: %v", err)
	}
	updated, err := store.Heartbeat(context.Background(), scope, enrollment.Sensor.ID, rotated.Token, Heartbeat{Capabilities: []string{"network", "process"}, Kernel: "6.8", BTF: true, EventRate: 4, Drops: 1})
	if err != nil || updated.LastHeartbeat.IsZero() || len(updated.Capabilities) != 2 {
		t.Fatalf("%+v %v", updated, err)
	}
	if _, err := store.Get(context.Background(), fixtureScope(4), enrollment.Sensor.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross scope: %v", err)
	}
}

func TestSensorCoverageAndDelete(t *testing.T) {
	store := fixtureStore()
	scope := fixtureScope(1)
	enrollment, err := store.Create(context.Background(), scope, Input{Name: "cluster-a", Mode: "full"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(context.Background(), scope, enrollment.Sensor.ID, Input{Name: "cluster-b", Mode: "metadata_only"}); err != nil {
		t.Fatal(err)
	}
	coverage, err := store.Coverage(context.Background(), scope, enrollment.Sensor.ID)
	if err != nil || coverage.Supported || coverage.Status != "awaiting_heartbeat" {
		t.Fatalf("%+v %v", coverage, err)
	}
	if err := store.Delete(context.Background(), scope, enrollment.Sensor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), scope, enrollment.Sensor.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestSensorRotationRejectsReusedToken(t *testing.T) {
	store := NewMemoryStore(func() (domain.ProductID, error) { return fixtureID(7), nil }, func() (string, error) { return "sensor_token_abcdefghijklmnopqrstuvwxyz012345", nil }, func() time.Time { return time.Date(2026, 8, 18, 9, 0, 0, 0, time.UTC) })
	scope := fixtureScope(1)
	enrollment, err := store.Create(context.Background(), scope, Input{Name: "cluster-a", Mode: "full"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Rotate(context.Background(), scope, enrollment.Sensor.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("got %v", err)
	}
}

func fixtureStore() *MemoryStore {
	return NewMemoryStore(func() (domain.ProductID, error) { return fixtureID(7), nil }, func() (string, error) { return "sensor_token_abcdefghijklmnopqrstuvwxyz012345", nil }, func() time.Time { return time.Date(2026, 8, 18, 9, 0, 0, 0, time.UTC) })
}
func fixtureID(seed byte) domain.ProductID {
	id, err := domain.ParseProductID("pid_00000000-0000-4000-8000-00000000000" + string('0'+seed))
	if err != nil {
		panic(err)
	}
	return id
}
func fixtureScope(seed byte) domain.Scope {
	scope, err := domain.NewScope(fixtureID(seed), fixtureID(seed+1), fixtureID(seed+2))
	if err != nil {
		panic(err)
	}
	return scope
}
