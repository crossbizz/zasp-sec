package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

func TestProductDiscoveryInstalledScheduleSource(t *testing.T) {
	dsn := os.Getenv("ZASP_P4B_SCHEDULER_DSN")
	if dsn == "" {
		t.Skip("requires owned72 PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var ref orchestration.DiscoveryScheduleRef
	if err := json.Unmarshal([]byte(os.Getenv("ZASP_P4B_SCHEDULE_REF")), &ref); err != nil {
		t.Fatal(err)
	}
	source, err := newTemporalDiscoveryScheduleSource(ctx, dsn, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close(context.Background())
	id, _ := orchestration.DiscoveryScheduleID(ref)
	unknown := errors.New("controlled RPC response lost")
	err = source.WithCurrentSchedule(ctx, ref, func(d orchestration.DiscoveryScheduleDesired) error {
		if d.Ref != ref || d.Revision != 2 || d.Enabled || d.Anchor.Location() != time.UTC {
			t.Fatal("source returned stale desired", d)
		}
		var acquired bool
		if err := peer.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, id).Scan(&acquired); err != nil || acquired {
			t.Fatal("callback not serialized by owned session", acquired, err)
		}
		return unknown
	})
	if !errors.Is(err, unknown) {
		t.Fatal("unknown RPC response lost", err)
	}
	var released bool
	if err := peer.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, id).Scan(&released); err != nil || !released {
		t.Fatal("serialization session leaked", released, err)
	}
	if _, err := peer.Exec(ctx, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, id); err != nil {
		t.Fatal(err)
	}
	if err = source.ReconcileDiscoveryDue(ctx, ref); err == nil {
		t.Fatal("unknown RPC admitted or acknowledged desired")
	}
	if err = source.WithCurrentSchedule(ctx, ref, func(orchestration.DiscoveryScheduleDesired) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err = source.ReconcileDiscoveryDue(ctx, ref); err != nil {
		t.Fatal(err)
	}
}
