package apiserver

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
)

func TestRuntimePrecisionSQLPreservesExactNanoseconds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, startDisposablePostgres(t))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	if _, err = admin.Exec(ctx, `CREATE ROLE zasp_discovery_authority NOLOGIN; CREATE ROLE precision_untrusted LOGIN`); err != nil {
		t.Fatal(err)
	}
	fragment, err := os.ReadFile("../migrations/sql/fragments/runtime_precision.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = admin.Exec(ctx, string(fragment)); err != nil {
		t.Fatal(err)
	}
	t.Run("exact-epoch", func(t *testing.T) {
		if _, err := admin.Exec(ctx, `SET TIME ZONE 'America/Los_Angeles'; SET DateStyle TO 'SQL, DMY'`); err != nil {
			t.Fatal(err)
		}
		var epoch string
		if err := admin.QueryRow(ctx, `SELECT zasp_runtime_precise_epoch('1970-01-01T00:00:01.000000001Z')::text`).Scan(&epoch); err != nil || epoch != "1.000000001" {
			t.Fatalf("absolute epoch changed with session settings: %q %v", epoch, err)
		}
		var difference string
		err := admin.QueryRow(ctx, `SELECT (zasp_runtime_precise_epoch('2026-08-20T12:00:00.123456789Z')-zasp_runtime_precise_epoch('2026-08-20T12:00:00.123456788Z'))::text`).Scan(&difference)
		if err != nil || difference != "0.000000001" {
			t.Fatalf("nanosecond collapsed: %q %v", difference, err)
		}
		for _, value := range []string{"1970-01-01T00:00:00.999999999Z", "1970-01-01T00:00:00Z", "1969-12-31T23:59:59Z", "0000-01-01T00:00:00Z", "2026-02-30T12:00:00Z", "2026-08-20T24:00:00Z", "2026-08-20T12:00:60Z", "2026-08-20T12:00:00.120Z", "2026-08-20T12:00:00.000Z", "2026-08-20T12:00:00+00:00", "2026-08-20T12:00:00.1234567891Z", "2026-08-20T12:00:00z", " 2026-08-20T12:00:00Z"} {
			var rejected bool
			if err := admin.QueryRow(ctx, `SELECT zasp_runtime_precise_epoch($1) IS NULL`, value).Scan(&rejected); err != nil || !rejected {
				t.Fatalf("invalid timestamp accepted %q: %v", value, err)
			}
		}
		for _, value := range []string{"1970-01-01T00:00:01Z", "2024-02-29T23:59:59.999999999Z", "9999-12-31T23:59:59.999999999Z"} {
			var accepted bool
			if err := admin.QueryRow(ctx, `SELECT zasp_runtime_precise_epoch($1) IS NOT NULL`, value).Scan(&accepted); err != nil || !accepted {
				t.Fatalf("valid timestamp rejected %q: %v", value, err)
			}
		}
	})
	t.Run("exact-occurrence-window", func(t *testing.T) {
		var before, after bool
		err := admin.QueryRow(ctx, `SELECT
		 abs(extract(epoch FROM '2026-08-20T11:55:00Z'::timestamptz)-zasp_runtime_precise_epoch('2026-08-20T12:00:00.000000001Z'))<=300,
		 abs(extract(epoch FROM '2026-08-20T12:05:00Z'::timestamptz)-zasp_runtime_precise_epoch('2026-08-20T12:00:00.000000001Z'))<=300`).Scan(&before, &after)
		if err != nil || before || !after {
			t.Fatalf("five-minute boundary rounded: before=%v after=%v %v", before, after, err)
		}
	})
	observation := runtimelineage.PreciseObservation{Observation: runtimelineage.Observation{Profile: "kubernetes-container-v2", ClusterUID: "12345678-1234-1234-1234-123456789001", NodeUID: "12345678-1234-1234-1234-123456789002", BootID: "12345678-1234-1234-1234-123456789003", PodUID: "12345678-1234-1234-1234-123456789004", ContainerID: "containerd://" + strings.Repeat("a", 64), ProcessID: "42", ProcessStartTime: "2026-08-20T12:00:00.123456789Z", CgroupID: "12345"}, SourceEventTime: "2026-08-20T12:00:00.123999999Z"}
	encoded, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, source, start, wire string
		want                      bool
	}{
		{"same-ms", observation.SourceEventTime, observation.ProcessStartTime, "2026-08-20T12:00:00.123Z", true},
		{"equal", observation.SourceEventTime, observation.SourceEventTime, "2026-08-20T12:00:00.123Z", true},
		{"future-1ns", "2026-08-20T12:00:00.123456788Z", observation.ProcessStartTime, "2026-08-20T12:00:00.123Z", false},
		{"wrong-bin", observation.SourceEventTime, observation.ProcessStartTime, "2026-08-20T12:00:00.124Z", false},
		{"next-second", "2026-08-20T12:00:01Z", observation.ProcessStartTime, "2026-08-20T12:00:01.000Z", true},
		{"trailing-zero", "2026-08-20T12:00:00.123999990Z", observation.ProcessStartTime, "2026-08-20T12:00:00.123Z", false},
		{"non-ms-display", observation.SourceEventTime, observation.ProcessStartTime, "2026-08-20T12:00:00.1239Z", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := observation
			value.SourceEventTime = test.source
			value.ProcessStartTime = test.start
			// Invalid values cannot be marshaled by the Go validator. Change the raw
			// representation independently so SQL receives the adversarial input.
			var raw map[string]any
			if err := json.Unmarshal(encoded, &raw); err != nil {
				t.Fatal(err)
			}
			raw["source_event_time"], raw["process_start_time"] = test.source, test.start
			body, err := json.Marshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			var got bool
			if err := admin.QueryRow(ctx, `SELECT zasp_runtime_precise_lineage_valid($1::jsonb,$2)`, body, test.wire).Scan(&got); err != nil || got != test.want {
				t.Fatalf("SQL valid=%v want=%v: %v", got, test.want, err)
			}
			wire, err := time.Parse("2006-01-02T15:04:05.000Z", test.wire)
			goValid := err == nil && value.ValidAt(wire)
			if goValid != test.want {
				t.Fatal("Go/SQL contract diverged")
			}
		})
	}
	t.Run("closed-lineage", func(t *testing.T) {
		for _, body := range []string{`null`, `{}`, strings.Replace(string(encoded), `"profile":`, `"tenant_id":"forged","profile":`, 1), strings.Replace(string(encoded), "kubernetes-container-v2", "kubernetes-container-v1", 1), strings.Replace(string(encoded), `"42"`, `"4294967296"`, 1), strings.Replace(string(encoded), `"12345"`, `"18446744073709551616"`, 1), strings.Replace(string(encoded), observation.ClusterUID, "00000000-0000-0000-0000-000000000000", 1), strings.Replace(string(encoded), `"process_id":"42",`, "", 1)} {
			var accepted bool
			if err := admin.QueryRow(ctx, `SELECT zasp_runtime_precise_lineage_valid($1::jsonb,'2026-08-20T12:00:00.123Z')`, body).Scan(&accepted); err != nil || accepted {
				t.Fatalf("hostile lineage accepted: %v", err)
			}
		}
		var absent map[string]any
		if err := json.Unmarshal(encoded, &absent); err != nil {
			t.Fatal(err)
		}
		delete(absent, "process_id")
		delete(absent, "process_start_time")
		delete(absent, "cgroup_id")
		body, err := json.Marshal(absent)
		if err != nil {
			t.Fatal(err)
		}
		var accepted bool
		if err := admin.QueryRow(ctx, `SELECT zasp_runtime_precise_lineage_valid($1::jsonb,'2026-08-20T12:00:00.123Z')`, body).Scan(&accepted); err != nil || !accepted {
			t.Fatal("optional identity became required", err)
		}
	})
	t.Run("private-invoker", func(t *testing.T) {
		var secure bool
		err := admin.QueryRow(ctx, `SELECT count(*)=2 AND bool_and(NOT p.prosecdef AND p.provolatile='i' AND pg_get_userbyid(p.proowner)='zasp_discovery_authority' AND NOT has_function_privilege('precision_untrusted',p.oid,'EXECUTE')) FROM pg_proc p WHERE p.oid IN ('zasp_runtime_precise_epoch(text)'::regprocedure,'zasp_runtime_precise_lineage_valid(jsonb,text)'::regprocedure)`).Scan(&secure)
		if err != nil || !secure {
			t.Fatal("SQL helper privilege widened", err)
		}
	})
}
