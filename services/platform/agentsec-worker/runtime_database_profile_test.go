package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestWorkerRuntimeDatabaseProfileClosedSelection(t *testing.T) {
	base := map[string]string{
		"ZASP_WORKER_MODE": "runtime-coordinator", "ZASP_POSTGRES_DSN": "postgres://runtime_coordinator@postgres.internal/zasp?sslmode=verify-full",
		"ZASP_DATABASE_AUTHORITY": "zasp_runtime_coordinator", "ZASP_WORKER_ID": "runtime-coordinator-01", "ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "30s", "ZASP_BATCH_SIZE": "10", "ZASP_SHUTDOWN_TIMEOUT": "20s",
		"ZASP_RUNTIME_QUEUE_URL": "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-runtime-events", "ZASP_AWS_REGION": "us-west-2",
		"ZASP_RUNTIME_ROLE_ARN": "arn:aws:iam::123456789012:role/zasp-production-runtime-coordinator", "ZASP_RUNTIME_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
	}
	for _, profile := range []string{"", migrations.AuthorizationRuntimeProfileName, "unknown", migrations.AuthorizationRuntimeProfileName + " ", "canonical61-temporal78-authorization79-80-worker-v1"} {
		t.Run(profile, func(t *testing.T) {
			values := cloneStringMap(base)
			values["ZASP_RUNTIME_DATABASE_PROFILE"] = profile
			cfg, err := loadWorkerRuntimeConfig(mapLookup(values))
			valid := profile == "" || profile == migrations.AuthorizationRuntimeProfileName
			if !valid {
				if err == nil {
					t.Fatal("unknown database profile accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			body, _ := json.Marshal(cfg)
			var fields map[string]any
			_ = json.Unmarshal(body, &fields)
			if fields["RuntimeDatabaseProfile"] != profile || cfg.RuntimeServices.Enabled {
				t.Fatal("SQL-only database profile was not retained independently")
			}
		})
	}
}

type runtimeProfileRow struct {
	value bool
	err   error
}

func (r runtimeProfileRow) Scan(values ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(values) != 1 {
		return errors.New("shape")
	}
	p, ok := values[0].(*bool)
	if !ok {
		return errors.New("type")
	}
	*p = r.value
	return nil
}

type runtimeProfileQuery struct {
	queries []string
	args    [][]any
	value   bool
	err     error
}

func (q *runtimeProfileQuery) QueryRow(_ context.Context, s string, args ...any) pgx.Row {
	q.queries = append(q.queries, s)
	q.args = append(q.args, args)
	if s == `SELECT to_regnamespace('zasp_authorization80_worker') IS NOT NULL` {
		return runtimeProfileRow{value: true}
	}
	return runtimeProfileRow{q.value, q.err}
}

func TestWorkerRuntimeSQLOnlyStartupFence(t *testing.T) {
	for _, mode := range []workerMode{workerModeRuntimeCoordinator, workerModeRuntimeArchive, workerModeRuntimeIndex, workerModeRuntimeCorrelation, workerModeRuntimeProjection, workerModeRuntimeComplete, workerModeRuntimeOutbox} {
		t.Run(string(mode), func(t *testing.T) {
			cfg := workerRuntimeConfig{Mode: mode, DatabaseAuthority: runtimeDatabaseAuthority(mode), RuntimeDatabaseProfile: migrations.AuthorizationRuntimeProfileName}
			q := &runtimeProfileQuery{value: true}
			if err := workerStartupProfileReady(context.Background(), q, cfg); err != nil || len(q.queries) != 1 || q.queries[0] != `SELECT zasp_authorization80_runtime.ready($1,$2)` || len(q.args[0]) != 2 || q.args[0][0] != migrations.AuthorizationRuntimeProfileChecksum() || q.args[0][1] != cfg.DatabaseAuthority {
				t.Fatal("SQL-only startup did not use exact role/profile", err)
			}
			for _, control := range []string{"false", "error", "wrong-role", "foreign-mode", "unknown-profile", "cancelled"} {
				t.Run(control, func(t *testing.T) {
					c := cfg
					db := &runtimeProfileQuery{value: true}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					switch control {
					case "false":
						db.value = false
					case "error":
						db.err = errors.New("undefined or malformed native readiness")
					case "wrong-role":
						c.DatabaseAuthority = "zasp_security_agent_worker"
					case "foreign-mode":
						c.Mode = workerModeSecurityAgent
					case "unknown-profile":
						c.RuntimeDatabaseProfile = "unknown"
					case "cancelled":
						cancel()
					}
					if workerStartupProfileReady(ctx, db, c) == nil {
						t.Fatal("startup refusal bypassed")
					}
					if len(db.queries) > 1 {
						t.Fatal("startup fell back to historical gate")
					}
				})
			}
			cfg.RuntimeDatabaseProfile = ""
			db := &runtimeProfileQuery{}
			if workerStartupProfileReady(context.Background(), db, cfg) == nil || len(db.queries) != 2 || db.queries[1] != `SELECT zasp_authorization80_worker.runtime_ready()` {
				t.Fatal("historical startup bypassed installed partial profile")
			}
		})
	}
}
