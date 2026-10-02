//go:build darwin || linux

package apiserver

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
)

// A valid release with a substituted principal must fail before any claim.
func TestSecurityAgentRelease61CompositionPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		deployment := orderedApplicationDeploymentConnection(t, ctx, owner)
		defer deployment.Close(ctx)
		red, adapter := orderedTestConnections(t, ctx, owner)
		defer red.Close(ctx)
		defer adapter.Close(ctx)
		database := func(c *pgx.Conn) JSONDatabase {
			db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: c})
			if err != nil {
				t.Fatal(err)
			}
			return db
		}
		store, err := artifactstore.New(&orderedTestArtifactDriver{objects: make(map[artifactstore.DriverLocator]artifactstore.DriverObject)}, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 1048576})
		if err != nil {
			t.Fatal(err)
		}
		c := SecurityAgentRelease61CompositionConfig{Worker: database(worker), Action: database(action), Deployment: database(deployment), TestWorker: database(red), Store: store}
		if got, err := NewSecurityAgentRelease61Composition(ctx, c); err != nil || got == nil {
			t.Fatal("private principal-separated composition absent", err)
		}
		for _, lane := range []string{"worker", "action", "deployment", "test"} {
			bad := c
			switch lane {
			case "worker":
				bad.Worker = database(api)
			case "action":
				bad.Action = c.Worker
			case "deployment":
				bad.Deployment = c.Action
			case "test":
				bad.TestWorker = c.Worker
			}
			if got, err := NewSecurityAgentRelease61Composition(ctx, bad); err == nil || got != nil {
				t.Fatal("composition accepted substituted principal", lane, err)
			}
		}
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if got, err := NewSecurityAgentRelease61Composition(cancelled, c); err == nil || got != nil {
			t.Fatal("composition ignored caller cancellation")
		}
		if _, err = owner.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_security_agent_multistep_fingerprint'`); err != nil {
			t.Fatal(err)
		}
		if got, err := NewSecurityAgentRelease61Composition(ctx, c); err == nil || got != nil {
			t.Fatal("composition accepted readiness drift")
		}
	})
}
