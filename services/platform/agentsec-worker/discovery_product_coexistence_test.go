package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestProductDiscoveryInstalledRetainedAuthority(t *testing.T) {
	input := os.Getenv("ZASP_P4B_RETAINED_DSNS")
	if input == "" {
		t.Skip("requires owned discovery72 PostgreSQL parent")
	}
	var dsns map[string]string
	if json.Unmarshal([]byte(input), &dsns) != nil {
		t.Fatal("DSNs")
	}
	for role, dsn := range dsns {
		t.Run(role, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			pool, err := pgxpool.New(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer pool.Close()
			db, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: pool})
			if err != nil {
				t.Fatal(err)
			}
			if role != apiserver.DiscoveryDatabaseAuthorityOutbox {
				repo, err := apiserver.NewDiscoveryExecutionRepository(db, role)
				if os.Getenv("ZASP_P4B_EXPECT_REFUSED") == "true" {
					if err == nil {
						t.Fatal("invalid72 fell back to legacy authority")
					}
					return
				}
				if err != nil {
					t.Fatal("retained exact authority", err)
				}
				if err := repo.Ready(ctx); err != nil {
					t.Fatal(err)
				}
				return
			}
			repo, err := apiserver.NewDiscoveryExecutionOutboxRepository(db)
			if os.Getenv("ZASP_P4B_EXPECT_REFUSED") == "true" {
				if err == nil {
					t.Fatal("invalid72 fell back to legacy transport")
				}
				return
			}
			if err != nil {
				t.Fatal("typed72 outbox", err)
			}
			if err := repo.Ready(ctx); err != nil {
				t.Fatal(err)
			}
			items, err := repo.ClaimOutboxTopic(ctx, "discovery-jobs", "typed72-transport", "typed72-transport-token-0001", 30, 1)
			if err != nil || len(items) != 1 {
				t.Fatal("typed outbox claim", err)
			}
			if _, err := repo.HeartbeatOutboxTopic(ctx, "discovery-jobs", "typed72-transport", "typed72-transport-token-0001", 30, 1); err != nil {
				t.Fatal("typed heartbeat", err)
			}
			x := items[0]
			o, _ := domain.ParseProductID(x.OrganizationID)
			w, _ := domain.ParseProductID(x.WorkspaceID)
			e, _ := domain.ParseProductID(x.EnvironmentID)
			scope, _ := domain.NewScope(o, w, e)
			if _, err := repo.AcknowledgeOutboxTopic(ctx, "discovery-jobs", scope, x.ID, "typed72-transport", "typed72-transport-token-0001", "sha256:"+strings.Repeat("a", 64)); err != nil {
				t.Fatal("typed ACK", err)
			}
		})
	}
}
