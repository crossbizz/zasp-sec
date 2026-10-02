package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// The owned PostgreSQL parent drives durable transitions. This child uses the
// shipped, registered API repository and its strict public wire decoders.
func TestProductDiscoveryInstalledReadback(t *testing.T) {
	dsn := os.Getenv("ZASP_P4B_API_DSN")
	if dsn == "" {
		t.Skip("requires owned discovery72 PostgreSQL parent")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
	repo, err := apiserver.NewDiscoveryRepositoryForAuthority(db, apiserver.DiscoveryDatabaseAuthorityAPI)
	if err != nil {
		t.Fatal("installed API constructor", err)
	}
	if err := repo.Ready(ctx); err != nil {
		t.Fatal("installed API readiness", err)
	}
	var ids []string
	if err := json.Unmarshal([]byte(os.Getenv("ZASP_P4B_READBACK_IDS")), &ids); err != nil || len(ids) != 5 {
		t.Fatal("scope input", err)
	}
	o, _ := domain.ParseProductID(ids[0])
	w, _ := domain.ParseProductID(ids[1])
	e, _ := domain.ParseProductID(ids[2])
	scope, err := domain.NewScope(o, w, e)
	if err != nil {
		t.Fatal(err)
	}
	attempt, _ := strconv.Atoi(os.Getenv("ZASP_P4B_EXPECT_ATTEMPT"))
	check := func(value apiserver.IntegrationSync) {
		t.Helper()
		if value.ID != ids[4] || value.Status != os.Getenv("ZASP_P4B_EXPECT_STATUS") || value.Attempt != attempt || (value.RetryAt != nil) != (os.Getenv("ZASP_P4B_EXPECT_RETRY") == "true") {
			t.Fatalf("public product-run projection: %+v", value)
		}
	}
	got, err := repo.GetIntegrationSync(ctx, scope, ids[3], ids[4])
	if err != nil {
		t.Fatal("typed detail", err)
	}
	check(got.Value)
	page, err := repo.ListIntegrationSyncs(ctx, scope, ids[3], nil, "", 100)
	if err != nil || len(page.Items) == 0 {
		t.Fatal("typed history", err)
	}
	found := false
	for _, item := range page.Items {
		if item.ID == ids[4] {
			check(item)
			found = true
		}
	}
	if !found {
		t.Fatal("sync absent from history")
	}
	freshness, err := repo.GetIntegrationFreshness(ctx, scope, ids[3])
	if err != nil {
		t.Fatal("typed freshness", err)
	}
	if freshness.LatestSync == nil {
		t.Fatal("freshness missing latest sync")
	}
	check(*freshness.LatestSync)
	if _, err := repo.GetIntegrationSchedule(ctx, scope, ids[3]); err != nil {
		t.Fatal("typed schedule", err)
	}
	foreign, _ := domain.ParseProductID("pid_72009999-0000-4000-8000-000000000099")
	other, _ := domain.NewScope(o, w, foreign)
	if _, err := repo.GetIntegrationSync(ctx, other, ids[3], ids[4]); err == nil {
		t.Fatal("cross tenant detail accepted")
	}
}

func TestProductDiscoveryInstalledPublicMutations(t *testing.T) {
	dsn := os.Getenv("ZASP_P4B_API_DSN")
	if dsn == "" {
		t.Skip("requires owned discovery72 PostgreSQL parent")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
	repo, err := apiserver.NewDiscoveryRepositoryForAuthority(db, apiserver.DiscoveryDatabaseAuthorityAPI)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	if json.Unmarshal([]byte(os.Getenv("ZASP_P4B_MUTATION_IDS")), &ids) != nil || len(ids) != 5 {
		t.Fatal("identity input")
	}
	o, _ := domain.ParseProductID(ids[0])
	w, _ := domain.ParseProductID(ids[1])
	e, _ := domain.ParseProductID(ids[2])
	p, _ := domain.ParseProductID(ids[3])
	scope, _ := domain.NewScope(o, w, e)
	identity := apiserver.RequestIdentity{PrincipalID: p, Scope: scope, Permissions: []string{"view", "manage_workflows"}, CredentialKind: apiserver.CredentialBrowserSession}
	id := func(n int) string { return fmt.Sprintf("pid_72700000-0000-4000-8000-%012d", n) }
	digest := sha256.Sum256([]byte("typed72-manual-request"))
	request := apiserver.PublicSyncRequest{IntegrationID: ids[4], IdempotencyKey: "typed72-manual-request", SyncID: id(1), JobID: id(2), OutboxID: id(3), ExpectedVersion: 1, RequestDigest: digest[:], ParserVersion: "parser_v1", ToolVersion: "tool_v1", AuditID: id(4), CorrelationID: id(5), ReceiptID: id(6)}
	got, err := repo.RequestIntegrationSync(ctx, identity, request)
	if err != nil || got.Value.Status != "queued" || got.Value.Attempt != 0 || got.Replayed {
		t.Fatalf("manual API: %+v %v", got, err)
	}
	replay, err := repo.RequestIntegrationSync(ctx, identity, request)
	if err != nil || !replay.Replayed || replay.Value.ID != got.Value.ID {
		t.Fatal("manual replay", err)
	}
	put := apiserver.PublicSchedulePut{IntegrationID: ids[4], IdempotencyKey: "typed72-enable-schedule", ExpectedVersion: 2, CadenceSeconds: 300, State: "enabled", AuditID: id(7), CorrelationID: id(8), ReceiptID: id(9)}
	schedule, err := repo.PutIntegrationSchedule(ctx, identity, put)
	if err != nil || schedule.Version != 3 || schedule.Value.State != "enabled" {
		t.Fatal("schedule enable API", err)
	}
	read, err := repo.GetIntegrationSchedule(ctx, scope, ids[4])
	if err != nil || read.Version != 3 || read.NextRunAt == nil {
		t.Fatal("read desired schedule", err)
	}
	del := apiserver.PublicScheduleDelete{IntegrationID: ids[4], IdempotencyKey: "typed72-delete-schedule", ExpectedVersion: 3, AuditID: id(10), CorrelationID: id(11), ReceiptID: id(12)}
	deleted, err := repo.DeleteIntegrationSchedule(ctx, identity, del)
	if err != nil || deleted.Version != 4 || deleted.Value.State != "deleted" {
		t.Fatal("delete API", err)
	}
	deleted, err = repo.DeleteIntegrationSchedule(ctx, identity, del)
	if err != nil || !deleted.Replayed {
		t.Fatal("delete replay API", err)
	}
	if _, err := repo.GetIntegrationSchedule(ctx, scope, ids[4]); err == nil {
		t.Fatal("deleted schedule remained visible")
	}
}
