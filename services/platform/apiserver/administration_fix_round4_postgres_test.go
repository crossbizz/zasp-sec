package apiserver

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestExpiredRevealSecretsAreGloballyDestroyedWithoutOwnerTraffic(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close(context.Background()) }()
	runRound2Migrations(t, ctx, connection)
	identity := fixtureRequestIdentity(t)
	organization := identity.Scope.OrganizationID().String()
	workspace := identity.Scope.WorkspaceID().String()
	environment := identity.Scope.EnvironmentID().String()
	tokenID := "pid_41000005-0000-4000-8000-000000000005"
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_product_api_tokens(token_digest,id,name,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at) VALUES(digest('round-four-token','sha256'),$1,'Round four token',$2,$3,$4,$5,'["view"]'::jsonb,transaction_timestamp()+interval '1 hour')`, tokenID, identity.PrincipalID.String(), organization, workspace, environment); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_api_token_reveal_grants(organization_id,workspace_id,environment_id,principal_id,token_id,grant_id,operation,ciphertext,nonce,authentication_tag,expires_at)
		SELECT $1,$2,$3,$4,$5,'pid_'||lpad((42000000+ordinal)::text,8,'0')||'-0000-4000-8000-'||lpad(ordinal::text,12,'0'),'createAPIToken',decode('01','hex'),decode(repeat('02',12),'hex'),decode(repeat('03',16),'hex'),transaction_timestamp()-interval '1 hour'
		FROM generate_series(1,1001) ordinal`, organization, workspace, environment, identity.PrincipalID.String(), tokenID); err != nil {
		t.Fatal(err)
	}
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	cleaned, err := repository.CleanupExpiredAPITokenRevealGrants(ctx, 1000)
	if err != nil || cleaned != 1000 {
		t.Fatalf("first global cleanup = (%d, %v), want 1000", cleaned, err)
	}
	var pendingSecrets int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_api_token_reveal_grants WHERE acknowledged_at IS NULL OR ciphertext IS NOT NULL OR nonce IS NOT NULL OR authentication_tag IS NOT NULL`).Scan(&pendingSecrets); err != nil || pendingSecrets != 1 {
		t.Fatalf("bounded cleanup remainder = (%d, %v), want 1", pendingSecrets, err)
	}
	if err := repository.Ready(ctx); err != nil {
		t.Fatalf("readiness cleanup: %v", err)
	}
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_api_token_reveal_grants WHERE acknowledged_at IS NULL OR ciphertext IS NOT NULL OR nonce IS NOT NULL OR authentication_tag IS NOT NULL`).Scan(&pendingSecrets); err != nil || pendingSecrets != 0 {
		t.Fatalf("readiness left ownerless expired secrets = (%d, %v)", pendingSecrets, err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_api_token_reveal_grants(organization_id,workspace_id,environment_id,principal_id,token_id,grant_id,operation,ciphertext,nonce,authentication_tag,expires_at)
		SELECT $1,$2,$3,$4,$5,'pid_'||lpad((43000000+ordinal)::text,8,'0')||'-0000-4000-8000-'||lpad(ordinal::text,12,'0'),'createAPIToken',decode('01','hex'),decode(repeat('02',12),'hex'),decode(repeat('03',16),'hex'),transaction_timestamp()-interval '1 hour'
		FROM generate_series(1,1500) ordinal`, organization, workspace, environment, identity.PrincipalID.String(), tokenID); err != nil {
		t.Fatal(err)
	}
	secondConnection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = secondConnection.Close(context.Background()) }()
	secondDatabase, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: secondConnection})
	if err != nil {
		t.Fatal(err)
	}
	secondRepository, err := NewPostgresRepository(secondDatabase)
	if err != nil {
		t.Fatal(err)
	}
	type cleanupResult struct {
		cleaned int
		err     error
	}
	results := make(chan cleanupResult, 2)
	for _, cleanupRepository := range []*PostgresRepository{repository, secondRepository} {
		go func(candidate *PostgresRepository) {
			count, cleanupErr := candidate.CleanupExpiredAPITokenRevealGrants(ctx, 1000)
			results <- cleanupResult{cleaned: count, err: cleanupErr}
		}(cleanupRepository)
	}
	total := 0
	for range 2 {
		result := <-results
		if result.err != nil || result.cleaned < 1 || result.cleaned > 1000 {
			t.Fatalf("concurrent cleanup = (%d, %v)", result.cleaned, result.err)
		}
		total += result.cleaned
	}
	if total != 1500 {
		t.Fatalf("concurrent cleanup total = %d, want 1500", total)
	}
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_api_token_reveal_grants WHERE acknowledged_at IS NULL OR ciphertext IS NOT NULL OR nonce IS NOT NULL OR authentication_tag IS NOT NULL`).Scan(&pendingSecrets); err != nil || pendingSecrets != 0 {
		t.Fatalf("overlapping cleanup left or double-counted secrets = (%d, %v)", pendingSecrets, err)
	}
}
