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

func TestInvalidRevealSecretsDoNotStarveBehindLivePendingGrants(t *testing.T) {
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
	liveTokenID := "pid_51000001-0000-4000-8000-000000000001"
	revokedTokenID := "pid_51000002-0000-4000-8000-000000000002"
	expiredTokenID := "pid_51000003-0000-4000-8000-000000000003"
	for _, token := range []struct {
		id      string
		expires string
		revoked bool
	}{
		{id: liveTokenID, expires: "1 hour"},
		{id: revokedTokenID, expires: "1 hour", revoked: true},
		{id: expiredTokenID, expires: "-1 hour"},
	} {
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_product_api_tokens(token_digest,id,name,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at,revoked_at) VALUES(digest($1,'sha256'),$1,'Cleanup token',$2,$3,$4,$5,'["view"]'::jsonb,transaction_timestamp()+$6::interval,CASE WHEN $7 THEN transaction_timestamp() ELSE NULL END)`, token.id, identity.PrincipalID.String(), organization, workspace, environment, token.expires, token.revoked); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_api_token_reveal_grants(organization_id,workspace_id,environment_id,principal_id,token_id,grant_id,operation,ciphertext,nonce,authentication_tag,expires_at)
		SELECT $1,$2,$3,$4,$5,'pid_'||lpad((10000000+ordinal)::text,8,'0')||'-0000-4000-8000-'||lpad(ordinal::text,12,'0'),'createAPIToken',decode('01','hex'),decode(repeat('02',12),'hex'),decode(repeat('03',16),'hex'),transaction_timestamp()+interval '1 hour'
		FROM generate_series(1,1000) ordinal`, organization, workspace, environment, identity.PrincipalID.String(), liveTokenID); err != nil {
		t.Fatal(err)
	}
	seedInvalid := func(prefix int, count int) {
		t.Helper()
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_api_token_reveal_grants(organization_id,workspace_id,environment_id,principal_id,token_id,grant_id,operation,ciphertext,nonce,authentication_tag,expires_at)
			SELECT $1,$2,$3,$4,
			       CASE WHEN ordinal<=500 THEN $5 WHEN ordinal<=1000 THEN $6 WHEN ordinal<=1200 THEN $7 ELSE 'pid_51000004-0000-4000-8000-000000000004' END,
			       'pid_'||lpad(($8+ordinal)::text,8,'0')||'-0000-4000-8000-'||lpad(ordinal::text,12,'0'),'createAPIToken',decode('01','hex'),decode(repeat('02',12),'hex'),decode(repeat('03',16),'hex'),
			       CASE WHEN ordinal<=500 THEN transaction_timestamp()-interval '1 hour' ELSE transaction_timestamp()+interval '1 hour' END
			FROM generate_series(1,$9) ordinal`, organization, workspace, environment, identity.PrincipalID.String(), liveTokenID, revokedTokenID, expiredTokenID, prefix, count); err != nil {
			t.Fatal(err)
		}
	}
	seedInvalid(90000000, 1500)
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(database)
	if err != nil {
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
	errors := make(chan error, 2)
	for _, cleanupRepository := range []*PostgresRepository{repository, secondRepository} {
		go func(candidate *PostgresRepository) { errors <- candidate.Ready(ctx) }(cleanupRepository)
	}
	for range 2 {
		if err := <-errors; err != nil {
			t.Fatalf("concurrent readiness: %v", err)
		}
	}
	var livePending, invalidPending int
	if err := connection.QueryRow(ctx, `SELECT count(*) FILTER (WHERE grant_id<'pid_80000000'),count(*) FILTER (WHERE grant_id>='pid_80000000') FROM zasp_api_token_reveal_grants WHERE acknowledged_at IS NULL AND ciphertext IS NOT NULL`).Scan(&livePending, &invalidPending); err != nil {
		t.Fatal(err)
	}
	if livePending != 1000 || invalidPending != 0 {
		t.Fatalf("concurrent cleanup pending live/invalid = %d/%d, want 1000/0", livePending, invalidPending)
	}

	seedInvalid(80000000, 1001)
	if err := repository.Ready(ctx); err != nil {
		t.Fatalf("first repeated readiness: %v", err)
	}
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_api_token_reveal_grants WHERE grant_id>='pid_80000000' AND grant_id<'pid_90000000' AND acknowledged_at IS NULL AND ciphertext IS NOT NULL`).Scan(&invalidPending); err != nil || invalidPending != 1 {
		t.Fatalf("first bounded readiness remainder = (%d, %v), want 1", invalidPending, err)
	}
	if err := repository.Ready(ctx); err != nil {
		t.Fatalf("second repeated readiness: %v", err)
	}
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_api_token_reveal_grants WHERE grant_id>='pid_80000000' AND grant_id<'pid_90000000' AND acknowledged_at IS NULL AND ciphertext IS NOT NULL`).Scan(&invalidPending); err != nil || invalidPending != 0 {
		t.Fatalf("second bounded readiness remainder = (%d, %v), want 0", invalidPending, err)
	}
}
