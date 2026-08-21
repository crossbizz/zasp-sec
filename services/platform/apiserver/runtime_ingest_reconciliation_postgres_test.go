package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

func TestProductionRuntimeIngestReconciliationPostgresRateLimitsAndLeasesByExactTenant(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	runner := migrateToTypedInventoryCutover(t, ctx, connection)

	first := fixtureRequestIdentity(t).Scope
	secondOrganization := "pid_77100001-0000-4000-8000-000000000001"
	secondWorkspace := "pid_77100002-0000-4000-8000-000000000002"
	secondEnvironment := "pid_77100003-0000-4000-8000-000000000003"
	for _, seed := range []struct {
		statement string
		arguments []any
	}{
		{`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Rate tenant','rate-tenant.invalid')`, []any{secondOrganization}},
		{`INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($2,$1,'Production')`, []any{secondOrganization, secondWorkspace}},
		{`INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($3,$1,$2,'Production','production')`, []any{secondOrganization, secondWorkspace, secondEnvironment}},
	} {
		if _, err := connection.Exec(ctx, seed.statement, seed.arguments...); err != nil {
			t.Fatalf("seed second tenant: %v", err)
		}
	}
	firstSensor := "pid_77100011-0000-4000-8000-000000000011"
	secondSensor := "pid_77100012-0000-4000-8000-000000000012"
	for _, fixture := range []struct {
		organization string
		workspace    string
		environment  string
		sensorID     string
	}{
		{first.OrganizationID().String(), first.WorkspaceID().String(), first.EnvironmentID().String(), firstSensor},
		{secondOrganization, secondWorkspace, secondEnvironment, secondSensor},
	} {
		if _, err := connection.Exec(ctx, `SELECT zasp_discovery_create_sensor($1,$2,$3,$4,'rate-sensor','tetragon')`, fixture.organization, fixture.workspace, fixture.environment, fixture.sensorID); err != nil {
			t.Fatalf("create sensor %s: %v", fixture.sensorID, err)
		}
	}
	if err := runner.UpProductionRuntimeDataPlane(ctx); err != nil {
		t.Fatalf("v15 up: %v", err)
	}

	type credentialFixture struct {
		locator []byte
		secret  []byte
	}
	issue := func(sensorID, tokenID string, seed byte) credentialFixture {
		t.Helper()
		locator := bytes.Repeat([]byte{seed}, 16)
		secret := bytes.Repeat([]byte{seed + 1}, 32)
		salt := bytes.Repeat([]byte{seed + 2}, 32)
		credential, err := sensor.NewTokenCredential(locator, secret)
		if err != nil {
			t.Fatal(err)
		}
		defer credential.Destroy()
		locatorDigest, _ := credential.LocatorDigest()
		tokenHash, _ := credential.Hash(sensor.SensorTokenAudienceEventIngest, mustProductID(t, tokenID), 1, salt)
		var issued json.RawMessage
		if err := connection.QueryRow(ctx, `SELECT zasp_runtime_issue_sensor_token((SELECT organization_id FROM zasp_sensors WHERE id=$1),(SELECT workspace_id FROM zasp_sensors WHERE id=$1),(SELECT environment_id FROM zasp_sensors WHERE id=$1),$1,$2,1,1,$3,$4,$5,transaction_timestamp()+interval '1 day')`, sensorID, tokenID, locatorDigest[:], salt, tokenHash[:]).Scan(&issued); err != nil {
			t.Fatalf("issue token %s: %v", tokenID, err)
		}
		return credentialFixture{locator: locator, secret: secret}
	}
	firstCredential := issue(firstSensor, "pid_77100021-0000-4000-8000-000000000021", 0x31)
	secondCredential := issue(secondSensor, "pid_77100022-0000-4000-8000-000000000022", 0x41)
	if err := runner.UpProductionRuntimeGatewayReconciliation(ctx); err != nil {
		t.Fatalf("v16 up: %v", err)
	}
	if err := runner.UpProductionRuntimeIngestReconciliation(ctx); err != nil {
		t.Fatalf("v17 up: %v", err)
	}
	metadata := migrations.ProductionRuntimeIngestReconciliation()
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_runtime_ingest_reconciliation_readiness($1,$2)`, metadata.Checksum(), migrations.ProductionRuntimeIngestReconciliationSemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatalf("v17 readiness=%t err=%v", ready, err)
	}

	loginNames := []string{"v17_api_login", "v17_discovery_login", "v17_ingest_login", "v17_runtime_login", "v17_outbox_login", "v17_gateway_login"}
	for _, principal := range loginNames {
		if _, err := connection.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`, principal)); err != nil {
			t.Fatal(err)
		}
	}
	var migrationPrincipal string
	if err := connection.QueryRow(ctx, `SELECT session_user`).Scan(&migrationPrincipal); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `SELECT zasp_discovery_register_principals($1,$2,$3,$4,$5,$6,$7)`, migrationPrincipal, loginNames[0], loginNames[1], loginNames[2], loginNames[3], loginNames[4], loginNames[5]); err != nil {
		t.Fatalf("register principals: %v", err)
	}
	ingest := connectRuntimeDataPlanePrincipal(t, ctx, dsn, loginNames[2])
	defer ingest.Close(context.Background())

	contentDigest := sha256.Sum256([]byte("v17-rate-limit"))
	reserve := `SELECT zasp_runtime_reserve_batch_v17($1,$2,'event-ingest',$3,$4,$5,'tetragon','application/json','runtime-event-v1',1,1000)`
	legacyReserve := `SELECT zasp_runtime_reserve_batch($1,$2,'event-ingest',$3,$4,$5,'tetragon','application/json','runtime-event-v1',1,1000)`
	var firstReservation json.RawMessage
	for index := 1; index <= 599; index++ {
		batchID := fmt.Sprintf("pid_77200000-0000-4000-8000-%012d", index)
		idempotency := fmt.Sprintf("v17-rate-limit-%04d", index)
		var result json.RawMessage
		statement := reserve
		if index == 1 {
			statement = legacyReserve
		}
		if err := ingest.QueryRow(ctx, statement, firstCredential.locator, firstCredential.secret, batchID, idempotency, contentDigest[:]).Scan(&result); err != nil {
			t.Fatalf("reserve %d: %v", index, err)
		}
		if index == 1 {
			firstReservation = append(json.RawMessage(nil), result...)
		}
	}
	type reservationResult struct {
		payload json.RawMessage
		err     error
	}
	reservationResults := make(chan reservationResult, 2)
	for index := 600; index <= 601; index++ {
		go func(index int) {
			configuration, connectErr := pgx.ParseConfig(dsn)
			if connectErr == nil {
				configuration.User = loginNames[2]
			}
			var workerConnection *pgx.Conn
			if connectErr == nil {
				workerConnection, connectErr = pgx.ConnectConfig(ctx, configuration)
			}
			if connectErr != nil {
				reservationResults <- reservationResult{err: connectErr}
				return
			}
			defer workerConnection.Close(context.Background())
			batchID := fmt.Sprintf("pid_77200000-0000-4000-8000-%012d", index)
			idempotency := fmt.Sprintf("v17-rate-limit-%04d", index)
			var payload json.RawMessage
			queryErr := workerConnection.QueryRow(ctx, reserve, firstCredential.locator, firstCredential.secret, batchID, idempotency, contentDigest[:]).Scan(&payload)
			reservationResults <- reservationResult{payload: payload, err: queryErr}
		}(index)
	}
	reservationLeft, reservationRight := <-reservationResults, <-reservationResults
	successes, rateLimits := 0, 0
	for _, result := range []reservationResult{reservationLeft, reservationRight} {
		var concurrentPostgresError *pgconn.PgError
		switch {
		case result.err == nil:
			successes++
		case errors.As(result.err, &concurrentPostgresError) && concurrentPostgresError.Code == "53300" && concurrentPostgresError.Message == "runtime batch rate limited":
			rateLimits++
		default:
			t.Fatalf("concurrent reservation result=%#v", result)
		}
	}
	if successes != 1 || rateLimits != 1 {
		t.Fatalf("concurrent rate boundary successes=%d rate_limits=%d left=%#v right=%#v", successes, rateLimits, reservationLeft, reservationRight)
	}
	var rejected json.RawMessage
	err = ingest.QueryRow(ctx, reserve, firstCredential.locator, firstCredential.secret, "pid_77200000-0000-4000-8000-000000000602", "v17-rate-limit-0602", contentDigest[:]).Scan(&rejected)
	var postgresError *pgconn.PgError
	if err == nil || !errors.As(err, &postgresError) || postgresError.Code != "53300" || postgresError.Message != "runtime batch rate limited" {
		t.Fatalf("rate rejection=%v pg=%#v", err, postgresError)
	}
	var replay json.RawMessage
	if err := ingest.QueryRow(ctx, reserve, firstCredential.locator, firstCredential.secret, "pid_77200000-0000-4000-8000-000000000001", "v17-rate-limit-0001", contentDigest[:]).Scan(&replay); err != nil || !bytes.Contains(replay, []byte(`"replayed": true`)) && !bytes.Contains(replay, []byte(`"replayed":true`)) {
		t.Fatalf("quota replay=%s original=%s err=%v", replay, firstReservation, err)
	}
	var otherTenant json.RawMessage
	if err := ingest.QueryRow(ctx, reserve, secondCredential.locator, secondCredential.secret, "pid_77300000-0000-4000-8000-000000000001", "v17-other-tenant-0001", contentDigest[:]).Scan(&otherTenant); err != nil {
		t.Fatalf("other tenant reserve: %v", err)
	}

	if _, err := connection.Exec(ctx, `UPDATE zasp_runtime_ingest_reconciliation_work SET available_at=transaction_timestamp()`); err != nil {
		t.Fatal(err)
	}
	type claimResult struct {
		worker string
		token  string
		items  []struct {
			OrganizationID string `json:"organization_id"`
			WorkspaceID    string `json:"workspace_id"`
			EnvironmentID  string `json:"environment_id"`
			BatchID        string `json:"batch_id"`
			Generation     int64  `json:"generation"`
			ArtifactKey    string `json:"artifact_key"`
			ContentDigest  string `json:"content_digest"`
		}
		err error
	}
	claims := make(chan claimResult, 2)
	for index := 1; index <= 2; index++ {
		go func(index int) {
			configuration, connectErr := pgx.ParseConfig(dsn)
			if connectErr == nil {
				configuration.User = loginNames[2]
			}
			var workerConnection *pgx.Conn
			if connectErr == nil {
				workerConnection, connectErr = pgx.ConnectConfig(ctx, configuration)
			}
			if connectErr != nil {
				claims <- claimResult{err: connectErr}
				return
			}
			defer workerConnection.Close(context.Background())
			var raw json.RawMessage
			worker := fmt.Sprintf("reconciler-%d", index)
			lease := fmt.Sprintf("v17-reconciliation-lease-%04d", index)
			queryErr := workerConnection.QueryRow(ctx, `SELECT zasp_runtime_claim_reconciliation($1,$2,60,1)`, worker, lease).Scan(&raw)
			result := claimResult{worker: worker, token: lease, err: queryErr}
			if queryErr == nil {
				result.err = json.Unmarshal(raw, &result.items)
			}
			claims <- result
		}(index)
	}
	left, right := <-claims, <-claims
	if left.err != nil || right.err != nil || len(left.items) != 1 || len(right.items) != 1 || left.items[0].BatchID == right.items[0].BatchID {
		t.Fatalf("concurrent claims left=%#v right=%#v", left, right)
	}
	var quarantined json.RawMessage
	if err := ingest.QueryRow(ctx, `SELECT zasp_runtime_quarantine_reconciliation($1,$2,$3,$4,$5,$6,$7)`, left.items[0].OrganizationID, left.items[0].WorkspaceID, left.items[0].EnvironmentID, left.items[0].BatchID, left.items[0].Generation, left.worker, left.token).Scan(&quarantined); err != nil || !bytes.Contains(quarantined, []byte(`"state": "quarantined"`)) && !bytes.Contains(quarantined, []byte(`"state":"quarantined"`)) {
		t.Fatalf("quarantine=%s err=%v", quarantined, err)
	}
	finishDigest, err := hex.DecodeString(right.items[0].ContentDigest)
	if err != nil {
		t.Fatal(err)
	}
	finishJob := "pid_77400001-0000-4000-8000-000000000001"
	finishOutbox := "pid_77400002-0000-4000-8000-000000000002"
	finishReference := "s3://zasp-runtime/" + right.items[0].ArtifactKey
	finishSQL := `SELECT zasp_runtime_finish_reconciliation($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'version-v17-reconciled',$12,1,$13)`
	finishArguments := []any{right.items[0].OrganizationID, right.items[0].WorkspaceID, right.items[0].EnvironmentID, right.items[0].BatchID, right.items[0].Generation, right.worker, right.token, finishJob, finishOutbox, finishReference, right.items[0].ArtifactKey, finishDigest, "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"}
	var finished json.RawMessage
	if err := ingest.QueryRow(ctx, finishSQL, finishArguments...).Scan(&finished); err != nil || !bytes.Contains(finished, []byte(`"state": "queued"`)) && !bytes.Contains(finished, []byte(`"state":"queued"`)) {
		t.Fatalf("finish=%s err=%v", finished, err)
	}
	if err := ingest.QueryRow(ctx, finishSQL, finishArguments...).Scan(&finished); err != nil || !bytes.Contains(finished, []byte(`"replayed": true`)) && !bytes.Contains(finished, []byte(`"replayed":true`)) {
		t.Fatalf("finish replay=%s err=%v", finished, err)
	}
	var quarantinedState, finishedState string
	var finishedStages, finishedOutboxRows int
	if err := connection.QueryRow(ctx, `SELECT (SELECT state FROM zasp_runtime_batch_authorities WHERE batch_id=$1),(SELECT state FROM zasp_runtime_batch_authorities WHERE batch_id=$2),(SELECT count(*) FROM zasp_runtime_stage_work WHERE batch_id=$2),(SELECT count(*) FROM zasp_discovery_outbox WHERE id=$3)`, left.items[0].BatchID, right.items[0].BatchID, finishOutbox).Scan(&quarantinedState, &finishedState, &finishedStages, &finishedOutboxRows); err != nil || quarantinedState != "quarantined" || finishedState != "queued" || finishedStages != 5 || finishedOutboxRows != 1 {
		t.Fatalf("terminal states quarantine=%q finish=%q stages=%d outbox=%d err=%v", quarantinedState, finishedState, finishedStages, finishedOutboxRows, err)
	}
	if err := runner.DownProductionRuntimeIngestReconciliation(ctx); !errors.Is(err, migrations.ErrInvalidState) {
		t.Fatalf("used v17 rollback error=%v", err)
	}
	if _, err := connection.Exec(ctx, `GRANT EXECUTE ON FUNCTION zasp_runtime_claim_reconciliation(text,text,integer,integer) TO zasp_runtime_worker`); err != nil {
		t.Fatal(err)
	}
	ready = true
	if err := connection.QueryRow(ctx, `SELECT zasp_runtime_ingest_reconciliation_readiness($1,$2)`, metadata.Checksum(), migrations.ProductionRuntimeIngestReconciliationSemanticFingerprint()).Scan(&ready); err != nil || ready {
		t.Fatalf("v17 ACL drift readiness=%t err=%v", ready, err)
	}
}
