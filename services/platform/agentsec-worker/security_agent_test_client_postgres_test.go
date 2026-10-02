package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"os"
	"strings"
	"testing"
	"time"
)

// Only the owned parent fixture supplies this DSN. No host database startup.
func TestExistingTestClientOwnedPostgres(t *testing.T) {
	dsn := os.Getenv("ZASP_RECONCILE_CLIENT_DSN")
	if dsn == "" {
		t.Skip("requires owned reconciliation fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.User = "security_agent_v33_worker_login"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var login string
	if err := pool.QueryRow(ctx, "SELECT session_user::text").Scan(&login); err != nil || login != "security_agent_v33_worker_login" {
		t.Fatalf("unexpected registered login: %q %v", login, err)
	}
	db, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: pool})
	if err != nil {
		t.Fatal(err)
	}
	o, _ := domain.ParseProductID(os.Getenv("ZASP_RECONCILE_ORG"))
	w, _ := domain.ParseProductID(os.Getenv("ZASP_RECONCILE_WORKSPACE"))
	e, _ := domain.ParseProductID(os.Getenv("ZASP_RECONCILE_ENVIRONMENT"))
	scope, err := domain.NewScope(o, w, e)
	if err != nil {
		t.Fatal(err)
	}
	var query existingTestQuery = db
	if os.Getenv("ZASP_RECONCILE_SETTLEMENT_FAILSTOP") == "true" {
		query = settlementExitAfterCommitQuery{db}
	}
	client, err := newExistingTestClient(query, "owned-reconcile-client", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("ZASP_RECONCILE_STOPPED_QUEUED") == "true" || os.Getenv("ZASP_RECONCILE_COMPOSE_STOPPED") == "true" {
		store, driver, _ := fixtureExistingTestEvidence(t)
		if err := client.ReconcileOne(ctx, scope, store); err != nil {
			t.Fatalf("stopped-parent reconciliation: %v", err)
		}
		if len(driver.reads) != 0 {
			t.Fatal("cancellation reconciliation read artifacts")
		}
		if err := client.ReconcileOne(ctx, scope, store); err != nil {
			t.Fatalf("settled cancellation repeat: %v", err)
		}
		if len(driver.reads) != 0 {
			t.Fatal("settled cancellation repeat read artifacts")
		}
		return
	}
	if os.Getenv("ZASP_RECONCILE_COMPOSE_ARTIFACTS") == "true" && os.Getenv("ZASP_RECONCILE_STATE") == "complete" {
		var files struct {
			Input, Output  []byte
			BaselineInput  []byte `json:"baseline_input"`
			BaselineOutput []byte `json:"baseline_output"`
			Mode           int
		}
		body, err := os.ReadFile(os.Getenv("ZASP_RECONCILE_ARTIFACT_FILE"))
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(body, &files); err != nil {
			t.Fatal(err)
		}
		var bundle existingTestEvidenceBundle
		if err = json.Unmarshal(files.Output, &bundle); err != nil || bundle.InputArtifact == nil {
			t.Fatalf("controlled bundle: %v", err)
		}
		driver := &existingTestEvidenceDriver{objects: map[artifactstore.DriverLocator]artifactstore.DriverObject{}}
		insert := func(receipt apiserver.RedTeamArtifactReference, bytes []byte) {
			t.Helper()
			locator, err := existingTestArtifactLocator(scope, receipt, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			key := strings.SplitN(strings.TrimPrefix(receipt.Reference, "s3://"), "/", 2)[1]
			l := artifactstore.DriverLocator{Scope: scope, Reference: locator.Reference, VersionID: receipt.VersionID, Key: key}
			driver.objects[l] = artifactstore.DriverObject{DriverLocator: l, MediaType: "application/json", Body: bytes, Size: int64(len(bytes)), SHA256: sha256.Sum256(bytes)}
		}
		insert(*bundle.InputArtifact, files.Input)
		digest := sha256.Sum256(files.Output)
		run := os.Getenv("ZASP_RECONCILE_TEST_RUN")
		insert(apiserver.RedTeamArtifactReference{Reference: "s3://zasp-evidence/organizations/" + o.String() + "/workspaces/" + w.String() + "/environments/" + e.String() + "/artifacts/" + run, VersionID: "controlled-output-version", SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(len(files.Output))}, files.Output)
		includeBaseline := os.Getenv("ZASP_RECONCILE_INCLUDE_BASELINE") == "true" && files.Mode == 3
		var beforeRun string
		if includeBaseline {
			var before existingTestEvidenceBundle
			if err := json.Unmarshal(files.BaselineOutput, &before); err != nil || before.InputArtifact == nil || before.Summary.Verdict != "fail" {
				t.Fatalf("saved failed bytes unavailable: %v", err)
			}
			beforeRun = before.Summary.RunID
			insert(*before.InputArtifact, files.BaselineInput)
			d := sha256.Sum256(files.BaselineOutput)
			insert(apiserver.RedTeamArtifactReference{Reference: "s3://zasp-evidence/organizations/" + o.String() + "/workspaces/" + w.String() + "/environments/" + e.String() + "/artifacts/" + beforeRun, VersionID: "controlled-output-version", SHA256: hex.EncodeToString(d[:]), SizeBytes: int64(len(files.BaselineOutput))}, files.BaselineOutput)
		}
		store, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 1 << 20})
		if err != nil {
			t.Fatal(err)
		}
		if err = client.ReconcileOne(ctx, scope, store); err != nil {
			t.Fatalf("registered artifact reconciliation: %v", err)
		}
		if files.Mode == 2 {
			if len(driver.reads) != 0 {
				t.Fatal("unknown execution read artifacts")
			}
		} else if includeBaseline {
			if len(driver.reads) != 4 || driver.reads[2].Reference.String() != "pid_99400101-0000-4000-8000-000000000004" || driver.reads[2].VersionID != "controlled-input-version" || driver.reads[3].Reference.String() != beforeRun || driver.reads[3].VersionID != "controlled-output-version" {
				t.Fatal("comparable baseline versions not read")
			}
		} else if files.Mode < 2 && len(driver.reads) != 2 || files.Mode == 3 && (len(driver.reads) != 3 || driver.reads[2].Reference.String() != "pid_99400101-0000-4000-8000-000000000004" || driver.reads[2].VersionID != "controlled-input-version") {
			t.Fatalf("artifact reads %d mode%d", len(driver.reads), files.Mode)
		}
		if claims, err := client.Claim(ctx, scope, 30, 1); err != nil || len(claims) != 0 {
			t.Fatalf("composed settled link reclaimed %d %v", len(claims), err)
		}
		return
	}
	claims, err := client.Claim(ctx, scope, 30, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("registered claim count%d error%v", len(claims), err)
	}
	claim := claims[0]
	if claim.run != os.Getenv("ZASP_RECONCILE_RUN") || claim.step != os.Getenv("ZASP_RECONCILE_STEP") {
		t.Fatal("client claimed wrong parent")
	}
	snapshot, err := client.Evidence(ctx, claim)
	state := os.Getenv("ZASP_RECONCILE_STATE")
	unknown := os.Getenv("ZASP_RECONCILE_UNKNOWN") == "true"
	if err != nil || snapshot.State != state || snapshot.OutcomeUnknown != unknown || state == "queued" && snapshot.After != nil || state == "complete" && (snapshot.After == nil || snapshot.After.Attempt != 3 || len(snapshot.After.Categories) != 3 || snapshot.After.Scope != scope || snapshot.After.RunID != claim.testRun) {
		t.Fatalf("registered evidence %#v %v", snapshot, err)
	}
	renewed, err := client.Heartbeat(ctx, claim, 60)
	if err != nil || !renewed.expires.After(claim.expires) {
		t.Fatalf("registered heartbeat %v", err)
	}
	if os.Getenv("ZASP_RECONCILE_CLIENT_SETTLE") == "true" && state == "complete" {
		// Deliberately unavailable storage: exercise the real fail-closed verifier
		// and registered settlement path, never assert remediation without bytes.
		proof := verifyExistingTestComparison(ctx, nil, snapshot.Before, *snapshot.After)
		if unknown {
			proof = existingTestVerification{SchemaVersion: "security-agent-test-verification-v1", Outcome: "inconclusive", Reason: "test_outcome_unknown"}
			body, _ := json.Marshal(proof)
			digest := sha256.Sum256(body)
			proof.Digest = hex.EncodeToString(digest[:])
		}
		request, err := client.PrepareSettlement(renewed, snapshot, proof)
		if err != nil {
			t.Fatalf("registered settlement preparation: %v", err)
		}
		receipt, err := client.Settle(ctx, request)
		if err != nil || receipt.State != "inconclusive" || receipt.StepState != "inconclusive" || receipt.Digest != proof.Digest {
			t.Fatalf("registered settlement: %#v %v", receipt, err)
		}
		replayed, err := client.Settle(ctx, request)
		if err != nil || replayed != receipt {
			t.Fatalf("registered exact replay: %#v %v", replayed, err)
		}
		if _, err := client.Evidence(ctx, renewed); err == nil {
			t.Fatal("settled claim still reads evidence")
		}
		if claims, err := client.Claim(ctx, scope, 30, 1); err != nil || len(claims) != 0 {
			t.Fatalf("settled link reclaimed: %d %v", len(claims), err)
		}
		return
	}
	if _, err := client.Release(ctx, renewed, 300); err != nil {
		t.Fatalf("registered release %v", err)
	}
	if _, err := client.Evidence(ctx, renewed); err == nil {
		t.Fatal("released lease still reads")
	}
	if claims, err := client.Claim(ctx, scope, 30, 1); err != nil || len(claims) != 0 {
		t.Fatalf("delayed link reclaimed %d %v", len(claims), err)
	}
}
