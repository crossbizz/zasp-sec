package runtimeevent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func preciseCandidateRepositoryFixture(t *testing.T) (StageLease, []byte, []byte, []byte) {
	t.Helper()
	lease, oldReceipt, _, oldBody := candidateRepositoryFixture(t)
	input, authority, now := preciseArchiveFixture(t, true)
	_, archive, err := decodePreciseProductionInput(input, authority, now)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := DecodeStageReceipt(oldReceipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.ImplementationVersion = "runtime-index-v2"
	receipt.ArchiveDigest = sha256.Sum256(archive)
	receipt.InputDigest = receipt.ArchiveDigest
	encoded, _, _, err := EncodeStageReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	lease.ImplementationVersion = "runtime-correlation-v4"
	var body map[string]any
	if err := json.Unmarshal(oldBody, &body); err != nil {
		t.Fatal(err)
	}
	body["schema"] = "runtime-candidate-snapshot-v3"
	body["archive_digest"] = hex.EncodeToString(receipt.ArchiveDigest[:])
	body["index_receipt_digest"] = hex.EncodeToString(sha256Bytes(encoded))
	candidate := body["candidates"].([]any)[0].(map[string]any)
	candidate["sandbox_id"] = "sandbox-observed"
	candidate["event_time"] = now.Add(5 * time.Minute).Format(timestampLayout)
	output, err := json.MarshalIndent(body, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	return lease, encoded, archive, output
}

func TestPreciseCandidateRepositoryBindsSnapshotAndCopies(t *testing.T) {
	lease, receipt, archive, body := preciseCandidateRepositoryFixture(t)
	database := &productionIngestDatabaseStub{responses: []json.RawMessage{candidateEnvelope(t, body)}}
	repository, _ := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityCorrelation)
	snapshot, err := repository.FreezePreciseCandidates(context.Background(), lease, "candidate-worker", strings.Repeat("a", 32), receipt, archive)
	if err != nil {
		t.Fatal("precise snapshot rejected", err)
	}
	if !snapshot.ValidFor(lease.Scope, lease.BatchID, lease.Generation, sha256.Sum256(archive)) || snapshot.Digest() != sha256.Sum256(body) || !bytes.Equal(snapshot.Bytes(), body) || len(snapshot.Candidates()) != 1 || snapshot.Candidates()[0].SandboxID != "sandbox-observed" {
		t.Fatal("snapshot binding lost")
	}
	if database.calls != 1 || database.statements[0] != `SELECT zasp_runtime_freeze_precise_candidates($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)` {
		t.Fatal("wrong SQL route")
	}
	if !reflect.DeepEqual(database.arguments[0], []any{lease.Scope.OrganizationID().String(), lease.Scope.WorkspaceID().String(), lease.Scope.EnvironmentID().String(), lease.BatchID.String(), lease.Generation, "candidate-worker", strings.Repeat("a", 32), lease.Attempt, lease.ImplementationVersion, lease.InputDigest[:], receipt, archive}) {
		t.Fatal("SQL execution binding changed")
	}
	copyBody, copyCandidates := snapshot.Bytes(), snapshot.Candidates()
	copyBody[0] = '!'
	copyCandidates[0].EventOrdinal = 0
	if !bytes.Equal(snapshot.Bytes(), body) || snapshot.Candidates()[0].EventOrdinal != 1 {
		t.Fatal("caller changed sealed snapshot")
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil || string(encoded) != "{}" || fmt.Sprintf("%#v", snapshot) != "runtime-precise-candidate-snapshot[private]" {
		t.Fatal("snapshot leaked private state")
	}
	if _, err := repository.FreezeCandidates(context.Background(), lease, "candidate-worker", strings.Repeat("a", 32), receipt, archive); err == nil || database.calls != 1 {
		t.Fatal("legacy method accepted precise data")
	}
}

func TestPreciseCandidateRepositorySanitizesProviderErrors(t *testing.T) {
	for _, test := range []struct {
		name           string
		provider, want error
	}{
		{"overflow", &pgconn.PgError{Code: "54000", Message: "private-provider-data"}, ErrCandidateSnapshotOverflow},
		{"denied", &pgconn.PgError{Code: "42501", Message: "private-provider-data"}, ErrCandidateSnapshotDenied},
		{"expired", &pgconn.PgError{Code: "P0002", Message: "private-provider-data"}, ErrProductionPipelineUnavailable},
		{"unknown", errors.New("private-provider-data"), ErrProductionPipelineUnavailable},
		{"panic", nil, ErrProductionPipelineUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			lease, receipt, archive, _ := preciseCandidateRepositoryFixture(t)
			database := candidateDatabaseFunc(func(context.Context, string, ...any) (json.RawMessage, error) {
				if test.name == "panic" {
					panic("private-provider-data")
				}
				return nil, test.provider
			})
			repository, _ := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityCorrelation)
			_, err := repository.FreezePreciseCandidates(context.Background(), lease, "candidate-worker", strings.Repeat("a", 32), receipt, archive)
			if !errors.Is(err, test.want) || strings.Contains(fmt.Sprint(err), "private-provider-data") {
				t.Fatal("provider error escaped classification", err)
			}
		})
	}
}

func TestPreciseCandidateRepositoryRetainsHistoricalUnknownSandbox(t *testing.T) {
	lease, receipt, archive, body := preciseCandidateRepositoryFixture(t)
	body = bytes.Replace(body, []byte(`"sandbox_id": "sandbox-observed"`), []byte(`"sandbox_id": null`), 1)
	envelope := bytes.Replace(candidateEnvelope(t, body), []byte(`"replayed":false`), []byte(`"replayed":true`), 1)
	database := &productionIngestDatabaseStub{responses: []json.RawMessage{envelope}}
	repository, _ := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityCorrelation)
	snapshot, err := repository.FreezePreciseCandidates(context.Background(), lease, "candidate-worker", strings.Repeat("a", 32), receipt, archive)
	if err != nil || !snapshot.Replayed() || len(snapshot.Candidates()) != 1 || snapshot.Candidates()[0].SandboxObserved || snapshot.Candidates()[0].SandboxID != "" {
		t.Fatal("historical unknown became observed", err)
	}
}

func TestPreciseCandidateRepositoryRejectsSnapshotMismatch(t *testing.T) {
	for _, name := range []string{"legacy-schema", "wrong-scope", "wrong-source", "wrong-digest", "before-exact-window", "own-batch", "duplicate", "unknown-field"} {
		t.Run(name, func(t *testing.T) {
			lease, receipt, archive, body := preciseCandidateRepositoryFixture(t)
			var raw map[string]any
			if err := json.Unmarshal(body, &raw); err != nil {
				t.Fatal(err)
			}
			candidate := raw["candidates"].([]any)[0].(map[string]any)
			switch name {
			case "legacy-schema":
				raw["schema"] = "runtime-candidate-snapshot-v2"
			case "wrong-scope":
				raw["organization_id"] = fixtureID(t, 900).String()
			case "wrong-source":
				raw["runtime_sensor_id"] = fixtureID(t, 901).String()
			case "wrong-digest":
				raw["archive_digest"] = strings.Repeat("a", 64)
			case "before-exact-window":
				candidate["event_time"] = "2026-08-20T11:55:00.123Z"
			case "own-batch":
				candidate["batch_id"] = lease.BatchID.String()
			case "duplicate":
				raw["candidates"] = []any{candidate, candidate}
			case "unknown-field":
				candidate["authority"] = "forged"
			}
			mutated, err := json.Marshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			database := &productionIngestDatabaseStub{responses: []json.RawMessage{candidateEnvelope(t, mutated)}}
			repository, _ := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityCorrelation)
			if _, err := repository.FreezePreciseCandidates(context.Background(), lease, "candidate-worker", strings.Repeat("a", 32), receipt, archive); err == nil {
				t.Fatal("invalid snapshot accepted")
			}
		})
	}
}

func TestPreciseCandidateRepositoryChecksAuthorityBeforeAndAfterProvider(t *testing.T) {
	for _, name := range []string{"version", "receipt", "archive", "expired", "canceled-after", "expired-after"} {
		t.Run(name, func(t *testing.T) {
			lease, receipt, archive, body := preciseCandidateRepositoryFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			now := time.Now().UTC()
			calls := 0
			database := candidateDatabaseFunc(func(context.Context, string, ...any) (json.RawMessage, error) {
				calls++
				if name == "canceled-after" {
					cancel()
				}
				if name == "expired-after" {
					now = lease.LeaseExpiresAt.Add(time.Second)
				}
				return candidateEnvelope(t, body), nil
			})
			repository, _ := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityCorrelation)
			repository.clock = func() time.Time { return now }
			switch name {
			case "version":
				lease.ImplementationVersion = "runtime-correlation-v3"
			case "receipt":
				receipt = bytes.Replace(receipt, []byte("runtime-index-v2"), []byte("runtime-index-v1"), 1)
			case "archive":
				archive = append(archive, ' ')
			case "expired":
				lease.LeaseExpiresAt = now.Add(-time.Second)
			}
			if _, err := repository.FreezePreciseCandidates(ctx, lease, "candidate-worker", strings.Repeat("a", 32), receipt, archive); err == nil {
				t.Fatal("invalid execution accepted")
			}
			expected := 0
			if strings.HasSuffix(name, "-after") {
				expected = 1
			}
			if calls != expected {
				t.Fatal("wrong provider boundary", calls)
			}
		})
	}
}
