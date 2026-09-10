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

func TestProductionCandidateRepositoryBindsExactBytesAndProtectsFrozenSnapshot(t *testing.T) {
	lease, receipt, archive, snapshotBody := candidateRepositoryFixture(t)
	database := &productionIngestDatabaseStub{responses: []json.RawMessage{candidateEnvelope(t, snapshotBody)}}
	repository, err := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityCorrelation)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("a", 32)
	snapshot, err := repository.FreezeCandidates(context.Background(), lease, "candidate-worker-01", token, receipt, archive)
	if err != nil {
		t.Fatal(err)
	}
	if database.calls != 1 || database.statements[0] != productionCandidateFreezeSQL || !reflect.DeepEqual(database.arguments[0], []any{lease.Scope.OrganizationID().String(), lease.Scope.WorkspaceID().String(), lease.Scope.EnvironmentID().String(), lease.BatchID.String(), lease.Generation, "candidate-worker-01", token, lease.Attempt, lease.ImplementationVersion, lease.InputDigest[:], receipt, archive}) {
		t.Fatal("freeze did not use the exact closed database call")
	}
	if !snapshot.ValidFor(lease.Scope, lease.BatchID, lease.Generation, sha256.Sum256(archive)) || snapshot.Digest() != sha256.Sum256(snapshotBody) || !bytes.Equal(snapshot.Bytes(), snapshotBody) || snapshot.Replayed() || len(snapshot.Candidates()) != 1 {
		t.Fatal("frozen snapshot binding or exact bytes were lost")
	}
	mutatedBody := snapshot.Bytes()
	mutatedBody[0] = '!'
	mutatedCandidates := snapshot.Candidates()
	mutatedCandidates[0].EventOrdinal = 0
	if !bytes.Equal(snapshot.Bytes(), snapshotBody) || snapshot.Candidates()[0].EventOrdinal != 1 {
		t.Fatal("caller mutated frozen state")
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil || string(encoded) != "{}" {
		t.Fatal("private snapshot unexpectedly serialized")
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if fmt.Sprintf(format, snapshot) != "runtime-candidate-snapshot[private]" || fmt.Sprintf(format, &snapshot) != "runtime-candidate-snapshot[private]" {
			t.Fatal("snapshot formatting exposed private state")
		}
	}
}

func TestProductionCandidateRepositoryRejectsInvalidAuthorityBeforeSQL(t *testing.T) {
	for _, name := range []string{"version", "expired", "attempt", "predecessor", "worker", "token", "receipt bytes", "archive bytes", "wrong stage", "wrong principal"} {
		t.Run(name, func(t *testing.T) {
			lease, receipt, archive, body := candidateRepositoryFixture(t)
			worker, token := "candidate-worker-01", strings.Repeat("a", 32)
			authority := ProductionPipelineAuthorityCorrelation
			switch name {
			case "version":
				lease.ImplementationVersion = "runtime-correlation-v1"
			case "expired":
				lease.LeaseExpiresAt = time.Now().UTC().Add(-time.Second)
			case "attempt":
				lease.Attempt = 101
			case "predecessor":
				lease.PredecessorDigest = nil
			case "worker":
				worker = "UPPERCASE"
			case "token":
				token = "short"
			case "receipt bytes":
				receipt = append(receipt, ' ')
			case "archive bytes":
				archive = append(archive, ' ')
			case "wrong stage":
				lease.Stage = RuntimeStageIndex
			case "wrong principal":
				authority = ProductionPipelineAuthorityIndex
			}
			database := &productionIngestDatabaseStub{responses: []json.RawMessage{candidateEnvelope(t, body)}}
			repository, _ := NewPostgresProductionPipelineRepository(database, authority)
			if _, err := repository.FreezeCandidates(context.Background(), lease, worker, token, receipt, archive); err == nil || database.calls != 0 {
				t.Fatal("invalid execution reached database")
			}
		})
	}
}

func TestProductionCandidateRepositoryUsesDedicatedBoundWithoutRelaxingSharedLimit(t *testing.T) {
	lease, receipt, archive, body := candidateRepositoryFixture(t)
	for _, size := range []int{maximumCandidateSnapshotBytes, maximumCandidateSnapshotBytes + 1} {
		padded := append(bytes.Clone(body), bytes.Repeat([]byte(" "), size-len(body))...)
		database := &productionIngestDatabaseStub{responses: []json.RawMessage{candidateEnvelope(t, padded)}}
		repository, _ := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityCorrelation)
		snapshot, err := repository.FreezeCandidates(context.Background(), lease, "candidate-worker-01", strings.Repeat("a", 32), receipt, archive)
		if size == maximumCandidateSnapshotBytes {
			if err != nil || !bytes.Equal(snapshot.Bytes(), padded) {
				t.Fatal("valid 1 MiB frozen bytes rejected", err)
			}
		} else if err == nil {
			t.Fatal("oversize frozen bytes accepted")
		}
	}
	var result map[string]any
	if strictProductionJSON(append(body, bytes.Repeat([]byte(" "), 16<<10)...), &result) == nil {
		t.Fatal("shared control response limit was relaxed")
	}
}

func TestProductionCandidateRepositorySanitizesFailuresAndUnknownOutcomes(t *testing.T) {
	lease, receipt, archive, _ := candidateRepositoryFixture(t)
	for _, scenario := range []struct {
		name    string
		failure error
		want    error
	}{
		{"overflow", &pgconn.PgError{Code: "54000", Message: "provider-secret"}, ErrCandidateSnapshotOverflow},
		{"denied", &pgconn.PgError{Code: "42501", Message: "provider-secret"}, ErrCandidateSnapshotDenied},
		{"lost outcome", errors.New("provider-secret"), ErrProductionPipelineUnavailable},
		{"lost lease", &pgconn.PgError{Code: "P0002", Message: "provider-secret"}, ErrProductionPipelineUnavailable},
		{"panic", nil, ErrProductionPipelineUnavailable},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			database := candidateDatabaseFunc(func(context.Context, string, ...any) (json.RawMessage, error) {
				if scenario.name == "panic" {
					panic("provider-secret")
				}
				return nil, scenario.failure
			})
			repository, _ := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityCorrelation)
			_, err := repository.FreezeCandidates(context.Background(), lease, "candidate-worker-01", strings.Repeat("a", 32), receipt, archive)
			if !errors.Is(err, scenario.want) || strings.Contains(fmt.Sprint(err), "provider-secret") {
				t.Fatal("database failure leaked or changed outcome classification")
			}
		})
	}
}

func TestProductionCandidateRepositoryRejectsCanceledOrExpiredResponse(t *testing.T) {
	for _, name := range []string{"canceled", "expired"} {
		t.Run(name, func(t *testing.T) {
			lease, receipt, archive, body := candidateRepositoryFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			now := time.Now().UTC()
			database := candidateDatabaseFunc(func(context.Context, string, ...any) (json.RawMessage, error) {
				if name == "canceled" {
					cancel()
				} else {
					now = lease.LeaseExpiresAt.Add(time.Second)
				}
				return candidateEnvelope(t, body), nil
			})
			repository, _ := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityCorrelation)
			repository.clock = func() time.Time { return now }
			snapshot, err := repository.FreezeCandidates(ctx, lease, "candidate-worker-01", strings.Repeat("a", 32), receipt, archive)
			if !errors.Is(err, ErrProductionPipelineUnavailable) || snapshot.ValidFor(lease.Scope, lease.BatchID, lease.Generation, sha256.Sum256(archive)) {
				t.Fatal("late response accepted as a current execution result", err)
			}
		})
	}
}

type candidateDatabaseFunc func(context.Context, string, ...any) (json.RawMessage, error)

func (function candidateDatabaseFunc) QueryJSON(ctx context.Context, statement string, arguments ...any) (json.RawMessage, error) {
	return function(ctx, statement, arguments...)
}

func TestProductionCandidateRepositoryRejectsHostileSnapshotEnvelopes(t *testing.T) {
	lease, receipt, archive, body := candidateRepositoryFixture(t)
	valid := candidateEnvelope(t, body)
	for name, payload := range map[string][]byte{
		"null": []byte("null"), "array": []byte("[]"), "unknown": bytes.Replace(valid, []byte("{"), []byte(`{"other":false,`), 1),
		"duplicate":    bytes.Replace(valid, []byte("{"), []byte(`{"replayed":false,`), 1),
		"case":         bytes.Replace(valid, []byte(`"snapshot"`), []byte(`"Snapshot"`), 1),
		"null replay":  bytes.Replace(valid, []byte(`"replayed":false`), []byte(`"replayed":null`), 1),
		"wrong digest": bytes.Replace(valid, []byte(hex.EncodeToString(sha256Bytes(body))), []byte(strings.Repeat("a", 64)), 1),
		"invalid utf8": append([]byte{0xff}, valid...),
		"oversize":     bytes.Repeat([]byte(" "), (2<<20)+1025),
	} {
		t.Run(name, func(t *testing.T) {
			database := &productionIngestDatabaseStub{responses: []json.RawMessage{payload}}
			repository, _ := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityCorrelation)
			if _, err := repository.FreezeCandidates(context.Background(), lease, "candidate-worker-01", strings.Repeat("a", 32), receipt, archive); err == nil {
				t.Fatal("hostile snapshot accepted")
			}
		})
	}
	for name, mutate := range map[string]func(map[string]any){
		"foreign scope":   func(value map[string]any) { value["workspace_id"] = fixtureID(t, 900).String() },
		"generation":      func(value map[string]any) { value["generation"] = 2 },
		"archive":         func(value map[string]any) { value["archive_digest"] = strings.Repeat("a", 64) },
		"receipt":         func(value map[string]any) { value["index_receipt_digest"] = strings.Repeat("a", 64) },
		"window":          func(value map[string]any) { value["window_seconds"] = 301 },
		"anchor":          func(value map[string]any) { value["runtime_sensor_id"] = nil },
		"null candidates": func(value map[string]any) { value["candidates"] = nil },
		"ordinal":         func(value map[string]any) { value["candidates"].([]any)[0].(map[string]any)["event_ordinal"] = 0 },
		"duplicate occurrence": func(value map[string]any) {
			values := value["candidates"].([]any)
			value["candidates"] = append(values, values[0])
		},
		"outside window": func(value map[string]any) {
			value["candidates"].([]any)[0].(map[string]any)["event_time"] = "2026-09-10T11:00:00.000Z"
		},
		"contradictory domain": func(value map[string]any) {
			value["candidates"].([]any)[0].(map[string]any)["observed_lineage"].(map[string]any)["node_uid"] = "12345678-1234-1234-1234-123456789099"
		},
	} {
		t.Run(name, func(t *testing.T) {
			var value map[string]any
			if json.Unmarshal(body, &value) != nil {
				t.Fatal("fixture invalid")
			}
			mutate(value)
			changed, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			database := &productionIngestDatabaseStub{responses: []json.RawMessage{candidateEnvelope(t, changed)}}
			repository, _ := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityCorrelation)
			if _, err := repository.FreezeCandidates(context.Background(), lease, "candidate-worker-01", strings.Repeat("a", 32), receipt, archive); err == nil {
				t.Fatal("unbound snapshot accepted")
			}
		})
	}
}

func candidateRepositoryFixture(t *testing.T) (StageLease, []byte, []byte, []byte) {
	t.Helper()
	scope := fixtureScope(t, 70)
	now := time.Date(2026, 9, 10, 10, 0, 0, 0, time.UTC)
	lineage := lineageObservationFixture()
	lineageBytes, err := json.Marshal(lineage)
	if err != nil {
		t.Fatal(err)
	}
	archive := bytes.Replace(productionEventBody(now), []byte(`"event_time":`), append(append([]byte(`"observed_lineage":`), lineageBytes...), []byte(`,"event_time":`)...), 1)
	if _, err := DecodeArchivedBatch(scope, archive); err != nil {
		t.Fatal(err)
	}
	archiveDigest := sha256.Sum256(archive)
	effectDigest := sha256.Sum256([]byte("candidate index effect"))
	batch := fixtureID(t, 801)
	receipt, _, _, err := EncodeStageReceipt(StageReceipt{Stage: RuntimeStageIndex, ImplementationVersion: "runtime-index-v1", Scope: scope, BatchID: batch, Generation: 1, InputReference: "s3://zasp-runtime/archive.json", InputVersionID: "archive-1", InputDigest: archiveDigest, ArchiveReference: "s3://zasp-runtime/archive.json", ArchiveVersionID: "archive-1", ArchiveDigest: archiveDigest, EffectDigest: effectDigest})
	if err != nil {
		t.Fatal(err)
	}
	lease := StageLease{Scope: scope, BatchID: batch, Generation: 1, Stage: RuntimeStageCorrelate, Attempt: 1, ImplementationVersion: "runtime-correlation-v2", PredecessorDigest: &effectDigest, InputDigest: effectDigest, InputReference: "s3://zasp-runtime/index.json", InputVersionID: "index-1", LeaseExpiresAt: time.Now().UTC().Add(time.Minute)}
	candidate := map[string]any{"batch_id": fixtureID(t, 802).String(), "generation": 1, "event_ordinal": 1, "source_sensor_id": fixtureID(t, 803).String(), "agent_id": fixtureID(t, 804).String(), "session_id": fixtureID(t, 805).String(), "archive_digest": strings.Repeat("b", 64), "index_receipt_digest": strings.Repeat("c", 64), "observed_lineage": lineage, "event_time": now.Format(timestampLayout)}
	value := map[string]any{"schema": "runtime-candidate-snapshot-v1", "organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "batch_id": batch.String(), "generation": 1, "source_sensor_id": fixtureID(t, 806).String(), "runtime_sensor_id": fixtureID(t, 806).String(), "archive_digest": hex.EncodeToString(archiveDigest[:]), "index_receipt_digest": hex.EncodeToString(sha256Bytes(receipt)), "window_seconds": 300, "candidates": []any{candidate}}
	// Preserve these exact non-Go-canonical bytes, as required for PostgreSQL jsonb.
	body, err := json.MarshalIndent(value, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	return lease, receipt, archive, body
}

func candidateEnvelope(t *testing.T, body []byte) []byte {
	t.Helper()
	value, err := json.Marshal(map[string]any{"snapshot": hex.EncodeToString(body), "sha256": hex.EncodeToString(sha256Bytes(body)), "replayed": false})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func sha256Bytes(body []byte) []byte { digest := sha256.Sum256(body); return digest[:] }
