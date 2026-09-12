package runtimeevent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

type preciseHTTPRepository struct {
	productionIngestRepositoryStub
	unready  bool
	lookups  int
	accepted bool
	lookup   IngestAcceptanceRequest
}

func (repository *preciseHTTPRepository) ReadyPrecision(context.Context) error {
	if repository.unready {
		return ErrProductionIngestUnavailable
	}
	return nil
}
func (repository *preciseHTTPRepository) LookupAcceptance(_ context.Context, _ *sensor.TokenCredential, request IngestAcceptanceRequest) (IngestAcceptance, error) {
	repository.lookups++
	repository.lookup = request
	if repository.accepted {
		return IngestAcceptance{Found: true, BatchID: request.BatchID, Generation: 1, State: "queued"}, nil
	}
	return IngestAcceptance{}, nil
}

func preciseHTTPRequest(t *testing.T, body []byte, authority IngestAuthority) *http.Request {
	t.Helper()
	binding, err := sensor.EnrollmentBinding(authority.Scope, authority.SensorID)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/runtime/events", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+productionSensorToken(t))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Zasp-Runtime-Schema", "runtime-event-enrollment-v2")
	request.Header.Set("X-Zasp-Expected-Enrollment", binding)
	request.Header.Set("Idempotency-Key", "runtime-v2:"+strings.Repeat("b", 64))
	return request
}

func TestPreciseHTTPArchivesEnrolledInputUnderAuthenticatedMode(t *testing.T) {
	for _, mode := range []string{"full", "metadata_only"} {
		body, authority, now := preciseArchiveFixture(t, true)
		authority.Mode = mode
		repository := &preciseHTTPRepository{productionIngestRepositoryStub: productionIngestRepositoryStub{authority: authority}}
		artifacts := &productionRawArtifactStub{}
		handler, err := NewPreciseProductionIngestHandler(ProductionIngestConfig{Repository: repository, Artifacts: artifacts, MaximumBytes: 1 << 20, Clock: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, preciseHTTPRequest(t, body, authority))
		if response.Code != http.StatusAccepted || repository.lookups != 1 || repository.reserveCalls != 1 || repository.finalizeCalls != 1 || artifacts.putCalls != 1 {
			t.Fatal("precise intake", mode, response.Code, repository.lookups, repository.reserveCalls, repository.finalizeCalls, artifacts.putCalls)
		}
		archived, err := DecodePreciseArchivedBatch(authority.Scope, artifacts.put.Body)
		if err != nil || len(archived.Records) != 1 || !archived.Records[0].ObservedLineage.Valid() {
			t.Fatal("precise archive binding", err)
		}
		if archived.Records[0].ObservedLineage.SourceEventTime != "2026-08-20T12:00:00.123999999Z" || archived.Records[0].ObservedLineage.ProcessStartTime != "2026-08-20T12:00:00.123456789Z" {
			t.Fatal("intake rounded source process times")
		}
		if mode == "metadata_only" && len(archived.Records[0].Content) != 0 {
			t.Fatal("collection mode ignored")
		}
		if repository.reserved.SchemaVersion != "runtime-event-v2" || repository.reserved.ContentDigest != sha256.Sum256(artifacts.put.Body) || repository.reserved.Scope != authority.Scope {
			t.Fatal("reservation lost schema/digest/tenant")
		}
		binding, _ := sensor.EnrollmentBinding(authority.Scope, authority.SensorID)
		if repository.lookup.SchemaVersion != "runtime-event-v2" || repository.lookup.Scope != authority.Scope || repository.lookup.ContentDigest != sha256.Sum256(artifacts.put.Body) || repository.lookup.EnrollmentBinding != binding || repository.lookup.BatchID != repository.finalized.BatchID || repository.lookup.JobID != repository.finalized.JobID || repository.lookup.OutboxID != repository.finalized.OutboxID || repository.lookup.JobID.IsZero() || repository.lookup.OutboxID.IsZero() {
			t.Fatal("acceptance lookup lost exact request binding")
		}
	}
}

func TestPreciseHTTPRejectsUnboundTransportBeforePersistence(t *testing.T) {
	for _, scenario := range []string{"missing enrollment", "wrong enrollment", "duplicate enrollment", "caller scope", "unready", "wrong source", "legacy handler", "legacy lineage"} {
		t.Run(scenario, func(t *testing.T) {
			body, authority, now := preciseArchiveFixture(t, true)
			if scenario == "legacy lineage" {
				body = bytes.Replace(body, []byte("kubernetes-container-v2"), []byte("kubernetes-container-v1"), 1)
			}
			if scenario == "wrong source" {
				body = bytes.Replace(body, []byte(`"source":"tetragon"`), []byte(`"source":"otlp"`), 1)
			}
			repository := &preciseHTTPRepository{productionIngestRepositoryStub: productionIngestRepositoryStub{authority: authority}, unready: scenario == "unready"}
			artifacts := &productionRawArtifactStub{}
			config := ProductionIngestConfig{Repository: repository, Artifacts: artifacts, MaximumBytes: 1 << 20, Clock: func() time.Time { return now }}
			handler, err := NewPreciseProductionIngestHandler(config)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "legacy handler" {
				handler, err = NewProductionIngestHandler(config)
				if err != nil {
					t.Fatal(err)
				}
			}
			request := preciseHTTPRequest(t, body, authority)
			switch scenario {
			case "missing enrollment":
				request.Header.Del("X-Zasp-Expected-Enrollment")
			case "wrong enrollment":
				request.Header.Set("X-Zasp-Expected-Enrollment", strings.Repeat("a", 64))
			case "duplicate enrollment":
				request.Header.Add("X-Zasp-Expected-Enrollment", request.Header.Get("X-Zasp-Expected-Enrollment"))
			case "caller scope":
				request.Header.Set("X-Zasp-Workspace", authority.Scope.WorkspaceID().String())
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			want := http.StatusBadRequest
			if scenario == "wrong enrollment" {
				want = http.StatusForbidden
			}
			if scenario == "unready" {
				want = http.StatusServiceUnavailable
			}
			if response.Code != want || repository.lookups != 0 || repository.reserveCalls != 0 || repository.finalizeCalls != 0 || artifacts.putCalls != 0 {
				t.Fatal("unbound intake persisted", response.Code, repository.lookups, repository.reserveCalls, repository.finalizeCalls, artifacts.putCalls)
			}
			if scenario == "unready" && repository.authenticateCalls != 0 {
				t.Fatal("unready precision intake authenticated")
			}
		})
	}
}

func TestPreciseHTTPAllowsUnqualifiedRecordsWithoutInventingLineage(t *testing.T) {
	body, authority, now := preciseArchiveFixture(t, false)
	repository := &preciseHTTPRepository{productionIngestRepositoryStub: productionIngestRepositoryStub{authority: authority}}
	artifacts := &productionRawArtifactStub{}
	handler, err := NewPreciseProductionIngestHandler(ProductionIngestConfig{Repository: repository, Artifacts: artifacts, MaximumBytes: 1 << 20, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, preciseHTTPRequest(t, body, authority))
	if response.Code != http.StatusAccepted {
		t.Fatal("unqualified V2 record refused", response.Code)
	}
	archive, err := DecodePreciseArchivedBatch(authority.Scope, artifacts.put.Body)
	if err != nil || len(archive.Records) != 1 || archive.Records[0].ObservedLineage.Profile != "" || archive.Records[0].ObservedLineage.SourceEventTime != "" {
		t.Fatal("unqualified record invented identity", err)
	}
}

func TestPreciseHTTPAcceptedReplayDoesNotRewriteArtifact(t *testing.T) {
	body, authority, now := preciseArchiveFixture(t, true)
	repository := &preciseHTTPRepository{productionIngestRepositoryStub: productionIngestRepositoryStub{authority: authority}, accepted: true}
	artifacts := &productionRawArtifactStub{}
	handler, err := NewPreciseProductionIngestHandler(ProductionIngestConfig{Repository: repository, Artifacts: artifacts, MaximumBytes: 1 << 20, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, preciseHTTPRequest(t, body, authority))
	if response.Code != http.StatusAccepted || repository.lookups != 1 || repository.reserveCalls != 0 || repository.finalizeCalls != 0 || artifacts.putCalls != 0 {
		t.Fatal("accepted replay repeated effects", response.Code)
	}
	_, archive, err := decodePreciseProductionInput(body, authority, now)
	if err != nil {
		t.Fatal(err)
	}
	binding, _ := sensor.EnrollmentBinding(authority.Scope, authority.SensorID)
	if repository.lookup.SchemaVersion != "runtime-event-v2" || repository.lookup.Scope != authority.Scope || repository.lookup.ContentDigest != sha256.Sum256(archive) || repository.lookup.EnrollmentBinding != binding || repository.lookup.JobID.IsZero() || repository.lookup.OutboxID.IsZero() {
		t.Fatal("accepted replay lookup lost request binding")
	}
}

type precisionReadyOnlyRepository struct{ ProductionIngestRepository }

func (*precisionReadyOnlyRepository) ReadyPrecision(context.Context) error { return nil }

type precisionAcceptanceOnlyRepository struct{ productionIngestRepositoryStub }

func (*precisionAcceptanceOnlyRepository) LookupAcceptance(context.Context, *sensor.TokenCredential, IngestAcceptanceRequest) (IngestAcceptance, error) {
	return IngestAcceptance{}, nil
}

func TestPreciseHTTPConstructorRequiresBothCapabilities(t *testing.T) {
	for _, repository := range []ProductionIngestRepository{&productionIngestRepositoryStub{}, &precisionReadyOnlyRepository{}, &precisionAcceptanceOnlyRepository{}} {
		if handler, err := NewPreciseProductionIngestHandler(ProductionIngestConfig{Repository: repository, Artifacts: &productionRawArtifactStub{}, MaximumBytes: 1 << 20, Clock: func() time.Time { return time.Now().UTC() }}); err == nil || handler != nil {
			t.Fatal("incomplete precision authority accepted")
		}
	}
}
