package runtimeevent

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

func TestProductionIngestEnrollmentConstraintBeforeBody(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	for _, name := range []string{"matching", "rotated generation", "different sensor", "same sensor other scope", "missing", "malformed", "uppercase", "duplicate", "case variant duplicate", "legacy header", "empty legacy header", "unsupported transport"} {
		t.Run(name, func(t *testing.T) {
			authority := IngestAuthority{Scope: fixtureScope(t, 70), SensorID: fixtureID(t, 73), TokenID: fixtureID(t, 74), TokenGeneration: 1, Source: "tetragon", Mode: "full"}
			expected, err := sensor.EnrollmentBinding(authority.Scope, authority.SensorID)
			if err != nil {
				t.Fatal(err)
			}
			body := &enrollmentReadObserver{Reader: bytes.NewReader(productionEventBody(now))}
			request := httptest.NewRequest(http.MethodPost, "/internal/v1/runtime/events", body)
			request.Header.Set("Authorization", "Bearer "+productionSensorToken(t))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Zasp-Runtime-Schema", "runtime-event-enrollment-v1")
			request.Header.Set("X-Zasp-Expected-Enrollment", expected)
			request.Header.Set("Idempotency-Key", "runtime-enrollment-binding-0001")
			want := http.StatusBadRequest
			wantAuth := 0
			switch name {
			case "matching":
				want, wantAuth = http.StatusAccepted, 1
			case "rotated generation":
				authority.TokenID, authority.TokenGeneration = fixtureID(t, 75), 2
				want, wantAuth = http.StatusAccepted, 1
			case "different sensor":
				authority.SensorID = fixtureID(t, 76)
				want, wantAuth = http.StatusForbidden, 1
			case "same sensor other scope":
				authority.Scope = fixtureScope(t, 80)
				want, wantAuth = http.StatusForbidden, 1
			case "missing":
				request.Header.Del("X-Zasp-Expected-Enrollment")
			case "malformed":
				request.Header.Set("X-Zasp-Expected-Enrollment", expected+" ")
			case "uppercase":
				request.Header.Set("X-Zasp-Expected-Enrollment", strings.ToUpper(expected))
			case "duplicate":
				request.Header.Add("X-Zasp-Expected-Enrollment", expected)
			case "case variant duplicate":
				request.Header["x-zasp-expected-enrollment"] = []string{expected}
			case "legacy header":
				request.Header.Set("X-Zasp-Runtime-Schema", "runtime-event-v1")
			case "empty legacy header":
				request.Header.Set("X-Zasp-Runtime-Schema", "runtime-event-v1")
				request.Header["X-Zasp-Expected-Enrollment"] = nil
			case "unsupported transport":
				request.Header.Set("X-Zasp-Runtime-Schema", "runtime-event-enrollment-v2")
			}
			repository := &productionIngestRepositoryStub{authority: authority}
			artifacts := &productionRawArtifactStub{}
			handler, err := NewProductionIngestHandler(ProductionIngestConfig{Repository: repository, Artifacts: artifacts, MaximumBytes: 1 << 20, Clock: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != want || repository.authenticateCalls != wantAuth {
				t.Fatalf("status=%d want=%d authentication=%d want=%d", response.Code, want, repository.authenticateCalls, wantAuth)
			}
			if want != http.StatusAccepted {
				if body.reads != 0 || repository.reserveCalls != 0 || repository.finalizeCalls != 0 || artifacts.putCalls != 0 {
					t.Fatal("rejected enrollment consumed body or produced effects")
				}
			} else if body.reads == 0 || repository.reserveCalls != 1 || repository.finalizeCalls != 1 || artifacts.putCalls != 1 || repository.reserved.SchemaVersion != "runtime-event-v1" || !bytes.Equal(artifacts.put.Body, productionEventBody(now)) {
				t.Fatal("matching enrollment changed the existing canonical archive contract")
			}
		})
	}
}

type enrollmentReadObserver struct {
	io.Reader
	reads int
}

func (reader *enrollmentReadObserver) Read(body []byte) (int, error) {
	reader.reads++
	return reader.Reader.Read(body)
}

func (*enrollmentReadObserver) Close() error { return nil }

func (*productionIngestRepositoryStub) LookupAcceptance(context.Context, *sensor.TokenCredential, IngestAcceptanceRequest) (IngestAcceptance, error) {
	return IngestAcceptance{}, nil
}
