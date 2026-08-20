package runtimeprojection

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
)

func TestProjectBuildsDeterministicSourceOwnedRiskEvidence(t *testing.T) {
	scope := projectionScope(t, 1)
	body := projectionBody()
	archiveDigest := sha256.Sum256(body)
	eventID := projectionEventID(t, scope, body)
	input := Batch{Scope: scope, BatchID: projectionID(t, 9), Generation: 2, ArchiveReference: "s3://zasp-evidence/runtime/v15/raw.json", ArchiveVersionID: "raw-version", ArchiveDigest: archiveDigest, Body: body, Correlations: []runtimecorrelation.Result{{EventID: eventID, SessionID: projectionID(t, 7), AgentID: projectionID(t, 6), Confidence: domain.EvidenceConfidenceExact}}}
	result, err := Project(input)
	if err != nil || result.BatchID != input.BatchID || result.Generation != 2 || result.ArchiveDigest != archiveDigest || result.ContentDigest == ([sha256.Size]byte{}) || len(result.Items) != 1 {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	item := result.Items[0]
	if item.ID == "" || item.EventID != eventID || item.Source != "tetragon" || item.EventClass != "file" || item.Action != "write" || item.Severity != "high" || item.Title != "Runtime file write" || item.AgentID != projectionID(t, 6) || item.SessionID != projectionID(t, 7) || item.Confidence != domain.EvidenceConfidenceExact || item.EvidenceID.IsZero() || item.ArchiveReference != input.ArchiveReference || item.ArchiveVersionID != input.ArchiveVersionID {
		t.Fatalf("item=%#v", item)
	}
	result.Items[0].Title = "mutated"
	again, err := Project(input)
	if err != nil || again.Items[0].Title != "Runtime file write" {
		t.Fatalf("mutable projection=%#v err=%v", again, err)
	}
}

func TestProjectRejectsCorrelationOmissionAndDrift(t *testing.T) {
	scope := projectionScope(t, 1)
	body := projectionBody()
	digest := sha256.Sum256(body)
	eventID := projectionEventID(t, scope, body)
	valid := Batch{Scope: scope, BatchID: projectionID(t, 9), Generation: 2, ArchiveReference: "s3://zasp-evidence/runtime/v15/raw.json", ArchiveVersionID: "raw-version", ArchiveDigest: digest, Body: body, Correlations: []runtimecorrelation.Result{{EventID: eventID, Confidence: domain.EvidenceConfidenceUnattributed}}}
	for _, test := range []struct {
		name   string
		mutate func(*Batch)
	}{
		{name: "missing correlation", mutate: func(value *Batch) { value.Correlations = nil }},
		{name: "foreign event", mutate: func(value *Batch) { value.Correlations[0].EventID = projectionID(t, 99) }},
		{name: "digest", mutate: func(value *Batch) { value.ArchiveDigest = sha256.Sum256([]byte("drift")) }},
		{name: "archive", mutate: func(value *Batch) { value.ArchiveReference = "https://untrusted.invalid/raw" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := valid
			input.Correlations = append([]runtimecorrelation.Result(nil), valid.Correlations...)
			test.mutate(&input)
			if result, err := Project(input); err != ErrInput || result.Items != nil {
				t.Fatalf("result=%#v err=%v", result, err)
			}
		})
	}
}

func TestProjectionReceiptRejectsRiskAndAuthorityTampering(t *testing.T) {
	scope := projectionScope(t, 1)
	body := projectionBody()
	digest := sha256.Sum256(body)
	eventID := projectionEventID(t, scope, body)
	projected, err := Project(Batch{Scope: scope, BatchID: projectionID(t, 9), Generation: 2, ArchiveReference: "s3://zasp-evidence/runtime/v15/raw.json", ArchiveVersionID: "raw-version", ArchiveDigest: digest, Body: body, Correlations: []runtimecorrelation.Result{{EventID: eventID, Confidence: domain.EvidenceConfidenceUnattributed}}})
	if err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{ImplementationVersion: "runtime-project-v1", Scope: scope, BatchID: projectionID(t, 9), Generation: 2, InputReference: "s3://zasp-evidence/correlation.json", InputVersionID: "correlation-version", InputDigest: sha256.Sum256([]byte("correlation")), ArchiveReference: "s3://zasp-evidence/runtime/v15/raw.json", ArchiveVersionID: "raw-version", ArchiveDigest: digest, EffectDigest: projected.ContentDigest, Items: projected.Items}
	encoded, objectDigest, reference, err := EncodeReceipt(receipt)
	if err != nil || objectDigest != sha256.Sum256(encoded) || reference.Validate() != nil {
		t.Fatalf("encoded=%s digest=%x reference=%s err=%v", encoded, objectDigest, reference.String(), err)
	}
	decoded, err := DecodeReceipt(encoded)
	if err != nil || decoded.EffectDigest != receipt.EffectDigest || len(decoded.Items) != 1 || decoded.Items[0] != receipt.Items[0] {
		t.Fatalf("decoded=%#v err=%v", decoded, err)
	}
	for _, hostile := range [][]byte{append(bytes.Clone(encoded), []byte(` {}`)...), bytes.Replace(encoded, []byte(`"severity":"high"`), []byte(`"severity":"critical"`), 1), bytes.Replace(encoded, []byte(`"generation":2`), []byte(`"generation":0`), 1)} {
		if decoded, err := DecodeReceipt(hostile); err != ErrInput || decoded.Items != nil {
			t.Fatalf("decoded=%#v err=%v body=%s", decoded, err, hostile)
		}
	}
}

func projectionBody() []byte {
	return []byte(`{"source":"tetragon","events":[{"event_id":"event-1","class":"file","action":"write","workload_id":"runtime-a","event_time":"2026-08-20T12:00:00.000Z","evidence_id":"pid_00000008-0000-4000-8000-000000000008","content":{"path_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}]}`)
}

func projectionEventID(t *testing.T, scope domain.Scope, body []byte) domain.ProductID {
	t.Helper()
	decoded, err := decodeBatch(scope, body)
	if err != nil {
		t.Fatal(err)
	}
	return decoded[0]
}

func projectionID(t *testing.T, value int) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(fmt.Sprintf("pid_%08d-0000-4000-8000-%012d", value, value))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func projectionScope(t *testing.T, value int) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(projectionID(t, value), projectionID(t, value+1), projectionID(t, value+2))
	if err != nil {
		t.Fatal(err)
	}
	return scope
}
