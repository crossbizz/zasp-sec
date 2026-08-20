package runtimecorrelation

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

func TestCorrelatorProducesDeterministicExactAndUnattributedResults(t *testing.T) {
	scope := correlationScope(t, 1)
	body := []byte(`{"source":"otlp","events":[{"event_id":"","class":"","action":"","workload_id":"","event_time":"2026-08-20T12:00:00.000Z","evidence_id":"pid_00000008-0000-4000-8000-000000000008","attributes":{"event.id":"event-1","event.class":"tool","event.action":"invoke","agent.id":"pid_00000006-0000-4000-8000-000000000006","session.id":"pid_00000007-0000-4000-8000-000000000007","task.id":"task-a","tool.id":"tool-a","sandbox.id":"sandbox-a","trace.id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","span.id":"bbbbbbbbbbbbbbbb"},"content":{}}]}`)
	digest := sha256.Sum256(body)
	input := Batch{Scope: scope, BatchID: correlationID(t, 9), Generation: 2, ArchiveDigest: digest, Body: body, Candidates: []runtimeevent.Candidate{{AgentID: correlationID(t, 6), SessionID: correlationID(t, 7), SandboxID: "sandbox-a"}}}
	result, err := Correlate(input)
	if err != nil || result.BatchID != input.BatchID || result.Generation != 2 || result.ArchiveDigest != digest || result.ContentDigest == ([sha256.Size]byte{}) || len(result.Results) != 1 || result.Results[0].Confidence != domain.EvidenceConfidenceExact || result.Results[0].AgentID != correlationID(t, 6) || result.Results[0].SessionID != correlationID(t, 7) {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	result.Results[0].AgentID = domain.ProductID{}
	again, err := Correlate(input)
	if err != nil || again.Results[0].AgentID != correlationID(t, 6) {
		t.Fatalf("mutable result=%#v err=%v", again, err)
	}

	input.Candidates = nil
	unattributed, err := Correlate(input)
	if err != nil || unattributed.Results[0].Confidence != domain.EvidenceConfidenceUnattributed || !unattributed.Results[0].AgentID.IsZero() || !unattributed.Results[0].SessionID.IsZero() || unattributed.ContentDigest == again.ContentDigest {
		t.Fatalf("unattributed=%#v err=%v", unattributed, err)
	}
}

func TestCorrelatorRejectsArchiveAndCandidateDrift(t *testing.T) {
	scope := correlationScope(t, 1)
	body := []byte(`{"source":"tetragon","events":[{"event_id":"event-1","class":"process","action":"exec","workload_id":"runtime-a","event_time":"2026-08-20T12:00:00.000Z","evidence_id":"pid_00000008-0000-4000-8000-000000000008","content":{}}]}`)
	digest := sha256.Sum256(body)
	valid := Batch{Scope: scope, BatchID: correlationID(t, 9), Generation: 2, ArchiveDigest: digest, Body: body}
	for _, test := range []struct {
		name   string
		mutate func(*Batch)
	}{
		{name: "scope", mutate: func(value *Batch) { value.Scope = domain.Scope{} }},
		{name: "batch", mutate: func(value *Batch) { value.BatchID = domain.ProductID{} }},
		{name: "generation", mutate: func(value *Batch) { value.Generation = 0 }},
		{name: "digest", mutate: func(value *Batch) { value.ArchiveDigest = sha256.Sum256([]byte("drift")) }},
		{name: "candidate", mutate: func(value *Batch) { value.Candidates = []runtimeevent.Candidate{{AgentID: correlationID(t, 6)}} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := valid
			test.mutate(&input)
			if result, err := Correlate(input); err != ErrInput || result.Results != nil {
				t.Fatalf("result=%#v err=%v", result, err)
			}
		})
	}
}

func TestCorrelationReceiptRoundTripsExactIndexAndArchiveAuthority(t *testing.T) {
	scope := correlationScope(t, 1)
	archiveDigest := sha256.Sum256([]byte("archive"))
	results := []Result{{EventID: correlationID(t, 5), SessionID: correlationID(t, 7), AgentID: correlationID(t, 6), Confidence: domain.EvidenceConfidenceExact}}
	effectDigest, err := correlationDigest(scope, correlationID(t, 9), 2, archiveDigest, results)
	if err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{ImplementationVersion: "runtime-correlation-v1", Scope: scope, BatchID: correlationID(t, 9), Generation: 2, InputReference: "s3://zasp-evidence/index-receipt.json", InputVersionID: "index-version", InputDigest: sha256.Sum256([]byte("index")), ArchiveReference: "s3://zasp-evidence/raw.json", ArchiveVersionID: "raw-version", ArchiveDigest: archiveDigest, EffectDigest: effectDigest, Results: results}
	body, objectDigest, reference, err := EncodeReceipt(receipt)
	if err != nil || objectDigest != sha256.Sum256(body) || reference.Validate() != nil {
		t.Fatalf("body=%s digest=%x reference=%s err=%v", body, objectDigest, reference.String(), err)
	}
	decoded, err := DecodeReceipt(body)
	if err != nil || decoded.ImplementationVersion != receipt.ImplementationVersion || decoded.Scope != scope || decoded.BatchID != receipt.BatchID || decoded.EffectDigest != effectDigest || len(decoded.Results) != 1 || decoded.Results[0] != results[0] {
		t.Fatalf("decoded=%#v err=%v", decoded, err)
	}
	for _, hostile := range [][]byte{append(bytes.Clone(body), []byte(` {}`)...), bytes.Replace(body, []byte(`"confidence":"exact"`), []byte(`"confidence":"unattributed"`), 1), bytes.Replace(body, []byte(`"generation":2`), []byte(`"generation":0`), 1)} {
		if decoded, err := DecodeReceipt(hostile); err != ErrInput || decoded.Results != nil {
			t.Fatalf("decoded=%#v err=%v body=%s", decoded, err, hostile)
		}
	}
}

func correlationID(t *testing.T, value int) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(fmt.Sprintf("pid_%08d-0000-4000-8000-%012d", value, value))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func correlationScope(t *testing.T, value int) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(correlationID(t, value), correlationID(t, value+1), correlationID(t, value+2))
	if err != nil {
		t.Fatal(err)
	}
	return scope
}
