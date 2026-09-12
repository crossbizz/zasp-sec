package runtimecorrelation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"strings"
	"testing"
)

func TestPreciseReceiptEncoderRejectsUnreplayableSize(t *testing.T) {
	r := preciseReceiptFixture(t)
	base := r.Results[0]
	r.Results = make([]Result, 1000)
	for i := range r.Results {
		r.Results[i] = base
		r.Results[i].EventID = correlationID(t, i+100)
		r.Results[i].SandboxID = strings.Repeat("<", 256)
	}
	r.EffectDigest, _ = versionedFrozenCorrelationDigest("zasp.runtime-correlation.batch.v4", r.Scope, r.BatchID, r.Generation, r.ArchiveDigest, r.CandidateSnapshotDigest, r.Results)
	if !validSandboxResults(r.Results) {
		t.Fatal("fixture must have valid bindings")
	}
	if body, _, _, err := EncodePreciseReceipt(r); err != ErrInput || len(body) != 0 {
		t.Fatal("encoder emitted an unreplayable oversized receipt", len(body), err)
	}
}

func preciseReceiptFixture(t *testing.T) Receipt {
	t.Helper()
	input, snapshot := preciseCorrelationFixture(t, nil)
	result, err := CorrelatePreciseFrozen(input, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return Receipt{ImplementationVersion: "runtime-correlation-v4", Scope: input.Scope, BatchID: input.BatchID, Generation: input.Generation, InputReference: "s3://zasp-evidence/index.json", InputVersionID: "index-v2", InputDigest: sha256.Sum256([]byte("index effect")), ArchiveReference: "s3://zasp-evidence/raw.json", ArchiveVersionID: "raw-v2", ArchiveDigest: input.ArchiveDigest, EffectDigest: result.ContentDigest, CandidateSnapshotDigest: snapshot.Digest(), Results: result.Results}
}

func TestPreciseReceiptRoundTripAndClosedVersionBoundary(t *testing.T) {
	r := preciseReceiptFixture(t)
	body, digest, ref, err := EncodePreciseReceipt(r)
	if err != nil || digest != sha256.Sum256(body) || !bytes.Contains(body, []byte(`"schema":"runtime-correlation-receipt-v4"`)) {
		t.Fatal("precise receipt rejected", err)
	}
	decoded, err := DecodePreciseReceipt(body)
	if err != nil || decoded.Results[0] != r.Results[0] || decoded.CandidateSnapshotDigest != r.CandidateSnapshotDigest || decoded.EffectDigest != r.EffectDigest {
		t.Fatal("precise replay lost binding", err)
	}
	again, againDigest, againRef, err := EncodePreciseReceipt(decoded)
	if err != nil || !bytes.Equal(again, body) || againDigest != digest || againRef != ref {
		t.Fatal("non-deterministic receipt", err)
	}
	if _, err := DecodeReceipt(body); err != ErrInput {
		t.Fatal("legacy reader consumed V4")
	}
	if _, _, _, err := EncodeReceipt(r); err != ErrInput {
		t.Fatal("legacy encoder consumed V4")
	}
	old := sandboxReceiptFixture(t)
	oldBody, _, _, err := EncodeReceipt(old)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePreciseReceipt(oldBody); err != ErrInput {
		t.Fatal("precise reader consumed V3")
	}
	if _, _, _, err := EncodePreciseReceipt(old); err != ErrInput {
		t.Fatal("precise encoder consumed V3")
	}
	for name, payload := range map[string][]byte{
		"schema":         bytes.Replace(body, []byte("receipt-v4"), []byte("receipt-v3"), 1),
		"implementation": bytes.Replace(body, []byte("correlation-v4"), []byte("correlation-v3"), 1),
		"sandbox":        bytes.Replace(body, []byte("sandbox-a"), []byte("sandbox-b"), 1),
		"duplicate":      bytes.Replace(body, []byte(`"generation":2`), []byte(`"generation":2,"generation":2`), 1),
		"alias":          bytes.Replace(body, []byte(`"generation"`), []byte(`"Generation"`), 1),
		"unknown":        append(append([]byte(nil), body[:len(body)-1]...), []byte(`,"unknown":0}`)...),
		"trailing":       append(append([]byte(nil), body...), ' '),
		"oversize":       bytes.Repeat([]byte(" "), (1<<20)+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodePreciseReceipt(payload); err != ErrInput {
				t.Fatal("invalid receipt accepted")
			}
		})
	}
}

func TestPreciseReceiptRejectsForgedConfidenceAndDigest(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		mutate func(*Receipt)
		accept bool
	}{
		{"exact", func(r *Receipt) { r.Results[0].Confidence = domain.EvidenceConfidenceExact }, false},
		{"missing source", func(r *Receipt) { r.Results[0].SandboxSourceSensorID = domain.ProductID{} }, false},
		{"unknown sandbox", func(r *Receipt) { r.Results[0].SandboxID = ""; r.Results[0].SandboxSourceSensorID = domain.ProductID{} }, true},
		{"missing snapshot", func(r *Receipt) { r.CandidateSnapshotDigest = [sha256.Size]byte{} }, false},
		{"probable residual", func(r *Receipt) {
			r.Results[0].Confidence = domain.EvidenceConfidenceProbable
			r.Results[0].SessionID = domain.ProductID{}
			r.Results[0].AgentID = domain.ProductID{}
		}, false},
		{"probable cleared", func(r *Receipt) {
			id := r.Results[0].EventID
			r.Results[0] = Result{EventID: id, Confidence: domain.EvidenceConfidenceProbable}
		}, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			r := preciseReceiptFixture(t)
			scenario.mutate(&r)
			r.EffectDigest, _ = versionedFrozenCorrelationDigest("zasp.runtime-correlation.batch.v4", r.Scope, r.BatchID, r.Generation, r.ArchiveDigest, r.CandidateSnapshotDigest, r.Results)
			body, _, _, err := EncodePreciseReceipt(r)
			if (err == nil) != scenario.accept {
				t.Fatal("validation mismatch", err)
			}
			// Forge canonical wire bytes directly, bypassing encoder validation.
			wire := receiptToWire(r)
			wire.Schema = "runtime-correlation-receipt-v4"
			wire.CandidateSnapshotDigest = hex.EncodeToString(r.CandidateSnapshotDigest[:])
			forged, marshalErr := json.Marshal(wire)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if _, decodeErr := DecodePreciseReceipt(forged); (decodeErr == nil) != scenario.accept {
				t.Fatal("decoder accepted forged authority or rejected valid result", decodeErr)
			}
			if scenario.accept {
				if _, err := DecodePreciseReceipt(body); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	r := preciseReceiptFixture(t)
	r.EffectDigest, _ = sandboxCorrelationDigest(r.Scope, r.BatchID, r.Generation, r.ArchiveDigest, r.CandidateSnapshotDigest, r.Results)
	if _, _, _, err := EncodePreciseReceipt(r); err != ErrInput {
		t.Fatal("accepted V3 effect digest")
	}
	// The old arbitrary-version V1 fallback must not accept the new reserved V4.
	r.Results[0].SandboxID = ""
	r.Results[0].SandboxSourceSensorID = domain.ProductID{}
	r.CandidateSnapshotDigest = [sha256.Size]byte{}
	r.EffectDigest, _ = correlationDigest(r.Scope, r.BatchID, r.Generation, r.ArchiveDigest, r.Results)
	if _, _, _, err := EncodeReceipt(r); err != ErrInput {
		t.Fatal("V4 downgraded through legacy fallback")
	}
	wire := receiptToWire(r)
	body, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeReceipt(body); err != ErrInput {
		t.Fatal("V4 legacy wire downgrade accepted")
	}
}
