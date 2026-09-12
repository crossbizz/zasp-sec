package runtimeprojection

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"strings"
	"testing"
)

func preciseProjectionReceipt(t *testing.T) Receipt {
	t.Helper()
	input := preciseProjectionInput(t)
	result, err := ProjectPrecise(input)
	if err != nil {
		t.Fatal(err)
	}
	return projectionReceiptFixture(input, result, "runtime-projection-v3")
}

func TestPreciseProjectionReceiptRoundTripAndVersionFence(t *testing.T) {
	r := preciseProjectionReceipt(t)
	body, digest, ref, err := EncodePreciseReceipt(r)
	if err != nil || digest != sha256.Sum256(body) || !bytes.Contains(body, []byte(`"schema":"runtime-projection-receipt-v3"`)) {
		t.Fatal("precise receipt unavailable", err)
	}
	decoded, err := DecodePreciseReceipt(body)
	if err != nil || decoded.Items[0] != r.Items[0] || decoded.EffectDigest != r.EffectDigest {
		t.Fatal("precise receipt lost binding", err)
	}
	again, d2, ref2, err := EncodePreciseReceipt(decoded)
	if err != nil || !bytes.Equal(body, again) || d2 != digest || ref2 != ref {
		t.Fatal("unstable receipt", err)
	}
	if _, err := DecodeReceipt(body); err != ErrInput {
		t.Fatal("legacy reader consumed V3")
	}
	if _, _, _, err := EncodeReceipt(r); err != ErrInput {
		t.Fatal("legacy encoder consumed V3")
	}
	old := sandboxProjectionInput(t)
	projected, err := ProjectSandbox(old)
	if err != nil {
		t.Fatal(err)
	}
	legacy := projectionReceiptFixture(old, projected, "runtime-projection-v2")
	oldBody, _, _, err := EncodeReceipt(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePreciseReceipt(oldBody); err != ErrInput {
		t.Fatal("precise reader consumed legacy receipt")
	}
	if _, _, _, err := EncodePreciseReceipt(legacy); err != ErrInput {
		t.Fatal("precise encoder consumed legacy receipt")
	}
	for name, payload := range map[string][]byte{
		"schema":    bytes.Replace(body, []byte("receipt-v3"), []byte("receipt-v2"), 1),
		"version":   bytes.Replace(body, []byte("projection-v3"), []byte("projection-v2"), 1),
		"sandbox":   bytes.Replace(body, []byte("sandbox-a"), []byte("sandbox-b"), 1),
		"duplicate": bytes.Replace(body, []byte(`"generation":2`), []byte(`"generation":2,"generation":2`), 1),
		"alias":     bytes.Replace(body, []byte(`"generation"`), []byte(`"Generation"`), 1),
		"null":      bytes.Replace(body, []byte(`"sandbox_id":"sandbox-a"`), []byte(`"sandbox_id":null`), 1),
		"trailing":  append(bytes.Clone(body), ' '),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodePreciseReceipt(payload); err != ErrInput {
				t.Fatal("noncanonical or altered receipt accepted")
			}
		})
	}
}

func rehashPreciseProjectionReceipt(r *Receipt) {
	for i := range r.Items {
		item := &r.Items[i]
		base := sandboxRiskID(Batch{Scope: r.Scope, BatchID: r.BatchID, ArchiveDigest: r.ArchiveDigest}, item.EventID, runtimeCorrelation(*item))
		digest := sha256.Sum256([]byte("zasp.runtime-risk.v3\x00" + base))
		item.ID = "rsk_" + hex.EncodeToString(digest[:])
	}
	r.EffectDigest, _ = projectionDigestDomain(r.Scope, r.BatchID, r.Generation, r.ArchiveDigest, r.Items, "zasp.runtime-projection.batch.v3")
}

func TestPreciseProjectionReceiptRejectsRehashedInvalidItems(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		change func(*Receipt)
		accept bool
	}{
		{"exact", func(r *Receipt) { r.Items[0].Confidence = domain.EvidenceConfidenceExact }, false},
		{"semantic", func(r *Receipt) {
			r.Items[0].Source = "otlp"
			r.Items[0].EventClass = "tool"
			r.Items[0].Action = "invoke"
			r.Items[0].Title = "Agent tool invocation"
		}, false},
		{"missing source", func(r *Receipt) { r.Items[0].SandboxSourceSensorID = domain.ProductID{} }, false},
		{"unknown sandbox", func(r *Receipt) { r.Items[0].SandboxID = ""; r.Items[0].SandboxSourceSensorID = domain.ProductID{} }, true},
		{"display nanos", func(r *Receipt) { r.Items[0].EventTime = "2026-09-10T10:00:00.000000002Z" }, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			r := preciseProjectionReceipt(t)
			scenario.change(&r)
			rehashPreciseProjectionReceipt(&r)
			_, _, _, err := EncodePreciseReceipt(r)
			if (err == nil) != scenario.accept {
				t.Fatal("encoder validation mismatch", err)
			}
			wire := receiptToWire(r)
			wire.Schema = "runtime-projection-receipt-v3"
			body, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodePreciseReceipt(body); (err == nil) != scenario.accept {
				t.Fatal("direct wire validation mismatch", err)
			}
		})
	}
}

func TestPreciseProjectionReceiptRejectsSerializedOverflow(t *testing.T) {
	r := preciseProjectionReceipt(t)
	base := r.Items[0]
	r.ArchiveVersionID = strings.Repeat("<", 1024)
	r.Items = make([]Item, 1000)
	for i := range r.Items {
		r.Items[i] = base
		r.Items[i].EventID = projectionID(t, i+100)
		r.Items[i].ArchiveVersionID = r.ArchiveVersionID
	}
	rehashPreciseProjectionReceipt(&r)
	if !validItemsProfile(r, true) {
		t.Fatal("overflow fixture must have otherwise-valid items")
	}
	if body, _, _, err := EncodePreciseReceipt(r); err != ErrInput || len(body) != 0 {
		t.Fatal("oversized receipt emitted", len(body), err)
	}
}
