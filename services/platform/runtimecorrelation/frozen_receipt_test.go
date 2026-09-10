package runtimecorrelation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestFrozenReceiptBindsSnapshotAndRejectsVersionConfusion(t *testing.T) {
	input, snapshot := frozenCorrelationFixture(t, "tetragon", nil)
	result, err := CorrelateFrozen(input, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{ImplementationVersion: "runtime-correlation-v2", Scope: input.Scope, BatchID: input.BatchID, Generation: input.Generation, InputReference: "s3://zasp-evidence/index.json", InputVersionID: "index-v1", InputDigest: sha256.Sum256([]byte("index effect")), ArchiveReference: "s3://zasp-evidence/raw.json", ArchiveVersionID: "raw-v1", ArchiveDigest: input.ArchiveDigest, EffectDigest: result.ContentDigest, CandidateSnapshotDigest: snapshot.Digest(), Results: result.Results}
	body, digest, reference, err := EncodeReceipt(receipt)
	if err != nil || digest != sha256.Sum256(body) || reference.Validate() != nil || !bytes.Contains(body, []byte(`"schema":"runtime-correlation-receipt-v2"`)) {
		t.Fatal("v2 receipt encode", err)
	}
	decoded, err := DecodeReceipt(body)
	if err != nil || decoded.CandidateSnapshotDigest != snapshot.Digest() || decoded.EffectDigest != result.ContentDigest || decoded.ImplementationVersion != "runtime-correlation-v2" || decoded.Results[0] != result.Results[0] {
		t.Fatal("v2 receipt round trip", err)
	}
	for _, name := range []string{"absent snapshot", "changed snapshot", "v1 effect", "v1 implementation"} {
		t.Run(name, func(t *testing.T) {
			changed := receipt
			switch name {
			case "absent snapshot":
				changed.CandidateSnapshotDigest = [sha256.Size]byte{}
			case "changed snapshot":
				changed.CandidateSnapshotDigest = sha256.Sum256([]byte("other snapshot"))
			case "v1 effect":
				changed.EffectDigest, _ = correlationDigest(input.Scope, input.BatchID, input.Generation, input.ArchiveDigest, result.Results)
			case "v1 implementation":
				changed.ImplementationVersion = "runtime-correlation-v1"
			}
			if _, _, _, err := EncodeReceipt(changed); err != ErrInput {
				t.Fatal("unbound receipt encoded")
			}
		})
	}
	hexDigest := hex.EncodeToString(receipt.CandidateSnapshotDigest[:])
	for name, hostile := range map[string][]byte{
		"v1 schema":          bytes.Replace(body, []byte(`runtime-correlation-receipt-v2`), []byte(`runtime-correlation-receipt-v1`), 1),
		"v1 implementation":  bytes.Replace(body, []byte(`runtime-correlation-v2`), []byte(`runtime-correlation-v1`), 1),
		"foreign snapshot":   bytes.Replace(body, []byte(hexDigest), []byte(strings.Repeat("a", 64)), 1),
		"null snapshot":      bytes.Replace(body, []byte(`"`+hexDigest+`"`), []byte(`null`), 1),
		"uppercase snapshot": bytes.Replace(body, []byte(hexDigest), []byte(strings.ToUpper(hexDigest)), 1),
		"duplicate snapshot": bytes.Replace(body, []byte(`{`), []byte(`{"candidate_snapshot_digest":"`+hexDigest+`",`), 1),
		"case snapshot":      bytes.Replace(body, []byte(`"candidate_snapshot_digest"`), []byte(`"Candidate_Snapshot_Digest"`), 1),
		"unknown":            bytes.Replace(body, []byte(`{`), []byte(`{"other":true,`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeReceipt(hostile); err != ErrInput {
				t.Fatal("hostile receipt accepted")
			}
		})
	}
}

func TestLegacyCorrelationReceiptBytesRemainExact(t *testing.T) {
	scope, batch := correlationScope(t, 1), correlationID(t, 9)
	archive, index := sha256.Sum256([]byte("archive")), sha256.Sum256([]byte("index"))
	results := []Result{{EventID: correlationID(t, 5), SessionID: correlationID(t, 7), AgentID: correlationID(t, 6), Confidence: domain.EvidenceConfidenceExact}}
	effect, err := correlationDigest(scope, batch, 2, archive, results)
	if err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{ImplementationVersion: "runtime-correlation-v1", Scope: scope, BatchID: batch, Generation: 2, InputReference: "s3://zasp-evidence/index.json", InputVersionID: "index-v1", InputDigest: index, ArchiveReference: "s3://zasp-evidence/raw.json", ArchiveVersionID: "raw-v1", ArchiveDigest: archive, EffectDigest: effect, Results: results}
	// This literal is the pre-v2 wire order and shape, independent of receiptWire.
	want := fmt.Sprintf(`{"schema":"runtime-correlation-receipt-v1","implementation_version":"runtime-correlation-v1","organization_id":"%s","workspace_id":"%s","environment_id":"%s","batch_id":"%s","generation":2,"input_reference":"s3://zasp-evidence/index.json","input_version_id":"index-v1","input_digest":"%x","archive_reference":"s3://zasp-evidence/raw.json","archive_version_id":"raw-v1","archive_digest":"%x","effect_digest":"%x","results":[{"event_id":"%s","session_id":"%s","agent_id":"%s","confidence":"exact"}]}`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batch.String(), index, archive, effect, results[0].EventID.String(), results[0].SessionID.String(), results[0].AgentID.String())
	body, _, _, err := EncodeReceipt(receipt)
	if err != nil || string(body) != want {
		t.Fatal("v1 receipt bytes changed", err)
	}
	decoded, err := DecodeReceipt([]byte(want))
	if err != nil || decoded.CandidateSnapshotDigest != ([sha256.Size]byte{}) || decoded.EffectDigest != effect {
		t.Fatal("v1 replay changed", err)
	}
}
