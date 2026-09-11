package runtimecorrelation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestSandboxChangesPreservePinnedHistoricalV2Receipt(t *testing.T) {
	// Captured with unchanged production code at 49faf28d7b762aac0e3fc316962fe8905ae15802.
	// This vector must not be regenerated with the encoder under test.
	const historicalBody = `{"schema":"runtime-correlation-receipt-v2","implementation_version":"runtime-correlation-v2","organization_id":"pid_00000001-0000-4000-8000-000000000001","workspace_id":"pid_00000002-0000-4000-8000-000000000002","environment_id":"pid_00000003-0000-4000-8000-000000000003","batch_id":"pid_00000009-0000-4000-8000-000000000009","generation":2,"input_reference":"s3://zasp-evidence/index.json","input_version_id":"index-v1","input_digest":"cb2b4a8c4e7a13e3fa70110c71e69ccb9f8c26327b5946bf4540cb1f7fdb72eb","archive_reference":"s3://zasp-evidence/raw.json","archive_version_id":"raw-v1","archive_digest":"28509e4c82aac455289858dd30d2c3feba4160e0c3e6d7ad1936a0eee550009c","effect_digest":"d42f36253fb24b71dc4ae05be68195e6304a68efcf7046baa7a2fb882c17ed4d","results":[{"event_id":"pid_5e7f7839-c0d2-4322-ad9a-68c206206253","session_id":"pid_00000007-0000-4000-8000-000000000007","agent_id":"pid_00000006-0000-4000-8000-000000000006","confidence":"strong"}],"candidate_snapshot_digest":"d5eb4311871693a488f5e7e8871d28551a44d49d06def7575cda4159013182ae"}`
	input, snapshot := frozenCorrelationFixture(t, "tetragon", nil)
	result, err := CorrelateFrozen(input, snapshot)
	if err != nil || hex.EncodeToString(result.ContentDigest[:]) != "d42f36253fb24b71dc4ae05be68195e6304a68efcf7046baa7a2fb882c17ed4d" {
		t.Fatal("historical v2 effect changed", err)
	}
	receipt := Receipt{ImplementationVersion: "runtime-correlation-v2", Scope: input.Scope, BatchID: input.BatchID, Generation: input.Generation, InputReference: "s3://zasp-evidence/index.json", InputVersionID: "index-v1", InputDigest: sha256.Sum256([]byte("index effect")), ArchiveReference: "s3://zasp-evidence/raw.json", ArchiveVersionID: "raw-v1", ArchiveDigest: input.ArchiveDigest, EffectDigest: result.ContentDigest, CandidateSnapshotDigest: snapshot.Digest(), Results: result.Results}
	body, digest, _, err := EncodeReceipt(receipt)
	if err != nil || string(body) != historicalBody || hex.EncodeToString(digest[:]) != "e27502c6b1e8a21a6da2651f61cecdd80d00c47304cbc9fdf18b06f96cad7b3d" {
		t.Fatal("historical v2 receipt bytes changed", err)
	}
	decoded, err := DecodeReceipt([]byte(historicalBody))
	if err != nil || len(decoded.Results) != 1 || decoded.Results[0] != result.Results[0] || decoded.EffectDigest != result.ContentDigest {
		t.Fatal("historical v2 replay changed", err)
	}
}

func sandboxReceiptFixture(t *testing.T) Receipt {
	t.Helper()
	input, snapshot := versionedFrozenCorrelationFixture(t, "otlp", true, nil)
	result, err := CorrelateSandboxFrozen(input, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return Receipt{ImplementationVersion: "runtime-correlation-v3", Scope: input.Scope, BatchID: input.BatchID, Generation: input.Generation, InputReference: "s3://zasp-evidence/index.json", InputVersionID: "index-v1", InputDigest: sha256.Sum256([]byte("index effect")), ArchiveReference: "s3://zasp-evidence/raw.json", ArchiveVersionID: "raw-v1", ArchiveDigest: input.ArchiveDigest, EffectDigest: result.ContentDigest, CandidateSnapshotDigest: snapshot.Digest(), Results: result.Results}
}

func TestSandboxReceiptRoundTripAndVersionIsolation(t *testing.T) {
	receipt := sandboxReceiptFixture(t)
	body, digest, _, err := EncodeReceipt(receipt)
	if err != nil || digest != sha256.Sum256(body) || !bytes.Contains(body, []byte(`"schema":"runtime-correlation-receipt-v3"`)) {
		t.Fatal("v3 receipt rejected", err)
	}
	decoded, err := DecodeReceipt(body)
	if err != nil || len(decoded.Results) != 1 || decoded.Results[0] != receipt.Results[0] || decoded.CandidateSnapshotDigest != receipt.CandidateSnapshotDigest || decoded.EffectDigest != receipt.EffectDigest {
		t.Fatal("v3 sandbox binding lost on replay", err)
	}
	for name, payload := range map[string][]byte{
		"old schema":         bytes.Replace(body, []byte("runtime-correlation-receipt-v3"), []byte("runtime-correlation-receipt-v2"), 1),
		"old implementation": bytes.Replace(body, []byte("runtime-correlation-v3"), []byte("runtime-correlation-v2"), 1),
		"changed sandbox":    bytes.Replace(body, []byte("sandbox-a"), []byte("sandbox-b"), 1),
		"changed source":     bytes.Replace(body, []byte(receipt.Results[0].SandboxSourceSensorID.String()), []byte(correlationID(t, 42).String()), 1),
		"null sandbox":       bytes.Replace(body, []byte(`"sandbox_id":"sandbox-a"`), []byte(`"sandbox_id":null`), 1),
		"case sandbox":       bytes.Replace(body, []byte(`"sandbox_id"`), []byte(`"Sandbox_ID"`), 1),
		"duplicate sandbox":  bytes.Replace(body, []byte(`"sandbox_id":"sandbox-a"`), []byte(`"sandbox_id":"sandbox-a","sandbox_id":"sandbox-a"`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeReceipt(payload); err != ErrInput {
				t.Fatal("changed receipt accepted")
			}
		})
	}
}

func TestSandboxReceiptCannotUseLegacyDigestEvenWhenRecomputed(t *testing.T) {
	for _, version := range []string{"runtime-correlation-v1", "runtime-correlation-v2"} {
		t.Run(version, func(t *testing.T) {
			receipt := sandboxReceiptFixture(t)
			receipt.ImplementationVersion = version
			if version == "runtime-correlation-v1" {
				receipt.CandidateSnapshotDigest = [sha256.Size]byte{}
				receipt.EffectDigest, _ = correlationDigest(receipt.Scope, receipt.BatchID, receipt.Generation, receipt.ArchiveDigest, receipt.Results)
			} else {
				receipt.EffectDigest, _ = frozenCorrelationDigest(receipt.Scope, receipt.BatchID, receipt.Generation, receipt.ArchiveDigest, receipt.CandidateSnapshotDigest, receipt.Results)
			}
			if _, _, _, err := EncodeReceipt(receipt); err != ErrInput {
				t.Fatal("legacy receipt accepted sandbox-bound results")
			}
		})
	}
}

func TestSandboxReceiptValidatesAllIdentityFieldsBeforeHash(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		mutate func(*Result)
		accept bool
	}{
		{"missing source", func(r *Result) { r.SandboxSourceSensorID = domain.ProductID{} }, false},
		{"source without sandbox", func(r *Result) { r.SandboxID = "" }, false},
		{"exact without sandbox", func(r *Result) { r.SandboxID = ""; r.SandboxSourceSensorID = domain.ProductID{} }, false},
		{"strong historical unknown", func(r *Result) {
			r.Confidence = domain.EvidenceConfidenceStrong
			r.SandboxID = ""
			r.SandboxSourceSensorID = domain.ProductID{}
		}, true},
		{"probable residual sandbox", func(r *Result) {
			r.Confidence = domain.EvidenceConfidenceProbable
			r.AgentID, r.SessionID = domain.ProductID{}, domain.ProductID{}
		}, false},
		{"unattributed residual sandbox", func(r *Result) {
			r.Confidence = domain.EvidenceConfidenceUnattributed
			r.AgentID, r.SessionID = domain.ProductID{}, domain.ProductID{}
		}, false},
		{"probable unassigned", func(r *Result) {
			r.Confidence = domain.EvidenceConfidenceProbable
			r.AgentID, r.SessionID, r.SandboxSourceSensorID = domain.ProductID{}, domain.ProductID{}, domain.ProductID{}
			r.SandboxID = ""
		}, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			receipt := sandboxReceiptFixture(t)
			scenario.mutate(&receipt.Results[0])
			receipt.EffectDigest, _ = sandboxCorrelationDigest(receipt.Scope, receipt.BatchID, receipt.Generation, receipt.ArchiveDigest, receipt.CandidateSnapshotDigest, receipt.Results)
			body, _, _, err := EncodeReceipt(receipt)
			if (err == nil) != scenario.accept {
				t.Fatal("sandbox identity validation mismatch", err)
			}
			if scenario.accept {
				decoded, err := DecodeReceipt(body)
				if err != nil || decoded.Results[0] != receipt.Results[0] {
					t.Fatal("unknown sandbox replay changed", err)
				}
			}
		})
	}
}
