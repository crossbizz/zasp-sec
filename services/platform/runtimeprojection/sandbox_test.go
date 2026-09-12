package runtimeprojection

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
)

func sandboxProjectionInput(t *testing.T) Batch {
	t.Helper()
	scope, body := projectionScope(t, 1), projectionBody()
	return Batch{Scope: scope, BatchID: projectionID(t, 9), Generation: 2, ArchiveReference: "s3://zasp-evidence/runtime/v15/raw.json", ArchiveVersionID: "raw-version", ArchiveDigest: sha256.Sum256(body), Body: body, Correlations: []runtimecorrelation.Result{{EventID: projectionEventID(t, scope, body), AgentID: projectionID(t, 6), SessionID: projectionID(t, 7), Confidence: domain.EvidenceConfidenceStrong}}}
}

func projectionReceiptFixture(input Batch, result ProjectedBatch, version string) Receipt {
	return Receipt{ImplementationVersion: version, Scope: input.Scope, BatchID: input.BatchID, Generation: input.Generation, InputReference: "s3://zasp-evidence/correlation.json", InputVersionID: "correlation-version", InputDigest: sha256.Sum256([]byte("correlation")), ArchiveReference: input.ArchiveReference, ArchiveVersionID: input.ArchiveVersionID, ArchiveDigest: input.ArchiveDigest, EffectDigest: result.ContentDigest, Items: result.Items}
}

func TestProjectionHistoricalReceiptVector(t *testing.T) {
	input := sandboxProjectionInput(t)
	result, err := Project(input)
	if err != nil {
		t.Fatal(err)
	}
	body, digest, _, err := EncodeReceipt(projectionReceiptFixture(input, result, "runtime-projection-v1"))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(result.ContentDigest[:]) != "056ae915931b47d0698539ad3fd6a649a425b92c6e5b92305438a9ef7b248c9e" || hex.EncodeToString(digest[:]) != "e9412869f845f846df23631a70bb8f42a1a4df70db2a691791a7352d13cc43bb" || sha256.Sum256(body) != digest {
		t.Fatal("historical projection receipt bytes changed")
	}
}

func TestSandboxProjectionRetainsBindingAndVersionedReceipt(t *testing.T) {
	input := sandboxProjectionInput(t)
	input.Correlations[0].SandboxID = "sandbox-a"
	input.Correlations[0].SandboxSourceSensorID = projectionID(t, 10)
	result, err := ProjectSandbox(input)
	if err != nil || len(result.Items) != 1 {
		t.Fatal("sandbox projection rejected", err)
	}
	if result.Items[0].SandboxID != "sandbox-a" || result.Items[0].SandboxSourceSensorID != projectionID(t, 10) {
		t.Fatal("projection discarded sandbox binding")
	}
	receipt := projectionReceiptFixture(input, result, "runtime-projection-v2")
	body, digest, _, err := EncodeReceipt(receipt)
	if err != nil || !bytes.Contains(body, []byte(`"schema":"runtime-projection-receipt-v2"`)) {
		t.Fatal("sandbox receipt not versioned", err)
	}
	decoded, err := DecodeReceipt(body)
	if err != nil || decoded.Items[0] != result.Items[0] || sha256.Sum256(body) != digest {
		t.Fatal("sandbox receipt changed binding", err)
	}
	receipt.ImplementationVersion = "runtime-projection-v1"
	if _, _, _, err := EncodeReceipt(receipt); err != ErrInput {
		t.Fatal("sandbox data crossed historical receipt version", err)
	}
	other := input
	other.Correlations = append([]runtimecorrelation.Result(nil), input.Correlations...)
	other.Correlations[0].SandboxID = "sandbox-b"
	changed, err := ProjectSandbox(other)
	if err != nil || changed.ContentDigest == result.ContentDigest || changed.Items[0].ID == result.Items[0].ID {
		t.Fatal("sandbox change did not bind effect and risk identity", err)
	}
	other.Correlations[0].SandboxID = "sandbox-a"
	other.Correlations[0].SandboxSourceSensorID = projectionID(t, 11)
	changed, err = ProjectSandbox(other)
	if err != nil || changed.ContentDigest == result.ContentDigest || changed.Items[0].ID == result.Items[0].ID {
		t.Fatal("source namespace omitted from effect and risk identity", err)
	}
}

func TestProjectionHistoricalPathRejectsSandboxWithoutLosingIt(t *testing.T) {
	for _, scenario := range []string{"binding", "source only", "sandbox only"} {
		input := sandboxProjectionInput(t)
		if scenario != "source only" {
			input.Correlations[0].SandboxID = "sandbox-a"
		}
		if scenario != "sandbox only" {
			input.Correlations[0].SandboxSourceSensorID = projectionID(t, 10)
		}
		if result, err := Project(input); err != ErrInput || result.Items != nil {
			t.Fatal("historical projector silently discarded sandbox identity", scenario, err)
		}
	}
}

func TestProjectionReceiptRejectsUnknownImplementation(t *testing.T) {
	input := sandboxProjectionInput(t)
	result, err := Project(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := EncodeReceipt(projectionReceiptFixture(input, result, "runtime-projection-v3")); err != ErrInput {
		t.Fatal("unimplemented projection version accepted", err)
	}
}

func TestSandboxProjectionValidatesConfidenceAndCompleteBinding(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		mutate func(*runtimecorrelation.Result)
		valid  bool
	}{
		{"strong", nil, true},
		{"exact", func(r *runtimecorrelation.Result) { r.Confidence = domain.EvidenceConfidenceExact }, true},
		{"historical unknown strong", func(r *runtimecorrelation.Result) { r.SandboxID = ""; r.SandboxSourceSensorID = domain.ProductID{} }, true},
		{"unknown exact", func(r *runtimecorrelation.Result) {
			r.Confidence = domain.EvidenceConfidenceExact
			r.SandboxID = ""
			r.SandboxSourceSensorID = domain.ProductID{}
		}, false},
		{"probable", func(r *runtimecorrelation.Result) {
			r.Confidence = domain.EvidenceConfidenceProbable
			r.AgentID = domain.ProductID{}
			r.SessionID = domain.ProductID{}
			r.SandboxID = ""
			r.SandboxSourceSensorID = domain.ProductID{}
		}, true},
		{"unattributed", func(r *runtimecorrelation.Result) {
			r.Confidence = domain.EvidenceConfidenceUnattributed
			r.AgentID = domain.ProductID{}
			r.SessionID = domain.ProductID{}
			r.SandboxID = ""
			r.SandboxSourceSensorID = domain.ProductID{}
		}, true},
		{"probable asserted binding", func(r *runtimecorrelation.Result) {
			r.Confidence = domain.EvidenceConfidenceProbable
			r.AgentID = domain.ProductID{}
			r.SessionID = domain.ProductID{}
		}, false},
		{"sandbox missing", func(r *runtimecorrelation.Result) { r.SandboxID = "" }, false},
		{"source missing", func(r *runtimecorrelation.Result) { r.SandboxSourceSensorID = domain.ProductID{} }, false},
		{"identity alias", func(r *runtimecorrelation.Result) { r.AgentID = r.SessionID }, false},
		{"unicode edge", func(r *runtimecorrelation.Result) { r.SandboxID = "\u00a0sandbox" }, false},
		{"newline", func(r *runtimecorrelation.Result) { r.SandboxID = "a\nb" }, false},
		{"nul", func(r *runtimecorrelation.Result) { r.SandboxID = "a\x00b" }, false},
		{"invalid utf8", func(r *runtimecorrelation.Result) { r.SandboxID = string([]byte{0xff}) }, false},
		{"max bytes", func(r *runtimecorrelation.Result) { r.SandboxID = strings.Repeat("é", 128) }, true},
		{"over max bytes", func(r *runtimecorrelation.Result) { r.SandboxID = strings.Repeat("é", 129) }, false},
		{"internal tab", func(r *runtimecorrelation.Result) { r.SandboxID = "a\tb" }, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			input := sandboxProjectionInput(t)
			input.Correlations[0].SandboxID = "sandbox-a"
			input.Correlations[0].SandboxSourceSensorID = projectionID(t, 10)
			if scenario.mutate != nil {
				scenario.mutate(&input.Correlations[0])
			}
			result, err := ProjectSandbox(input)
			if (err == nil) != scenario.valid || !scenario.valid && result.Items != nil {
				t.Fatal("sandbox projection validation", err)
			}
			if scenario.valid {
				body, _, _, err := EncodeReceipt(projectionReceiptFixture(input, result, "runtime-projection-v2"))
				if err != nil {
					t.Fatal("valid binding refused by receipt", err)
				}
				decoded, err := DecodeReceipt(body)
				if err != nil || decoded.Items[0].SandboxID != input.Correlations[0].SandboxID || decoded.Items[0].SandboxSourceSensorID != input.Correlations[0].SandboxSourceSensorID {
					t.Fatal("binding did not roundtrip", err)
				}
			}
		})
	}
}

func TestSandboxProjectionReceiptRejectsIdentityAndVersionTampering(t *testing.T) {
	input := sandboxProjectionInput(t)
	input.Correlations[0].SandboxID = "sandbox-a"
	input.Correlations[0].SandboxSourceSensorID = projectionID(t, 10)
	result, err := ProjectSandbox(input)
	if err != nil {
		t.Fatal(err)
	}
	receipt := projectionReceiptFixture(input, result, "runtime-projection-v2")
	body, _, _, err := EncodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct{ from, to string }{
		{`"sandbox_id":"sandbox-a"`, `"sandbox_id":"sandbox-b"`},
		{`"sandbox_id":"sandbox-a"`, `"Sandbox_ID":"sandbox-a"`},
		{`"sandbox_id":"sandbox-a"`, `"sandbox_id":null`},
		{`"sandbox_id":"sandbox-a"`, `"sandbox_id":"sandbox-a","sandbox_id":"sandbox-a"`},
		{`"sandbox_source_sensor_id":"pid_00000010-0000-4000-8000-000000000010"`, `"sandbox_source_sensor_id":"pid_00000011-0000-4000-8000-000000000011"`},
		{`"schema":"runtime-projection-receipt-v2"`, `"schema":"runtime-projection-receipt-v1"`},
		{`"implementation_version":"runtime-projection-v2"`, `"implementation_version":"runtime-projection-v1"`},
	} {
		forged := bytes.Replace(body, []byte(change.from), []byte(change.to), 1)
		if bytes.Equal(body, forged) {
			t.Fatal("mutation didn't reach fixture")
		}
		if _, err := DecodeReceipt(forged); err != ErrInput {
			t.Fatal("forged receipt accepted", change.to, err)
		}
	}
	// Even self-consistent old digests cannot authorize sandbox fields on v1.
	receipt.ImplementationVersion = "runtime-projection-v1"
	receipt.Items[0].ID = riskID(input, input.Correlations[0].EventID, input.Correlations[0])
	receipt.EffectDigest, err = projectionDigest(input.Scope, input.BatchID, input.Generation, input.ArchiveDigest, receipt.Items, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := EncodeReceipt(receipt); err != ErrInput {
		t.Fatal("recomputed historical digest laundered sandbox fields", err)
	}
}
