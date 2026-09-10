package runtimeprojection

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
)

func TestProjectSemanticObservationsPreservesSourceOwnedLabelsAndReceipts(t *testing.T) {
	for _, test := range []struct{ class, action, metadata, severity, title string }{
		{"credential", "use", `"credential_id":"pid_00000013-0000-4000-8000-000000000013"`, "medium", "Observed credential use"},
		{"policy", "allow", `"decision":"allow"`, "low", "Observed policy allow"},
		{"policy", "monitor", `"decision":"monitor"`, "medium", "Observed policy monitor"},
		{"policy", "block", `"decision":"block"`, "medium", "Observed policy block"},
	} {
		t.Run(test.class+"/"+test.action, func(t *testing.T) {
			scope := projectionScope(t, 1)
			body := []byte(fmt.Sprintf(`{"source":"otlp","events":[{"search_metadata":{%s},"event_time":"2026-08-20T12:00:00.000Z","evidence_id":"pid_00000008-0000-4000-8000-000000000008","attributes":{"event.id":"semantic-observation-1","event.class":%q,"event.action":%q,"agent.id":"pid_00000006-0000-4000-8000-000000000006","session.id":"pid_00000007-0000-4000-8000-000000000007","task.id":"task-a","tool.id":"tool-a","sandbox.id":"sandbox-a","trace.id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","span.id":"bbbbbbbbbbbbbbbb"}}]}`, test.metadata, test.class, test.action))
			event := projectionEventID(t, scope, body)
			input := Batch{Scope: scope, BatchID: projectionID(t, 9), Generation: 1, ArchiveReference: "s3://zasp-evidence/runtime/v15/raw.json", ArchiveVersionID: "observed-version", ArchiveDigest: sha256.Sum256(body), Body: body, Correlations: []runtimecorrelation.Result{{EventID: event, Confidence: domain.EvidenceConfidenceUnattributed}}}
			result, err := Project(input)
			if err != nil || len(result.Items) != 1 {
				t.Fatalf("semantic observation projection rejected: %v", err)
			}
			item := result.Items[0]
			if item.Source != "otlp" || item.EventClass != test.class || item.Action != test.action || item.Title != test.title || item.Severity != test.severity || item.Confidence != domain.EvidenceConfidenceUnattributed || !item.SessionID.IsZero() || !item.AgentID.IsZero() {
				t.Fatal("semantic observation changed source, deterministic label or correlation")
			}
			receipt := Receipt{ImplementationVersion: "runtime-projection-v1", Scope: scope, BatchID: input.BatchID, Generation: 1, InputReference: "s3://zasp-evidence/correlation.json", InputVersionID: "correlation-version", InputDigest: sha256.Sum256([]byte("semantic correlation")), ArchiveReference: input.ArchiveReference, ArchiveVersionID: input.ArchiveVersionID, ArchiveDigest: input.ArchiveDigest, EffectDigest: result.ContentDigest, Items: result.Items}
			encoded, _, _, err := EncodeReceipt(receipt)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeReceipt(encoded)
			if err != nil || len(decoded.Items) != 1 || decoded.Items[0] != item {
				t.Fatal("semantic receipt round trip changed evidence", err)
			}
			receipt.Items[0].Title = "Gateway enforcement confirmed"
			if _, _, _, err := EncodeReceipt(receipt); err == nil {
				t.Fatal("provider-controlled enforcement label accepted")
			}
		})
	}
}
