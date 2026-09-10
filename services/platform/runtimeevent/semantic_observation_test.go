package runtimeevent

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimemetadata"
)

func TestOTLPCredentialAndPolicyObservationsPreserveCanonicalEvidence(t *testing.T) {
	for _, action := range []string{"use", "allow", "monitor", "block"} {
		t.Run(action, func(t *testing.T) {
			record := fixtureRecord(t, "semantic-observation-"+action)
			event, err := canonicalIngestEvent(record)
			if err != nil {
				t.Fatal(err)
			}
			class := "policy"
			event.SearchMetadata = runtimemetadata.Fields{Decision: action}
			if action == "use" {
				class = "credential"
				event.SearchMetadata = runtimemetadata.Fields{CredentialID: fixtureID(t, 13).String()}
			}
			event.Attributes["event.class"], event.Attributes["event.action"] = class, action
			event.Content = nil
			body, err := json.Marshal(ingestInput{Source: "otlp", Events: []ingestEvent{event}})
			if err != nil {
				t.Fatal(err)
			}
			_, canonical, err := decodeProductionInput(body, IngestAuthority{Scope: record.Scope, Source: "otlp", Mode: "metadata_only"}, record.EventTime)
			if err != nil {
				t.Fatalf("supported observation rejected: %v", err)
			}
			decoded, err := DecodeArchivedBatch(record.Scope, canonical)
			if err != nil || len(decoded.Records) != 1 {
				t.Fatalf("observation archive: %v", err)
			}
			got := decoded.Records[0]
			if got.Class != class || got.Action != action || got.SearchMetadata != event.SearchMetadata || got.ID != record.ID || got.Event.Evidence != record.Event.Evidence || got.AgentID != record.AgentID || got.SessionID != record.SessionID || len(got.Content) != 0 {
				t.Fatal("semantic observation changed evidence, identity, or content policy")
			}
			replayed, err := canonicalIngestEvent(got)
			if err != nil {
				t.Fatal(err)
			}
			again, err := json.Marshal(ingestInput{Source: "otlp", Events: []ingestEvent{replayed}})
			if err != nil || !bytes.Equal(canonical, again) {
				t.Fatal("observation replay changed canonical bytes")
			}
		})
	}
}

func TestOTLPSemanticObservationsRejectMissingClaimsAndRawContent(t *testing.T) {
	for _, fault := range []string{"credential reference missing", "policy decision missing", "policy decision mismatch", "unknown action", "raw content", "missing agent", "missing session"} {
		t.Run(fault, func(t *testing.T) {
			record := fixtureRecord(t, "semantic-rejected")
			event, _ := canonicalIngestEvent(record)
			event.Attributes["event.class"], event.Attributes["event.action"] = "policy", "block"
			event.SearchMetadata = runtimemetadata.Fields{Decision: "block"}
			event.Content = nil
			switch fault {
			case "credential reference missing":
				event.Attributes["event.class"], event.Attributes["event.action"] = "credential", "use"
				event.SearchMetadata = runtimemetadata.Fields{}
			case "policy decision missing":
				event.SearchMetadata = runtimemetadata.Fields{}
			case "policy decision mismatch":
				event.SearchMetadata.Decision = "allow"
			case "unknown action":
				event.Attributes["event.action"] = "execute"
			case "raw content":
				event.Content = map[string]string{"credential": "must-not-be-retained"}
			case "missing agent":
				event.Attributes["agent.id"] = ""
			case "missing session":
				event.Attributes["session.id"] = ""
			}
			body, err := json.Marshal(ingestInput{Source: "otlp", Events: []ingestEvent{event}})
			if err != nil {
				t.Fatal(err)
			}
			for _, mode := range []string{"metadata_only", "full"} {
				if _, _, err := decodeProductionInput(body, IngestAuthority{Scope: record.Scope, Source: "otlp", Mode: mode}, record.EventTime); err == nil {
					t.Fatal("invalid semantic observation accepted", mode)
				}
			}
		})
	}
}
