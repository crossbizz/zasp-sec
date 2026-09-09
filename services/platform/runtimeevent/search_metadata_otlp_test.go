package runtimeevent

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimemetadata"
)

func TestOTLPObservedSearchMetadataKeepsCanonicalIDsAndReplayBytes(t *testing.T) {
	record := fixtureRecord(t, "semantic-search-metadata")
	digest, _ := runtimemetadata.DigestSelector("domain", "api.example.com")
	metadata := runtimemetadata.Fields{
		PrincipalID: fixtureID(t, 12).String(), ProcessDigest: strings.Repeat("a", 64),
		FileDigest: strings.Repeat("b", 64), DomainDigest: digest, CredentialID: fixtureID(t, 13).String(),
		ResourceDigest: strings.Repeat("c", 64), Decision: "block",
	}
	record.SearchMetadata = metadata
	event, err := canonicalIngestEvent(record)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(ingestInput{Source: "otlp", Events: []ingestEvent{event}})
	if err != nil {
		t.Fatal(err)
	}
	authority := IngestAuthority{Scope: record.Scope, Source: "otlp", Mode: "metadata_only"}
	_, canonical, err := decodeProductionInput(body, authority, record.EventTime)
	if err != nil || !bytes.Equal(body, canonical) {
		t.Fatalf("semantic canonicalization drift: %v", err)
	}
	decoded, err := DecodeArchivedBatch(record.Scope, canonical)
	if err != nil || len(decoded.Records) != 1 {
		t.Fatalf("semantic archive decode: %v", err)
	}
	got := decoded.Records[0]
	if got.SearchMetadata != metadata || got.ID != record.ID || got.AgentID != record.AgentID || got.SessionID != record.SessionID || got.ToolID != record.ToolID {
		t.Fatal("semantic search selectors altered canonical event or attribution IDs")
	}
	// Search selectors never override correlation confidence or identity.
	poisoned := bytes.Replace(body, []byte(`"search_metadata":{`), []byte(`"search_metadata":{"agent_id":"`+fixtureID(t, 99).String()+`",`), 1)
	if _, _, err := decodeProductionInput(poisoned, authority, record.EventTime); err == nil {
		t.Fatal("metadata overrode agent attribution")
	}
}

func TestLegacyArchiveWithoutSearchMetadataRemainsByteCompatible(t *testing.T) {
	record := fixtureRecord(t, "legacy-no-search-metadata")
	event, err := canonicalIngestEvent(record)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(ingestInput{Source: "otlp", Events: []ingestEvent{event}})
	if err != nil || bytes.Contains(body, []byte("search_metadata")) {
		t.Fatal("legacy archive acquired a new field")
	}
	_, canonical, err := decodeProductionInput(body, IngestAuthority{Scope: record.Scope, Source: "otlp", Mode: "metadata_only"}, record.EventTime)
	if err != nil || !bytes.Equal(body, canonical) {
		t.Fatal("legacy archive bytes changed")
	}
}
