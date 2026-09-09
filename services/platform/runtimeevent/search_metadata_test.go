package runtimeevent

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRuntimeSearchMetadataSurvivesMetadataOnlyArchiveWithoutProviderContent(t *testing.T) {
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	scope := fixtureScope(t, 70)
	digest := strings.Repeat("a", 64)
	body := bytes.Replace(productionEventBody(now), []byte(`"content":`), []byte(`"search_metadata":{"process_digest":"`+digest+`"},"content":`), 1)
	authority := IngestAuthority{Scope: scope, Source: "tetragon", Mode: "metadata_only"}
	_, canonical, err := decodeProductionInput(body, authority, now)
	if err != nil {
		t.Fatalf("supported search metadata rejected: %v", err)
	}
	if bytes.Contains(canonical, []byte(`"binary":"agent"`)) {
		t.Fatal("provider content escaped metadata-only filtering")
	}
	var archived struct {
		Events []struct {
			Search map[string]string `json:"search_metadata"`
		} `json:"events"`
	}
	if json.Unmarshal(canonical, &archived) != nil || len(archived.Events) != 1 || archived.Events[0].Search["process_digest"] != digest {
		t.Fatalf("search metadata lost from archive: %s", canonical)
	}
	decoded, err := DecodeArchivedBatch(scope, canonical)
	if err != nil || len(decoded.Records) != 1 {
		t.Fatalf("archive replay=%v", err)
	}
	replay, err := canonicalIngestEvent(decoded.Records[0])
	if err != nil {
		t.Fatal(err)
	}
	replayBody, err := json.Marshal(ingestInput{Source: "tetragon", Events: []ingestEvent{replay}})
	if err != nil || !bytes.Equal(canonical, replayBody) {
		t.Fatal("search metadata changed on archive replay")
	}
}

func TestRuntimeSearchMetadataRejectsRawFieldsAndInvalidDigests(t *testing.T) {
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	for _, metadata := range []string{
		`{"process_digest":"/usr/bin/agent"}`, `{"process_digest":"` + strings.Repeat("A", 64) + `"}`,
		`{"file":"/private/file"}`, `{"raw_query":"*:*"}`, `{"credential":"provider-secret"}`,
		`{"principal_id":"pid_00000001-0000-4000-8000-000000000001"}`,
		`{"decision":"allow"}`, `{"process_digest":"` + strings.Repeat("a", 64) + `","process_digest":"` + strings.Repeat("b", 64) + `"}`,
	} {
		body := bytes.Replace(productionEventBody(now), []byte(`"content":`), []byte(`"search_metadata":`+metadata+`,"content":`), 1)
		if _, _, err := decodeProductionInput(body, IngestAuthority{Scope: fixtureScope(t, 70), Source: "tetragon", Mode: "metadata_only"}, now); err == nil {
			t.Fatalf("hostile search metadata admitted: %s", metadata)
		}
	}
}
