package opensearchdriver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
)

func TestSessionSchemaInitializationIsSeparateImmutableAndReplayable(t *testing.T) {
	mapping, marker, writes := false, false, 0
	index := &SessionIndex{transport: testDriver(t, httpDoerFunc(func(request *http.Request) (*http.Response, error) {
		switch request.Method + " " + request.URL.Path {
		case "GET /zasp-runtime-sessions-v1/_mapping":
			if !mapping {
				return jsonResponse(404, `{"error":"missing"}`), nil
			}
			return jsonResponse(200, `{"zasp-runtime-sessions-v1":`+sessionIndexSchemaJSON+`}`), nil
		case "PUT /zasp-runtime-sessions-v1":
			body, _ := io.ReadAll(request.Body)
			if string(body) != sessionIndexSchemaJSON || mapping {
				t.Fatal("schema overwritten or changed")
			}
			mapping = true
			writes++
			return jsonResponse(200, `{"acknowledged":true,"shards_acknowledged":true,"index":"zasp-runtime-sessions-v1"}`), nil
		case "GET /zasp-runtime-sessions-v1/_doc/_zasp_session_schema_v1":
			if !marker {
				return jsonResponse(404, `{"found":false}`), nil
			}
			body, _ := json.Marshal(expectedSessionSchemaMarker())
			return jsonResponse(200, `{"_index":"zasp-runtime-sessions-v1","_id":"_zasp_session_schema_v1","_version":1,"_seq_no":0,"_primary_term":1,"found":true,"_source":`+string(body)+`}`), nil
		case "PUT /zasp-runtime-sessions-v1/_doc/_zasp_session_schema_v1":
			body, _ := io.ReadAll(request.Body)
			want, _ := json.Marshal(expectedSessionSchemaMarker())
			if string(body) != string(want) || request.URL.Query().Get("op_type") != "create" || request.URL.Query().Get("refresh") != "wait_for" || marker {
				t.Fatal("schema marker not immutable")
			}
			marker = true
			writes++
			return jsonResponse(201, `{"_index":"zasp-runtime-sessions-v1","_id":"_zasp_session_schema_v1","_version":1,"result":"created","_seq_no":0,"_primary_term":1,"_shards":{"total":1,"successful":1,"failed":0}}`), nil
		default:
			t.Fatalf("unexpected schema operation %s %s", request.Method, request.URL)
			return nil, nil
		}
	}))}
	if err := index.Ready(context.Background()); err == nil {
		t.Fatal("missing schema ready")
	}
	for i := 0; i < 2; i++ {
		if err := index.InitializeSchema(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := index.Ready(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if writes != 2 {
		t.Fatalf("schema replay wrote %d times", writes)
	}
}

func TestSessionSchemaDriftCannotBeRepairedByOverwrite(t *testing.T) {
	for _, mapping := range []string{
		`{"zasp-runtime-sessions-v1":` + strings.Replace(sessionIndexSchemaJSON, `"dynamic":"strict"`, `"dynamic":true`, 1) + `}`,
		`{"zasp-runtime-events-v1":` + sessionIndexSchemaJSON + `}`,
		`{"zasp-runtime-sessions-v1":` + strings.Replace(sessionIndexSchemaJSON, `"investigation_id":{"type":"keyword"}`, `"investigation_id":{"type":"text"}`, 1) + `}`,
	} {
		index := &SessionIndex{transport: testDriver(t, httpDoerFunc(func(request *http.Request) (*http.Response, error) {
			if request.Method != http.MethodGet || request.URL.Path != "/zasp-runtime-sessions-v1/_mapping" {
				t.Fatal("drift attempted another operation")
			}
			return jsonResponse(200, mapping), nil
		}))}
		if err := index.InitializeSchema(context.Background()); !errors.Is(err, runtimeindex.ErrDrift) {
			t.Fatalf("mapping drift admitted: %v", err)
		}
	}
}

func TestSessionSchemaMappingCoversOnlyFixedSearchAndProvenanceFields(t *testing.T) {
	var definition struct {
		Mappings struct {
			Dynamic    string                       `json:"dynamic"`
			Properties map[string]map[string]string `json:"properties"`
		} `json:"mappings"`
	}
	if json.Unmarshal([]byte(sessionIndexSchemaJSON), &definition) != nil || definition.Mappings.Dynamic != "strict" {
		t.Fatal("schema is not strict")
	}
	for _, field := range []string{"agent_id", "observed_principal_id", "tool_id", "process_digest", "file_digest", "domain_digest", "credential_id", "resource_digest", "decision", "investigation_id", "receipt_digest", "document_id"} {
		if definition.Mappings.Properties[field]["type"] != "keyword" {
			t.Fatalf("not exact keyword: %s", field)
		}
	}
	for _, field := range []string{"content", "command_line", "raw_path", "credential_secret", "query_string"} {
		if _, found := definition.Mappings.Properties[field]; found {
			t.Fatalf("provider content field: %s", field)
		}
	}
	if definition.Mappings.Properties["event_time"]["type"] != "date" || definition.Mappings.Properties["event_time"]["format"] != "strict_date_time" {
		t.Fatal("unbounded event time mapping")
	}
}
