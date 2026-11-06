package connectormaintenancecutover

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const readbackModelID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

// This roster is the existing descriptor-reviewed runtime-adapter contract.
// Pin it independently so adding a permissive omission requires explicit review.
func reviewedResponse(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile("readback_defaults.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != "d4c42d89fa77b89513e732b6d5bdd206c808111096307d38784cc6f1ba639835" {
		t.Fatal("reviewed roster changed")
	}
	var rows []struct {
		Segments []any `json:"segments"`
		Default  any   `json:"default"`
	}
	var model map[string]any
	if json.Unmarshal(data, &rows) != nil || len(rows) != 312 || json.Unmarshal(productModel, &model) != nil {
		t.Fatal("invalid reviewed contract")
	}
	for _, row := range rows {
		var parent any = model
		for _, part := range row.Segments[:len(row.Segments)-1] {
			switch key := part.(type) {
			case string:
				parent = parent.(map[string]any)[key]
			case float64:
				parent = parent.([]any)[int(key)]
			default:
				t.Fatal("invalid fixed path")
			}
		}
		key := row.Segments[len(row.Segments)-1].(string)
		if _, exists := parent.(map[string]any)[key]; exists {
			t.Fatal("default overwrites product field")
		}
		parent.(map[string]any)[key] = row.Default
	}
	model["id"] = readbackModelID
	return map[string]any{"authorization_model": model}
}

func TestControlledModelReadbackCompatibility(t *testing.T) {
	for _, mutation := range []string{"reviewed defaults", "unknown model field", "unknown nested field", "nondefault metadata", "changed relation", "changed condition", "wrong id", "type order"} {
		t.Run(mutation, func(t *testing.T) {
			response := reviewedResponse(t)
			model := response["authorization_model"].(map[string]any)
			types := model["type_definitions"].([]any)
			switch mutation {
			case "unknown model field":
				model["future"] = nil
			case "unknown nested field":
				types[0].(map[string]any)["future"] = nil
			case "nondefault metadata":
				types[0].(map[string]any)["metadata"] = map[string]any{}
			case "changed relation":
				types[0].(map[string]any)["relations"] = map[string]any{"member": map[string]any{"this": map[string]any{}}}
			case "changed condition":
				model["conditions"].(map[string]any)["task_bound"].(map[string]any)["expression"] = "true"
			case "wrong id":
				model["id"] = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
			case "type order":
				types[0], types[1] = types[1], types[0]
			}
			raw, _ := json.Marshal(response)
			err := wholeRawModel(raw, productModel, readbackModelID)
			if (err == nil) != (mutation == "reviewed defaults") {
				t.Fatalf("unexpected acceptance: %v", err)
			}
		})
	}
	for _, raw := range []string{`{"authorization_model":{},"authorization_model":{}}`, `{} {}`, strings.Repeat("[", 66) + strings.Repeat("]", 66), string([]byte{0xff}), strings.Repeat(" ", (1<<20)+1)} {
		if wholeRawModel([]byte(raw), productModel, readbackModelID) == nil {
			t.Fatal("ambiguous/unbounded response accepted")
		}
	}
}

func TestControlledModelSDKReadbackBoundary(t *testing.T) {
	response, _ := json.Marshal(reviewedResponse(t))
	old := "old-controlled-credential"
	next := "new-controlled-credential"
	var withdrawn atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/stores/"+readbackModelID+"/authorization-models/"+readbackModelID {
			t.Error("unexpected endpoint")
			w.WriteHeader(404)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+next && (withdrawn.Load() || r.Header.Get("Authorization") != "Bearer "+old) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			w.Write([]byte(`{"code":"unauthenticated","message":"refused"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(response)
	}))
	defer server.Close()
	root := t.TempDir()
	for name, value := range map[string]string{"old": old, "new": next} {
		if os.WriteFile(filepath.Join(root, name), []byte(value), 0600) != nil {
			t.Fatal("credential fixture unavailable")
		}
	}
	evidence, err := newEvidence(server.URL, readbackModelID, readbackModelID, filepath.Join(root, "old"), filepath.Join(root, "new"))
	if err != nil {
		t.Fatal(err)
	}
	defer evidence.close()
	if evidence.oldModel(context.Background()) != nil || evidence.newModel(context.Background()) != nil {
		t.Fatal("reviewed defaults rejected before or after SDK decoding")
	}
	withdrawn.Store(true)
	if evidence.oldUnauthorized(context.Background()) != nil || evidence.newModel(context.Background()) != nil {
		t.Fatal("credential withdrawal boundary changed")
	}
}

func TestControlledModelReadbackRejectsAlteredDefaults(t *testing.T) {
	data, err := os.ReadFile("readback_defaults.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Segments []any `json:"segments"`
	}
	if json.Unmarshal(data, &rows) != nil {
		t.Fatal("invalid fixed roster")
	}
	for index, row := range rows {
		response := reviewedResponse(t)
		var parent any = response["authorization_model"]
		for _, part := range row.Segments[:len(row.Segments)-1] {
			switch key := part.(type) {
			case string:
				parent = parent.(map[string]any)[key]
			case float64:
				parent = parent.([]any)[int(key)]
			}
		}
		parent.(map[string]any)[row.Segments[len(row.Segments)-1].(string)] = map[string]any{"unreviewed": true}
		raw, _ := json.Marshal(response)
		if wholeRawModel(raw, productModel, readbackModelID) == nil {
			t.Fatalf("altered reviewed path %d accepted", index)
		}
	}
	response, _ := json.Marshal(reviewedResponse(t))
	if wholeRawModel(response, append(append([]byte{}, productModel...), '\n'), readbackModelID) == nil {
		t.Fatal("roster accepted an unpinned product source")
	}
}
