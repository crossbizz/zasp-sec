package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOptionalIntentClassifierUsesBoundedMetadataAndDraftCodes(t *testing.T) {
	t.Setenv("ZASP_INTENT_CLASSIFIER_ENABLED", "")
	t.Setenv("ZASP_INTENT_CLASSIFIER_KEY_FILE", filepath.Join(t.TempDir(), "test-key"))
	if configuredIntentClassifier() != nil {
		t.Fatal("provider enabled without deployment consent")
	}
	t.Setenv("ZASP_INTENT_CLASSIFIER_ENABLED", "true")
	client := configuredIntentClassifier().(*openRouterIntentClassifier)
	transport := &securityAgentPlannerTransport{responseStatus: 200}
	client.client.Transport = transport
	if _, err := client.Classify(context.Background(), intentFeatures{Destination: "internal"}); err == nil || transport.calls != 0 {
		t.Fatal("contacted provider without credentials")
	}
	token := "sk-or-v1-" + strings.Repeat("x", 32)
	if err := os.WriteFile(client.tokenPath, []byte(token), 0400); err != nil {
		t.Fatal(err)
	}
	content := func(answer string) []byte {
		reply := map[string]any{"model": intentModel, "choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": answer}}}}
		blob, _ := json.Marshal(reply)
		return blob
	}
	transport.responseBody = content(`{"recommendation":"review_destination"}`)
	f := intentFeatures{Destination: "external", DestinationMismatch: true}
	code, err := client.Classify(t.Context(), f)
	if err != nil || code != "review_destination" || transport.request.URL.String() != intentEndpoint || transport.request.Header.Get("Authorization") != "Bearer "+token {
		t.Fatalf("classification = %s, %v", code, err)
	}
	var sent securityAgentOpenRouterRequest
	if err := json.Unmarshal(transport.requestBody, &sent); err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(f)
	if len(sent.Messages) != 2 || sent.Messages[1].Content != string(want) || bytes.Contains(transport.requestBody, []byte(token)) || sent.Provider.DataCollection != "deny" || !sent.Provider.RequireParameters {
		t.Fatalf("unexpected provider boundary %s", transport.requestBody)
	}
	for _, result := range []string{`{"recommendation":"block"}`, `{"recommendation":"none","policy":"active"}`, `{"recommendation":"none","recommendation":"review_purpose"}`, strings.Repeat("X", 8193)} {
		transport.responseBody = content(result)
		if value, err := client.Classify(t.Context(), f); err == nil || value != "" {
			t.Fatal("unreviewed or malformed answer")
		}
	}
	calls := transport.calls
	if _, err := client.Classify(t.Context(), intentFeatures{Destination: "private.example.org"}); err == nil || transport.calls != calls {
		t.Fatal("unbounded destination reached provider")
	}
	transport.err = errors.New("upstream unavailable")
	if value, err := client.Classify(t.Context(), f); err == nil || value != "" {
		t.Fatal("outage produced a draft")
	}
	if err := client.client.CheckRedirect(nil, []*http.Request{}); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatal("provider credentials could follow a redirect")
	}
}
