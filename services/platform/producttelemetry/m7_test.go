package producttelemetry

import (
	"context"
	"testing"
	"time"
)

func TestProductEventSerializerAndFlagFallback(t *testing.T) {
	record, err := SerializeProductEvent(ProductEvent{Name: "screen_viewed", Fields: map[string]string{"screen": "sessions", "surface": "product"}})
	if err != nil || record["screen"] != "sessions" {
		t.Fatalf("record=%+v err=%v", record, err)
	}
	for _, field := range []string{"prompt", "tool_args", "secret", "ip", "raw_evidence"} {
		if _, err := SerializeProductEvent(ProductEvent{Name: "screen_viewed", Fields: map[string]string{field: "sensitive"}}); err == nil {
			t.Fatalf("accepted %s", field)
		}
	}
	cache := NewFlagCache(map[string]bool{"ai_explanations": false}, time.Minute)
	if value := cache.Resolve(context.Background(), "ai_explanations", func(context.Context, string) (bool, error) { return true, nil }, time.Now().UTC()); !value {
		t.Fatal("fresh provider value rejected")
	}
	if value := cache.Resolve(context.Background(), "ai_explanations", func(context.Context, string) (bool, error) { return false, ErrCapture }, time.Now().UTC().Add(2*time.Minute)); value {
		t.Fatal("outage did not return deterministic default")
	}
}
