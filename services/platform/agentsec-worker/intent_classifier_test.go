package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/aigateway"
)

type intentStub struct {
	output string
	calls  int
}

func (s *intentStub) Evaluate(_ context.Context, p aigateway.Purpose, r json.RawMessage) (json.RawMessage, error) {
	s.calls++
	var fields map[string]any
	if p != aigateway.PurposeAlignment || json.Unmarshal(r, &fields) != nil || len(fields) != 6 {
		return nil, errors.New("unexpected request")
	}
	return json.RawMessage(s.output), nil
}

func TestPrivateIntentClassifierConfig(t *testing.T) {
	t.Setenv("ZASP_INTENT_CLASSIFIER_ENABLED", "true")
	t.Setenv("ZASP_INTENT_CLASSIFIER_MODEL", aigateway.ModelShieldstral)
	t.Setenv("ZASP_INTENT_CLASSIFIER_RESIDENCY", "eu")
	t.Setenv("ZASP_INTENT_CLASSIFIER_MAX_NANO_CREDITS", "123")
	t.Setenv("ZASP_INTENT_CLASSIFIER_PRIVATE_IP", "10.3.4.5")
	t.Setenv("ZASP_INTENT_CLASSIFIER_WEIGHTS_SHA256", strings.Repeat("a", 64))
	t.Setenv("ZASP_INTENT_CLASSIFIER_ENDPOINT", "https://inference.internal/v1/chat/completions")
	if c := configuredIntentClassifier(); c == nil || len(c.deployment) != 71 {
		t.Fatal("missing private deployment")
	}
	for _, invalid := range [][2]string{{"ENABLED", "false"}, {"MODEL", "unrecognized"}, {"RESIDENCY", "any"}, {"PRIVATE_IP", "192.0.2.1"}, {"ENDPOINT", "http://inference.internal/v1/chat/completions"}, {"MAX_NANO_CREDITS", "0"}, {"WEIGHTS_SHA256", "unpinned"}} {
		t.Run(invalid[0], func(t *testing.T) {
			t.Setenv("ZASP_INTENT_CLASSIFIER_"+invalid[0], invalid[1])
			if configuredIntentClassifier() != nil {
				t.Fatal("accepted invalid profile")
			}
		})
	}
}
func TestPrivateIntentDraftIsOnlyAReviewCode(t *testing.T) {
	driver := &intentStub{}
	c := privateIntentClassifier{driver: driver}
	features := intentFeatures{Destination: "external", DestinationMismatch: true}
	driver.output = `{"verdict":"drift","violated_clause":"destination","confidence":0.9}`
	if got, err := c.Classify(t.Context(), features); err != nil || got != "review_destination" {
		t.Fatal(got, err)
	}
	for _, bad := range []string{`{"verdict":"drift","violated_clause":"none","confidence":1}`, `{"verdict":"uncertain","violated_clause":"none","confidence":0}`, `{}`, `{"verdict":"aligned","verdict":"drift","violated_clause":"purpose","confidence":1}`} {
		driver.output = bad
		if got, err := c.Classify(t.Context(), features); err == nil || got != "" {
			t.Fatal("accepted ambiguous output", got)
		}
	}
	calls := driver.calls
	if _, err := c.Classify(t.Context(), intentFeatures{Destination: "raw host"}); err == nil || driver.calls != calls {
		t.Fatal("raw destination reached driver")
	}
}
