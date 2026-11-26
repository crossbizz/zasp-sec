package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/infraprovider"
)

func TestInfrastructureProviderConfigCheckRejectsUnsupportedQueue(t *testing.T) {
	env := map[string]string{"ZASP_QUEUE_PROVIDER": "mistakenly-pasted-secret"}
	lookup := func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
	var output bytes.Buffer
	handled, err := runConfigurationCommand([]string{"--check-config"}, lookup, &output)
	var selection *infraprovider.SelectionError
	if !handled || !errors.As(err, &selection) {
		t.Fatalf("unsupported selection did not reach check-config: %v", err)
	}
	if text := output.String(); !strings.Contains(text, "ZASP_QUEUE_PROVIDER") || !strings.Contains(text, "sqs") || strings.Contains(text, env["ZASP_QUEUE_PROVIDER"]) {
		t.Fatal("check-config must explain the refusal without echoing input")
	}
}
