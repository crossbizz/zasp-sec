package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

func testOrderedHTTPRuntimeConfig(t *testing.T, values map[string]string) {
	t.Helper()
	for _, value := range []string{"", "false", "true", "0", "1", "FALSE", "TRUE", "enabled", " true", "true ", "yes"} {
		selected := mapsClone(values)
		selected["ZASP_SECURITY_AGENT_ORDERED_HTTP_ENABLED"] = value
		config, err := loadRuntimeConfig(func(key string) string { return selected[key] })
		valid := value == "" || value == "false" || value == "true" || value == "0" || value == "1" || value == "FALSE" || value == "TRUE"
		if (err == nil) != valid {
			t.Fatalf("ordered HTTP flag %q: %v", value, err)
		}
		if !valid {
			continue
		}
		if config.SecurityAgentOrderedHTTPEnabled != (value == "true" || value == "1" || value == "TRUE") {
			t.Fatalf("ordered HTTP flag %q enabled=%t", value, config.SecurityAgentOrderedHTTPEnabled)
		}
	}
}

type orderedHTTPVerifierDatabase struct {
	apiserver.JSONDatabase
	ctx context.Context
	err error
}

func (d *orderedHTTPVerifierDatabase) VerifySecurityAgentOrderedHTTPRelease(ctx context.Context) error {
	d.ctx = ctx
	return d.err
}

func TestOrderedHTTPTracingVerifier(t *testing.T) {
	for _, failure := range []error{nil, errors.New("private SQL error"), context.Canceled, context.DeadlineExceeded} {
		next := &orderedHTTPVerifierDatabase{err: failure}
		db := &tracedJSONDatabase{next: next}
		v, ok := any(db).(apiserver.SecurityAgentOrderedHTTPReleaseVerifier)
		if !ok {
			t.Fatal("tracing drops ordered HTTP verifier")
		}
		ctx, cancel := context.WithCancel(context.Background())
		err := v.VerifySecurityAgentOrderedHTTPRelease(ctx)
		if (err == nil) != (failure == nil) || err != nil && err != apiserver.ErrRepositoryUnavailable {
			t.Fatal(err)
		}
		if next.ctx == nil {
			t.Fatal("verifier not forwarded")
		}
		cancel()
		if next.ctx.Err() != context.Canceled {
			t.Fatal("cancellation lost")
		}
		if err := v.VerifySecurityAgentOrderedHTTPRelease(ctx); err != apiserver.ErrRepositoryUnavailable {
			t.Fatal("canceled verifier", err)
		}
	}
	for _, db := range []*tracedJSONDatabase{nil, {}, {next: &orderedHTTPVerifierDatabase{}}} {
		v, ok := any(db).(apiserver.SecurityAgentOrderedHTTPReleaseVerifier)
		if !ok {
			t.Fatal("verifier absent")
		}
		if err := v.VerifySecurityAgentOrderedHTTPRelease(nil); err != apiserver.ErrRepositoryUnavailable {
			t.Fatal(err)
		}
	}
}

func TestOrderedHTTPRuntimeCompositionRequiresAuthority(t *testing.T) {
	t.Setenv("HOSTNAME", "ordered-composition-test")
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("composition made remote request") }))
	defer server.Close()
	for _, enabled := range []bool{false, true} {
		config := fixtureRuntimeConfig()
		config.Environment = "test"
		config.PolicyHistoryEndpoint = server.URL
		config.SecurityAgentOrderedHTTPEnabled = enabled
		db := &sessionCompositionDatabase{}
		dependencies, err := composeRuntimeDependencies(config, db, apiserver.CallbackProviderFunc(func(context.Context, string, string) (apiserver.SessionGrant, error) {
			t.Fatal("composition called identity provider")
			return apiserver.SessionGrant{}, nil
		}))
		if enabled && err != errRuntimeUnavailable || !enabled && err != nil {
			t.Fatalf("enabled=%t err=%v", enabled, err)
		}
		if enabled && dependencies.ProductHandler != nil {
			t.Fatal("enabled flag reached legacy-only product")
		}
		for _, closer := range dependencies.Closers {
			if err := closer.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
}
