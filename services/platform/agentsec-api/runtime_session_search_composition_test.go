package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type sessionCompositionDatabase struct {
	boundaryDatabase
	events    []string
	arguments []any
	gate      json.RawMessage
	gateErr   error
	composed  bool
}

func (database *sessionCompositionDatabase) SchemaVersion(context.Context) (string, error) {
	database.events = append(database.events, "schema")
	return apiserver.ReferenceSchemaVersion, nil
}

const sessionCompositionGateSQL = `SELECT to_jsonb(zasp_production_runtime_sandbox_binding_readiness($1,$2))`

func (database *sessionCompositionDatabase) QueryJSON(_ context.Context, query string, arguments ...any) (json.RawMessage, error) {
	database.events = append(database.events, query)
	if !database.composed && (query == `SELECT to_jsonb(zasp_connector_readiness($1,$2))` || query == `SELECT to_jsonb(zasp_reference_authorization_readiness($1,$2))` || query == `SELECT to_jsonb(zasp_discovery_principal_ready($1))`) {
		return json.RawMessage(`true`), nil
	}
	if query == sessionCompositionGateSQL {
		database.arguments = append([]any(nil), arguments...)
		return database.gate, database.gateErr
	}
	return nil, errors.New("stop at the first legacy repository operation")
}

// Replacing the configured repository selector with the default constructor
// must fail here, even if the separately constructed provider still selects v2.
func TestRuntimeSessionSearchCompositionSelectsRepositoryAuthority(t *testing.T) {
	for _, item := range []struct {
		name, index, gate string
		gateErr           error
		passesGate        bool
	}{
		{name: "default", index: ""},
		{name: "explicit v1", index: "zasp-runtime-sessions-v1"},
		{name: "v2 ready", index: "zasp-runtime-sessions-v2", gate: "true", passesGate: true},
		{name: "v2 denied", index: "zasp-runtime-sessions-v2", gate: "false"},
		{name: "v2 malformed", index: "zasp-runtime-sessions-v2", gate: `{"ready":true}`},
		{name: "v2 missing", index: "zasp-runtime-sessions-v2", gateErr: errors.New("function missing")},
	} {
		t.Run(item.name, func(t *testing.T) {
			t.Setenv("HOSTNAME", "session-composition-test")
			var providerCalls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				providerCalls.Add(1)
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			defer server.Close()
			config := fixtureRuntimeConfig()
			config.Environment, config.PolicyHistoryEndpoint, config.RuntimeSessionIndex = "test", server.URL, item.index
			database := &sessionCompositionDatabase{gate: json.RawMessage(item.gate), gateErr: item.gateErr}
			dependencies, err := composeRuntimeDependencies(config, database, apiserver.CallbackProviderFunc(func(context.Context, string, string) (apiserver.SessionGrant, error) {
				providerCalls.Add(1)
				return apiserver.SessionGrant{}, errors.New("identity provider must not be called")
			}))
			if err != nil {
				t.Fatal("compose actual production dependencies", err)
			}
			database.composed = true
			defer func() {
				for _, closer := range dependencies.Closers {
					if err := closer.Close(); err != nil {
						t.Error(err)
					}
				}
			}()
			for attempt := 0; attempt < 2; attempt++ {
				database.events, database.arguments = nil, nil
				if err := dependencies.ReadinessCheck(context.Background()); !errors.Is(err, errRuntimeUnavailable) {
					t.Fatal("boundary failure did not stop readiness", err)
				}
				if item.index == "zasp-runtime-sessions-v2" {
					if len(database.events) == 0 || database.events[0] != sessionCompositionGateSQL {
						t.Fatal("configured v2 did not gate repository readiness first", database.events)
					}
					wantArguments := []any{migrations.ProductionRuntimeSandboxBinding().Checksum(), migrations.ProductionRuntimeSandboxBindingSemanticFingerprint()}
					if !reflect.DeepEqual(database.arguments, wantArguments) {
						t.Fatal("readiness did not use compiled release50 pins", database.arguments)
					}
					if !item.passesGate && len(database.events) != 1 {
						t.Fatal("rejected v2 readiness fell back or continued", database.events)
					}
					if item.passesGate && (len(database.events) < 2 || database.events[1] != "schema") {
						t.Fatal("accepted v2 readiness did not continue through repository", database.events)
					}
				} else {
					if len(database.events) < 2 || database.events[0] != "schema" || database.arguments != nil {
						t.Fatal("legacy selector changed readiness authority", database.events)
					}
				}
				if providerCalls.Load() != 0 {
					t.Fatal("repository readiness failure reached a provider", providerCalls.Load())
				}
			}
		})
	}
}

// Omitting sessionSearch.Close must leave this real keep-alive socket open.
func TestProductionPolicyHistoryClosesIdleSessionSearchConnection(t *testing.T) {
	type stateChange struct {
		connection net.Conn
		state      http.ConnState
	}
	states := make(chan stateChange, 16)
	requests := make(chan string, 2)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"missing"}`))
	}))
	server.Config.ConnState = func(connection net.Conn, state http.ConnState) { states <- stateChange{connection, state} }
	server.Start()
	defer server.Close()
	config := fixtureRuntimeConfig()
	config.Environment, config.PolicyHistoryEndpoint, config.RuntimeSessionIndex = "test", server.URL, "zasp-runtime-sessions-v2"
	history, err := newProductionPolicyHistory(config)
	if err != nil {
		t.Fatal(err)
	}
	defer history.Close()
	if err := history.sessionSearch.Ready(context.Background()); err == nil {
		t.Fatal("missing mapping accepted")
	}
	select {
	case path := <-requests:
		if path != "/zasp-runtime-sessions-v2/_mapping" {
			t.Fatal("wrong session transport request", path)
		}
	default:
		t.Fatal("session transport made no request")
	}
	var idle net.Conn
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for idle == nil {
		select {
		case event := <-states:
			if event.state == http.StateIdle {
				idle = event.connection
			}
		case <-timer.C:
			t.Fatal("session transport did not retain an idle connection")
		}
	}
	if err := history.Close(); err != nil {
		t.Fatal(err)
	}
	for {
		select {
		case event := <-states:
			if event.connection == idle && event.state == http.StateClosed {
				return
			}
		case <-timer.C:
			t.Fatal("policy history Close left its idle session-search socket open")
		}
	}
}
