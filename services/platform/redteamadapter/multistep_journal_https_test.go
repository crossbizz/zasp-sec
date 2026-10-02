package redteamadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// The apiserver parent creates application evidence, approval, the successor
// lease and dispatch through real private repositories. This child owns only a
// controlled TLS target and registered adapter connection, not fixture receipts.
func TestOrderedJournalOwnedHTTPS(t *testing.T) {
	dsn := os.Getenv("ZASP_ORDERED_JOURNAL_OWNER_DSN")
	if dsn == "" {
		t.Skip("requires owned release61 PostgreSQL fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	owner, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	config := owner.Config().Copy()
	config.User = "ordered_test_red_adapter"
	adapter, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close(ctx)
	ids := make([]domain.ProductID, 3)
	for index, key := range []string{"ZASP_ORDERED_ORG", "ZASP_ORDERED_WORKSPACE", "ZASP_ORDERED_ENVIRONMENT"} {
		ids[index], err = domain.ParseProductID(os.Getenv(key))
		if err != nil {
			t.Fatal(err)
		}
	}
	scope, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		t.Fatal(err)
	}
	run := os.Getenv("ZASP_ORDERED_TEST_RUN")
	newClient := func(connection *pgx.Conn) *PostgresInvocationJournal {
		base, err := NewPostgresInvocationJournal(ownedJournalDatabase{connection}, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint())
		if err != nil {
			t.Fatal(err)
		}
		if base.Ready(ctx) == nil {
			t.Fatal("historical journal accepted61")
		}
		client, err := base.ordered()
		if err != nil || client.Ready(ctx) != nil {
			t.Fatal("private ordered journal unavailable", err)
		}
		return client
	}
	client := newClient(adapter)
	lease := os.Getenv("ZASP_ORDERED_LEASE")
	if lease == "" {
		lease = strings.Repeat("a", 32)
	}
	binding, err := client.ResolveTarget(ctx, TargetResolution{Scope: scope, RunID: run, LeaseToken: lease, TargetID: "pid_89000011-0000-4000-8000-000000000001", TargetKind: "agent_endpoint", Category: "prompt_injection"})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	response := `{"output":"controlled target refused"}`
	unknown := os.Getenv("ZASP_ORDERED_UNKNOWN") == "1"
	reproduced := os.Getenv("ZASP_ORDERED_REPRODUCED") == "1"
	if unknown {
		response = `{"output":null}`
	}
	if reproduced {
		response = `{"output":"ZASP_RED_TEAM_PROMPT_INJECTION"}`
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		payload, readErr := io.ReadAll(r.Body)
		digest := sha256.Sum256(payload)
		var committed bool
		err := owner.QueryRow(ctx, `SELECT count(*)=1 FROM zasp_security_agent_test_invocations WHERE test_run_id=$1 AND category='prompt_injection' AND state='started' AND request_digest=$2`, run, digest[:]).Scan(&committed)
		if readErr != nil || err != nil || !committed || r.Header.Get("X-Zasp-Payload-Digest") != "sha256:"+hex.EncodeToString(digest[:]) {
			t.Errorf("provider reached without committed exact start: %v %v %v", committed, readErr, err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, response)
	}))
	defer server.Close()
	invoker, err := newHTTPSInvoker(&http.Client{Transport: newRewriteRoundTripper(t, server)}, &credentialResolverStub{secret: []byte("0123456789abcdef0123456789abcdef"), destroyed: &atomic.Bool{}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request := JournalRequest{Invocation: Invocation{Scope: scope, RunID: run, Category: "prompt_injection", Input: curatedInputs["prompt_injection"], Binding: binding}, LeaseToken: lease}
	if _, err = invoker.InvokeJournaled(ctx, request, ownedLostAckJournal{client}); err == nil || calls.Load() != 1 {
		t.Fatal("lost completion acknowledgement reported success", err, calls.Load())
	}
	restart, err := pgx.ConnectConfig(ctx, config.Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer restart.Close(ctx)
	observation, err := invoker.InvokeJournaled(ctx, request, newClient(restart))
	if unknown {
		if err == nil || calls.Load() != 1 {
			t.Fatal("unknown outcome retried provider", err, calls.Load())
		}
		return
	}
	if err != nil || observation.Protected == nil || *observation.Protected == reproduced || observation.CredentialVersionDigest != strings.Repeat("d", 64) || calls.Load() != 1 {
		t.Fatal("restart lost terminal observation or resent provider", err, observation, calls.Load())
	}
	if os.Getenv("ZASP_ORDERED_MIXED") == "1" {
		var toolCalls atomic.Int32
		toolServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			toolCalls.Add(1)
			payload, err := io.ReadAll(r.Body)
			digest := sha256.Sum256(payload)
			var committed bool
			var document map[string]any
			if err != nil || json.Unmarshal(payload, &document) != nil || document["category"] != "tool_abuse" {
				t.Error("tool invocation payload changed")
			}
			if err = owner.QueryRow(ctx, `SELECT count(*)=1 FROM zasp_security_agent_test_invocations WHERE test_run_id=$1 AND category='tool_abuse' AND state='started' AND request_digest=$2`, run, digest[:]).Scan(&committed); err != nil || !committed {
				t.Error("tool request before journal", err)
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"output":"ZASP_RED_TEAM_TOOL_ABUSE"}`)
		}))
		defer toolServer.Close()
		binding, err := client.ResolveTarget(ctx, TargetResolution{Scope: scope, RunID: run, LeaseToken: lease, TargetID: "pid_89000011-0000-4000-8000-000000000001", TargetKind: "agent_endpoint", Category: "tool_abuse"})
		if err != nil {
			t.Fatal(err)
		}
		toolInvoker, err := newHTTPSInvoker(&http.Client{Transport: newRewriteRoundTripper(t, toolServer)}, &credentialResolverStub{secret: []byte("0123456789abcdef0123456789abcdef"), destroyed: &atomic.Bool{}}, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		toolRequest := JournalRequest{Invocation: Invocation{Scope: scope, RunID: run, Category: "tool_abuse", Input: curatedInputs["tool_abuse"], Binding: binding}, LeaseToken: lease}
		if _, err = toolInvoker.InvokeJournaled(ctx, toolRequest, ownedLostAckJournal{client}); err == nil || toolCalls.Load() != 1 {
			t.Fatal("tool lost ack failed", err)
		}
		got, err := toolInvoker.InvokeJournaled(ctx, toolRequest, newClient(restart))
		if err != nil || got.Protected == nil || *got.Protected || toolCalls.Load() != 1 {
			t.Fatal("mixed outcome replay changed", got, err)
		}
	}
}
