package redteamadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
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

func TestRelease61OwnedHTTPS(t *testing.T) {
	dsn := os.Getenv("ZASP_ORDERED_JOURNAL_OWNER_DSN")
	if dsn == "" {
		t.Skip("requires owned release61 component database")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || cfg.User != "zasp_e2e" || cfg.Database != "postgres" || net.ParseIP(cfg.Host) == nil || !net.ParseIP(cfg.Host).IsLoopback() {
		t.Fatal("owned loopback required")
	}
	for _, f := range cfg.Fallbacks {
		if net.ParseIP(f.Host) == nil || !net.ParseIP(f.Host).IsLoopback() {
			t.Fatal("foreign fallback")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	owner, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	cfg = cfg.Copy()
	cfg.User = "ordered_test_red_adapter"
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	database := &release61JournalFaultDB{ownedJournalDatabase: ownedJournalDatabase{conn}, fault: os.Getenv("ZASP_RELEASE61_JOURNAL_FAULT")}
	base, err := NewPostgresInvocationJournal(database, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint())
	if err != nil {
		t.Fatal(err)
	}
	journal, err := base.Release61(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]domain.ProductID, 3)
	for i, k := range []string{"ZASP_ORDERED_ORG", "ZASP_ORDERED_WORKSPACE", "ZASP_ORDERED_ENVIRONMENT"} {
		ids[i], err = domain.ParseProductID(os.Getenv(k))
		if err != nil {
			t.Fatal(err)
		}
	}
	scope, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		t.Fatal(err)
	}
	run, lease := os.Getenv("ZASP_ORDERED_TEST_RUN"), os.Getenv("ZASP_ORDERED_LEASE")
	var categories []string
	if json.Unmarshal([]byte(os.Getenv("ZASP_RELEASE61_CATEGORIES")), &categories) != nil || len(categories) == 0 {
		t.Fatal("categories")
	}
	for _, category := range categories {
		database.fault = os.Getenv("ZASP_RELEASE61_JOURNAL_FAULT")
		if selected := os.Getenv("ZASP_RELEASE61_JOURNAL_CATEGORY"); selected != "" && selected != category {
			database.fault = ""
		}
		binding, err := journal.ResolveTarget(ctx, TargetResolution{Scope: scope, RunID: run, LeaseToken: lease, TargetID: os.Getenv("ZASP_RELEASE61_TARGET"), TargetKind: os.Getenv("ZASP_RELEASE61_KIND"), Category: category})
		if err != nil {
			t.Fatal(err)
		}
		var prior int
		if err = owner.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_test_invocations WHERE test_run_id=$1 AND category=$2 AND state='completed'`, run, category).Scan(&prior); err != nil {
			t.Fatal(err)
		}
		var calls atomic.Int32
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			payload, readErr := io.ReadAll(r.Body)
			digest := sha256.Sum256(payload)
			var committed bool
			err := owner.QueryRow(ctx, `SELECT count(*)=1 FROM zasp_security_agent_test_invocations WHERE test_run_id=$1 AND category=$2 AND state='started' AND request_digest=$3`, run, category, digest[:]).Scan(&committed)
			if readErr != nil || err != nil || !committed || r.Header.Get("X-Zasp-Payload-Digest") != "sha256:"+hex.EncodeToString(digest[:]) {
				t.Error("provider before exact journal", readErr, err)
				w.WriteHeader(500)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"output":"controlled target refused"}`)
		}))
		invoker, err := newHTTPSInvoker(&http.Client{Transport: newRewriteRoundTripper(t, server)}, &credentialResolverStub{secret: []byte("0123456789abcdef0123456789abcdef"), destroyed: &atomic.Bool{}}, time.Second)
		if err != nil {
			server.Close()
			t.Fatal(err)
		}
		request := JournalRequest{Invocation: Invocation{Scope: scope, RunID: run, Category: category, Input: curatedInputs[category], Binding: binding}, LeaseToken: lease}
		observation, err := invoker.InvokeJournaled(ctx, request, journal)
		if database.fault != "" {
			server.Close()
			wantCalls := int32(0)
			if database.fault == "complete" {
				wantCalls = 1
			}
			if err == nil || !database.fired || calls.Load() != wantCalls {
				t.Fatal("journal fault boundary not reached", err, database.fired, calls.Load())
			}
			t.Logf("release61 journal fault joined: %s provider_calls=%d", database.fault, calls.Load())
			return
		}
		if err != nil || observation.Protected == nil || !*observation.Protected || calls.Load() != int32(1-prior) {
			server.Close()
			t.Fatal("journaled component invocation", err, calls.Load(), prior)
		}
		replay, err := invoker.InvokeJournaled(ctx, request, journal)
		server.Close()
		if err != nil || replay.ResponseDigest != observation.ResponseDigest || calls.Load() != int32(1-prior) {
			t.Fatal("completed journal resent", err, calls.Load())
		}
		t.Logf("release61 category joined: %s provider_calls=%d component-only TLS", category, calls.Load())
	}
}

type release61JournalFaultDB struct {
	ownedJournalDatabase
	fault string
	fired bool
}

func (d *release61JournalFaultDB) QueryJSON(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	raw, err := d.ownedJournalDatabase.QueryJSON(ctx, query, args...)
	if err == nil && !d.fired && d.fault != "" && strings.Contains(query, ".test_invocation_"+d.fault+"(") {
		d.fired = true
		return nil, errors.New("controlled journal acknowledgement loss")
	}
	return raw, err
}
