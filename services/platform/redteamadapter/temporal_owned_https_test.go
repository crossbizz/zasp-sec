package redteamadapter

import (
	"context"
	"crypto/sha256"
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

// Invoked by the owned68 PostgreSQL fixture, never a shared database.
func TestTemporalOwnedHTTPS(t *testing.T) {
	dsn := os.Getenv("ZASP_TEMPORAL_JOURNAL_OWNER_DSN")
	if dsn == "" {
		t.Skip("requires owned68 component database")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || net.ParseIP(cfg.Host) == nil || !net.ParseIP(cfg.Host).IsLoopback() {
		t.Fatal("owned loopback required")
	}
	for _, f := range cfg.Fallbacks {
		if net.ParseIP(f.Host) == nil || !net.ParseIP(f.Host).IsLoopback() {
			t.Fatal("foreign fallback")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	owner, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	if os.Getenv("ZASP_TEST74_NATIVE") == "true" {
		var checksum, fingerprint string
		if err := owner.QueryRow(ctx, `SELECT checksum,fingerprint FROM zasp_temporal74.registration WHERE singleton`).Scan(&checksum, &fingerprint); err != nil || checksum != migrations.ProductionTemporalTestExecutor().Checksum() || fingerprint != migrations.TemporalTestExecutorFingerprint() {
			t.Fatalf("test74 subprocess build differs from installed fixture: installed=%s/%s compiled=%s/%s err=%v", checksum, fingerprint, migrations.ProductionTemporalTestExecutor().Checksum(), migrations.TemporalTestExecutorFingerprint(), err)
		}
	}
	cfg = cfg.Copy()
	cfg.User = "ordered_test_red_adapter"
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	mode := os.Getenv("ZASP_TEMPORAL_JOURNAL_MODE")
	database := &temporalLostAckDatabase{ownedJournalDatabase: ownedJournalDatabase{conn}, mode: mode}
	manual := os.Getenv("ZASP_P3C_LEGACY_LINKED") == "true"
	var journal interface {
		TargetResolver
		InvocationJournal
		Ready(context.Context) error
	}
	if manual {
		journal, err = NewLegacyJournalRouter(ctx, database)
	} else if os.Getenv("ZASP_TEST74_NATIVE") == "true" {
		journal, err = NewTestEffectRouter(ctx, database)
	} else {
		journal, err = NewTemporalPostgresJournal(database, migrations.ProductionTemporalExecutor().Checksum(), migrations.TemporalExecutorFingerprint())
	}
	if err != nil || journal.Ready(ctx) != nil {
		t.Fatal("68 journal unavailable", err)
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
	child, key, category := os.Getenv("ZASP_ORDERED_TEST_RUN"), os.Getenv("ZASP_TEMPORAL_EFFECT_KEY"), os.Getenv("ZASP_TEMPORAL_CATEGORY")
	resolution := TargetResolution{Scope: scope, RunID: child, EffectKey: key, TargetID: os.Getenv("ZASP_TEMPORAL_TARGET"), TargetKind: os.Getenv("ZASP_TEMPORAL_KIND"), Category: category}
	if manual {
		resolution.EffectKey = ""
		resolution.LeaseToken = os.Getenv("ZASP_P3C_LEGACY_LEASE")
	}
	binding, err := journal.ResolveTarget(ctx, resolution)
	if err != nil {
		t.Fatal("68 target resolution", err)
	}
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, readErr := io.ReadAll(r.Body)
		digest := sha256.Sum256(body)
		var committed bool
		var err error
		if manual {
			err = owner.QueryRow(ctx, `SELECT count(*)=1 FROM zasp_security_agent_test_invocations WHERE test_run_id=$1 AND category=$2 AND request_digest=$3 AND state='started'`, child, category, digest[:]).Scan(&committed)
		} else if os.Getenv("ZASP_TEST74_NATIVE") == "true" {
			err = owner.QueryRow(ctx, `SELECT count(*)=1 FROM zasp_temporal74.invocations WHERE test_run_id=$1 AND category=$2 AND effect_key=$3 AND request_digest=$4 AND state='started'`, child, category, key, digest[:]).Scan(&committed)
		} else {
			err = owner.QueryRow(ctx, `SELECT count(*)=1 FROM zasp_temporal68.invocations WHERE test_run_id=$1 AND category=$2 AND effect_key=$3 AND request_digest=$4 AND state='started'`, child, category, key, digest[:]).Scan(&committed)
		}
		if readErr != nil || err != nil || !committed {
			t.Error("network before durable exact intent", readErr, err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if os.Getenv("ZASP_TEST74_NATIVE") == "true" && os.Getenv("ZASP_TEST74_UNSAFE") == "true" {
			json.NewEncoder(w).Encode(map[string]string{"output": "ZASP_RED_TEAM_" + strings.ToUpper(category)})
			return
		}
		io.WriteString(w, `{"output":"controlled target refused"}`)
	}))
	defer server.Close()
	credentials := &credentialResolverStub{secret: []byte("0123456789abcdef0123456789abcdef"), destroyed: &atomic.Bool{}}
	invoker, err := newHTTPSInvoker(&http.Client{Transport: newRewriteRoundTripper(t, server)}, credentials, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request := JournalRequest{Invocation: Invocation{Scope: scope, RunID: child, Binding: binding, Category: category, Input: curatedInputs[category]}, EffectKey: key}
	if manual {
		request.EffectKey = ""
		request.LeaseToken = resolution.LeaseToken
	}
	if os.Getenv("ZASP_TEST76_LIVE") == "true" {
		var actor string
		if err := owner.QueryRow(ctx, `SELECT a.requester_id FROM zasp_temporal76.admissions a JOIN zasp_temporal74.run_owners x ON(x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(a.organization_id,a.workspace_id,a.environment_id,a.run_id) WHERE x.test_run_id=$1 AND a.source_kind='resource65' AND x.source_kind='resource65'`, child).Scan(&actor); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE(organization_id,principal_id)=($1,$2)`, scope.OrganizationID().String(), actor); err != nil {
			t.Fatal(err)
		}
		_, deniedErr := invoker.InvokeJournaled(ctx, request, journal)
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=true WHERE(organization_id,principal_id)=($1,$2)`, scope.OrganizationID().String(), actor); err != nil {
			t.Fatal(err)
		}
		if deniedErr == nil || calls.Load() != 0 || credentials.calls != 0 {
			t.Fatal("revoked76 human crossed registered adapter fresh IO", deniedErr, calls.Load(), credentials.calls)
		}
		t.Log("registered adapter refused revoked76 human after target binding:0 credential reads,0 HTTP sends; restored same actor")
	}
	observation, err := invoker.InvokeJournaled(ctx, request, journal)
	if mode == "success" {
		if err != nil || calls.Load() != 1 || observation.CredentialVersionDigest != strings.Repeat("d", 64) {
			t.Fatal("real68 invocation", observation, err, calls.Load())
		}
	} else if err == nil || !database.fired {
		t.Fatal("acknowledgement fault missed", err, database.fired)
	}
	want := int32(1)
	if mode == "lost_start" {
		want = 0
	}
	for i := 0; i < 2; i++ {
		again, err := invoker.InvokeJournaled(ctx, request, journal)
		if mode == "lost_start" {
			if err == nil {
				t.Fatal("unknown start permitted send")
			}
		} else if err != nil || again.CredentialVersionDigest != strings.Repeat("d", 64) {
			t.Fatal("durable completion replay", again, err)
		}
	}
	if calls.Load() != want || credentials.calls != int(want) {
		t.Fatal("duplicate network or credential IO", calls.Load(), credentials.calls, want)
	}
	if (mode == "lost_start" || mode == "lost_complete") && !database.fired {
		t.Fatal("committed acknowledgement loss was not injected")
	}
	protocol := "temporal68"
	if os.Getenv("ZASP_TEST74_NATIVE") == "true" {
		protocol = "single_test74"
	}
	if os.Getenv("ZASP_P3C_LEGACY_LINKED") == "true" {
		protocol = "legacy71"
	}
	t.Logf("%s %s provider_calls=%d credential_reads=%d, component-only TLS", protocol, mode, calls.Load(), credentials.calls)
}

type temporalLostAckDatabase struct {
	ownedJournalDatabase
	mode  string
	fired bool
}

func (d *temporalLostAckDatabase) QueryJSON(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	raw, err := d.ownedJournalDatabase.QueryJSON(ctx, query, args...)
	if err == nil && !d.fired && (query == temporalInvocationSQL || query == `SELECT zasp_temporal74.invocation($1::jsonb)`) && len(args) == 1 {
		body, _ := args[0].([]byte)
		var q map[string]any
		json.Unmarshal(body, &q)
		if d.mode == "lost_start" && q["operation"] == "start" || d.mode == "lost_complete" && q["operation"] == "complete" {
			d.fired = true
			return nil, errors.New("controlled committed acknowledgement loss")
		}
	}
	return raw, err
}
