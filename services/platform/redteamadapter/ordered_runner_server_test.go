package redteamadapter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	fga "github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

type orderedRunnerJournalDatabase struct{ pool *pgxpool.Pool }

func (d orderedRunnerJournalDatabase) QueryJSON(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	var value json.RawMessage
	err := d.pool.QueryRow(ctx, query, args...).Scan(&value)
	return value, err
}

type orderedRunnerTargetTransport struct{ next http.RoundTripper }

func (t orderedRunnerTargetTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != "POST" || r.URL.String() != "https://adapter.customer.example/v1/evaluate" {
		return nil, ErrAdapter
	}
	return t.next.RoundTrip(r)
}

// A separate test process makes the actual handler/journal/HTTPSInvoker
// available to the pinned engine without exporting production test seams.
// Only the customer endpoint and secret material are controlled fixtures.
func TestP7OrderedRunnerAdapterServer(t *testing.T) {
	dsn := os.Getenv("ZASP_P7_ORDERED_OWNER_DSN")
	if dsn == "" {
		t.Skip("owned Ordered runner parent required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var pins runtimeservices.Config
	if json.Unmarshal([]byte(os.Getenv("ZASP_P7_ORDERED_CONFIG")), &pins) != nil || pins.FGAURL != "http://127.0.0.1:8088" {
		t.Fatal("owned FGA pins required")
	}
	run := os.Getenv("ZASP_P7_ORDERED_PARENT")
	postAdapter := os.Getenv("ZASP_P7_ORDERED_POST_ADAPTER")
	if postAdapter != "" && postAdapter != "test-response-revoked" && postAdapter != "test-disconnected" {
		t.Fatal("unknown controlled customer boundary")
	}
	directory := os.Getenv("ZASP_P7_ORDERED_ADAPTER_DIRECTORY")
	if !filepath.IsAbs(directory) || run == "" {
		t.Fatal("owned adapter coordinates required")
	}
	poolFor := func(login string) *pgxpool.Pool {
		cfg, err := pgxpool.ParseConfig(dsn)
		if err != nil || net.ParseIP(cfg.ConnConfig.Host) == nil || !net.ParseIP(cfg.ConnConfig.Host).IsLoopback() {
			t.Fatal("owned loopback database required")
		}
		for _, fallback := range cfg.ConnConfig.Fallbacks {
			if net.ParseIP(fallback.Host) == nil || !net.ParseIP(fallback.Host).IsLoopback() {
				t.Fatal("foreign database fallback")
			}
		}
		if login != "" {
			cfg.ConnConfig.User = login
		}
		cfg.MaxConns = 2
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal("owned pool", err)
		}
		t.Cleanup(pool.Close)
		return pool
	}
	owner := poolFor("")
	var adapterLogin string
	if err := owner.QueryRow(ctx, `SELECT principal_name FROM public.zasp_red_team_principal_bindings WHERE authority_role='zasp_red_team_adapter'`).Scan(&adapterLogin); err != nil || adapterLogin == "" {
		t.Fatal("actual registered adapter login", err)
	}
	adapter, comp := poolFor(adapterLogin), poolFor("temporal_compensation_test_login")
	data, err := exec.CommandContext(ctx, "docker", "inspect", "zasp-runtime-services-openfga-1").Output()
	if err != nil {
		t.Fatal("owned FGA service unavailable")
	}
	var containers []struct{ Config struct{ Env []string } }
	if json.Unmarshal(data, &containers) != nil || len(containers) != 1 {
		t.Fatal("owned FGA service identity")
	}
	token := ""
	for _, entry := range containers[0].Config.Env {
		if strings.HasPrefix(entry, "OPENFGA_AUTHN_PRESHARED_KEYS=") {
			token = strings.TrimPrefix(entry, "OPENFGA_AUTHN_PRESHARED_KEYS=")
		}
	}
	if token == "" || strings.Contains(token, ",") {
		t.Fatal("owned FGA credential missing")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	t.Cleanup(transport.CloseIdleConnections)
	client, err := fga.NewSdkClient(&fga.ClientConfiguration{ApiUrl: pins.FGAURL, Credentials: &credentials.Credentials{Method: credentials.CredentialsMethodApiToken, Config: &credentials.Config{ApiToken: token}}, HTTPClient: &http.Client{Transport: transport, Timeout: 5 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	checker, err := authorization.NewOpenFGA(client, pins)
	if err != nil {
		t.Fatal(err)
	}
	forwardKey, _ := authorization.NewWorkerKey(authorization.WorkerForward, bytes.Repeat([]byte{91}, 32))
	compKey, _ := authorization.NewWorkerKey(authorization.CapturedCompensation, bytes.Repeat([]byte{92}, 32))
	forward, err := authorization.NewWorkerAdapter(adapter, checker, pins.StoreID, pins.ModelID, forwardKey)
	if err != nil {
		t.Fatal(err)
	}
	compensation, err := authorization.NewWorkerExecutor(comp, nil, "", "", compKey)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := NewWorkerOrderedTestPostgresJournal(orderedRunnerJournalDatabase{adapter}, migrations.ProductionTemporalExecutor().Checksum(), migrations.TemporalExecutorFingerprint(), forward, compensation)
	if err != nil || journal.Ready(ctx) != nil {
		t.Fatal("actual Ordered journal readiness", err)
	}
	var sends atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 65537))
		digest := sha256.Sum256(body)
		var held bool
		if err != nil || len(body) > 65536 {
			w.WriteHeader(400)
			return
		}
		if err := owner.QueryRow(r.Context(), `SELECT count(*)=1 FROM zasp_temporal68.invocations j JOIN zasp_temporal68.effects f USING(effect_key) WHERE f.run_id=$1 AND j.request_digest=$2 AND j.state='started'`, run, digest[:]).Scan(&held); err != nil || !held {
			t.Error("actual target send before durable category start", err)
			w.WriteHeader(500)
			return
		}
		sends.Add(1)
		if postAdapter == "test-response-revoked" {
			tag, err := owner.Exec(r.Context(), `UPDATE public.zasp_identity_memberships m SET active=false FROM public.zasp_security_agent_runs r WHERE r.run_id=$1 AND(m.organization_id,m.principal_id)=(r.organization_id,r.requested_by) AND m.active`, run)
			if err != nil || tag.RowsAffected() != 1 {
				t.Error("actual post-start requester revocation", err)
				w.WriteHeader(500)
				return
			}
		}
		if postAdapter == "test-disconnected" {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error("owned customer disconnect", err)
				return
			}
			_ = connection.Close()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"output":"controlled customer refusal"}`)
	}))
	t.Cleanup(target.Close)
	credential := &credentialResolverStub{secret: bytes.Repeat([]byte{77}, 32), destroyed: &atomic.Bool{}}
	invoker, err := newHTTPSInvoker(&http.Client{Transport: orderedRunnerTargetTransport{newRewriteRoundTripper(t, target)}}, credential, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewEffectJournaledHandler(Config{WorkerToken: bytes.Repeat([]byte{'a'}, 64), MaximumRequestBytes: 4096}, journal, invoker, journal)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"agentsec-red-team-adapter.zasp-system.svc.cluster.local"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "token"), bytes.Repeat([]byte{'a'}, 64), 0400); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/effects/evaluate" || r.Host != "agentsec-red-team-adapter.zasp-system.svc.cluster.local" {
			w.WriteHeader(400)
			return
		}
		handler.ServeHTTP(w, r)
	}), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 10 * time.Second}
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}}))
	}()
	t.Cleanup(func() {
		_ = server.Close()
		if err := <-done; err != http.ErrServerClosed {
			t.Error(err)
		}
	})
	ready, _ := json.Marshal(map[string]any{"port": listener.Addr().(*net.TCPAddr).Port})
	if err := os.WriteFile(filepath.Join(directory, "ready.json"), ready, 0400); err != nil {
		t.Fatal(err)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(stop)
	select {
	case <-stop:
	case <-ctx.Done():
		t.Fatal("owning runner did not join adapter")
	}
	if sends.Load() != 1 || credential.calls != int(sends.Load()) {
		t.Fatal("actual adapter send/credential cardinality", sends.Load(), credential.calls)
	}
	t.Log("actual Ordered HTTPS adapter joined", "sends", sends.Load(), "credential_reads", credential.calls)
}
