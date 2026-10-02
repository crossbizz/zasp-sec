package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	fga "github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

// Owned provider transport under the real production collector's scoped effect
// and credential guard. No external credentials or provider service is used.
type discoveryNativeProvider struct {
	t            *testing.T
	client       *http.Client
	url          string
	beforeSend   func()
	afterSend    func()
	partial      bool
	lostResponse bool
}

func (p *discoveryNativeProvider) WithResumeSeed(collection.ResumeSeed) (collection.ProviderClient, error) {
	return p, nil
}
func (p *discoveryNativeProvider) CollectWithCredential(ctx context.Context, q collection.Request, _ []byte) (collection.Outcome, error) {
	if p.beforeSend != nil {
		p.beforeSend()
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return nil, err
	}
	response, err := p.client.Do(r)
	if err != nil {
		return nil, err
	}
	_ = response.Body.Close()
	if p.afterSend != nil {
		p.afterSend()
	}
	if p.lostResponse {
		return nil, errors.New("owned provider response lost after observed send")
	}
	manifest := workerManifest(p.t, q)
	cursor := collection.Cursor{Provider: q.Provider, Version: "cursor_v1", Value: "owned-next"}
	if p.partial {
		return collection.NewPartialResult(q, q.ExpectedSubject, cursor, manifest, collection.FailurePartial)
	}
	candidate, err := collection.NewTypedSnapshotCandidate(q.Provider, q.ParserVersion, q.ToolVersion, []byte(`[]`), []byte(`[]`), []byte(`[]`))
	if err != nil {
		return nil, err
	}
	return collection.NewCompleteResult(q, q.ExpectedSubject, cursor, manifest, candidate)
}

func TestP7Discovery72ProductMachineNative(t *testing.T) {
	discovery72MachineFixture(t, "product")
}

func TestP7Discovery72ProductMachinePreflight(t *testing.T) {
	discovery72MachineFixture(t, "preflight")
}

func TestP7Discovery72ProofLockWaitNative(t *testing.T) {
	discovery72MachineFixture(t, "lock-wait")
}

func TestP7Discovery72AuthorityLockWaitNative(t *testing.T) {
	discovery72MachineFixture(t, "authority-wait")
}

func TestP7Discovery72PartialRevokeNative(t *testing.T) {
	discovery72MachineFixture(t, "partial-revoke")
}

func TestP7Discovery72PerSendRevokeNative(t *testing.T) {
	discovery72MachineFixture(t, "per-send-revoke")
}

func TestP7Discovery72LostResponseNative(t *testing.T) {
	discovery72MachineFixture(t, "lost-response")
}

func TestP7Discovery72RevokedSourceNative(t *testing.T) {
	discovery72MachineFixture(t, "source-denied")
}

func discovery72MachineFixture(t *testing.T, mode string) {
	dsn := os.Getenv("ZASP_P7_DISCOVERY_OWNER_DSN")
	if dsn == "" {
		t.Skip("owned API parent required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	ownerCfg, err := pgx.ParseConfig(dsn)
	if err != nil || net.ParseIP(ownerCfg.Host) == nil || !net.ParseIP(ownerCfg.Host).IsLoopback() {
		t.Fatal("owned loopback database required")
	}
	owner, err := pgx.ConnectConfig(ctx, ownerCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	var pins runtimeservices.Config
	var q struct {
		Organization, Workspace, Environment, Job, Integration, Digest, Grantor string
		Deadline                                                                time.Time
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal([]byte(os.Getenv("ZASP_P7_DISCOVERY_FGA_CONFIG")), &pins) != nil || pins.FGAURL != "http://127.0.0.1:8088" || json.Unmarshal([]byte(os.Getenv("ZASP_P7_DISCOVERY_REQUEST")), &raw) != nil {
		t.Fatal("owned consumer inputs required")
	}
	for k, dst := range map[string]*string{"organization_id": &q.Organization, "workspace_id": &q.Workspace, "environment_id": &q.Environment, "job_id": &q.Job, "integration_id": &q.Integration, "input_digest": &q.Digest, "grantor_id": &q.Grantor} {
		if json.Unmarshal(raw[k], dst) != nil {
			t.Fatal("owned request field", k)
		}
	}
	if json.Unmarshal(raw["deadline"], &q.Deadline) != nil {
		t.Fatal("owned deadline")
	}
	start := orchestration.DiscoveryStart{Ref: orchestration.RunRef{OrganizationID: q.Organization, WorkspaceID: q.Workspace, EnvironmentID: q.Environment, RunID: q.Job}, IntegrationID: q.Integration, InputDigest: q.Digest}
	var discoveryLogin, compensationLogin, outboxLogin string
	for _, item := range []struct {
		query, role string
		target      *string
	}{{`SELECT principal_name FROM zasp_temporal72.principals WHERE authority_role=$1`, "zasp_discovery_worker", &discoveryLogin}, {`SELECT principal::text FROM zasp_temporal68.principals WHERE authority=$1`, "zasp_temporal_compensation", &compensationLogin}, {`SELECT principal_name FROM zasp_discovery_principal_bindings WHERE authority_role=$1`, "zasp_outbox_worker", &outboxLogin}} {
		if err = owner.QueryRow(ctx, item.query, item.role).Scan(item.target); err != nil {
			t.Fatal(err)
		}
	}
	poolFor := func(login string) *pgxpool.Pool {
		t.Helper()
		pc, _ := pgxpool.ParseConfig(dsn)
		pc.ConnConfig.User = login
		pc.MaxConns = 2
		pool, err := pgxpool.NewWithConfig(ctx, pc)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		return pool
	}
	discoveryPool := poolFor(discoveryLogin)
	db, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: discoveryPool})
	if err != nil {
		t.Fatal(err)
	}
	data, err := exec.CommandContext(ctx, "docker", "inspect", "zasp-runtime-services-openfga-1").Output()
	if err != nil {
		t.Fatal("owned FGA unavailable")
	}
	var containers []struct{ Config struct{ Env []string } }
	if json.Unmarshal(data, &containers) != nil || len(containers) != 1 {
		t.Fatal("owned FGA configuration")
	}
	token := ""
	for _, entry := range containers[0].Config.Env {
		if strings.HasPrefix(entry, "OPENFGA_AUTHN_PRESHARED_KEYS=") {
			token = strings.TrimPrefix(entry, "OPENFGA_AUTHN_PRESHARED_KEYS=")
		}
	}
	if token == "" || strings.Contains(token, ",") {
		t.Fatal("owned FGA credential")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	fgaTransport := &workerNativeFGATransport{base: transport}
	client, err := fga.NewSdkClient(&fga.ClientConfiguration{ApiUrl: pins.FGAURL, Credentials: &credentials.Credentials{Method: credentials.CredentialsMethodApiToken, Config: &credentials.Config{ApiToken: token}}, HTTPClient: &http.Client{Transport: fgaTransport, Timeout: 5 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	checker, err := authorization.NewOpenFGA(client, pins)
	if err != nil {
		t.Fatal(err)
	}
	observed := &workerNativeCountingChecker{delegate: checker}
	writer, err := authorization.NewOpenFGATupleWriter(client, pins)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := authorization.NewPostgresProjectionRepository(poolFor(outboxLogin))
	if err != nil {
		t.Fatal(err)
	}
	reconcile := func() {
		t.Helper()
		if result, err := authorization.Reconcile(ctx, projection, writer, q.Organization, pins.StoreID, pins.ModelID); err != nil || !result.Applied {
			t.Fatalf("discovery reconcile applied=%t error=%v", result.Applied, err)
		}
	}
	var sends atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sends.Add(1); w.WriteHeader(204) }))
	defer endpoint.Close()
	provider := &discoveryNativeProvider{t: t, client: &http.Client{Transport: collection.EffectTransport{Next: transport}, Timeout: 30 * time.Second}, url: endpoint.URL}
	secrets := &discoverySecretReaderStub{values: map[string][]byte{"ref:aws/external-id/customer-0001": []byte("owned-external-id-customer-0001")}}
	assume := &discoveryAssumeRoleStub{out: &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{AccessKeyId: aws.String("ASIAEXAMPLE000001"), SecretAccessKey: aws.String(strings.Repeat("s", 40)), SessionToken: aws.String(strings.Repeat("t", 32)), Expiration: aws.Time(time.Now().UTC().Add(15 * time.Minute))}}}
	credentialsResolver, err := newProductionDiscoveryCredentialResolver(productionDiscoveryCredentialConfig{Secrets: secrets, AssumeRole: assume, GitHub: &discoveryGitHubMintStub{}, Okta: &discoveryOktaExchangeStub{}, GitHubAppID: "123456", GitHubPrivateKeyReference: "ref:github/app-private-key-0001", OktaClientID: "0oa1234567890abcdef", OktaClientSecretReference: "ref:okta/client-secret-0001", Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	factory, err := newProductionDiscoveryCollectorFactory(testFirstPartyCollectionFactory(t, provider), credentialsResolver)
	if err != nil {
		t.Fatal(err)
	}
	product, err := newTemporalDiscoveryProduct(db, factory)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, seed byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, bytes.Repeat([]byte{seed}, 32), 0400); err != nil {
			t.Fatal(err)
		}
		return path
	}
	cfg := workerRuntimeConfig{PostgresDSN: discoveryOwnedLoginDSN(ownerCfg, discoveryLogin), TemporalCompensationDSN: discoveryOwnedLoginDSN(ownerCfg, compensationLogin), RuntimeServices: pins, WorkerAuthorizationKeyFile: write("forward", 41), CompensationAuthorizationKeyFile: write("captured", 73)}
	for _, entry := range []struct {
		pool    *pgxpool.Pool
		purpose authorization.WorkerPurpose
		seed    byte
	}{{discoveryPool, authorization.WorkerForward, 41}, {poolFor(compensationLogin), authorization.CapturedCompensation, 73}} {
		key, _ := authorization.NewWorkerKey(entry.purpose, bytes.Repeat([]byte{entry.seed}, 32))
		var ready bool
		// key_ready privately checks the native/worker catalogs. Compensation
		// deliberately has no direct EXECUTE grant on native72.current_ready.
		if err := entry.pool.QueryRow(ctx, `SELECT zasp_authorization80_worker.discovery72_key_ready($1,$2)`, string(entry.purpose), key.Version()).Scan(&ready); err != nil || !ready {
			t.Fatal("exact discovery startup key/session/catalog", entry.purpose, ready, err)
		}
	}
	if workerProductionProfileReady(ctx, discoveryPool) == nil {
		t.Fatal("partial runtime opened")
	}
	closePools, err := bindDiscoveryWorkerAuthorization(ctx, cfg, observed, product)
	if err != nil {
		t.Fatal("shipped discovery binder", err)
	}
	defer closePools()
	reconcile()
	if mode == "source-denied" {
		if _, err = product.CollectDiscoveryPage(ctx, orchestration.DiscoveryPageCommand{Start: start, Deadline: q.Deadline}); !errors.Is(err, authorization.ErrDenied) {
			t.Fatal("changed source authorized fresh collection", err)
		}
		if sends.Load() != 0 || len(secrets.calls) != 0 {
			t.Fatal("changed source reached credential/provider")
		}
		return
	}
	if mode == "partial-revoke" || mode == "per-send-revoke" || mode == "lost-response" {
		revoke := func() {
			if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=$2`, q.Organization, q.Grantor); err != nil {
				t.Fatal("owned revocation", err)
			}
		}
		discovery72BoundaryRevocation(t, ctx, owner, product, provider, start, q.Deadline, mode, revoke, func() { fgaTransport.unavailable.Store(true) }, func() (int32, int, int) { return sends.Load(), len(secrets.calls), observed.calls })
		return
	}
	if mode == "authority-wait" {
		discovery72AuthorityLockWait(t, ctx, owner, product, start, q.Deadline, discoveryLogin, reconcile, func() int { return observed.calls })
		if sends.Load() != 0 || len(secrets.calls) != 0 {
			t.Fatal("authority expiry reached credential/provider")
		}
		return
	}
	if mode == "lock-wait" {
		discovery72ProofLockWait(t, ctx, owner, product, start, q.Deadline, discoveryLogin, compensationLogin)
		if sends.Load() != 0 || len(secrets.calls) != 0 {
			t.Fatal("expired proof reached credential/provider")
		}
		return
	}
	if mode == "preflight" {
		if sends.Load() != 0 || len(secrets.calls) != 0 {
			t.Fatal("startup preflight performed provider IO")
		}
		t.Log("owned startup preflight: exact roles, purpose keys, catalogs, FGA projection and shipped binder; no provider IO; full runtime closed")
		return
	}
	// Ruling 25: equivalent native bookkeeping must not invalidate the
	// two-check proof, while terminal or authority transitions must still touch.
	// Removing the narrow capture exception breaks these real revision checks.
	revision := func() int64 {
		t.Helper()
		var desired int64
		if err := owner.QueryRow(ctx, `SELECT desired FROM zasp_authorization79.organizations WHERE organization_id=$1`, q.Organization).Scan(&desired); err != nil {
			t.Fatal(err)
		}
		return desired
	}
	beforeCollection := revision()
	for _, state := range []string{"running", "queued"} {
		if _, err = owner.Exec(ctx, `UPDATE zasp_discovery_syncs SET state=$2 WHERE id=(SELECT sync_id FROM zasp_temporal72.runs WHERE job_id=$1)`, q.Job, state); err != nil {
			t.Fatal("equivalent bookkeeping", err)
		}
		if revision() != beforeCollection {
			t.Fatal("equivalent queued/running bookkeeping changed authority revision")
		}
	}
	page, err := product.CollectDiscoveryPage(ctx, orchestration.DiscoveryPageCommand{Start: start, Deadline: q.Deadline})
	if err != nil || page.Outcome != "complete" || sends.Load() != 1 || len(secrets.calls) != 1 {
		t.Fatalf("actual collection outcome=%s sends=%d credentials=%d error=%v", page.Outcome, sends.Load(), len(secrets.calls), err)
	}
	if observed.calls < 8 {
		t.Fatal("grantor/task integration checks omitted", observed.calls)
	}
	if revision() != beforeCollection {
		t.Fatal("native collection bookkeeping invalidated current authority")
	}
	reconcile()
	receipt, err := product.ApplyDiscoverySnapshot(ctx, orchestration.DiscoveryApplyCommand{Start: start, Deadline: q.Deadline, CompleteReceiptDigest: page.ReceiptDigest})
	if err != nil || receipt == "" {
		t.Fatal("actual snapshot commit", err)
	}
	if revision() <= beforeCollection {
		t.Fatal("terminal snapshot commit failed to advance authority revision")
	}
	beforeRevoke := revision()
	if _, err = owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=$2`, q.Organization, q.Grantor); err != nil {
		t.Fatal(err)
	}
	if revision() <= beforeRevoke {
		t.Fatal("grantor revocation failed to advance authority revision")
	}
	fgaTransport.unavailable.Store(true)
	checks := observed.calls
	replayed, err := product.CollectDiscoveryPage(ctx, orchestration.DiscoveryPageCommand{Start: start, Deadline: q.Deadline})
	if err != nil || replayed != page {
		t.Fatal("captured page replay after revoke/outage", err)
	}
	replayedReceipt, err := product.ApplyDiscoverySnapshot(ctx, orchestration.DiscoveryApplyCommand{Start: start, Deadline: q.Deadline, CompleteReceiptDigest: page.ReceiptDigest})
	if err != nil || replayedReceipt != receipt {
		t.Fatal("captured apply replay after revoke/outage", err)
	}
	if err = product.FinishDiscovery(ctx, orchestration.DiscoveryFinish{Start: start, Outcome: "succeeded", ReceiptDigest: receipt}); err != nil {
		t.Fatal("captured finish", err)
	}
	if observed.calls != checks || sends.Load() != 1 || len(secrets.calls) != 1 {
		t.Fatal("captured replay performed fresh work")
	}
	terminal := start
	terminal.Ref.RunID = "pid_72008015-0000-4000-8000-000000000015"
	if err = owner.QueryRow(ctx, `SELECT encode(request_digest,'hex') FROM zasp_temporal72.runs WHERE job_id=$1`, terminal.Ref.RunID).Scan(&terminal.InputDigest); err != nil {
		t.Fatal(err)
	}
	if err = product.FinishDiscovery(ctx, orchestration.DiscoveryFinish{Start: terminal, Outcome: "incomplete"}); err != nil {
		t.Fatal("retained terminal capture replay after revoke/outage", err)
	}
	if observed.calls != checks || sends.Load() != 1 || len(secrets.calls) != 1 {
		t.Fatal("retained terminal replay performed fresh work")
	}
	// The original separate task was admitted through the native API before
	// upgrade. Revoke must refuse fresh work before another credential or send.
	var other orchestration.DiscoveryStart
	var deadline time.Time
	other.Ref = start.Ref
	other.Ref.RunID = "pid_72008005-0000-4000-8000-000000000005"
	other.IntegrationID = start.IntegrationID
	if err = owner.QueryRow(ctx, `SELECT encode(request_digest,'hex'),deadline FROM zasp_temporal72.runs WHERE job_id=$1`, other.Ref.RunID).Scan(&other.InputDigest, &deadline); err != nil {
		t.Fatal(err)
	}
	if _, err = product.CollectDiscoveryPage(ctx, orchestration.DiscoveryPageCommand{Start: other, Deadline: deadline}); !errors.Is(err, authorization.ErrDenied) {
		t.Fatal("revoked task disclosed fresh input", err)
	}
	if sends.Load() != 1 || len(secrets.calls) != 1 {
		t.Fatal("revoked task reached credential/provider")
	}
	var invariant bool
	if err = owner.QueryRow(ctx, `SELECT bool_and(deadline=admitted_at+interval '24 hours') AND NOT zasp_authorization80_worker.runtime_ready() FROM zasp_temporal72.runs`).Scan(&invariant); err != nil || !invariant {
		t.Fatal("deadline/runtime invariant", err)
	}
}

func discoveryOwnedLoginDSN(cfg *pgx.ConnConfig, login string) string {
	// ConnConfig.ConnString returns its original text, not updated User fields.
	// This is the same explicit owned-loopback URL used by retained live tests.
	return (&url.URL{Scheme: "postgres", User: url.User(login), Host: net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))), Path: "/" + cfg.Database, RawQuery: "sslmode=disable"}).String()
}

func TestP7Discovery72OwnedLoginDSNs(t *testing.T) {
	owner, err := pgx.ParseConfig("postgres://owned_migration@127.0.0.1:54321/postgres?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	forward, compensation := discoveryOwnedLoginDSN(owner, "owned_discovery"), discoveryOwnedLoginDSN(owner, "owned_compensation")
	if forward == compensation || forward == owner.ConnString() || compensation == owner.ConnString() {
		t.Fatal("owned role DSNs alias migration or each other")
	}
	for raw, want := range map[string]string{forward: "owned_discovery", compensation: "owned_compensation"} {
		cfg, err := pgx.ParseConfig(raw)
		if err != nil || cfg.User != want || cfg.Host != owner.Host || cfg.Port != owner.Port || cfg.Database != owner.Database {
			t.Fatal("owned role DSN changed identity or database")
		}
	}
}
