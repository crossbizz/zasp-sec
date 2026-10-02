package authorization

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	fga "github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

// This test lives beside WorkerDecision so it can consume a genuine unchanged
// envelope at an independently callable native entry. No production accessor,
// substitute checker, proof re-signing or dispatcher bypass is added to code.
func TestP7Discovery72DirectNativeAuthorityExpiry(t *testing.T) {
	dsn := os.Getenv("ZASP_P7_DISCOVERY_OWNER_DSN")
	if dsn == "" {
		t.Skip("owned API admission parent required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || net.ParseIP(cfg.Host) == nil || !net.ParseIP(cfg.Host).IsLoopback() {
		t.Fatal("owned loopback required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	owner, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	var pins runtimeservices.Config
	var input struct {
		Organization string    `json:"organization_id"`
		Workspace    string    `json:"workspace_id"`
		Environment  string    `json:"environment_id"`
		Job          string    `json:"job_id"`
		Integration  string    `json:"integration_id"`
		Digest       string    `json:"input_digest"`
		Deadline     time.Time `json:"deadline"`
	}
	if json.Unmarshal([]byte(os.Getenv("ZASP_P7_DISCOVERY_FGA_CONFIG")), &pins) != nil || pins.FGAURL != "http://127.0.0.1:8088" || json.Unmarshal([]byte(os.Getenv("ZASP_P7_DISCOVERY_REQUEST")), &input) != nil {
		t.Fatal("owned inputs required")
	}
	var login string
	if err = owner.QueryRow(ctx, `SELECT principal_name FROM zasp_temporal72.principals WHERE authority_role='zasp_discovery_worker'`).Scan(&login); err != nil {
		t.Fatal(err)
	}
	pc, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	pc.ConnConfig.User = login
	pc.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var callable bool
	if err = pool.QueryRow(ctx, `SELECT session_user=$1 AND has_function_privilege(session_user,'zasp_temporal72.guard_page_effect(text,text,text,text,text,timestamptz)','EXECUTE')`, login).Scan(&callable); err != nil || !callable {
		t.Fatal("registered native entry is not directly callable", err)
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
	client, err := fga.NewSdkClient(&fga.ClientConfiguration{ApiUrl: pins.FGAURL, Credentials: &credentials.Credentials{Method: credentials.CredentialsMethodApiToken, Config: &credentials.Config{ApiToken: token}}, HTTPClient: &http.Client{Transport: transport, Timeout: 5 * time.Second}})
	if err != nil {
		t.Fatal("owned FGA client")
	}
	checker, err := NewOpenFGA(client, pins)
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewWorkerKey(WorkerForward, bytes.Repeat([]byte{41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	worker, err := NewWorkerDiscovery(pool, checker, pins.StoreID, pins.ModelID, key)
	if err != nil {
		t.Fatal(err)
	}
	var until time.Time
	var capture bool
	if err = owner.QueryRow(ctx, `SELECT a.authority_until,a.authority_until=c.expires_at AND a.authority_until<r.deadline AND r.deadline=r.admitted_at+interval '24 hours' AND a.credential_facts=zasp_authorization80_worker.discovery72_credentials(r) FROM zasp_authorization80_worker.discovery_associations a JOIN zasp_temporal72.runs r USING(organization_id,workspace_id,environment_id,job_id) JOIN zasp_connector_credentials c ON(c.organization_id,c.workspace_id,c.environment_id,c.integration_id,c.id)=(a.organization_id,a.workspace_id,a.environment_id,a.integration_id,'pid_72008025-0000-4000-8000-000000000025') WHERE a.job_id=$1`, input.Job).Scan(&until, &capture); err != nil || !capture {
		t.Fatal("exact persisted credential capture", err)
	}
	request := func(phase string, extra map[string]any) json.RawMessage {
		q := map[string]any{"organization_id": input.Organization, "workspace_id": input.Workspace, "environment_id": input.Environment, "job_id": input.Job, "integration_id": input.Integration, "input_digest": input.Digest, "operation": phase, "budget_us": input.Deadline.UnixMicro()}
		for k, v := range extra {
			q[k] = v
		}
		raw, err := json.Marshal(q)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	prepare := request("prepare_page", map[string]any{"expected": 0, "expected_digest": ""})
	decision, err := worker.Authorize(ctx, "discovery72.prepare_page", prepare)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = worker.Execute(ctx, decision); err != nil {
		t.Fatal("genuine preparation", err)
	}
	var effect string
	if err = owner.QueryRow(ctx, `SELECT effect_id FROM zasp_temporal72.page_effects WHERE job_id=$1 AND expected_version=0 AND result IS NULL`, input.Job).Scan(&effect); err != nil {
		t.Fatal(err)
	}
	if delay := time.Until(until.Add(-15 * time.Second)); delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	decision, err = worker.Authorize(ctx, "discovery72.guard_page", request("guard_page", map[string]any{"effect_id": effect}))
	if err != nil {
		t.Fatal("genuine guard authorization", err)
	}
	// Read timing from the real opaque envelope without changing any byte.
	var envelope struct {
		Body []byte `json:"body"`
	}
	var proof struct {
		IssuedAt  int64 `json:"issued_at"`
		ExpiresAt int64 `json:"expires_at"`
	}
	if json.Unmarshal(decision.envelope, &envelope) != nil || json.Unmarshal(envelope.Body, &proof) != nil || proof.ExpiresAt-proof.IssuedAt != 30000 || time.Until(until) < 3*time.Second {
		t.Fatal("live original proof timing")
	}
	lock, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = lock.Exec(ctx, `SELECT effect_id FROM zasp_temporal72.page_effects WHERE job_id=$1 AND effect_id=$2 FOR UPDATE`, input.Job, effect); err != nil {
		_ = lock.Rollback(ctx)
		t.Fatal(err)
	}
	executeCtx, cancelExecute := context.WithCancel(ctx)
	finished := make(chan error, 1)
	joined := false
	defer func() {
		cancelExecute()
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := lock.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error("direct lock cleanup", err)
		}
		if !joined {
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			select {
			case <-finished:
			case <-timer.C:
				t.Error("direct native execution not joined")
			}
		}
	}()
	go func() {
		tx, err := pool.BeginTx(executeCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			finished <- err
			return
		}
		defer func() {
			// Report terminal only after rollback has joined.
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			rollbackErr := tx.Rollback(cleanup)
			if err == nil {
				err = rollbackErr
			}
			finished <- err
		}()
		if _, err = tx.Exec(executeCtx, `SELECT set_config('zasp.worker_proof',$1,true)`, string(decision.envelope)); err == nil {
			var allowed bool
			err = tx.QueryRow(executeCtx, `SELECT zasp_temporal72.guard_page_effect($1,$2,$3,$4,$5,$6)`, input.Organization, input.Workspace, input.Environment, input.Job, effect, input.Deadline).Scan(&allowed)
			if err == nil && !allowed {
				err = ErrDenied
			}
		}
		// The native guard has no write effect; defer rolls back even on allow.
	}()
	waiting := false
	for limit := time.Now().Add(8 * time.Second); time.Now().Before(limit); {
		if err = lock.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND wait_event_type='Lock' AND $2::integer=ANY(pg_blocking_pids(pid)))`, login, int32(owner.PgConn().PID())).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if !waiting || !time.Now().Before(until) {
		t.Fatal("direct entry did not reach effect-row wait before credential expiry")
	}
	if delay := time.Until(until.Add(150 * time.Millisecond)); delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	var expired bool
	if err = lock.QueryRow(ctx, `SELECT clock_timestamp()>$1::timestamptz AND clock_timestamp()<to_timestamp($2::double precision/1000)`, until, proof.ExpiresAt).Scan(&expired); err != nil || !expired {
		t.Fatal("credential/proof clocks do not isolate the boundary", err)
	}
	if err = lock.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-finished:
		joined = true
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if time.Now().UnixMilli() >= proof.ExpiresAt {
		t.Fatal("proof expiry masked direct credential result")
	}
	var native *pgconn.PgError
	if !errors.As(err, &native) || native.Code != "42501" {
		t.Fatal("direct registered native entry accepted expired credential under live genuine proof", err)
	}
	var unchanged bool
	if err = owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(result IS NULL) AND NOT EXISTS(SELECT 1 FROM zasp_temporal72.apply_effects WHERE job_id=$1) FROM zasp_temporal72.page_effects WHERE job_id=$1`, input.Job).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("direct refusal changed captured debt", err)
	}
	t.Log("direct registered native entry refused authority expiry after observed source lock; genuine proof remained live and unchanged")
}
