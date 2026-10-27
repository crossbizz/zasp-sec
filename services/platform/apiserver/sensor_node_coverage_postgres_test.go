package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/nodecoveragewire"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

// Unexecuted native application acceptance. The existing guarded fixture owns
// PostgreSQL/OpenFGA and authentic stored credentials. No alternate startup,
// resource guard or caller-manufactured authorization decision is introduced.
func TestSensorNodeCoverageNormalPostgres(t *testing.T) { runSensorNodeCoverageNative(t, false) }
func TestSensorNodeCoverageAuditPostgres(t *testing.T)  { runSensorNodeCoverageNative(t, true) }
func runSensorNodeCoverageNative(t *testing.T, audit bool) {
	t.Helper()
	if audit {
		t.Setenv("ZASP_P7_AUDIT_TEST", "1")
		t.Setenv("ZASP_P7_IDENTITY_TEST", "1")
	} else {
		t.Setenv("ZASP_P7_AUDIT_TEST", "")
		t.Setenv("ZASP_P7_IDENTITY_TEST", "")
	}
	f := newEnvironmentClassNativeFixture(t)
	ctx := f.ctx
	scope := f.identity.Scope
	o, w, e := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	runner, err := migrations.NewRunner(&integrationMigrationDatabase{connection: f.owner})
	if err != nil {
		t.Fatal("native coverage runner refused")
	}
	pin := migrations.SensorNodeCoverageProfileChecksum()
	install := runner.UpProductionSensorNodeCoverageProfile
	if audit {
		pin = migrations.SensorNodeCoverageAuditProfileChecksum()
		install = runner.UpProductionSensorNodeCoverageAuditProfile
	}
	if install(ctx) != nil {
		t.Fatal("native selected coverage recipe refused")
	}
	exec := func(q string, a ...any) {
		t.Helper()
		if _, err := f.bootstrap.Exec(ctx, q, a...); err != nil {
			t.Fatal("owned coverage fixture statement refused")
		}
	}
	const id = "pid_8c000001-0000-4000-8000-000000000001"
	const tokenID = "pid_8c000002-0000-4000-8000-000000000002"
	const patID = "pid_8c000003-0000-4000-8000-000000000003"
	const pat = "owned-node-coverage-native-pat"
	exec(`SELECT zasp_discovery_create_sensor($1,$2,$3,$4,'Owned coverage sensor','tetragon')`, o, w, e, id)
	token, locator, salt, hash := envelopeLifecycleCredential(t, tokenID, 1, 0xc1)
	exec(`SELECT zasp_runtime_issue_sensor_token($1,$2,$3,$4,$5,1,1,$6,$7,$8,clock_timestamp()+interval '1 hour')`, o, w, e, id, tokenID, locator, salt, hash)
	exec(`INSERT INTO public.zasp_product_api_tokens(token_digest,id,name,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at) VALUES(digest($1,'sha256'),$2,'Owned native coverage token',$3,$4,$5,$6,'["view"]'::jsonb,clock_timestamp()+interval '1 hour')`, pat, patID, f.identity.PrincipalID.String(), o, w, e)
	f.reconcile()
	var login string
	if f.bootstrap.QueryRow(ctx, `SELECT principal_name FROM public.zasp_discovery_principal_bindings WHERE authority_role='zasp_runtime_ingest'`).Scan(&login) != nil || login == "" {
		t.Fatal("original registered ingest principal missing")
	}
	pc, err := pgxpool.ParseConfig(f.configDSN)
	if err != nil {
		t.Fatal("owned pool configuration refused")
	}
	pc.ConnConfig.User = login
	pc.MaxConns = 2
	pc.MinConns = 0
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal("owned ingest pool unavailable")
	}
	t.Cleanup(pool.Close)
	database := &nodeCoverageNativeDatabase{pool: pool}
	ingest, err := runtimeevent.NewPostgresNodeCoverageIngestRepository(database, pin)
	if err != nil {
		t.Fatal("actual current ingest constructor refused")
	}
	private, err := sensor.NewPrivateNodeCoverageHeartbeatHandler(ingest, func() time.Time { return time.Now().UTC() }, 30*time.Second)
	if err != nil {
		t.Fatal("actual private handler refused")
	}
	public, err := NewSensorPublicRepository(f.db)
	if err != nil || public.RequireSensorNodeCoverageProfile(pin) != nil {
		t.Fatal("actual public repository mount refused")
	}
	handler, err := NewSensorPublicHTTPHandler(public, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal("public handler refused")
	}
	policy, err := authorization.LookupOperation("getSensorCoverage")
	if err != nil {
		t.Fatal(err)
	}
	router, err := NewRouter([]Operation{{Method: policy.Method, Pattern: policy.Path, OperationID: policy.ID, Permission: policy.Permission, Security: []CredentialKind{CredentialBrowserSession, CredentialBearerToken}, Handler: handler}})
	if err != nil {
		t.Fatal(err)
	}
	router.(*operationRouter).authorizer = f.authorizer
	app, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://console.example", MaximumBodyBytes: 65536, Authenticate: f.repository.Authenticate, GenerateCorrelationID: func() string { v, _ := newWorkflowProductID(); return v }}, router)
	if err != nil {
		t.Fatal("current middleware mount refused")
	}
	send := func(raw []byte, credential string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, sensor.PrivateHeartbeatPath, bytes.NewReader(raw))
		r.Header.Set("Content-Type", sensor.PrivateHeartbeatMediaType)
		r.Header.Set("X-Zasp-Schema-Version", nodecoveragewire.HeartbeatSchema)
		r.Header.Set("Authorization", "Bearer "+credential)
		out := httptest.NewRecorder()
		private.ServeHTTP(out, r.WithContext(ctx))
		return out
	}
	read := func(credential, expected string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/sensors/"+id+"/coverage", nil)
		r.Header.Set(expectedScopeHeader, expected)
		r.Header.Set("X-Zasp-Schema-Version", nodecoveragewire.ReadSchema)
		if credential == "browser" {
			r.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "hierarchy80-session"})
		} else {
			r.Header.Set("Authorization", "Bearer "+credential)
		}
		out := httptest.NewRecorder()
		app.ServeHTTP(out, r.WithContext(ctx))
		return out
	}
	decode := func(out *httptest.ResponseRecorder) SensorNodeCoverage {
		t.Helper()
		v, ok := decodeSensorNodeCoverage(out.Body.Bytes(), id)
		if out.Code != http.StatusOK || !ok {
			t.Fatal("real API returned no authoritative observation")
		}
		return v
	}
	ack := func(out *httptest.ResponseRecorder, kind string) nodecoveragewire.Receipt {
		t.Helper()
		v, err := nodecoveragewire.ParseReceipt(out.Body.Bytes())
		if out.Code != http.StatusOK || err != nil || v.Disposition != kind {
			t.Fatal("real private commit did not return exact terminal receipt")
		}
		return v
	}
	var acceptedRaw []byte
	var accepted nodecoveragewire.Receipt
	t.Run("accepted_original_observation_expired_replay_and_terminal_gap", func(t *testing.T) {
		acceptedRaw = nodeCoverageNativeWire(t, scope, id, 1, time.Now().UTC(), 6)
		accepted = ack(send(acceptedRaw, token), "accepted")
		f.reconcile()
		observed := decode(read("browser", expectedScopeValue(scope)))
		if observed.NodeObservation.Receipt == nil || observed.NodeObservation.Receipt.Sequence != 1 || observed.NodeObservation.Receipt.RequestDigest != accepted.RequestDigest {
			t.Fatal("public read lost exact accepted receipt")
		}
		waitNodeCoverageNative(t, ctx, accepted.ExpiresAt.Add(100*time.Millisecond))
		replay := ack(send(acceptedRaw, token), "accepted")
		if !replay.Replayed || replay.RequestDigest != accepted.RequestDigest || !replay.ResolvedAt.Equal(accepted.ResolvedAt) || !replay.SourceObservedAt.Equal(accepted.SourceObservedAt) {
			t.Fatal("expired replay changed original evidence")
		}
		expired := nodeCoverageNativeWire(t, scope, id, 2, time.Now().UTC().Add(-time.Minute), 6)
		ack(send(expired, token), "expired_not_committed")
		unchanged := decode(read(pat, expectedScopeValue(scope)))
		if unchanged.NodeObservation.Receipt == nil || unchanged.NodeObservation.Receipt.Sequence != 1 || unchanged.NodeObservation.State != "source_expired" {
			t.Fatal("terminal nonacceptance replaced accepted observation")
		}
		next := nodeCoverageNativeWire(t, scope, id, 3, time.Now().UTC(), 30)
		ack(send(next, token), "accepted")
		f.reconcile()
		current := decode(read(pat, expectedScopeValue(scope)))
		if current.NodeObservation.Receipt == nil || current.NodeObservation.Receipt.Sequence != 3 || current.NodeObservation.State != "source_current" {
			t.Fatal("real native sequence gap refused or fabricated coverage")
		}
	})
	t.Run("stored_credentials_scope_and_rotated_sensor_authority", func(t *testing.T) {
		if read("browser", strings.Repeat("f", 64)).Code < 400 {
			t.Fatal("wrong expected scope accepted")
		}
		exec(`UPDATE public.zasp_product_api_tokens SET revoked_at=clock_timestamp() WHERE id=$1`, patID)
		if read(pat, expectedScopeValue(scope)).Code < 400 {
			t.Fatal("revoked stored PAT read observation")
		}
		nextID := "pid_8c000004-0000-4000-8000-000000000004"
		nextWire, ld, ss, hh := envelopeLifecycleCredential(t, nextID, 2, 0xc5)
		exec(`SELECT zasp_runtime_rotate_sensor_token($1,$2,$3,$4,$5,$6,2,1,$7,$8,$9,clock_timestamp()+interval '1 hour')`, o, w, e, id, tokenID, nextID, ld, ss, hh)
		if send(nodeCoverageNativeWire(t, scope, id, 4, time.Now().UTC(), 30), token).Code < 400 {
			t.Fatal("rotated sensor credential still admitted")
		}
		ack(send(nodeCoverageNativeWire(t, scope, id, 4, time.Now().UTC(), 30), nextWire), "accepted")
	})
	t.Run("actual_transaction_token_wait_expires_before_final_clock_check", func(t *testing.T) {
		shortSensor := "pid_8c000005-0000-4000-8000-000000000005"
		shortID := "pid_8c000006-0000-4000-8000-000000000006"
		exec(`SELECT zasp_discovery_create_sensor($1,$2,$3,$4,'Short native token','tetragon')`, o, w, e, shortSensor)
		wireToken, ld, ss, hh := envelopeLifecycleCredential(t, shortID, 1, 0xc9)
		var expires time.Time
		if f.bootstrap.QueryRow(ctx, `SELECT clock_timestamp()+interval '2 seconds'`).Scan(&expires) != nil {
			t.Fatal("actual server clock unavailable")
		}
		exec(`SELECT zasp_runtime_issue_sensor_token($1,$2,$3,$4,$5,1,1,$6,$7,$8,$9)`, o, w, e, shortSensor, shortID, ld, ss, hh, expires)
		caseCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		lock, err := f.bootstrap.Begin(caseCtx)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		var l, secret []byte
		var done chan error
		workerStarted, joined := false, false
		// Registered before the worker. Release the lock and join before clearing
		// borrowed credential copies, including every t.Fatal/cancellation path.
		t.Cleanup(func() {
			cancel()
			rollbackCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			_ = lock.Rollback(rollbackCtx)
			stop()
			if workerStarted && !joined {
				timer := time.NewTimer(3 * time.Second)
				defer timer.Stop()
				select {
				case <-done:
					joined = true
				case <-timer.C:
					t.Error("native worker did not join; borrowed credential buffers retained")
				}
			}
			if !workerStarted || joined {
				clear(l)
				clear(secret)
			}
		})
		if _, err = lock.Exec(caseCtx, `SELECT 1 FROM zasp_sensor_tokens WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4 FOR UPDATE`, o, w, e, shortID); err != nil {
			t.Fatal("actual token lock unavailable")
		}
		var blockerPID int
		if lock.QueryRow(caseCtx, `SELECT pg_backend_pid()`).Scan(&blockerPID) != nil {
			t.Fatal("owned blocker identity unavailable")
		}
		c, err := sensor.ParseTokenCredential(wireToken)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Destroy()
		l, secret, err = c.Parts()
		if err != nil {
			t.Fatal(err)
		}
		payload := nodeCoverageNativeWire(t, scope, shortSensor, 1, time.Now().UTC(), 30)
		signal := &nodeCoverageNativeBeginSignal{pool: pool, begun: make(chan struct{})}
		done = make(chan error, 1)
		workerStarted = true
		go func() {
			_, err := runtimeevent.CommitProductionNodeCoverage(caseCtx, signal, l, secret, payload)
			done <- err
		}()
		select {
		case <-signal.begun:
			if signal.started.IsZero() || !signal.started.Before(expires) || signal.pid == 0 {
				t.Fatal("live-token wait precondition not established before expiry")
			}
		case <-caseCtx.Done():
			t.Fatal("native transaction never began")
		}
		// Observe the exact production DAL backend blocked by our exact owned token
		// holder, not merely that a goroutine or transaction started.
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			if _, err = lock.Exec(caseCtx, `SELECT pg_stat_clear_snapshot()`); err != nil {
				t.Fatal("owned wait-observer snapshot refresh failed")
			}
			var blocked, beforeExpiry bool
			if err = lock.QueryRow(caseCtx, `SELECT $1=ANY(pg_blocking_pids($2)) AND EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$2 AND state='active' AND wait_event_type='Lock'),clock_timestamp()<$3`, blockerPID, signal.pid, expires).Scan(&blocked, &beforeExpiry); err != nil {
				t.Fatal("actual owned token wait could not be observed")
			}
			if blocked {
				if !beforeExpiry {
					t.Fatal("owned token wait was not observed before expiry")
				}
				break
			}
			select {
			case <-done:
				joined = true
				t.Fatal("production transaction ended before owned token wait")
			case <-ticker.C:
			case <-caseCtx.Done():
				t.Fatal("owned token wait observation deadline expired")
			}
		}
		waitNodeCoverageNative(t, caseCtx, expires.Add(100*time.Millisecond))
		if lock.Commit(caseCtx) != nil {
			t.Fatal("owned token lock release failed")
		}
		select {
		case err = <-done:
			joined = true
			if err == nil {
				t.Fatal("transaction_timestamp admitted expired token after real wait")
			}
		case <-caseCtx.Done():
			t.Fatal("native transaction completion deadline expired")
		}

		var n int
		if f.bootstrap.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_sensor_coverage_v1.accepted_observations WHERE sensor_id=$1)+(SELECT count(*) FROM zasp_sensor_coverage_v1.resolved_attempts WHERE sensor_id=$1)`, shortSensor).Scan(&n) != nil || n != 0 {
			t.Fatal("expired blocked token mutated accepted/resolved facts")
		}
	})
}

// Uses the identical production DAL helper, not a copied SQL transaction.
type nodeCoverageNativeDatabase struct{ pool *pgxpool.Pool }

func (d *nodeCoverageNativeDatabase) QueryJSON(c context.Context, q string, a ...any) (json.RawMessage, error) {
	var raw []byte
	err := d.pool.QueryRow(c, q, a...).Scan(&raw)
	return raw, err
}
func (d *nodeCoverageNativeDatabase) CommitNodeCoverage(c context.Context, l, s, b []byte) (nodecoveragewire.Receipt, error) {
	return runtimeevent.CommitProductionNodeCoverage(c, d.pool, l, s, b)
}

type nodeCoverageNativeBeginSignal struct {
	pool    *pgxpool.Pool
	begun   chan struct{}
	started time.Time
	pid     int
}

func (p *nodeCoverageNativeBeginSignal) BeginTx(c context.Context, o pgx.TxOptions) (pgx.Tx, error) {
	defer close(p.begun)
	tx, e := p.pool.BeginTx(c, o)
	if e != nil {
		return nil, e
	}
	// Observe the actual transaction clock only; no invented token authority.
	if e = tx.QueryRow(c, `SELECT transaction_timestamp(),pg_backend_pid()`).Scan(&p.started, &p.pid); e != nil {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(c), 3*time.Second)
		_ = tx.Rollback(rollbackCtx)
		cancel()
		return nil, e
	}
	return tx, nil
}
func waitNodeCoverageNative(t *testing.T, c context.Context, at time.Time) {
	t.Helper()
	timer := time.NewTimer(time.Until(at))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-c.Done():
		t.Fatal("original native deadline expired")
	}
}
func nodeCoverageNativeWire(t *testing.T, scope domain.Scope, sensorID string, seq int64, at time.Time, ttl int64) []byte {
	t.Helper()
	id, err := domain.ParseProductID(sensorID)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := sensor.EnrollmentBinding(scope, id)
	if err != nil {
		t.Fatal(err)
	}
	target := nodecoveragewire.CoverageTarget{Namespace: "sensor", Name: "agent", Release: "zasp", ReleaseNamespace: "sensor", Image: "example/sensor@sha256:" + strings.Repeat("b", 64), ServiceAccount: "agent", Container: "agent"}
	other := target
	other.Name = "tetragon"
	v := nodecoveragewire.Envelope{Heartbeat: nodecoveragewire.Heartbeat{Sequence: seq, Status: "degraded", Capabilities: []string{"process"}, Kernel: "unknown"}, CoverageSchema: nodecoveragewire.CoverageSchema, StateUID: "11111111-1111-4111-8111-111111111111", StorageEpoch: seq, Selection: nodecoveragewire.NodeCoverageSelection{SourceProfile: "tetragon-local-stream-v2", ClusterUID: "22222222-2222-4222-8222-222222222222", EnrollmentBinding: binding, MatchLabels: map[string]string{"group": "selected"}, Sensor: target, Tetragon: other}, TargetDigest: strings.Repeat("c", 64), InventoryObservedAt: at, SourceObservedAt: at, TTLSeconds: ttl, SensorDaemonSetUID: "33333333-3333-4333-8333-333333333333", TetragonDaemonSetUID: "44444444-4444-4444-8444-444444444444", SelectedNodes: []nodecoveragewire.SelectedNode{{NodeName: "node-a", NodeUID: "55555555-5555-4555-8555-555555555555", BootID: "66666666-6666-4666-8666-666666666666"}}, Reports: []nodecoveragewire.NodeCoverageV2{}}
	raw, err := nodecoveragewire.MarshalEnvelope(v)
	if err != nil {
		t.Fatal("strict native wire refused")
	}
	return raw
}
