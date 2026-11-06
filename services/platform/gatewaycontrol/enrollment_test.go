package gatewaycontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	wire "github.com/zasp-ai/zasp-sec/services/platform/gatewayenrollmentwire"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func enrollmentFixture(t *testing.T) (wire.Request, []byte, wire.Receipt, []byte, []byte) {
	t.Helper()
	pub, _ := fixtureGatewayKey(t)
	a := fixtureAuthority(pub)
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	request := wire.Request{Schema: wire.RequestSchema, OrganizationID: a.OrganizationID, WorkspaceID: a.WorkspaceID, EnvironmentID: a.EnvironmentID, DeviceID: a.DeviceID, EnrollmentID: fixtureID(7), TokenGeneration: 1, CredentialID: a.CredentialID, CredentialGeneration: a.CredentialGeneration, KeyID: a.KeyID, Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(pub), ExpiresAt: now.Add(time.Hour)}
	raw, e := json.Marshal(request)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	receipt := wire.Receipt{Schema: wire.ReceiptSchema, RequestSHA256: hex.EncodeToString(sum[:]), OrganizationID: request.OrganizationID, WorkspaceID: request.WorkspaceID, EnvironmentID: request.EnvironmentID, DeviceID: request.DeviceID, EnrollmentID: request.EnrollmentID, TokenGeneration: request.TokenGeneration, CredentialID: request.CredentialID, CredentialGeneration: request.CredentialGeneration, KeyID: request.KeyID, Algorithm: request.Algorithm, PublicKey: request.PublicKey, Audience: GatewayAudience, IssuedAt: now, ExpiresAt: request.ExpiresAt}
	return request, raw, receipt, bytes.Repeat([]byte{0x81}, 16), bytes.Repeat([]byte{0x82}, 32)
}
func enrollmentSignedRequest(t *testing.T, raw, locator, secret []byte) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://gateway-control.zasp.example"+EnrollmentPath, bytes.NewReader(raw))
	r.Header.Set("Content-Type", JSONMediaType)
	_, key := fixtureGatewayKey(t)
	if e := SignRequest(r, raw, fixtureID(5), key, time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)); e != nil {
		t.Fatal(e)
	}
	r.Header.Set(AuthorizationHeader, wire.AuthorizationScheme+" "+base64.RawURLEncoding.EncodeToString(locator)+"."+base64.RawURLEncoding.EncodeToString(secret))
	return r
}

type enrollmentRepositoryStub struct {
	receipt              wire.Receipt
	readyErr             error
	calls                int
	locator, secret, raw []byte
}

func (s *enrollmentRepositoryStub) EnrollmentReady(context.Context) error { return s.readyErr }
func (s *enrollmentRepositoryStub) EnrollGateway(_ context.Context, l, secret, raw []byte) (wire.Receipt, error) {
	s.calls++
	s.locator = append([]byte(nil), l...)
	s.secret = append([]byte(nil), secret...)
	s.raw = append([]byte(nil), raw...)
	return s.receipt, nil
}

func TestGatewayEnrollmentSignedHTTPAdmission(t *testing.T) {
	for _, name := range []string{"accepted", "off", "catalog_failure", "wrong_scope_receipt", "bad_proof", "scope_header", "malformed", "oversize", "duplicate_authorization", "wrong_media", "query"} {
		t.Run(name, func(t *testing.T) {
			_, raw, receipt, l, s := enrollmentFixture(t)
			own := &enrollmentRepositoryStub{receipt: receipt}
			legacy := &controlRepositoryStub{}
			var capability EnrollmentRepository = own
			want := 200
			switch name {
			case "off":
				capability = nil
				want = 404
			case "catalog_failure":
				own.readyErr = errors.New("own catalog absent")
				want = 503
			case "wrong_scope_receipt":
				own.receipt.DeviceID = fixtureID(9)
				want = 503
			case "bad_proof", "scope_header", "duplicate_authorization":
				want = 401
			case "malformed":
				raw = []byte(`{}`)
				want = 400
			case "oversize":
				raw = bytes.Repeat([]byte(" "), 4097)
				want = 400
			case "wrong_media", "query":
				want = 404
			}
			handler, e := NewHTTPHandler(HTTPHandlerConfig{Repository: legacy, EnrollmentRepository: capability, Clock: func() time.Time { return receipt.IssuedAt }, OperationTimeout: time.Second, MaximumBodyBytes: 16384})
			if e != nil {
				t.Fatal(e)
			}
			req := enrollmentSignedRequest(t, raw, l, s)
			switch name {
			case "bad_proof":
				req.Header.Set(SignatureHeader, strings.Repeat("A", 86))
			case "scope_header":
				req.Header.Set("X-Tenant-ID", fixtureID(9))
			case "duplicate_authorization":
				req.Header.Add(AuthorizationHeader, req.Header.Get(AuthorizationHeader))
			case "wrong_media":
				req.Header.Set("Content-Type", "text/plain")
			case "query":
				req.URL.RawQuery = "unexpected=1"
			}
			out := httptest.NewRecorder()
			handler.ServeHTTP(out, req)
			if out.Code != want {
				t.Fatalf("status=%d want=%d body=%s", out.Code, want, out.Body)
			}
			if name == "accepted" {
				if own.calls != 1 || !bytes.Equal(own.raw, raw) || !bytes.Equal(own.locator, l) || !bytes.Equal(own.secret, s) || legacy.authorityCalls != 0 || out.Header().Get("Content-Type") != JSONMediaType || out.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("not original bounded bootstrap route without preexisting Device credential")
				}
				var got wire.Receipt
				if json.Unmarshal(out.Body.Bytes(), &got) != nil || got.RequestSHA256 != receipt.RequestSHA256 {
					t.Fatal("receipt mismatch")
				}
			} else if name != "wrong_scope_receipt" && own.calls != 0 {
				t.Fatal("rejected request reached native enrollment")
			}
			if bytes.Contains(out.Body.Bytes(), []byte(base64.RawURLEncoding.EncodeToString(s))) {
				t.Fatal("secret echoed")
			}
		})
	}
}

type enrollmentTxPool struct {
	tx      *enrollmentTx
	options pgx.TxOptions
}

func (p *enrollmentTxPool) BeginTx(_ context.Context, o pgx.TxOptions) (pgx.Tx, error) {
	p.options = o
	return p.tx, nil
}

type enrollmentTx struct {
	pgx.Tx
	responses          []any
	queries            []string
	arguments          [][]any
	commits, rollbacks int
	commitErr          error
}

func (t *enrollmentTx) QueryRow(_ context.Context, q string, args ...any) pgx.Row {
	t.queries = append(t.queries, q)
	t.arguments = append(t.arguments, args)
	if len(t.responses) == 0 {
		return enrollmentRow{err: errors.New("unexpected query")}
	}
	v := t.responses[0]
	t.responses = t.responses[1:]
	return enrollmentRow{value: v}
}
func (t *enrollmentTx) Commit(context.Context) error   { t.commits++; return t.commitErr }
func (t *enrollmentTx) Rollback(context.Context) error { t.rollbacks++; return nil }

type enrollmentRow struct {
	value any
	err   error
}

func (r enrollmentRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	switch p := dest[0].(type) {
	case *[]byte:
		b, ok := r.value.([]byte)
		if !ok {
			return errors.New("wrong row")
		}
		*p = append([]byte(nil), b...)
	case *bool:
		v, ok := r.value.(bool)
		if !ok {
			return errors.New("wrong fence row")
		}
		*p = v
	case *time.Time:
		v, ok := r.value.(time.Time)
		if !ok {
			return errors.New("wrong clock row")
		}
		*p = v
	default:
		return errors.New("unexpected scan")
	}
	return nil
}
func TestGatewayEnrollmentTransactionCurrentAuthorityBeforeCommit(t *testing.T) {
	// Late constructor controls are source acceptance, not executed baseline RED.
	t.Run("own_profile_pins", func(t *testing.T) {
		for _, pin := range []string{migrations.GatewayBootstrapProfileChecksum(), migrations.GatewayBootstrapAuditProfileChecksum()} {
			db := &installationReadyDatabase{ready: true}
			legacy, e := NewPostgresRepository(db, time.Second)
			if e != nil {
				t.Fatal(e)
			}
			own, e := legacy.EnrollmentRepositoryForProfile(pin)
			if e != nil || db.calls != 0 {
				t.Fatal("own constructor changed/readied legacy repository")
			}
			if e = own.EnrollmentReady(context.Background()); e != nil || db.query != enrollmentReadySQL || len(db.args) != 1 || db.args[0] != pin {
				t.Fatalf("query=%s err=%v", db.query, e)
			}
			db.ready = false
			if own.EnrollmentReady(context.Background()) == nil {
				t.Fatal("bad profile admitted")
			}
		}
		if own, e := NewPostgresEnrollmentRepository(&installationReadyDatabase{}, time.Second, "uncompiled"); e == nil || own != nil {
			t.Fatal("uncompiled profile admitted")
		}
	})

	for _, name := range []string{"committed", "exact_replay", "foreign_initial_scope", "changed_final_token", "wrong_current_key", "expired_after_wait", "unknown_commit", "bad_native_receipt", "token_expired_at_final_fence"} {
		t.Run(name, func(t *testing.T) {
			request, raw, receipt, l, s := enrollmentFixture(t)
			auth := map[string]any{"organization_id": request.OrganizationID, "workspace_id": request.WorkspaceID, "environment_id": request.EnvironmentID, "device_id": request.DeviceID, "device_version": 3, "enrollment_id": request.EnrollmentID, "token_generation": request.TokenGeneration, "consumed": false, "audience": "runtime-gateway-enroll"}
			if name == "exact_replay" {
				auth["consumed"] = true
				auth["device_version"] = 4
			}
			initial, _ := json.Marshal(auth)
			auth["consumed"] = true
			auth["device_version"] = 4
			final, _ := json.Marshal(auth)
			native := map[string]any{"id": request.CredentialID, "device_id": request.DeviceID, "credential_generation": request.CredentialGeneration, "key_id": request.KeyID, "algorithm": "Ed25519", "audience": GatewayAudience, "issued_at": receipt.IssuedAt, "expires_at": request.ExpiresAt, "replayed": name == "exact_replay"}
			nativeRaw, _ := json.Marshal(native)
			pub, _ := fixtureGatewayKey(t)
			authority := fixtureAuthority(pub)
			authority.ExpiresAt = request.ExpiresAt
			authorityRaw, _ := json.Marshal(authorityPayload{OrganizationID: authority.OrganizationID, WorkspaceID: authority.WorkspaceID, EnvironmentID: authority.EnvironmentID, DeviceID: authority.DeviceID, DeviceVersion: 4, ReplayFloor: authority.ReplayFloor, CredentialID: authority.CredentialID, CredentialGeneration: authority.CredentialGeneration, KeyID: authority.KeyID, Algorithm: authority.Algorithm, PublicKey: request.PublicKey, Audience: GatewayAudience, ExpiresAt: request.ExpiresAt})
			clock := receipt.IssuedAt
			switch name {
			case "foreign_initial_scope":
				auth["organization_id"] = fixtureID(9)
				initial, _ = json.Marshal(auth)
			case "changed_final_token":
				auth["token_generation"] = uint64(2)
				final, _ = json.Marshal(auth)
			case "wrong_current_key":
				authorityRaw = bytes.Replace(authorityRaw, []byte(request.PublicKey), []byte(base64.RawURLEncoding.EncodeToString(make([]byte, 32))), 1)
			case "expired_after_wait":
				clock = request.ExpiresAt
			case "bad_native_receipt":
				nativeRaw = []byte(`{}`)
			}
			tx := &enrollmentTx{responses: []any{initial, nativeRaw, final, authorityRaw, clock, name != "token_expired_at_final_fence"}}
			if name == "unknown_commit" {
				tx.commitErr = errors.New("connection lost")
			}
			pool := &enrollmentTxPool{tx: tx}
			got, e := CommitProductionGatewayEnrollment(context.Background(), pool, l, s, raw, migrations.GatewayBootstrapProfileChecksum())
			success := name == "committed" || name == "exact_replay"
			if (e == nil) != success {
				t.Fatalf("receipt=%#v err=%v queries=%v", got, e, tx.queries)
			}
			if tx.rollbacks != 1 {
				t.Fatalf("cleanup=%d", tx.rollbacks)
			}
			if success {
				want := []string{`SELECT public.zasp_runtime_authenticate_gateway_enrollment($1,$2,'runtime-gateway-enroll')`, `SELECT public.zasp_runtime_gateway_enroll($1,$2,'runtime-gateway-enroll',$3,$4,$5,'Ed25519',$6,$7)`, `SELECT public.zasp_runtime_authenticate_gateway_enrollment($1,$2,'runtime-gateway-enroll')`, `SELECT public.zasp_runtime_gateway_credential_authority($1,'runtime-gateway')`, `SELECT clock_timestamp()`, `SELECT zasp_gateway_bootstrap_v1.enrollment_final_fence($1,$2,$3,$4::jsonb,$5)`}
				if tx.commits != 1 || pool.options.IsoLevel != pgx.ReadCommitted || strings.Join(tx.queries, "\n") != strings.Join(want, "\n") || got.RequestSHA256 != receipt.RequestSHA256 || got.Replayed != (name == "exact_replay") {
					t.Fatalf("transaction/receipt mismatch: %#v %#v", tx, got)
				}
				if len(tx.arguments[5]) != 5 || !bytes.Equal(tx.arguments[5][0].([]byte), l) || !bytes.Equal(tx.arguments[5][1].([]byte), s) || tx.arguments[5][2] != request.CredentialID || tx.arguments[5][4] != migrations.GatewayBootstrapProfileChecksum() {
					t.Fatal("unbound final fence")
				}
				var fencedReceipt wire.Receipt
				if json.Unmarshal(tx.arguments[5][3].(json.RawMessage), &fencedReceipt) != nil || fencedReceipt.RequestSHA256 != receipt.RequestSHA256 || fencedReceipt.CredentialID != request.CredentialID {
					t.Fatal("fence receipt changed original request binding")
				}
				if !bytes.Equal(tx.arguments[0][0].([]byte), l) || !bytes.Equal(tx.arguments[0][1].([]byte), s) {
					t.Fatal("different original enrollment token")
				}
			} else if name != "unknown_commit" && tx.commits != 0 {
				t.Fatal("unconfirmed enrollment committed")
			}
		})
	}
}
