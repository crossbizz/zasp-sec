package gatewaycontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	wire "github.com/zasp-ai/zasp-sec/services/platform/gatewayinstallationwire"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type installationStub struct {
	receipt              wire.Receipt
	raw                  []byte
	credential           string
	calls                int
	readyErr, errorValue error
}

func (s *installationStub) InstallationReady(context.Context) error { return s.readyErr }
func (s *installationStub) RecordInstallation(_ context.Context, id string, raw []byte) (wire.Receipt, error) {
	s.calls++
	s.credential = id
	s.raw = append([]byte(nil), raw...)
	return s.receipt, s.errorValue
}
func installationFixture(t *testing.T) (Authority, []byte, wire.Receipt) {
	t.Helper()
	pub, _ := fixtureGatewayKey(t)
	a := fixtureAuthority(pub)
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	o := wire.Observation{Schema: wire.ObservationSchema, CredentialGeneration: a.CredentialGeneration, ContractVersion: 1, KeyID: "policy-key-1", Algorithm: "Ed25519", Audience: PolicyAudience, Sequence: 4, PolicyVersion: 3, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), FailureMode: "closed", PayloadDigest: strings.Repeat("a", 64), Signature: base64.RawURLEncoding.EncodeToString(make([]byte, 64)), InstalledObservedAt: now}
	raw, e := json.Marshal(o)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	r := wire.Receipt{Schema: wire.ReceiptSchema, RequestSHA256: digest, OrganizationID: a.OrganizationID, WorkspaceID: a.WorkspaceID, EnvironmentID: a.EnvironmentID, DeviceID: a.DeviceID, CredentialID: a.CredentialID, CredentialGeneration: a.CredentialGeneration, Disposition: "recorded", RepresentativeSHA256: digest, RepresentativeSequence: 4, RepresentativeInstalledObservedAt: now, RepresentativeRecordedAt: now}
	return a, raw, r
}
func installationRequest(t *testing.T, body []byte) *http.Request {
	t.Helper()
	_, key := fixtureGatewayKey(t)
	a, _, _ := installationFixture(t)
	r := httptest.NewRequest(http.MethodPost, "https://gateway-control.zasp.example"+InstallationPath, bytes.NewReader(body))
	r.Header.Set("Content-Type", JSONMediaType)
	if e := SignRequest(r, body, a.CredentialID, key, time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)); e != nil {
		t.Fatal(e)
	}
	return r
}
func TestInstallationSignedHandlerConnectedAdmission(t *testing.T) {
	for _, name := range []string{"recorded", "off", "catalog_failure", "foreign_receipt", "generation_mismatch", "malformed", "oversize", "scope_injection", "mutated_signature", "wrong_media", "query"} {
		t.Run(name, func(t *testing.T) {
			a, raw, receipt := installationFixture(t)
			s := &installationStub{receipt: receipt}
			repo := &controlRepositoryStub{authority: a}
			var optional InstallationRepository = s
			want := 200
			switch name {
			case "off":
				optional = nil
				want = 404
			case "catalog_failure":
				s.readyErr = errors.New("unavailable")
				want = 503
			case "foreign_receipt":
				s.receipt.OrganizationID = fixtureID(9)
				want = 503
			case "generation_mismatch":
				s.receipt.CredentialGeneration++
				want = 503
			case "malformed":
				raw = []byte(`{}`)
				want = 400
			case "oversize":
				raw = []byte(strings.Repeat(" ", 4097))
				want = 400
			case "scope_injection", "mutated_signature":
				want = 401
			case "wrong_media", "query":
				want = 404
			}
			h, e := NewHTTPHandler(HTTPHandlerConfig{Repository: repo, InstallationRepository: optional, Clock: func() time.Time { return receipt.RepresentativeRecordedAt }, OperationTimeout: time.Second, MaximumBodyBytes: 16384})
			if e != nil {
				t.Fatal(e)
			}
			req := installationRequest(t, raw)
			switch name {
			case "scope_injection":
				req.Header.Set("X-Tenant-ID", fixtureID(9))
			case "mutated_signature":
				req.Body = io.NopCloser(strings.NewReader(string(raw) + " "))
			case "wrong_media":
				req.Header.Set("Content-Type", "text/plain")
			case "query":
				req.URL.RawQuery = "x=1"
				_, key := fixtureGatewayKey(t)
				if e := SignRequest(req, raw, a.CredentialID, key, receipt.RepresentativeRecordedAt); e != nil {
					t.Fatal(e)
				}
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != want {
				t.Fatalf("status=%d want=%d body=%s", rr.Code, want, rr.Body)
			}
			if name == "recorded" {
				if s.calls != 1 || s.credential != a.CredentialID || !bytes.Equal(s.raw, raw) || rr.Header().Get("Cache-Control") != "no-store" || rr.Header().Get("Content-Type") != JSONMediaType {
					t.Fatalf("bad connected request/response: %#v", s)
				}
			} else if name != "foreign_receipt" && name != "generation_mismatch" && s.calls != 0 {
				t.Fatal("rejected request reached record")
			}
			// A failed optional installation catalog must never poison the original authority route.
			if name == "catalog_failure" {
				q := installationRequest(t, nil)
				q.Method = http.MethodGet
				q.URL.Path = AuthorityPath
				q.Body = nil
				_, key := fixtureGatewayKey(t)
				_ = SignRequest(q, nil, a.CredentialID, key, receipt.RepresentativeRecordedAt)
				out := httptest.NewRecorder()
				h.ServeHTTP(out, q)
				if out.Code != 200 {
					t.Fatalf("original authority gated: %d", out.Code)
				}
			}
		})
	}
}

type installationRoundTrip func(*http.Request) (*http.Response, error)

func (f installationRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestInstallationSignedClientStrictReceipt(t *testing.T) {
	for _, name := range []string{"recorded", "coalesced", "legacy_204", "foreign_scope", "wrong_generation", "wrong_digest", "bad_rank", "oversize", "duplicate", "missing_no_store", "wrong_media"} {
		t.Run(name, func(t *testing.T) {
			a, raw, r := installationFixture(t)
			status := 200
			media, cache := JSONMediaType, "no-store"
			switch name {
			case "coalesced":
				r.Disposition = "coalesced"
				r.RepresentativeSequence++
				r.RepresentativeSHA256 = strings.Repeat("b", 64)
			case "legacy_204":
				status = 204
			case "foreign_scope":
				r.DeviceID = fixtureID(9)
			case "wrong_generation":
				r.CredentialGeneration++
			case "wrong_digest":
				r.RequestSHA256 = strings.Repeat("c", 64)
			case "bad_rank":
				r.Disposition = "coalesced"
			case "missing_no_store":
				cache = ""
			case "wrong_media":
				media = "text/plain"
			}
			body, _ := json.Marshal(r)
			if name == "oversize" {
				body = bytes.Repeat([]byte(" "), 4097)
			}
			if name == "duplicate" {
				body = append([]byte(`{"schema":"gateway-policy-installation-receipt-v1",`), body[1:]...)
			}
			_, key := fixtureGatewayKey(t)
			calls := 0
			c, e := newHTTPClient(HTTPClientConfig{BaseURL: "https://gateway-control.zasp.example", OrganizationID: a.OrganizationID, WorkspaceID: a.WorkspaceID, EnvironmentID: a.EnvironmentID, DeviceID: a.DeviceID, CredentialID: a.CredentialID, KeyID: a.KeyID, PrivateKey: key, OperationTimeout: time.Second, Clock: func() time.Time { return r.RepresentativeRecordedAt }}, &http.Client{Transport: installationRoundTrip(func(req *http.Request) (*http.Response, error) {
				calls++
				got, _ := io.ReadAll(req.Body)
				if req.Method != "POST" || req.URL.Path != InstallationPath || req.URL.RawQuery != "" || !bytes.Equal(got, raw) || req.Header.Get(SignatureHeader) == "" {
					t.Fatal("not original signed installation bytes")
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{media}, "Cache-Control": []string{cache}}, Body: io.NopCloser(bytes.NewReader(body))}, nil
			})})
			if e != nil {
				t.Fatal(e)
			}
			got, e := c.RecordInstallation(context.Background(), a.CredentialID, raw)
			success := name == "recorded" || name == "coalesced"
			if (e == nil) != success || calls != 1 || success && got.RequestSHA256 != r.RequestSHA256 {
				t.Fatalf("receipt=%#v err=%v calls=%d", got, e, calls)
			}
		})
	}
}

type installationTxPool struct {
	tx      *installationTx
	options pgx.TxOptions
}

func (p *installationTxPool) BeginTx(_ context.Context, o pgx.TxOptions) (pgx.Tx, error) {
	p.options = o
	return p.tx, nil
}

type installationTx struct {
	pgx.Tx
	receipt            []byte
	calls              []string
	confirmed          bool
	commitErr          error
	commits, rollbacks int
}

func (t *installationTx) QueryRow(_ context.Context, q string, args ...any) pgx.Row {
	t.calls = append(t.calls, q)
	if len(t.calls) == 1 {
		return installationRow{raw: t.receipt}
	}
	return installationRow{value: t.confirmed}
}
func (t *installationTx) Commit(context.Context) error   { t.commits++; return t.commitErr }
func (t *installationTx) Rollback(context.Context) error { t.rollbacks++; return nil }

type installationRow struct {
	raw   []byte
	value bool
}

func (r installationRow) Scan(dest ...any) error {
	switch d := dest[0].(type) {
	case *[]byte:
		*d = append([]byte(nil), r.raw...)
	case *bool:
		*d = r.value
	default:
		return errors.New("unexpected destination")
	}
	return nil
}
func TestInstallationTransactionRequiresConfirmedCommit(t *testing.T) {
	for _, name := range []string{"committed", "confirmation_false", "unknown_commit", "malformed_receipt", "wrong_generation"} {
		t.Run(name, func(t *testing.T) {
			a, raw, r := installationFixture(t)
			if name == "wrong_generation" {
				r.CredentialGeneration++
			}
			body, _ := json.Marshal(r)
			if name == "malformed_receipt" {
				body = []byte(`{}`)
			}
			tx := &installationTx{receipt: body, confirmed: name != "confirmation_false"}
			if name == "unknown_commit" {
				tx.commitErr = errors.New("connection lost")
			}
			pool := &installationTxPool{tx: tx}
			got, e := CommitProductionGatewayInstallation(context.Background(), pool, a.CredentialID, raw)
			if (e == nil) != (name == "committed") {
				t.Fatalf("receipt=%#v err=%v calls=%v", got, e, tx.calls)
			}
			if tx.rollbacks != 1 {
				t.Fatalf("rollback=%d", tx.rollbacks)
			}
			if name == "committed" && (tx.commits != 1 || pool.options.IsoLevel != pgx.ReadCommitted || len(tx.calls) != 2 || tx.calls[0] != `SELECT zasp_gateway_installation_v1.record_installation($1,$2)` || tx.calls[1] != `SELECT zasp_gateway_installation_v1.confirm_receipt($1,$2,$3::jsonb)`) {
				t.Fatalf("transaction=%#v", tx)
			}
			if (name == "confirmation_false" || name == "malformed_receipt" || name == "wrong_generation") && tx.commits != 0 {
				t.Fatal("unconfirmed transaction committed")
			}
		})
	}
}

func TestInstallationRepositoryUsesOwnCompiledProfileWithoutLegacyReadiness(t *testing.T) {
	for _, pin := range []string{migrations.GatewayInstallationProfileChecksum(), migrations.GatewayInstallationAuditProfileChecksum()} {
		db := &installationReadyDatabase{ready: true}
		legacy, e := NewPostgresRepository(db, time.Second)
		if e != nil {
			t.Fatal(e)
		}
		own, e := legacy.InstallationRepositoryForProfile(pin)
		if e != nil || db.calls != 0 {
			t.Fatalf("constructor mutated/readied old repository: %v", e)
		}
		if e = own.InstallationReady(context.Background()); e != nil || db.calls != 1 || db.query != installationReadySQL || len(db.args) != 1 || db.args[0] != pin {
			t.Fatalf("query=%s args=%v err=%v", db.query, db.args, e)
		}
		db.ready = false
		if own.InstallationReady(context.Background()) == nil {
			t.Fatal("false catalog ready admitted")
		}
	}
	db := &installationReadyDatabase{}
	if own, e := NewPostgresInstallationRepository(db, time.Second, "uncompiled"); e == nil || own != nil || db.calls != 0 {
		t.Fatal("uncompiled pin admitted")
	}
}

type installationReadyDatabase struct {
	ready bool
	calls int
	query string
	args  []any
}

func (d *installationReadyDatabase) QueryRow(_ context.Context, q string, args ...any) pgx.Row {
	d.calls++
	d.query = q
	d.args = args
	return installationRow{value: d.ready}
}
func (*installationReadyDatabase) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) {
	return nil, errors.New("not used")
}
