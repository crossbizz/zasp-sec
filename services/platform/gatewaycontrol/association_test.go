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
	wire "github.com/zasp-ai/zasp-sec/services/platform/gatewayassociationwire"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func associationFixture(t *testing.T) (Authority, []byte, wire.AcceptResponse, wire.DeviceBinding, time.Time) {
	t.Helper()
	pub, _ := fixtureGatewayKey(t)
	a := fixtureAuthority(pub)
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	q := wire.Challenge{Schema: wire.ChallengeSchema, ChallengeID: fixtureID(7), AssociationID: fixtureID(8), OrganizationID: a.OrganizationID, WorkspaceID: a.WorkspaceID, EnvironmentID: a.EnvironmentID, AgentID: fixtureID(9), AgentSourceDigest: strings.Repeat("a", 64), DeviceID: a.DeviceID, ExpectedAssociationVersion: 0, Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), ExpiresAt: now.Add(3 * time.Minute)}
	rawChallenge, _ := json.Marshal(q)
	sum := sha256.Sum256(rawChallenge)
	challengeDigest := hex.EncodeToString(sum[:])
	raw, _ := json.Marshal(struct {
		Schema          string `json:"schema"`
		ChallengeWire   string `json:"challenge_wire"`
		ChallengeSHA256 string `json:"challenge_sha256"`
	}{wire.AcceptSchema, base64.RawURLEncoding.EncodeToString(rawChallenge), challengeDigest})
	sum = sha256.Sum256(raw)
	response := wire.AcceptResponse{ChallengeID: q.ChallengeID, ChallengeSHA256: challengeDigest, AssociationID: q.AssociationID, Acceptance: wire.Acceptance{RequestSHA256: hex.EncodeToString(sum[:]), Credential: wire.DeviceCredential{CredentialID: a.CredentialID, CredentialGeneration: a.CredentialGeneration, ExpiresAt: a.ExpiresAt}, AcceptedAt: now, ExpiresAt: q.ExpiresAt}, Replayed: false}
	binding := wire.DeviceBinding{OrganizationID: a.OrganizationID, WorkspaceID: a.WorkspaceID, EnvironmentID: a.EnvironmentID, DeviceID: a.DeviceID, CredentialID: a.CredentialID, CredentialGeneration: a.CredentialGeneration, PublicKey: base64.RawURLEncoding.EncodeToString(a.PublicKey), ExpiresAt: a.ExpiresAt}
	return a, raw, response, binding, now
}

type associationRepositoryStub struct {
	response wire.AcceptResponse
	readyErr error
	calls    int
	raw      []byte
	binding  wire.DeviceBinding
}

func (s *associationRepositoryStub) AssociationReady(context.Context) error { return s.readyErr }
func (s *associationRepositoryStub) AcceptAgentDevice(_ context.Context, raw []byte, b wire.DeviceBinding) (wire.AcceptResponse, error) {
	s.calls++
	s.raw = append([]byte(nil), raw...)
	s.binding = b
	return s.response, nil
}
func TestAgentDeviceAssociationSignedAcceptRequiresCurrentDevice(t *testing.T) {
	for _, name := range []string{"accepted", "off", "catalog_failure", "bad_signature", "scope_header", "malformed", "oversize", "wrong_receipt_generation", "wrong_media", "query", "foreign_device", "expired_authority", "empty_query"} {
		t.Run(name, func(t *testing.T) {
			authority, raw, response, binding, now := associationFixture(t)
			repo := &controlRepositoryStub{authority: authority}
			own := &associationRepositoryStub{response: response}
			var optional AssociationRepository = own
			want := 200
			switch name {
			case "off":
				optional = nil
				want = 404
			case "catalog_failure":
				own.readyErr = errors.New("not installed")
				want = 503
			case "foreign_device":
				repo.authority.DeviceID = fixtureID(6)
				want = 401
			case "expired_authority":
				repo.authority.ExpiresAt = now
				want = 401
			case "bad_signature", "scope_header":
				want = 401
			case "malformed":
				raw = []byte(`{}`)
				want = 400
			case "oversize":
				raw = bytes.Repeat([]byte(" "), 16385)
				want = 400
			case "wrong_receipt_generation":
				own.response.Acceptance.Credential.CredentialGeneration++
				want = 503
			case "wrong_media", "query", "empty_query":
				want = 404
			}
			handler, e := NewHTTPHandler(HTTPHandlerConfig{Repository: repo, AssociationRepository: optional, Clock: func() time.Time { return now }, OperationTimeout: time.Second, MaximumBodyBytes: 1024})
			if e != nil {
				t.Fatal(e)
			}
			request := httptest.NewRequest(http.MethodPost, "https://gateway-control.zasp.example"+AssociationAcceptPath, bytes.NewReader(raw))
			request.Header.Set("Content-Type", JSONMediaType)
			if name == "query" {
				request.URL.RawQuery = "unexpected=1"
			}
			if name == "empty_query" {
				request.URL.ForceQuery = true
			}
			_, key := fixtureGatewayKey(t)
			if SignRequest(request, raw, authority.CredentialID, key, now) != nil {
				t.Fatal("fixture signing")
			}
			switch name {
			case "bad_signature":
				request.Header.Set(SignatureHeader, strings.Repeat("A", 86))
			case "scope_header":
				request.Header.Set("X-Tenant-ID", fixtureID(6))
			case "wrong_media":
				request.Header.Set("Content-Type", "text/plain")
			}
			out := httptest.NewRecorder()
			handler.ServeHTTP(out, request)
			if out.Code != want {
				t.Fatalf("status=%d want=%d body=%s", out.Code, want, out.Body)
			}
			if name == "accepted" {
				if own.calls != 1 || own.binding != binding || !bytes.Equal(own.raw, raw) || repo.authorityCalls != 1 || out.Header().Get("Cache-Control") != "no-store" || out.Header().Get("Pragma") != "no-cache" {
					t.Fatal("signed route lost exact authority/body/response")
				}
				var got map[string]any
				if json.Unmarshal(out.Body.Bytes(), &got) != nil || len(got) != 5 || got["new_mutation"] != nil {
					t.Fatal("private marker leaked")
				}
			} else if name != "wrong_receipt_generation" && own.calls != 0 {
				t.Fatal("rejected request mutated")
			}
			if name == "catalog_failure" {
				probe := httptest.NewRequest(http.MethodGet, "https://gateway-control.zasp.example"+AuthorityPath, nil)
				_ = SignRequest(probe, nil, authority.CredentialID, key, now)
				prior := httptest.NewRecorder()
				handler.ServeHTTP(prior, probe)
				if prior.Code != 200 {
					t.Fatal("own catalog poisoned original authority")
				}
			}
		})
	}
}

type associationTx struct {
	pgx.Tx
	response           []byte
	confirmed          bool
	commitErr          error
	queries            []string
	args               [][]any
	commits, rollbacks int
}

func (t *associationTx) QueryRow(_ context.Context, q string, args ...any) pgx.Row {
	t.queries = append(t.queries, q)
	t.args = append(t.args, args)
	if len(t.queries) == 1 {
		return associationRow{raw: t.response}
	}
	return associationRow{confirmed: t.confirmed}
}
func (t *associationTx) Commit(context.Context) error   { t.commits++; return t.commitErr }
func (t *associationTx) Rollback(context.Context) error { t.rollbacks++; return nil }

type associationRow struct {
	raw       []byte
	confirmed bool
}

func (r associationRow) Scan(dest ...any) error {
	switch p := dest[0].(type) {
	case *[]byte:
		*p = append([]byte(nil), r.raw...)
	case *bool:
		*p = r.confirmed
	default:
		return errors.New("badscan")
	}
	return nil
}

type associationPool struct {
	tx      *associationTx
	options pgx.TxOptions
}

func (p *associationPool) BeginTx(_ context.Context, o pgx.TxOptions) (pgx.Tx, error) {
	p.options = o
	return p.tx, nil
}
func TestAgentDeviceAssociationSamePoolConfirmBeforeCommit(t *testing.T) {
	// Late grouped strict wrapper controls; declared only until root execution.
	t.Run("strict_private_wrapper", func(t *testing.T) {
		_, raw, response, binding, now := associationFixture(t)
		receipt, _ := json.Marshal(response)
		valid, _ := json.Marshal(map[string]any{"receipt": response, "new_mutation": true})
		variants := [][]byte{
			append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"new_mutation":true}`)...),
			append(append([]byte(nil), valid[:len(valid)-1]...), append([]byte(`,"receipt":`), append(receipt, '}')...)...),
			bytes.Replace(valid, []byte(`"new_mutation"`), []byte(`"NEW_MUTATION"`), 1),
			[]byte(`{"receipt":null,"new_mutation":true}`),
			append(append([]byte(`{"receipt":`), receipt...), []byte(`,"new_mutation":null}`)...),
			append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"extra":true}`)...),
			append(append([]byte(nil), valid...), 0xff),
			append(append([]byte(`{"receipt":`), receipt...), []byte(`,"new_mutation":"true"}`)...),
			append(append([]byte(nil), valid...), []byte(` {}`)...),
		}
		for index, internal := range variants {
			tx := &associationTx{response: internal, confirmed: true}
			pool := &associationPool{tx: tx}
			if _, e := CommitProductionAgentDeviceAcceptance(context.Background(), pool, raw, binding, migrations.AgentDeviceAssociationProfileChecksum(), now); e == nil || tx.commits != 0 || len(tx.queries) != 1 {
				t.Fatalf("invalid wrapper %d reached confirmation or commit: %v", index, e)
			}
		}
	})

	// Late compiled-profile controls, not a new executed RED.
	t.Run("own_profile_pins", func(t *testing.T) {
		for _, pin := range []string{migrations.AgentDeviceAssociationProfileChecksum(), migrations.AgentDeviceAssociationAuditProfileChecksum()} {
			database := &installationReadyDatabase{ready: true}
			base, e := NewPostgresRepository(database, time.Second)
			if e != nil {
				t.Fatal(e)
			}
			own, e := base.AssociationRepositoryForProfile(pin)
			if e != nil || database.calls != 0 {
				t.Fatal("capability altered original readiness")
			}
			if e = own.AssociationReady(context.Background()); e != nil || database.query != associationReadySQL || len(database.args) != 1 || database.args[0] != pin {
				t.Fatal("own readiness missing exact compiled profile")
			}
			database.ready = false
			if own.AssociationReady(context.Background()) == nil {
				t.Fatal("unready own profile admitted")
			}
		}
		if own, e := NewPostgresAssociationRepository(&installationReadyDatabase{}, time.Second, "uncompiled"); e == nil || own != nil {
			t.Fatal("uncompiled profile admitted")
		}
	})

	for _, name := range []string{"accepted", "replay", "final_fence_false", "unknown_commit", "wrong_generation", "missing_private_marker", "historical_marker_mismatch"} {
		t.Run(name, func(t *testing.T) {
			_, raw, response, binding, now := associationFixture(t)
			if name == "replay" {
				response.Replayed = true
			}
			if name == "wrong_generation" {
				response.Acceptance.Credential.CredentialGeneration++
			}
			newMutation := name != "replay" && name != "historical_marker_mismatch"
			internal, _ := json.Marshal(map[string]any{"receipt": response, "new_mutation": newMutation})
			if name == "missing_private_marker" {
				internal, _ = json.Marshal(map[string]any{"receipt": response})
			}
			tx := &associationTx{response: internal, confirmed: name != "final_fence_false"}
			if name == "unknown_commit" {
				tx.commitErr = errors.New("connection lost")
			}
			pool := &associationPool{tx: tx}
			pin := migrations.AgentDeviceAssociationProfileChecksum()
			got, e := CommitProductionAgentDeviceAcceptance(context.Background(), pool, raw, binding, pin, now)
			success := name == "accepted" || name == "replay"
			if (e == nil) != success {
				t.Fatalf("receipt=%#v err=%v queries=%v", got, e, tx.queries)
			}
			if tx.rollbacks != 1 {
				t.Fatal("rollback cleanup missing")
			}
			if success {
				if pool.options.IsoLevel != pgx.ReadCommitted || tx.commits != 1 || len(tx.queries) != 2 || tx.queries[0] != `SELECT zasp_agent_device_association_v1.accept_intent($1,$2,$3)` || tx.queries[1] != `SELECT zasp_agent_device_association_v1.confirm_device($1,$2,$3::jsonb,$4)` {
					t.Fatal("not original samepool closed transaction")
				}
				if tx.args[0][0] != binding.CredentialID || !bytes.Equal(tx.args[0][1].([]byte), raw) || tx.args[0][2] != pin || tx.args[1][3] != pin || !bytes.Equal(tx.args[1][2].(json.RawMessage), internal) {
					t.Fatal("confirm changed exact private wrapper/request/pin")
				}
			} else if name != "unknown_commit" && tx.commits != 0 {
				t.Fatal("unconfirmed acceptance committed")
			}
		})
	}
}
