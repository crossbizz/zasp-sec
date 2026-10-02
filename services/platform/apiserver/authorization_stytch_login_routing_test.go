package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5"
	platformidentity "github.com/zasp-ai/zasp-sec/services/platform/identity"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Constructor metadata is controlled, not installed PostgreSQL readiness proof.
// The real adapter, repository, provider, session handler and router execute.
type loginRoutingDriver struct {
	queryCalls, execCalls, beginCalls int
	stateDigest                       [32]byte
	returnPath                        string
}

type loginRoutingRow func(...any) error

func (r loginRoutingRow) Scan(dest ...any) error { return r(dest...) }

func (d *loginRoutingDriver) QueryRow(_ context.Context, query string, args ...any) PostgresRow {
	d.queryCalls++
	return loginRoutingRow(func(dest ...any) error {
		switch query {
		case postgresSchemaMarkerSQL:
			if len(args) == 0 && len(dest) == 1 {
				if value, ok := dest[0].(*string); ok {
					*value = ProductionRecoverySchemaVersion
					return nil
				}
			}
		case postgresProductionRecoverySchemaVersionSQL:
			expected := []any{expectedProductionRecoverySchemaChecksum(), expectedProductionRecoverySchemaFingerprint(), migrations.ProductionRuntimeAcceptance().Checksum(), migrations.ProductionRuntimeAcceptanceSemanticFingerprint(), migrations.ProductionRuntimeCorrelationRouting().Checksum(), migrations.ProductionRuntimeCorrelationRoutingSemanticFingerprint()}
			if reflect.DeepEqual(args, expected) && len(dest) == 1 {
				if value, ok := dest[0].(*string); ok {
					*value = ProductionRecoverySchemaVersion
					return nil
				}
			}
		case postgresAuthorizationReadySQL:
			if reflect.DeepEqual(args, []any{migrations.ProductionAuthorizationEnforcement().Checksum()}) && len(dest) == 1 {
				if value, ok := dest[0].(*bool); ok {
					*value = true
					return nil
				}
			}
		case `SELECT zasp_authorization80.ready($1), public.zasp_discovery_principal_ready('zasp_discovery_api')`:
			if reflect.DeepEqual(args, []any{migrations.ProductionAuthorizationEnforcement().Checksum()}) && len(dest) == 2 {
				left, leftOK := dest[0].(*bool)
				right, rightOK := dest[1].(*bool)
				if leftOK && rightOK {
					*left, *right = true, true
					return nil
				}
			}
		}
		return errors.New("unexpected login characterization metadata contract")
	})
}

func (d *loginRoutingDriver) Exec(_ context.Context, query string, args ...any) error {
	d.execCalls++
	if query != postgresBeginIdentitySQL || len(args) != 2 {
		return errors.New("unexpected login characterization execution")
	}
	state, stateOK := args[0].(string)
	path, pathOK := args[1].(string)
	decoded, err := base64.RawURLEncoding.DecodeString(state)
	if !stateOK || !pathOK || err != nil || len(decoded) != 32 || path != "/discovery/assets" {
		return errors.New("invalid login characterization state arguments")
	}
	// Model only the digest-backed INSERT's accepted arguments. No SQL engine,
	// expiry, persistence or provider semantics are claimed by this fixture.
	d.stateDigest, d.returnPath = sha256.Sum256([]byte(state)), path
	return nil
}

func (d *loginRoutingDriver) Begin(context.Context) (pgx.Tx, error) {
	d.beginCalls++
	return nil, errors.New("unexpected login characterization transaction")
}

func (*loginRoutingDriver) Close() error { return nil }

type loginRoutingAuthenticator struct{ calls int }

func (a *loginRoutingAuthenticator) Authenticate(context.Context, string) (platformidentity.ExternalPrincipal, error) {
	a.calls++
	return platformidentity.ExternalPrincipal{}, errors.New("login start must not authenticate externally")
}

func (*loginRoutingAuthenticator) Ready(context.Context) error { return nil }

// Diagnostic of current behavior, not a desired-login regression test. A future
// lifecycle repair must replace the denial expectation with its closed contract.
func TestP7StytchLoginStartRoutingCharacterization(t *testing.T) {
	for _, enforcing := range []bool{true, false} {
		name := "current80-denies-before-state-insert"
		if !enforcing {
			name = "explicit-non-enforcing-compatibility-control"
		}
		t.Run(name, func(t *testing.T) {
			driver := &loginRoutingDriver{}
			database, err := NewPostgresJSONDatabase(driver)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := database.Close(); err != nil {
					t.Error(err)
				}
			})
			if enforcing {
				if err := database.RequireCurrentAuthorization(); err != nil {
					t.Fatal(err)
				}
			}
			repository, err := NewPostgresRepository(database)
			if err != nil || repository.currentAuthorization != enforcing || driver.queryCalls != 2 {
				t.Fatalf("controlled constructor failed: error=%v metadata_queries=%d", err, driver.queryCalls)
			}
			authenticator := &loginRoutingAuthenticator{}
			provider, err := NewRepositoryIdentityProviderWithStart(authenticator, repository, repository,
				"https://test.stytch.com/v1/b2b/public/oauth/google/start", "public-token-characterization", "organization-characterization", "https://app.zasp.example/auth/callback")
			if err != nil {
				t.Fatal(err)
			}
			handler := &sessionHTTPHandler{repository: repository, provider: provider, cookie: CookiePolicy{Secure: true}}
			var operations []Operation
			for _, definition := range coreOperations {
				if definition.OperationID == "startSession" {
					if definition.Method != http.MethodGet || definition.Pattern != "/api/v1/session/start" || definition.Permission != "" || len(definition.Security) != 0 {
						t.Fatal("login start registry contract changed")
					}
					operations = append(operations, Operation{Method: definition.Method, Pattern: definition.Pattern, OperationID: definition.OperationID, Handler: handler})
				}
			}
			if len(operations) != 1 {
				t.Fatal("login start must have one registered route")
			}
			router, err := NewRouter(operations)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, "/api/v1/session/start?return_to=%2Fdiscovery%2Fassets", nil)
			if _, ok := IdentityFromRequest(request); ok {
				t.Fatal("unexpected authenticated fixture request")
			}
			if _, ok := requestAuthorizationFromContext(request.Context()); ok {
				t.Fatal("unexpected request authorization fixture")
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Header().Get("Set-Cookie") != "" || driver.beginCalls != 0 || driver.queryCalls != 2 || authenticator.calls != 0 {
				t.Fatal("unexpected cookie, transaction, post-constructor query or provider authentication")
			}
			if enforcing {
				var body struct {
					Code string `json:"code"`
				}
				if response.Code != http.StatusServiceUnavailable || json.Unmarshal(response.Body.Bytes(), &body) != nil || body.Code != "provider_unavailable" || response.Header().Get("Location") != "" || driver.execCalls != 0 || driver.stateDigest != ([32]byte{}) {
					t.Fatalf("expected mounted refusal: status=%d exec=%d", response.Code, driver.execCalls)
				}
			} else {
				target, parseErr := url.Parse(response.Header().Get("Location"))
				if response.Code != http.StatusFound || parseErr != nil || target.Scheme != "https" || target.Host != "test.stytch.com" || target.Path != "/v1/b2b/public/oauth/google/start" || driver.execCalls != 1 || driver.returnPath != "/discovery/assets" {
					t.Fatalf("expected compatibility redirect: status=%d exec=%d", response.Code, driver.execCalls)
				}
				query := target.Query()
				callback, callbackErr := url.Parse(query.Get("login_redirect_url"))
				if callbackErr != nil || callback.Scheme != "https" || callback.Host != "app.zasp.example" || callback.Path != "/auth/callback" || sha256.Sum256([]byte(callback.Query().Get("state"))) != driver.stateDigest || query.Get("signup_redirect_url") != callback.String() || query.Get("public_token") != "public-token-characterization" || query.Get("organization_id") != "organization-characterization" {
					t.Fatal("configured redirect or digest-state binding mismatched")
				}
			}
			t.Logf("enforcing=%t status=%d controlled_metadata_queries=%d state_insert_calls=%d transactions=%d provider_authentication_calls=%d", enforcing, response.Code, driver.queryCalls, driver.execCalls, driver.beginCalls, authenticator.calls)
		})
	}
}
