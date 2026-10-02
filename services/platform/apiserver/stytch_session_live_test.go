package apiserver

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestStytchLiveSessionAdapter checks our post-OAuth-exchange session boundary,
// not an OAuth browser login or a deployed product session. The proof harness
// supplies a disposable Test-project session and deletes its organization.
// Wrong request serialization, response mapping, or accepting provider refusal
// must fail this test. Never log credentials, response bodies, or principals.
func TestStytchLiveSessionAdapter(t *testing.T) {
	if os.Getenv("ZASP_RUN_LIVE_STYTCH_SESSION_TEST") != "1" {
		t.Skip("requires an explicitly supplied disposable Stytch Test session")
	}
	project, secret := os.Getenv("STYTCH_PROJECT_ID"), os.Getenv("STYTCH_SECRET")
	jwt := os.Getenv("ZASP_LIVE_STYTCH_SESSION_JWT")
	member := os.Getenv("ZASP_LIVE_STYTCH_MEMBER_ID")
	organization := os.Getenv("ZASP_LIVE_STYTCH_ORGANIZATION_ID")
	session := os.Getenv("ZASP_LIVE_STYTCH_SESSION_ID")
	phase := os.Getenv("ZASP_LIVE_STYTCH_SESSION_PHASE")
	if !strings.HasPrefix(project, "project-test-") || !strings.HasPrefix(secret, "secret-test-") ||
		!strings.HasPrefix(member, "member-test-") || !strings.HasPrefix(organization, "organization-test-") ||
		!strings.HasPrefix(session, "member-session-test-") || strings.Count(jwt, ".") != 2 ||
		(phase != "active" && phase != "revoked") {
		t.Fatal("invalid disposable Test-project proof configuration")
	}
	auth, err := NewStytchOAuthAuthenticator("https://test.stytch.com", project, secret, 5*time.Second,
		func() time.Time { return time.Now().UTC().Truncate(time.Millisecond) })
	if err != nil {
		t.Fatal("application authenticator construction failed")
	}
	observer := &liveStytchSessionTransport{base: http.DefaultTransport}
	auth.client.Transport = observer
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	principal, err := auth.adapter.Authenticate(ctx, jwt)
	if phase == "revoked" {
		if err == nil || observer.calls != 1 || !observer.refused() {
			t.Fatalf("revoked session must be refused by provider: calls=%d status=%d", observer.calls, observer.status)
		}
		return
	}
	if err != nil || observer.calls != 1 || observer.status != http.StatusOK {
		t.Fatalf("active session was not accepted: calls=%d status=%d", observer.calls, observer.status)
	}
	if principal.MemberReference() != member || principal.OrganizationReference() != organization || principal.SessionReference() != session ||
		principal.AuthenticatedAt().After(time.Now()) || !principal.ExpiresAt().After(time.Now()) {
		t.Fatal("application principal did not preserve provider session scope and validity")
	}
	// Change the first signature character, not unused trailing base64 bits.
	position := strings.LastIndexByte(jwt, '.') + 1
	if position >= len(jwt) {
		t.Fatal("missing session signature")
	}
	replacement := "A"
	if jwt[position] == 'A' {
		replacement = "B"
	}
	tampered := jwt[:position] + replacement + jwt[position+1:]
	if _, err = auth.adapter.Authenticate(ctx, tampered); err == nil || observer.calls != 2 || !observer.refused() {
		t.Fatalf("tampered session must be refused by provider: calls=%d status=%d", observer.calls, observer.status)
	}
}

type liveStytchSessionTransport struct {
	base   http.RoundTripper
	calls  int
	status int
}

func (transport *liveStytchSessionTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.calls++
	transport.status = 0
	response, err := transport.base.RoundTrip(request)
	if response != nil {
		transport.status = response.StatusCode
	}
	return response, err
}

func (transport *liveStytchSessionTransport) refused() bool {
	switch transport.status {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return true
	default:
		return false
	}
}
