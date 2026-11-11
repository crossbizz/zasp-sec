package apiserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// invitationRecorder is a callback provider that records which completion the
// session handler chose and which provider token type it carried.
type invitationRecorder struct {
	grant      SessionGrant
	completed  []string
	invitation []string
}

func (recorder *invitationRecorder) Complete(ctx context.Context, token, state string) (SessionGrant, error) {
	recorder.completed = append(recorder.completed, ProviderTokenTypeFromContext(ctx)+":"+token+":"+state)
	return recorder.grant, nil
}

func (recorder *invitationRecorder) CompleteInvitation(_ context.Context, token string) (SessionGrant, error) {
	recorder.invitation = append(recorder.invitation, token)
	return recorder.grant, nil
}

func (*invitationRecorder) Ready(context.Context) error { return nil }

func postSessionCallback(t *testing.T, provider CallbackProvider, body string) *httptest.ResponseRecorder {
	t.Helper()
	repository, err := NewPostgresRepository(newPersistentJSONDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	handlers, _, err := NewProductionHandlers(repository, provider, http.NotFoundHandler(), fixtureCookiePolicy())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://app.zasp.test/api/v1/session/callback", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handlers.Session.ServeHTTP(response, request)
	return response
}

const callbackState = "ssssssssssssssssssssssssssssssss"

func TestSessionCallbackAcceptsAProviderInvitationWithoutProductState(t *testing.T) {
	recorder := &invitationRecorder{grant: sessionGrant(t, "3")}
	response := postSessionCallback(t, recorder, `{"provider_token":"invitation-token","provider_token_type":"multi_tenant_magic_links"}`)
	if response.Code != http.StatusOK || len(response.Result().Cookies()) != 1 {
		t.Fatalf("invitation callback = %d %s", response.Code, response.Body.String())
	}
	if len(recorder.invitation) != 1 || recorder.invitation[0] != "invitation-token" || len(recorder.completed) != 0 {
		t.Fatalf("completions = invitation %v, stateful %v", recorder.invitation, recorder.completed)
	}
}

func TestSessionCallbackKeepsProductStateMandatoryForEveryOtherExchange(t *testing.T) {
	for name, body := range map[string]string{
		"oauth without state":          `{"provider_token":"oauth-token"}`,
		"explicit oauth without state": `{"provider_token":"oauth-token","provider_token_type":"oauth"}`,
		"oauth with short state":       `{"provider_token":"oauth-token","state":"short"}`,
		"unknown token type":           `{"provider_token":"sso-token","state":"` + callbackState + `","provider_token_type":"sso"}`,
		"session jwt as token type":    `{"provider_token":"jwt","provider_token_type":"session_jwt"}`,
		"invitation with short state":  `{"provider_token":"invitation-token","state":"short","provider_token_type":"multi_tenant_magic_links"}`,
	} {
		t.Run(name, func(t *testing.T) {
			recorder := &invitationRecorder{grant: sessionGrant(t, "3")}
			response := postSessionCallback(t, recorder, body)
			if response.Code == http.StatusOK || len(response.Result().Cookies()) != 0 || len(recorder.invitation)+len(recorder.completed) != 0 {
				t.Fatalf("callback = %d, invitation %v, stateful %v", response.Code, recorder.invitation, recorder.completed)
			}
		})
	}
}

func TestSessionCallbackCarriesTheTokenTypeIntoAStatefulCompletion(t *testing.T) {
	for body, want := range map[string]string{
		`{"provider_token":"oauth-token","state":"` + callbackState + `"}`:                                                 "oauth:oauth-token:" + callbackState,
		`{"provider_token":"link-token","state":"` + callbackState + `","provider_token_type":"multi_tenant_magic_links"}`: "multi_tenant_magic_links:link-token:" + callbackState,
	} {
		recorder := &invitationRecorder{grant: sessionGrant(t, "3")}
		response := postSessionCallback(t, recorder, body)
		if response.Code != http.StatusOK || len(recorder.completed) != 1 || recorder.completed[0] != want || len(recorder.invitation) != 0 {
			t.Fatalf("callback %s = %d, stateful %v, invitation %v", body, response.Code, recorder.completed, recorder.invitation)
		}
	}
}

// A provider that cannot accept invitations must refuse them rather than fall
// back to a stateless OAuth completion.
func TestSessionCallbackRefusesAnInvitationWhenTheProviderCannotAcceptOne(t *testing.T) {
	called := false
	provider := CallbackProviderFunc(func(context.Context, string, string) (SessionGrant, error) {
		called = true
		return sessionGrant(t, "3"), nil
	})
	response := postSessionCallback(t, provider, `{"provider_token":"invitation-token","provider_token_type":"multi_tenant_magic_links"}`)
	if response.Code != http.StatusUnauthorized || called || len(response.Result().Cookies()) != 0 {
		t.Fatalf("callback = %d, stateful completion called = %v", response.Code, called)
	}
}
