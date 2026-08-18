package identity

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestAPITokenIsReturnedOnceAuthenticatesInScopeAndRevokes(t *testing.T) {
	now := fixtureNow
	sequence := 800
	tokens, err := NewAPITokenStore(func() (domain.ProductID, error) {
		sequence++
		return fixtureID(t, sequence), nil
	}, bytes.NewReader(bytes.Repeat([]byte{0x5a}, 32)), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	organization := fixtureID(t, 810)
	principal := fixtureID(t, 811)
	scope := fixtureScope(t, organization, 812)
	credential, err := tokens.Create(context.Background(), APITokenSpec{
		OrganizationID: organization, PrincipalID: principal, Scope: scope, Name: "CI scanner",
		Permissions: []Permission{PermissionView, PermissionRunTests}, ExpiresAt: now.Add(time.Hour),
	})
	if err != nil || !strings.HasPrefix(credential.RawToken(), "zasp_pat_") {
		t.Fatalf("Create() = %#v, %v", credential, err)
	}
	raw := credential.RawToken()
	listed, err := tokens.List(context.Background(), organization)
	if err != nil || len(listed) != 1 || listed[0].ID() != credential.Token().ID() || strings.Contains(fmt.Sprintf("%#v", tokens), raw) {
		t.Fatalf("List()/storage = %#v, %v", listed, err)
	}
	authorization, err := tokens.Authenticate(context.Background(), raw, scope, PermissionRunTests)
	if err != nil || authorization.PrincipalID() != principal || authorization.Scope() != scope {
		t.Fatalf("Authenticate() = %#v, %v", authorization, err)
	}
	foreign := fixtureScope(t, organization, 820)
	if _, err := tokens.Authenticate(context.Background(), raw, foreign, PermissionView); err != ErrAuthentication {
		t.Fatalf("cross-scope Authenticate() error = %v", err)
	}
	if _, err := tokens.Revoke(context.Background(), organization, credential.Token().ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.Authenticate(context.Background(), raw, scope, PermissionView); err != ErrAuthentication {
		t.Fatalf("revoked Authenticate() error = %v", err)
	}
}

func TestAPITokenRejectsExpiredAndUnauthorizedPermission(t *testing.T) {
	now := fixtureNow
	tokens, err := NewAPITokenStore(func() (domain.ProductID, error) { return fixtureID(t, 830), nil },
		bytes.NewReader(bytes.Repeat([]byte{0x31}, 32)), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	organization := fixtureID(t, 831)
	scope := fixtureScope(t, organization, 832)
	credential, err := tokens.Create(context.Background(), APITokenSpec{
		OrganizationID: organization, PrincipalID: fixtureID(t, 834), Scope: scope, Name: "Read only",
		Permissions: []Permission{PermissionView}, ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.Authenticate(context.Background(), credential.RawToken(), scope, PermissionManageIdentity); err != ErrForbidden {
		t.Fatalf("permission error = %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := tokens.Authenticate(context.Background(), credential.RawToken(), scope, PermissionView); err != ErrAuthentication {
		t.Fatalf("expiry error = %v", err)
	}
}
