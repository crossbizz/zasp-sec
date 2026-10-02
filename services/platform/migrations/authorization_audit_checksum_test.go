package migrations

import "testing"

func TestAuthorizationAuditProfileChecksum(t *testing.T) {
	_, want := authorizationAuditProfileSource()
	if got := AuthorizationAuditProfileChecksum(); got != want || len(got) != 64 {
		t.Fatalf("compiled accessor differs from installer")
	}
}
