package apiserver

import (
	"net/http/httptest"
	"testing"
)

func TestV3RecoveryIntentOnInstalledBaseline(t *testing.T) {
	b := startInstalledV2Baseline(t)
	member := func() installedPrincipal {
		return b.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	}
	owner, peer := member(), member()
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	h := recoveryIntentEndpoint{db: b.product}
	do := func(a installedPrincipal, op, method, id, body string) *httptest.ResponseRecorder {
		return b.serve(h, a, op, method, "/api/v1/recovery/intents/"+id, map[string]string{"id": id}, body, nil)
	}
	backup, restore := b.id(), b.id()
	params := `{"kind":"backup","backup_id":"` + backup + `","retention_days":30}`
	for i := 0; i < 2; i++ {
		if r := do(owner, "putRecoveryIntent", "PUT", backup, params); r.Code != 200 {
			t.Fatal(r.Code, r.Body)
		}
	}
	if r := do(owner, "putRecoveryIntent", "PUT", backup, `{"kind":"backup","backup_id":"`+backup+`","retention_days":90}`); r.Code != 409 {
		t.Fatal(r.Code, r.Body)
	}
	if r := do(peer, "getRecoveryIntent", "GET", backup, ""); r.Code != 404 {
		t.Fatal(r.Code, r.Body)
	}
	if r := do(owner, "getRecoveryIntent", "GET", backup, ""); r.Code != 200 {
		t.Fatal(r.Code, r.Body)
	}
	if r := do(owner, "putRecoveryIntent", "PUT", restore, `{"kind":"restore","backup_id":"`+backup+`","target_environment":"production"}`); r.Code != 400 {
		t.Fatal(r.Code, r.Body)
	}
	if r := do(owner, "putRecoveryIntent", "PUT", restore, `{"kind":"restore","backup_id":"`+backup+`","target_environment":"trial-recovery"}`); r.Code != 200 {
		t.Fatal(r.Code, r.Body)
	}
	if r := do(peer, "getRecoveryIntent", "GET", restore, ""); r.Code != 404 {
		t.Fatal(r.Code, r.Body)
	}
}
