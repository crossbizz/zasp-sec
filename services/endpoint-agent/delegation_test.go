package main

import (
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/delegation/testfixture"
)

func TestTaskGrantPrecedesEndpointMonitorAndCachedReceipt(t *testing.T) {
	grant := testfixture.Read(t, "../../sdks/fixtures/task-delegation.json")
	f := newFixture(t)
	f.now = time.Unix(grant.Issued, 0).UTC()
	f.p.IssuedAt = f.now.Add(-time.Minute)
	f.p.ExpiresAt = f.now.Add(time.Hour)
	f.publish(t, f.p)
	f.b.delegation = &grant.Verifier
	req := request{Operation: "pre-tool", Hook: event("session", "call", "internal")}
	check := func(want string) {
		t.Helper()
		v := f.b.process(req, f.b.uid)
		if v.Decision == nil || v.Decision.Verdict != want {
			t.Fatalf("%+v", v)
		}
	}
	check("deny")
	req.Delegation = grant.Token
	check("continue")
	req.Hook = event("session", "other", "external")
	check("deny")
	req.Hook = event("session", "call", "internal")
	f.now = f.now.Add(time.Minute)
	check("deny")
}
