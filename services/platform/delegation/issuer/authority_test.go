package issuer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"github.com/zasp-ai/zasp-sec/services/platform/delegation"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Authority, Tenant, IssueRequest, time.Time) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tenant := Tenant{"org", "ws", "staging"}
	all := Scope{[]string{"draft_reply", "send_reply"}, []string{"inbox", "archive"}}
	task := Scope{[]string{"draft_reply"}, []string{"inbox"}}
	c := Configuration{Seed: key.Seed(), Agents: []Agent{
		{tenant, "lead", "parent-credential", false, all}, {tenant, "helper", "helper-credential", true, all}, {tenant, "peer", "peer-credential", true, all},
	}, Tasks: []Task{{Binding{tenant, "reply-task", "lead"}, task, 3}}, Policies: []Policy{{tenant, all}}}
	a, err := NewAuthority(c)
	if err != nil {
		t.Fatal(err)
	}
	return a, tenant, IssueRequest{Scope: task, Task: "reply-task", Child: "helper", MaxDepth: 2, TTL: 60}, time.Now().Truncate(time.Second)
}

func TestTaskAuthority(t *testing.T) {
	a, tenant, r, now := fixture(t)
	g, err := a.Issue(tenant, "parent-credential", r, now)
	if err != nil || g.Depth != 1 {
		t.Fatalf("first grant %v", err)
	}
	check := func(credential, task, token, op, resource string, want delegation.Decision, when time.Time) {
		t.Helper()
		if got := a.Check(tenant, credential, task, token, op, resource, when); got != want {
			t.Fatalf("%s/%s: got %v want %v", task, op, got, want)
		}
	}
	allow, deny := delegation.Decision{"verified", true}, delegation.Decision{Status: "denied"}
	check("helper-credential", r.Task, g.Token, "draft_reply", "inbox", allow, now)
	check("helper-credential", r.Task, "", "draft_reply", "inbox", delegation.Decision{Status: "delegation_unverified"}, now)
	check("helper-credential", r.Task, g.Token, "send_reply", "inbox", deny, now)
	check("helper-credential", r.Task, g.Token, "draft_reply", "archive", deny, now)
	check("peer-credential", r.Task, g.Token, "draft_reply", "inbox", deny, now)
	check("helper-credential", "wrong-task", g.Token, "draft_reply", "inbox", deny, now)
	check("helper-credential", r.Task, g.Token, "draft_reply", "inbox", deny, now.Add(60*time.Second))
	parts := strings.Split(g.Token, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sig[7] ^= 128
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	check("helper-credential", r.Task, strings.Join(parts, "."), "draft_reply", "inbox", deny, now)
	check("helper-credential", r.Task, g.Token, "draft_reply", "inbox", deny, now.Add(-time.Second))
	cross := tenant
	cross.Environment = "production"
	if a.Check(cross, "helper-credential", r.Task, g.Token, "draft_reply", "inbox", now).Allowed {
		t.Fatal("cross environment")
	}
}

func TestChildCannotWidenTaskOrSubdelegateBeyondGrant(t *testing.T) {
	a, tenant, r, now := fixture(t)
	g, err := a.Issue(tenant, "parent-credential", r, now)
	if err != nil {
		t.Fatal(err)
	}
	child := r
	child.ParentToken = g.Token
	child.Child = "peer"
	child.TTL = 40
	g2, err := a.Issue(tenant, "helper-credential", child, now)
	if err != nil || g2.Depth != 2 {
		t.Fatalf("child grant %v", err)
	}
	for _, mutate := range []func(*IssueRequest){
		func(x *IssueRequest) { x.ParentToken = "" }, func(x *IssueRequest) { x.MaxDepth = 3 }, func(x *IssueRequest) { x.TTL = 61 },
		func(x *IssueRequest) { x.Operations = []string{"send_reply"} }, func(x *IssueRequest) { x.Resources = []string{"archive"} },
		func(x *IssueRequest) { x.Child = "lead" }, func(x *IssueRequest) { x.MaxDepth = 1 },
	} {
		v := child
		mutate(&v)
		if _, err := a.Issue(tenant, "helper-credential", v, now); err == nil {
			t.Fatal("wider grant accepted")
		}
	}
	child.ParentToken = g2.Token
	child.Child = "helper"
	if _, err := a.Issue(tenant, "peer-credential", child, now); err == nil {
		t.Fatal("depth limit")
	}
}

func TestMCPRoutingIsExact(t *testing.T) {
	for _, tc := range []struct{ raw, op string }{
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"draft_reply","arguments":{}}}`, "draft_reply"},
		{`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"draft_reply"}}`, ""},
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"NAME":"send_reply","name":"draft_reply"}}`, ""},
		{`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, "mcp:tools/list"},
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mcp:tools/list"}}`, ""},
		{`{"jsonrpc":"2.0","id":1,"method":"admin/run"}`, ""},
	} {
		if got := delegation.MCPOperation([]byte(tc.raw)); got != tc.op {
			t.Fatalf("got %q want %q", got, tc.op)
		}
	}
}
