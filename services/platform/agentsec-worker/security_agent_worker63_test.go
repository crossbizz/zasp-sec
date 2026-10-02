package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type worker63Database struct {
	calls int
	raw   json.RawMessage
	err   error
	check func(context.Context, string, []any)
}

func (d *worker63Database) QueryJSON(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
	d.calls++
	if d.check != nil {
		d.check(ctx, sql, args)
	}
	return d.raw, d.err
}

func worker63TestClaim() orderedDispatchClaim {
	return orderedDispatchClaim{WorkerID: "dispatch-worker", LeaseToken: "dispatch-token-00000001", LeaseSeconds: 30, Limit: 1, Planner: orderedDispatchPlanner{Provider: "openrouter", Model: "openai/gpt-5-mini", RequestPolicyVersion: "security-agent-planner-v1", RequestTokenLimit: 256, CredentialDigest: "sha256:" + strings.Repeat("ab", 32)}}
}

// Missing local validation must cause a database call in each rejection case.
func TestWorker63RejectsBeforeIO(t *testing.T) {
	for _, name := range []string{"worker", "token", "zero-token", "seconds-low", "seconds-high", "limit", "provider", "model", "policy", "tokens-low", "tokens-high", "digest", "nil-context", "cancelled", "nil-db", "typed-nil-db"} {
		t.Run(name, func(t *testing.T) {
			q := worker63TestClaim()
			db := &worker63Database{raw: json.RawMessage(`{"contract_version":63,"outcome":"empty","item":null}`)}
			r := &orderedDispatchRepository{database: db}
			ctx := context.Background()
			switch name {
			case "worker":
				q.WorkerID = "bad worker"
			case "token":
				q.LeaseToken = "short"
			case "zero-token":
				q.LeaseToken = strings.Repeat("0", 32)
			case "seconds-low":
				q.LeaseSeconds = 29
			case "seconds-high":
				q.LeaseSeconds = 301
			case "limit":
				q.Limit = 2
			case "provider":
				q.Planner.Provider = "other"
			case "model":
				q.Planner.Model = "openai/other"
			case "policy":
				q.Planner.RequestPolicyVersion = "other"
			case "tokens-low":
				q.Planner.RequestTokenLimit = 0
			case "tokens-high":
				q.Planner.RequestTokenLimit = 4097
			case "digest":
				q.Planner.CredentialDigest = "raw-secret"
			case "nil-context":
				ctx = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil-db":
				r.database = nil
			case "typed-nil-db":
				var missing *worker63Database
				r.database = missing
			}
			if _, err := r.claim(ctx, q); err != apiserver.ErrRepositoryOperation || db.calls != 0 {
				t.Fatalf("invalid request reached authority: %v calls=%d", err, db.calls)
			}
		})
	}
}

func TestWorker63ExactBoundaryAndSafeErrors(t *testing.T) {
	q := worker63TestClaim()
	db := &worker63Database{raw: json.RawMessage(`{"contract_version":63,"outcome":"empty","item":null}`)}
	db.check = func(ctx context.Context, sql string, args []any) {
		if sql != `SELECT zasp_ordered_worker63.worker($1,$2,$3::jsonb)` || len(args) != 3 || args[0] != migrations.ProductionSecurityAgentWorker().Checksum() || args[1] != migrations.SecurityAgentWorkerFingerprint() {
			t.Fatal("wrong SQL or pins", sql, args)
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 5*time.Second {
			t.Fatal("unbounded operation")
		}
		raw, ok := args[2].(json.RawMessage)
		if !ok {
			t.Fatal("request not bounded JSON")
		}
		var request map[string]any
		if json.Unmarshal(raw, &request) != nil || len(request) != 6 || request["operation"] != "claim" || request["worker_id"] != "dispatch-worker" || request["lease_token"] != "dispatch-token-00000001" || request["limit"] != float64(1) {
			t.Fatal("open or wrong request", string(raw))
		}
	}
	r := &orderedDispatchRepository{database: db}
	for i := 0; i < 2; i++ {
		v, err := r.claim(context.Background(), q)
		if err != nil || v.Outcome != "empty" || v.Item != nil {
			t.Fatal(v, err)
		}
	}
	if db.calls != 2 {
		t.Fatal("readiness boundary was cached", db.calls)
	}
	db.err = errors.New("SQL credential_reference=private")
	if _, err := r.claim(context.Background(), q); err != apiserver.ErrRepositoryUnavailable {
		t.Fatal("unsafe SQL error", err)
	}
}

func TestWorker63StrictResponses(t *testing.T) {
	for _, raw := range []string{`null`, `{}`, `{"contract_version":62,"outcome":"empty","item":null}`, `{"contract_version":63,"outcome":"claimed","item":null}`, `{"contract_version":63,"outcome":"empty","item":null,"lease_token":"secret"}`, `{"contract_version":63,"contract_version":63,"outcome":"empty","item":null}`, `{"contract_version":63,"outcome":"empty"}`, `{"contract_version":63,"outcome":"finished","item":null}`, strings.Repeat(" ", 8193)} {
		db := &worker63Database{raw: json.RawMessage(raw)}
		r := &orderedDispatchRepository{database: db}
		if _, err := r.claim(context.Background(), worker63TestClaim()); err != apiserver.ErrRepositoryUnavailable {
			t.Fatal("malformed response accepted", raw, err)
		}
	}
}

func worker63ItemFixture() string {
	return `{"contract_version":63,"outcome":"claimed","item":{"dispatch_id":"pid_6a000010-0000-4000-8000-000000000010","organization_id":"pid_6a000001-0000-4000-8000-000000000001","workspace_id":"pid_6a000002-0000-4000-8000-000000000002","environment_id":"pid_6a000003-0000-4000-8000-000000000003","run_id":"pid_6a000004-0000-4000-8000-000000000004","definition_id":"pid_6a000005-0000-4000-8000-000000000005","definition_version":2,"run_version":2,"state":"planning","dispatch_version":1,"lease_expires_at":"` + time.Now().UTC().Add(time.Minute).Format("2006-01-02T15:04:05.000000Z") + `","pricing":{"provider":"openrouter","model":"openai/gpt-5-mini","request_policy_version":"security-agent-planner-v1","request_token_limit":256,"credential_digest":"sha256:` + strings.Repeat("ab", 32) + `","account_profile":"local-controlled-account","cost_unit":"openrouter_credit","credential_reference":"secret_ref_planner/pid_6a000001-0000-4000-8000-000000000001/pid_6a000002-0000-4000-8000-000000000002/pid_6a000003-0000-4000-8000-000000000003/local-credential","policy_id":"pid_6a000006-0000-4000-8000-000000000006","policy_version":1,"policy_digest":"sha256:` + strings.Repeat("cd", 32) + `","account_id":"pid_6a000007-0000-4000-8000-000000000007","account_version":1}}}`
}

func TestWorker63ClaimItemAndMutations(t *testing.T) {
	raw := worker63ItemFixture()
	db := &worker63Database{raw: json.RawMessage(raw)}
	r := &orderedDispatchRepository{database: db}
	v, err := r.claim(context.Background(), worker63TestClaim())
	if err != nil || v.Item == nil || v.Item.RunVersion != 2 || v.Item.Pricing.AccountProfile != "local-controlled-account" {
		t.Fatal(v, err)
	}
	for _, level := range []string{"item", "pricing"} {
		var body map[string]any
		_ = json.Unmarshal([]byte(raw), &body)
		object := body["item"].(map[string]any)
		if level == "pricing" {
			object = object["pricing"].(map[string]any)
		}
		for key := range object {
			for _, fault := range []string{"missing", "null", "wrong-type"} {
				var changed map[string]any
				_ = json.Unmarshal([]byte(raw), &changed)
				target := changed["item"].(map[string]any)
				if level == "pricing" {
					target = target["pricing"].(map[string]any)
				}
				switch fault {
				case "missing":
					delete(target, key)
				case "null":
					target[key] = nil
				case "wrong-type":
					target[key] = []any{}
				}
				db.raw, _ = json.Marshal(changed)
				if _, err = r.claim(context.Background(), worker63TestClaim()); err != apiserver.ErrRepositoryUnavailable {
					t.Fatalf("%s %s %s accepted", level, key, fault)
				}
			}
		}
	}
	for _, change := range [][2]string{{`"state":"planning"`, `"state":"succeeded"`}, {`"run_version":2`, `"run_version":3`}, {`"policy_version":1`, `"policy_version":0`}, {`"account_version":1`, `"account_version":1000001`}, {`"request_token_limit":256`, `"request_token_limit":4097`}, {`"local-controlled-account"`, `"bad profile"`}, {`/local-credential"`, `/../private"`}, {`"pricing":{`, `"pricing":{"provider_body":"secret",`}, {`"dispatch_id":`, `"raw_receipt":"secret","dispatch_id":`}} {
		db.raw = json.RawMessage(strings.Replace(raw, change[0], change[1], 1))
		if _, err = r.claim(context.Background(), worker63TestClaim()); err != apiserver.ErrRepositoryUnavailable {
			t.Fatal("contradiction accepted", change, err)
		}
	}
	a := orderedDispatchAuthority{WorkerID: "dispatch-worker", LeaseToken: "dispatch-token-00000001", DispatchID: "pid_6a000010-0000-4000-8000-000000000010", RunVersion: 2, DispatchVersion: 1}
	db.raw = json.RawMessage(strings.Replace(strings.Replace(raw, `"outcome":"claimed"`, `"outcome":"extended"`, 1), `"dispatch_version":1`, `"dispatch_version":2`, 1))
	if v, err = r.heartbeat(context.Background(), a, 30); err != nil || v.Outcome != "extended" {
		t.Fatal(v, err)
	}
	db.raw = json.RawMessage(`{"contract_version":63,"outcome":"finished","item":null}`)
	if v, err = r.finish(context.Background(), a); err != nil || v.Outcome != "finished" {
		t.Fatal(v, err)
	}
	for _, outcome := range []string{"recovery_deferred", "reconciled"} {
		db.raw = json.RawMessage(`{"contract_version":63,"outcome":"` + outcome + `","item":null}`)
		if v, err = r.abandon(context.Background(), a); err != nil || v.Outcome != outcome {
			t.Fatal(v, err)
		}
	}
	db.raw = json.RawMessage(`{"contract_version":63,"ready":true}`)
	if err = r.ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"dispatch", "worker", "token", "run-version", "dispatch-version", "duration"} {
		bad := a
		seconds := 30
		switch fault {
		case "dispatch":
			bad.DispatchID = "foreign"
		case "worker":
			bad.WorkerID = ""
		case "token":
			bad.LeaseToken = ""
		case "run-version":
			bad.RunVersion = 0
		case "dispatch-version":
			bad.DispatchVersion = 1000001
		case "duration":
			seconds = 301
		}
		before := db.calls
		if _, err = r.heartbeat(context.Background(), bad, seconds); err != apiserver.ErrRepositoryOperation || db.calls != before {
			t.Fatal("invalid mutation reached database", fault, err)
		}
	}
}

func TestWorker63CancelledDuringIO(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db := &worker63Database{raw: json.RawMessage(`{"contract_version":63,"outcome":"empty","item":null}`)}
	db.check = func(context.Context, string, []any) { cancel() }
	if _, err := (&orderedDispatchRepository{database: db}).claim(ctx, worker63TestClaim()); err != apiserver.ErrRepositoryUnavailable {
		t.Fatal("cancelled result escaped", err)
	}
}

func TestWorker63HeartbeatUsesExactRunStates(t *testing.T) {
	a := orderedDispatchAuthority{DispatchID: "pid_6a000010-0000-4000-8000-000000000010", RunVersion: 3, DispatchVersion: 1}
	raw := strings.Replace(strings.Replace(strings.Replace(worker63ItemFixture(), `"outcome":"claimed"`, `"outcome":"extended"`, 1), `"dispatch_version":1`, `"dispatch_version":2`, 1), `"run_version":2`, `"run_version":3`, 1)
	if _, err := decodeDispatchResult(json.RawMessage(strings.Replace(raw, `"state":"planning"`, `"state":"needs_human"`, 1)), "heartbeat", &a); err != nil {
		t.Fatal("valid conservative terminal rejected", err)
	}
	for _, state := range []string{"stopped", "failed", "inconclusive"} {
		if _, err := decodeDispatchResult(json.RawMessage(strings.Replace(raw, `"state":"planning"`, `"state":"`+state+`"`, 1)), "heartbeat", &a); err == nil {
			t.Error("unreviewed aggregate state accepted", state)
		}
	}
}
