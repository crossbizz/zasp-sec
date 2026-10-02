package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"strings"
	"testing"
	"time"
)

func scheduler64TestClaim() orderedScheduleClaim {
	return orderedScheduleClaim{orderedScheduleIdentity: orderedScheduleIdentity{WorkerID: "schedule-worker", ScheduleToken: "schedule-token-0001", ActionWorkerID: "action-worker", ActionLeaseToken: strings.Repeat("a", 32), DeploymentWorkerID: "deployment-worker", DeploymentLeaseToken: strings.Repeat("b", 32)}, LeaseSeconds: 30, ExecutorLeaseSeconds: 30, Limit: 1}
}

// Break: caller inputs reach SQL without validation or compiled pins; SQL
// errors expose the driver's detail, or requests run without a deadline.
func TestScheduler64Boundary(t *testing.T) {
	q := scheduler64TestClaim()
	db := &worker63Database{raw: json.RawMessage(`{"contract_version":64,"outcome":"empty","item":null}`)}
	db.check = func(ctx context.Context, sql string, args []any) {
		if sql != `SELECT zasp_ordered_scheduler64.scheduler($1,$2,$3::jsonb)` || len(args) != 3 || args[0] != migrations.ProductionSecurityAgentScheduler().Checksum() || args[1] != migrations.SecurityAgentSchedulerFingerprint() {
			t.Fatal("wrong SQL or pins")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 30*time.Second {
			t.Fatal("unbounded scheduler call")
		}
		raw, ok := args[2].(json.RawMessage)
		if !ok {
			t.Fatal("wrong argument type")
		}
		var v map[string]any
		if json.Unmarshal(raw, &v) != nil || len(v) != 10 || v["operation"] != "claim" || v["schedule_token"] != "schedule-token-0001" || v["action_worker_id"] != "action-worker" || v["deployment_lease_token"] != strings.Repeat("b", 32) || v["executor_lease_seconds"] != float64(30) {
			t.Fatal("open or wrong request")
		}
	}
	r := &orderedScheduleRepository{database: db}
	for i := 0; i < 2; i++ {
		v, err := r.claim(context.Background(), q)
		if err != nil || v.Outcome != "empty" || v.Item != nil {
			t.Fatal("scheduler boundary unavailable", v, err)
		}
	}
	if db.calls != 2 {
		t.Fatal("cached boundary")
	}
	db.err = errors.New("raw sql token=private")
	if _, err := r.claim(context.Background(), q); err != apiserver.ErrRepositoryUnavailable {
		t.Fatal("unsafe error", err)
	}
}

func TestScheduler64ZeroIO(t *testing.T) {
	for _, name := range []string{"worker", "action-worker", "deployment-worker", "token", "action-token", "deployment-token", "same-token", "low", "high", "executor-low", "executor-high", "limit", "nil-db", "typed-nil", "nil-context", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			q := scheduler64TestClaim()
			db := &worker63Database{}
			r := &orderedScheduleRepository{database: db}
			ctx := context.Background()
			switch name {
			case "worker":
				q.WorkerID = "Invalid Worker"
			case "action-worker":
				q.ActionWorkerID = "bad_worker"
			case "deployment-worker":
				q.DeploymentWorkerID = "x"
			case "token":
				q.ScheduleToken = "short"
			case "action-token":
				q.ActionLeaseToken = strings.Repeat("0", 32)
			case "deployment-token":
				q.DeploymentLeaseToken = "secret space token"
			case "same-token":
				q.ScheduleToken = q.ActionLeaseToken
			case "low":
				q.LeaseSeconds = 29
			case "high":
				q.LeaseSeconds = 301
			case "executor-low":
				q.ExecutorLeaseSeconds = 29
			case "executor-high":
				q.ExecutorLeaseSeconds = 301
			case "limit":
				q.Limit = 2
			case "nil-db":
				r.database = nil
			case "typed-nil":
				var absent *worker63Database
				r.database = absent
			case "nil-context":
				ctx = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := r.claim(ctx, q); err != apiserver.ErrRepositoryOperation || db.calls != 0 {
				t.Fatal("invalid caller reached I/O", err, db.calls)
			}
		})
	}
}

func scheduler64ItemFixture() string {
	return strings.NewReplacer(`"contract_version":63`, `"contract_version":64`, `"dispatch_id":"pid_6a000010-0000-4000-8000-000000000010"`, `"schedule_id":"pid_7292a9de-549e-418c-8b29-91c768983634"`, `"dispatch_version"`, `"schedule_version"`, `"run_version":2`, `"run_version":4`, `"state":"planning"`, `"state":"running","state_class":"application"`, `pid_6a000006-0000-4000-8000-000000000006`, `pid_2a58c1b6-78e2-4cac-83af-718fb0428567`, `pid_6a000007-0000-4000-8000-000000000007`, `pid_89822088-485e-4960-8b83-f36a1e8f989d`).Replace(worker63ItemFixture())
}

// Break: a correct claimed item cannot be read, or the decoder accepts open
// JSON, fabricated classes, malformed identities or inconsistent scope/pricing.
func TestScheduler64Decoder(t *testing.T) {
	raw := scheduler64ItemFixture()
	db := &worker63Database{raw: json.RawMessage(raw)}
	r := &orderedScheduleRepository{database: db}
	v, err := r.claim(context.Background(), scheduler64TestClaim())
	if err != nil || v.Item == nil || v.Item.StateClass != "application" || v.Item.RunVersion != 4 {
		t.Fatal("claimed authority undecodable", v, err)
	}
	for _, level := range []string{"root", "item", "pricing"} {
		var base map[string]any
		_ = json.Unmarshal([]byte(raw), &base)
		fields := base
		if level != "root" {
			fields = base["item"].(map[string]any)
		}
		if level == "pricing" {
			fields = fields["pricing"].(map[string]any)
		}
		for key := range fields {
			for _, mode := range []string{"missing", "null", "wrong-type"} {
				var body map[string]any
				_ = json.Unmarshal([]byte(raw), &body)
				target := body
				if level != "root" {
					target = body["item"].(map[string]any)
				}
				if level == "pricing" {
					target = target["pricing"].(map[string]any)
				}
				switch mode {
				case "missing":
					delete(target, key)
				case "null":
					target[key] = nil
				case "wrong-type":
					target[key] = []any{}
				}
				db.raw, _ = json.Marshal(body)
				if _, err = r.claim(context.Background(), scheduler64TestClaim()); err != apiserver.ErrRepositoryUnavailable {
					t.Fatalf("accepted %s %s %s", level, key, mode)
				}
			}
		}
	}
	for _, change := range [][2]string{{`"state":"running"`, `"state":"cancelled"`}, {`"state_class":"application"`, `"state_class":"approval"`}, {`"run_version":4`, `"run_version":2`}, {`"schedule_version":1`, `"schedule_version":0`}, {`"policy_version":1`, `"policy_version":0`}, {`"account_version":1`, `"account_version":1000001`}, {`"item":{`, `"item":{"schedule_token":"secret",`}, {`"pricing":{`, `"pricing":{"body":"secret",`}, {`"contract_version":64`, `"contract_version":64,"contract_version":64`}, {`pid_7292a9de-549e-418c-8b29-91c768983634`, `pid_7292a9de-549e-418c-8b29-91c768983635`}, {`/local-credential`, `/../secret`}, {`pid_2a58c1b6-78e2-4cac-83af-718fb0428567`, `pid_89822088-485e-4960-8b83-f36a1e8f989d`}} {
		db.raw = json.RawMessage(strings.Replace(raw, change[0], change[1], 1))
		if _, err = r.claim(context.Background(), scheduler64TestClaim()); err != apiserver.ErrRepositoryUnavailable {
			t.Fatal("contradiction accepted", change)
		}
	}
}

func TestScheduler64TypedMutations(t *testing.T) {
	db := &worker63Database{}
	expectedOperation := "heartbeat"
	db.check = func(ctx context.Context, sql string, args []any) {
		if sql != `SELECT zasp_ordered_scheduler64.scheduler($1,$2,$3::jsonb)` || len(args) != 3 || args[0] != migrations.ProductionSecurityAgentScheduler().Checksum() || args[1] != migrations.SecurityAgentSchedulerFingerprint() {
			t.Fatal("wrong mutation SQL/pins")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 30*time.Second {
			t.Fatal("unbounded mutation")
		}
		raw, ok := args[2].(json.RawMessage)
		if !ok {
			t.Fatal("wrong mutation argument type")
		}
		var q map[string]any
		if json.Unmarshal(raw, &q) != nil || q["operation"] != expectedOperation {
			t.Fatal("wrong typed operation")
		}
		size := 10
		if expectedOperation == "heartbeat" {
			size = 11
		}
		if expectedOperation == "ready" {
			size = 1
		}
		if len(q) != size {
			t.Fatal("open mutation wire", expectedOperation, len(q))
		}
		if size > 1 && (q["schedule_id"] != "pid_7292a9de-549e-418c-8b29-91c768983634" || q["run_version"] != float64(4) || q["schedule_version"] != float64(1) || q["schedule_token"] != "schedule-token-0001") {
			t.Fatal("wrong bound mutation fields")
		}
	}
	r, ok := any(&orderedScheduleRepository{database: db}).(interface {
		ready(context.Context) error
		heartbeat(context.Context, orderedScheduleAuthority, int) (orderedScheduleResult, error)
		finish(context.Context, orderedScheduleAuthority) (orderedScheduleResult, error)
		abandon(context.Context, orderedScheduleAuthority) (orderedScheduleResult, error)
	})
	if !ok {
		t.Fatal("typed scheduler mutation boundary absent")
	}
	a := orderedScheduleAuthority{orderedScheduleIdentity: scheduler64TestClaim().orderedScheduleIdentity, ScheduleID: "pid_7292a9de-549e-418c-8b29-91c768983634", RunVersion: 4, ScheduleVersion: 1}
	db.raw = json.RawMessage(strings.NewReplacer(`"outcome":"claimed"`, `"outcome":"extended"`, `"schedule_version":1`, `"schedule_version":2`).Replace(scheduler64ItemFixture()))
	if v, err := r.heartbeat(context.Background(), a, 30); err != nil || v.Outcome != "extended" {
		t.Fatal(v, err)
	}
	for _, fault := range []string{"schedule", "run-version", "schedule-version", "action-token", "seconds"} {
		bad := a
		seconds := 30
		switch fault {
		case "schedule":
			bad.ScheduleID = "bad"
		case "run-version":
			bad.RunVersion = 0
		case "schedule-version":
			bad.ScheduleVersion = 1000000
		case "action-token":
			bad.ActionLeaseToken = "short"
		case "seconds":
			seconds = 301
		}
		before := db.calls
		if _, err := r.heartbeat(context.Background(), bad, seconds); err != apiserver.ErrRepositoryOperation || before != db.calls {
			t.Fatal("invalid mutation reached I/O", fault, err)
		}
	}
	expectedOperation = "finish"
	db.raw = json.RawMessage(`{"contract_version":64,"outcome":"finished","item":null}`)
	if _, err := r.finish(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	expectedOperation = "abandon"
	for _, outcome := range []string{"released", "recovery_deferred"} {
		db.raw = json.RawMessage(`{"contract_version":64,"outcome":"` + outcome + `","item":null}`)
		if _, err := r.abandon(context.Background(), a); err != nil {
			t.Fatal(err)
		}
	}
	expectedOperation = "ready"
	db.raw = json.RawMessage(`{"contract_version":64,"ready":true}`)
	if err := r.ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	db.raw = json.RawMessage(`{"contract_version":64,"ready":false}`)
	if err := r.ready(context.Background()); err != apiserver.ErrRepositoryUnavailable {
		t.Fatal("unready accepted")
	}
}
