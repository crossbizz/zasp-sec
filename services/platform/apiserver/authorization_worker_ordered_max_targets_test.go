package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

type ordered68ObservedChecks struct {
	next     authorization.Checker
	deny     string
	requests []authorization.CheckRequest
}

func (c *ordered68ObservedChecks) Check(ctx context.Context, q authorization.CheckRequest) (authorization.Decision, error) {
	c.requests = append(c.requests, q)
	d, err := c.next.Check(ctx, q)
	// A fail-closed fault only: every positive still comes from actual FGA.
	if err == nil && q.ResourceType == "gateway_device" && q.ResourceID == c.deny {
		d.Allowed = false
	}
	return d, err
}

func ordered68MaximumDevice(i int) string { return fmt.Sprintf("pid_8f001001-0000-4000-8000-%012d", i) }

// Removing a late destination/check, lowering the retained limit, omitting
// source rereads or accepting an added101st target must fail this native test.
// This is NOT100 completed deliveries: full serial product-loop capacity is
// a separate gate, explicitly not inferred from first/last source signing.
func TestP7Ordered68MaximumTargetBoundary(t *testing.T) {
	runOrdered68PolicyAcceptance(t, false, false, false, &ordered68PolicyAcceptance{
		prepare: func(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e string) {
			// Existing producer creates actual scoped device/enrollment/credential
			// prerequisites. Capture, effects, policy targets and proofs below
			// are all produced by the installed native named operations.
			for i := 1; i <= 99; i++ {
				seedOrderedApplicationGatewayAt(t, ctx, owner, o, w, e, ordered68MaximumDevice(i))
			}
		},
		consume: func(f ordered68PolicyAcceptanceContext) {
			var definition, principal, grantor string
			if err := f.owner.QueryRow(f.ctx, `SELECT definition_id,public.zasp_discovery_canonical_id(organization_id,workspace_id,environment_id,'security_agent_definition_service',definition_id),requested_by FROM zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, f.o, f.w, f.e, f.run).Scan(&definition, &principal, &grantor); err != nil || grantor != f.actor {
				f.t.Fatal("actual maximum admission identity", ordered68ErrorClass(err))
			}
			assertChecks := func(requests []authorization.CheckRequest) {
				f.t.Helper()
				if !ordered68MaximumChecksMatch(f.o, f.w, f.e, f.run, definition, grantor, principal, requests) {
					f.t.Fatal("exact maximum grantor/task check set", len(requests))
				}
			}
			observed := &ordered68ObservedChecks{next: f.checker}
			w := f.newWorker(observed)
			q := f.request("reserve", map[string]any{})
			f.capture(w, "ordered68.effect.reserve", q)
			observed.deny = ordered68MaximumDevice(99)
			before := f.evidence()
			func() {
				c, cancel := context.WithTimeout(f.ctx, 10*time.Second)
				defer cancel()
				_, err := w.worker.Authorize(c, "ordered68.effect.reserve", q)
				if !errors.Is(err, authorization.ErrDenied) || len(observed.requests) < 100 || !bytes.Equal(before, f.evidence()) {
					f.t.Fatal("last destination denial did not stop reservation", err, len(observed.requests))
				}
			}()
			observed.deny = ""
			observed.requests = nil
			var stale authorization.WorkerDecision
			func() {
				c, cancel := context.WithTimeout(f.ctx, 10*time.Second)
				defer cancel()
				var err error
				stale, err = w.worker.Authorize(c, "ordered68.effect.reserve", q)
				if err != nil {
					f.t.Fatal("actual maximum source authorization", err)
				}
			}()
			assertChecks(observed.requests)
			// Add a genuine selected credential/device after Check. The stale
			// decision and a new101-target capture must both refuse before any
			// native reservation; this is not forged source metadata.
			extra := ordered68MaximumDevice(100)
			seedOrderedApplicationGatewayAt(f.t, f.ctx, f.owner, f.o, f.w, f.e, extra)
			func() {
				c, cancel := context.WithTimeout(f.ctx, 10*time.Second)
				defer cancel()
				_, err := w.worker.Execute(c, stale)
				if !errors.Is(err, authorization.ErrConflict) || !bytes.Equal(before, f.evidence()) {
					f.t.Fatal("stale maximum target set accepted", err)
				}
			}()
			func() {
				c, cancel := context.WithTimeout(f.ctx, 10*time.Second)
				defer cancel()
				err := w.worker.PrepareOrdered68Operation(c, "ordered68.effect.reserve", q)
				if !errors.Is(err, authorization.ErrConflict) || !bytes.Equal(before, f.evidence()) {
					f.t.Fatal("101st native target accepted", err)
				}
			}()
			cfg := f.owner.Config().Copy()
			if err := f.owner.QueryRow(f.ctx, `SELECT principal_name FROM zasp_discovery_principal_bindings WHERE authority_role='zasp_discovery_api'`).Scan(&cfg.User); err != nil {
				f.t.Fatal(err)
			}
			api, err := pgx.ConnectConfig(f.ctx, cfg)
			if err != nil {
				f.t.Fatal(err)
			}
			defer func() {
				c, cancel := context.WithTimeout(context.WithoutCancel(f.ctx), 3*time.Second)
				defer cancel()
				if err := api.Close(c); err != nil {
					f.t.Error(err)
				}
			}()
			if _, err = api.Exec(f.ctx, `SELECT public.zasp_discovery_transition_gateway_device($1,$2,$3,$4,1,'revoked')`, f.o, f.w, f.e, extra); err != nil {
				f.t.Fatal("retire extra fixture device through registered API", err)
			}
			f.capture(w, "ordered68.effect.reserve", q)
			observed.requests = nil
			f.execute(w, "ordered68.effect.reserve", q)
			assertChecks(observed.requests)
			proof := w.trace.take()
			defer clear(proof)
			var wire struct{ Body []byte }
			var body struct {
				Facts struct {
					IDs []string `json:"ordered_device_ids"`
				} `json:"facts"`
			}
			if json.Unmarshal(proof, &wire) != nil || len(wire.Body) > 32768 || json.Unmarshal(wire.Body, &body) != nil || len(body.Facts.IDs) != 100 {
				f.t.Fatal("actual signed maximum proof truncated or oversized", len(wire.Body))
			}
			f.reconcile()
			observed.requests = nil
			f.execute(w, "ordered68.effect.start", f.request("start", map[string]any{}))
			assertChecks(observed.requests)
			f.reconcile()
			var result struct {
				Targets []struct {
					ID    string `json:"device_id"`
					State string `json:"state"`
				} `json:"targets"`
			}
			raw := f.execute(w, "ordered68.application.read", f.request("read", map[string]any{}))
			if json.Unmarshal(raw, &result) != nil || len(result.Targets) != 100 {
				f.t.Fatal("actual maximum claim truncated")
			}
			for i, target := range result.Targets {
				want := orderedApplicationDevice
				if i > 0 {
					want = ordered68MaximumDevice(i)
				}
				if target.ID != want || target.State != "planned" {
					f.t.Fatal("native maximum target order/identity", i)
				}
			}
			for _, device := range []string{orderedApplicationDevice, ordered68MaximumDevice(99)} {
				source := f.request("source", map[string]any{"device_id": device})
				f.capture(w, "ordered68.application.source", source)
				func() {
					c, cancel := context.WithTimeout(f.ctx, 10*time.Second)
					defer cancel()
					began := time.Now()
					d, err := w.worker.Authorize(c, "ordered68.application.source", source)
					if err != nil {
						f.t.Fatal(err)
					}
					calls := 0
					_, err = w.worker.SignOrderedPolicy(c, d, "ordered-key-01", f.keys, func(c context.Context, input policy.GatewayPolicySigningInput) (policy.GatewayPolicyEnvelope, error) {
						calls++
						if input.Binding.DeviceID != device {
							f.t.Fatal("native signer selected a different target")
						}
						return policy.SignGatewayPolicyEnvelope(input, f.private)
					})
					if err != nil || calls != 1 {
						f.t.Fatal("first/last maximum source signing", err, calls)
					}
					f.t.Log("maximum target source signing elapsed_ms", time.Since(began).Milliseconds())
				}()
				f.reconcile()
			}
			var exact bool
			if err = f.owner.QueryRow(f.ctx, `SELECT
 (SELECT count(*)=100 AND count(*) FILTER(WHERE state='stored')=2 AND count(*) FILTER(WHERE state='planned')=98 FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$1 AND step_id=$2 AND phase='apply')
 AND (SELECT count(*)=1 AND bool_and(jsonb_array_length(snapshot->'targets')=100 AND state='started') FROM zasp_temporal68.effects WHERE run_id=$1 AND step_id=$2)
 AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_receipts WHERE run_id=$1 AND step_id=$2)
 AND NOT zasp_authorization80_worker.runtime_ready()`, f.run, f.step).Scan(&exact); err != nil || !exact {
				f.t.Fatal("maximum boundary cardinality or fabricated completion", err)
			}
			f.t.Log("100 native targets and204 actual checks accepted;101/stale/late-deny refused; first/last sources only, full100-delivery capacity remains unproven; proof_bytes", len(wire.Body))
		},
	})
}

func ordered68MaximumChecksMatch(o, w, e, run, definition, grantor, principal string, requests []authorization.CheckRequest) bool {
	if len(requests) != 204 {
		return false
	}
	want := map[authorization.CheckRequest]int{}
	add := func(kind, id string) {
		want[authorization.CheckRequest{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, PrincipalKind: "user", PrincipalID: grantor, ResourceType: kind, ResourceID: id, Permission: "manage_workflows"}]++
		want[authorization.CheckRequest{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, PrincipalKind: "service", PrincipalID: principal, TaskID: run, ResourceType: kind, ResourceID: id, Permission: "manage_workflows"}]++
	}
	add("security_agent", definition)
	add("security_agent_run", run)
	for i := 0; i < 100; i++ {
		id := orderedApplicationDevice
		if i > 0 {
			id = ordered68MaximumDevice(i)
		}
		add("gateway_device", id)
	}
	for _, q := range requests {
		if want[q] != 1 {
			return false
		}
		delete(want, q)
	}
	return len(want) == 0
}

func TestOrdered68MaximumCheckOracle(t *testing.T) {
	var requests []authorization.CheckRequest
	for i := -2; i < 100; i++ {
		kind, id := "gateway_device", orderedApplicationDevice
		switch {
		case i == -2:
			kind, id = "security_agent", "definition"
		case i == -1:
			kind, id = "security_agent_run", "run"
		case i > 0:
			id = ordered68MaximumDevice(i)
		}
		requests = append(requests, authorization.CheckRequest{OrganizationID: "o", WorkspaceID: "w", EnvironmentID: "e", PrincipalKind: "user", PrincipalID: "actor", ResourceType: kind, ResourceID: id, Permission: "manage_workflows"}, authorization.CheckRequest{OrganizationID: "o", WorkspaceID: "w", EnvironmentID: "e", PrincipalKind: "service", PrincipalID: "principal", TaskID: "run", ResourceType: kind, ResourceID: id, Permission: "manage_workflows"})
	}
	match := func(q []authorization.CheckRequest) bool {
		return ordered68MaximumChecksMatch("o", "w", "e", "run", "definition", "actor", "principal", q)
	}
	if !match(requests) {
		t.Fatal("unchanged complete set refused")
	}
	mutations := map[string]func([]authorization.CheckRequest){
		"grantor":      func(q []authorization.CheckRequest) { q[202].PrincipalID = "wrong" },
		"service":      func(q []authorization.CheckRequest) { q[203].PrincipalID = "wrong" },
		"kind":         func(q []authorization.CheckRequest) { q[203].PrincipalKind = "agent" },
		"task":         func(q []authorization.CheckRequest) { q[203].TaskID = "" },
		"organization": func(q []authorization.CheckRequest) { q[203].OrganizationID = "wrong" },
		"workspace":    func(q []authorization.CheckRequest) { q[203].WorkspaceID = "wrong" },
		"environment":  func(q []authorization.CheckRequest) { q[203].EnvironmentID = "wrong" },
		"permission":   func(q []authorization.CheckRequest) { q[203].Permission = "view" },
		"resource":     func(q []authorization.CheckRequest) { q[203].ResourceType = "environment" },
		"id":           func(q []authorization.CheckRequest) { q[203].ResourceID = "wrong" },
		"duplicate":    func(q []authorization.CheckRequest) { q[203] = q[201] },
		"definition":   func(q []authorization.CheckRequest) { q[0].ResourceID = "wrong" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			q := append([]authorization.CheckRequest(nil), requests...)
			mutate(q)
			if match(q) {
				t.Fatal("changed full request accepted")
			}
		})
	}
	if match(requests[:203]) {
		t.Fatal("truncated set accepted")
	}
}
