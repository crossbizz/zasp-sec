//go:build darwin || linux

package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// Preflight of the reviewed authorities, not an orchestration implementation.
// The break this catches: cancellation between a durable source/deployment
// commit and the application receipt leaves no authorized cleanup handoff.
// Planning/provider usage/artifacts/admission, approval, source and deployment
// evidence are produced through their real private boundaries. Owner writes
// only establish queued input and controlled configuration, never success.
func TestSecurityAgentRelease61OrchestrationPreflightPostgres(t *testing.T) {
	buildCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	binary := multistepBudgetWorkerBinary(t, buildCtx)
	for _, boundary := range []string{"source_store", "deployment_claim", "deployment_claim_cross_run", "deployment_store", "deployment_read", "deployment_finish", "stopped", "kill_switch", "deadline", "lease_loss", "source_drift", "mixed_targets", "composition", "cleanup_unknown"} {
		t.Run(boundary, func(t *testing.T) {
			runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
				r, binding := release61PreflightPlan(t, ctx, owner, binary, o, w, e, testID, actor)
				action := orderedActionFenceConnection(t, ctx, owner)
				defer action.Close(ctx)
				seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
				if boundary == "mixed_targets" {
					seedOrderedApplicationGatewayAt(t, ctx, owner, o, w, e, "pid_8f000008-0000-4000-8000-000000000008")
				}
				persistent := policy.Policy{ID: "retained-partial-persistent", Name: "Retained policy", Scope: "environment", Trigger: "tool", Conditions: []policy.Condition{{Field: "action", Operator: "equals", Value: "write"}}, Action: policy.ActionBlock, Rollout: "enforced", FailureMode: "closed"}
				body, _ := json.Marshal(persistent)
				if _, err := owner.Exec(ctx, `INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'policy',$4,$5::jsonb)`, o, w, e, persistent.ID, body); err != nil {
					t.Fatal(err)
				}
				var step string
				var rv int
				if err := owner.QueryRow(ctx, `SELECT s.step_id,r.version FROM zasp_security_agent_runs r JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id) WHERE (r.organization_id,r.workspace_id,r.environment_id,r.run_id,s.step_index)=($1,$2,$3,$4,0)`, o, w, e, r).Scan(&step, &rv); err != nil {
					t.Fatal(err)
				}
				approved, err := orderedProgressionCall(ctx, api, "transition", orderedProgressionRequest(o, w, e, r, step, "approve", orderedProgressionApprover, rv))
				if err != nil {
					t.Fatal("real planning-to-approval handoff", err)
				}
				rv = int(approved["run_version"].(float64))
				claim, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, r, step, "claim", rv, 0), policy.GatewayPolicyKeys{})
				if err != nil {
					t.Fatal("real planning-to-application handoff", err)
				}
				_, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
				q := orderedApplicationStoreRequest(t, o, w, e, r, step, claim, key)
				if boundary == "deployment_claim_cross_run" {
					// The two ordered runs have identical policy IDs. Let A's
					// authentic source expire naturally before B composes, without
					// changing any committed source/audit or seeding success.
					source := q["envelope"].(map[string]any)
					now := time.Now().UTC().Truncate(time.Second)
					expires := now.Add(45 * time.Second)
					target := TemporaryPolicyTarget{DeviceID: source["device_id"].(string), CredentialID: source["credential_id"].(string), Sequence: source["sequence"].(int64), PolicyVersion: source["policy_version"].(int64)}
					var compiled []policy.CompiledPolicy
					if err = json.Unmarshal(source["policies"].(json.RawMessage), &compiled); err != nil {
						t.Fatal(err)
					}
					value := postgresTemporaryPolicyEnvelope(t, TemporaryPolicyEffectClaim{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, Phase: "apply"}, target, "ordered-key-01", key, expires.Add(-time.Duration(claim["ttl_seconds"].(float64))*time.Second), expires, compiled)
					source["issued_at"], source["expires_at"], source["signature"], source["envelope_digest"] = value.IssuedAt.Format(time.RFC3339Nano), value.ExpiresAt.Format(time.RFC3339Nano), base64.StdEncoding.EncodeToString(value.Signature), value.EnvelopeDigest
					source["payload_digest"] = value.PayloadDigest
				}
				q["run_version"] = claim["run_version"]
				stored, err := orderedApplicationCall(ctx, action, q, keys)
				if err != nil {
					t.Fatal("real source store", err)
				}
				if boundary == "deployment_finish" {
					deployOrderedApplication(t, ctx, owner, key, stored)
				}
				partialDeployment := strings.HasPrefix(boundary, "deployment_claim") || boundary == "deployment_store" || boundary == "deployment_read"
				var expiredDeployment map[string]any
				if partialDeployment {
					expiredDeployment = release61PreflightPartialDeployment(t, ctx, owner, key, stored, boundary)
				}
				var otherRun, otherSource string
				if boundary == "composition" || partialDeployment && boundary != "deployment_claim_cross_run" {
					otherRun, _ = release61PreflightOtherSource(t, ctx, owner, api, action, binary, binding, o, w, e, r, testID, actor, key, keys)
					if err = owner.QueryRow(ctx, `SELECT to_jsonb(t)::text FROM zasp_security_agent_temporary_policy_targets t WHERE run_id=$1`, otherRun).Scan(&otherSource); err != nil {
						t.Fatal(err)
					}
				}
				rv = int(stored["run_version"].(float64))
				q = orderedProgressionRequest(o, w, e, r, step, "cancel", orderedProgressionApprover, rv)
				q["approval_version"] = 2
				terminalConnection, wantState := api, "cancelled"
				if boundary == "stopped" || boundary == "deadline" || boundary == "kill_switch" {
					// Each stop input must independently produce the conservative
					// durable transition; switch-only never seeds a budget stop.
					fault := `UPDATE zasp_security_agent_run_budgets SET stop_reason='budget_usage_unknown' WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3`
					if boundary == "deadline" {
						fault = `UPDATE zasp_security_agent_run_budgets SET deadline_at=started_at+interval '1 microsecond' WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3`
					}
					if boundary != "kill_switch" {
						if _, err = owner.Exec(ctx, fault, o, w, e); err != nil {
							t.Fatal(err)
						}
					}
					if boundary == "stopped" || boundary == "kill_switch" {
						if _, err = owner.Exec(ctx, `UPDATE zasp_security_agent_kill_switches SET execution_enabled=false WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3`, o, w, e); err != nil {
							t.Fatal(err)
						}
					}
					var successor string
					if err = owner.QueryRow(ctx, `SELECT step_id FROM zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_index)=($1,$2,$3,$4,1)`, o, w, e, r).Scan(&successor); err != nil {
						t.Fatal(err)
					}
					q = orderedProgressionRequest(o, w, e, r, successor, "progress", "ordered-progress-worker", rv)
					if boundary == "kill_switch" {
						db, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
						stateQ := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": r, "worker_id": "ordered-progress-worker", "lease_token": "not-a-foreign-secret", "deployment_worker_id": "ordered-delivery-worker", "deployment_lease_token": "not-a-delivery-secret"}
						stateRaw, readErr := (&securityAgentMultistepAdmissionRepository{database: db}).orchestrationState(ctx, mustJSON(t, stateQ))
						var state map[string]any
						if readErr != nil || json.Unmarshal(stateRaw, &state) != nil || state["stop_required"] != true {
							t.Fatal("switch-only stop read", state, readErr)
						}
						before := orderedCleanupSnapshot(t, ctx, owner, r)
						if _, err := orderedProgressionCall(ctx, worker, "transition", q); err == nil || before != orderedCleanupSnapshot(t, ctx, owner, r) {
							t.Fatal("ordinary progress consumed worker-only stop", err)
						}
						q["operation"] = "stop"
					}
					terminalConnection, wantState = worker, "needs_human"
				}
				cancelled, err := orderedProgressionCall(ctx, terminalConnection, "transition", q)
				if err != nil || cancelled["run_state"] != wantState {
					t.Fatal("private cancellation", cancelled, err)
				}
				rv = int(cancelled["run_version"].(float64))
				var retained bool
				if err = owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,phase,state)=($1,$2,$3,$4,'apply','stored')) AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_receipts WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_controls WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4))`, o, w, e, r).Scan(&retained); err != nil || !retained {
					t.Fatal("pre-receipt cancellation evidence", retained, err)
				}
				// A cancelled parent must not be reopened to manufacture the
				// application receipt which the cleanup snapshot currently needs.
				if _, err = orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, r, step, "complete", rv, 2), keys); err == nil {
					t.Fatal("cancelled application completed")
				}
				if boundary == "source_drift" {
					release61PartialDriftRefusals(t, ctx, owner, action, o, w, e, r, step, rv, keys)
				}
				if partialDeployment {
					before := orderedCleanupSnapshot(t, ctx, owner, r)
					if _, err = orderedCleanupRestartCall(ctx, action, orderedCleanupRequest(o, w, e, r, step, "claim", rv, 2, 0), keys); err == nil || before != orderedCleanupSnapshot(t, ctx, owner, r) {
						t.Fatal("live application deployment lease was stolen", err)
					}
					// Let the actual committed lease expire; do not rewrite its
					// provenance to manufacture an expired positive fixture.
					if _, err = owner.Exec(ctx, `SELECT pg_sleep(GREATEST(0,extract(epoch FROM lease_expires_at-clock_timestamp()))+0.01) FROM zasp_policy_deployment_work WHERE organization_id=$1`, o); err != nil {
						t.Fatal(err)
					}
					if boundary == "deployment_read" || boundary == "deployment_claim" {
						release61HandoffDriftRefusals(t, ctx, owner, action, o, w, e, r, step, rv, keys)
					}
					for _, field := range []string{"organization_id", "step_id", "run_version", "effect_version"} {
						bad := orderedCleanupRequest(o, w, e, r, step, "claim", rv, 2, 0)
						if strings.HasSuffix(field, "_id") {
							bad[field] = orderedProgressionApprover
						} else {
							bad[field] = 1
						}
						before := orderedCleanupSnapshot(t, ctx, owner, r)
						if _, err = orderedCleanupRestartCall(ctx, action, bad, keys); err == nil || before != orderedCleanupSnapshot(t, ctx, owner, r) {
							t.Fatal("expired application handoff accepted wrong "+field, err)
						}
						if _, err = orderedProgressionCall(ctx, action, "cleanup", bad); err == nil || before != orderedCleanupSnapshot(t, ctx, owner, r) {
							t.Fatal("SQL expired application handoff accepted wrong "+field, err)
						}
					}
				}
				cleanup, err := orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, r, step, "claim", rv, 2, 0), keys)
				if err != nil {
					// Diagnose below the repository's deliberately redacted error
					// boundary. The same private call must still reject, without
					// manufacturing an application receipt or cleanup evidence.
					raw, _ := json.Marshal(orderedCleanupRequest(o, w, e, r, step, "claim", rv, 2, 0))
					var response []byte
					sqlErr := action.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.cleanup($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), raw).Scan(&response)
					var diagnostic *pgconn.PgError
					if errors.As(sqlErr, &diagnostic) {
						t.Log("private SQL detail", diagnostic.Detail, "context", diagnostic.Where)
					}
					if partialDeployment {
						var differences string
						diagErr := owner.QueryRow(ctx, `SELECT jsonb_build_object('envelope',(SELECT jsonb_object_agg(x.key,jsonb_build_array(x.value,zasp_sa_multistep_prior.cleanup_bundle_snapshot(b)->x.key)) FROM jsonb_each(a.body->'request'->'envelope') x WHERE x.value IS DISTINCT FROM zasp_sa_multistep_prior.cleanup_bundle_snapshot(b)->x.key),'work',(SELECT jsonb_object_agg(x.key,jsonb_build_array(x.value,to_jsonb(d)->x.key)) FROM jsonb_each(a.body->'work') x WHERE x.key NOT IN('desired_generation','available_at','updated_at') AND x.value IS DISTINCT FROM to_jsonb(d)->x.key))::text FROM zasp_security_agent_audit a JOIN zasp_policy_deployment_work d ON d.organization_id=a.organization_id JOIN zasp_runtime_gateway_policy_bundles b ON b.organization_id=d.organization_id AND b.sequence=d.leased_sequence WHERE a.run_id=$1 AND a.event_kind='ordered_delivery_store'`, r).Scan(&differences)
						t.Log("handoff predicate differences", differences, diagErr)
					}
					t.Fatalf("cancelled retained %s has no private cleanup handoff: %v; private SQL diagnostic: %v", boundary, err, sqlErr)
				}
				if cleanup["run_state"] != wantState || cleanup["state"] != "leased" {
					t.Fatal("cleanup suppressed cancellation", cleanup)
				}
				if partialDeployment {
					if err = owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(d.state='pending' AND d.lease_token IS NULL AND d.leased_sequence IS NULL AND to_jsonb(d)->'applied_generation'=a.body->'work'->'applied_generation' AND to_jsonb(d)->'applied_envelope_digest'=a.body->'work'->'applied_envelope_digest' AND to_jsonb(d)->'desired_generation'=a.body->'work'->'desired_generation') FROM zasp_security_agent_audit a JOIN zasp_policy_deployment_work d ON (d.organization_id,d.workspace_id,d.environment_id,d.device_id)=(a.organization_id,a.workspace_id,a.environment_id,a.body->>'device_id') WHERE a.run_id=$1 AND a.event_kind='ordered_partial_deployment_handoff'`, r).Scan(&retained); err != nil || !retained {
						t.Fatal("handoff fabricated deployment application or discarded newer generation", retained, err)
					}
					deployment := orderedApplicationDeploymentConnection(t, ctx, owner)
					before := orderedCleanupSnapshot(t, ctx, owner, r)
					_, staleErr := orderedCompositionDeploymentCall(ctx, deployment, expiredDeployment, keys)
					deployment.Close(ctx)
					if staleErr == nil || before != orderedCleanupSnapshot(t, ctx, owner, r) {
						t.Fatal("stale application deployment reopened after handoff", staleErr)
					}
				}
				var handoffBefore, otherBundle string
				if boundary == "deployment_claim_cross_run" {
					if err = owner.QueryRow(ctx, `SELECT to_jsonb(a)::text FROM zasp_security_agent_audit a WHERE run_id=$1 AND event_kind='ordered_partial_deployment_handoff'`, r).Scan(&handoffBefore); err != nil {
						t.Fatal(err)
					}
					if _, err = owner.Exec(ctx, `SELECT pg_sleep(GREATEST(0,extract(epoch FROM expires_at-clock_timestamp()))+0.01) FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$1 AND phase='apply'`, r); err != nil {
						t.Fatal(err)
					}
					var otherStored map[string]any
					otherRun, otherStored = release61PreflightOtherSource(t, ctx, owner, api, action, binary, binding, o, w, e, r, testID, actor, key, keys)
					deployOrderedApplication(t, ctx, owner, key, otherStored)
					if err = owner.QueryRow(ctx, `SELECT to_jsonb(t)::text FROM zasp_security_agent_temporary_policy_targets t WHERE run_id=$1`, otherRun).Scan(&otherSource); err != nil {
						t.Fatal(err)
					}
					if err = owner.QueryRow(ctx, `SELECT a.body->'bundle'='null'::jsonb AND b.sequence=(a.body->'work'->>'leased_sequence')::bigint AND EXISTS(SELECT 1 FROM zasp_security_agent_audit p WHERE p.run_id=$2 AND p.event_kind='ordered_delivery_store' AND p.body->'request'->'sequence'=to_jsonb(b.sequence)) FROM zasp_security_agent_audit a JOIN zasp_runtime_gateway_policy_bundles b ON b.organization_id=a.organization_id WHERE a.run_id=$1 AND a.event_kind='ordered_partial_deployment_handoff'`, r, otherRun).Scan(&retained); err != nil || !retained {
						t.Fatal("B did not legitimately reuse A's historically absent sequence", retained, err)
					}
					if err = owner.QueryRow(ctx, `SELECT to_jsonb(b)::text FROM zasp_security_agent_audit a JOIN zasp_runtime_gateway_policy_bundles b ON (b.organization_id,b.device_id,b.sequence)=(a.organization_id,a.body->>'device_id',(a.body->'work'->>'leased_sequence')::bigint) WHERE a.run_id=$1 AND a.event_kind='ordered_partial_deployment_handoff'`, r).Scan(&otherBundle); err != nil {
						t.Fatal(err)
					}
				}
				// The next break is a false application-success receipt or
				// inability to settle exact removal after this partial claim.
				if boundary != "deployment_finish" {
					deployment := orderedApplicationDeploymentConnection(t, ctx, owner)
					deployment.Close(ctx)
				}
				lease := "ordered-cleanup-lease"
				if boundary == "lease_loss" || partialDeployment {
					if _, err = owner.Exec(ctx, `UPDATE zasp_sa_multistep_prior.cleanups SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1; UPDATE zasp_security_agent_effects SET lease_expires_at=(SELECT lease_expires_at FROM zasp_sa_multistep_prior.cleanups WHERE run_id=$1) WHERE run_id=$1`, pgx.QueryExecModeSimpleProtocol, r); err != nil {
						t.Fatal(err)
					}
					if _, err = orderedCleanupRestartCall(ctx, action, orderedCleanupRequest(o, w, e, r, step, "heartbeat", rv, 3, 1), keys); err == nil {
						t.Fatal("expired partial cleanup heartbeat accepted")
					}
					reconciled, reconcileErr := orderedCleanupRestartCall(ctx, action, orderedCleanupRequest(o, w, e, r, step, "reconcile", rv, 3, 1), keys)
					if reconcileErr != nil || reconciled["reason"] != "no_external_call" || reconciled["run_state"] != wantState {
						t.Fatal("partial cleanup expiry fabricated success", reconciled, reconcileErr)
					}
					rv = int(reconciled["run_version"].(float64))
					q = orderedCleanupRequest(o, w, e, r, step, "claim", rv, 4, 2)
					lease = "ordered-partial-recovered-lease"
					q["lease_token"] = lease
					recovered, recoverErr := orderedCleanupRestartCall(ctx, action, q, keys)
					if recoverErr != nil || recovered["cleanup_id"] != cleanup["cleanup_id"] || recovered["reservation_id"] != cleanup["reservation_id"] || recovered["attempt"] != float64(2) {
						t.Fatal("partial cleanup recovery duplicated identity", recovered, recoverErr)
					}
					cleanup = recovered
				}
				q = orderedCleanupStoreRequest(t, o, w, e, r, step, cleanup, key)
				q["lease_token"] = lease
				if boundary == "deployment_claim_cross_run" {
					release61HistoricalHandoffRefusals(t, ctx, owner, action, r, otherRun, q, keys)
				}
				for _, deny := range []string{"tenant", "stale_lease", "stale_version"} {
					bad := cloneOrderedApplicationRequest(t, q)
					switch deny {
					case "tenant":
						bad["organization_id"] = orderedProgressionApprover
					case "stale_lease":
						bad["lease_token"] = "not-the-current-cleanup-lease"
					case "stale_version":
						bad["effect_version"] = 1
					}
					before := orderedCleanupSnapshot(t, ctx, owner, r)
					if _, err = orderedCleanupRestartCall(ctx, action, bad, keys); err == nil || before != orderedCleanupSnapshot(t, ctx, owner, r) {
						t.Fatal("partial cleanup accepted "+deny, err)
					}
					if _, err = orderedProgressionCall(ctx, action, "cleanup", bad); err == nil || before != orderedCleanupSnapshot(t, ctx, owner, r) {
						t.Fatal("private SQL partial cleanup accepted "+deny, err)
					}
				}
				storedCleanup, err := orderedCleanupRestartCall(ctx, action, q, keys)
				if err != nil {
					t.Fatal("partial cleanup source store", err)
				}
				storedCleanup["cleanup_lease_token"] = lease
				if boundary == "cleanup_unknown" {
					deployOrderedCleanup(t, ctx, owner, key, storedCleanup, "stored")
					before := orderedCleanupSnapshot(t, ctx, owner, r)
					if _, err = orderedCleanupRestartCall(ctx, action, orderedCleanupRequest(o, w, e, r, step, "complete", rv, 4, 2), keys); err == nil || before != orderedCleanupSnapshot(t, ctx, owner, r) {
						t.Fatal("unacknowledged partial removal reported cleaned", err)
					}
					if _, err = owner.Exec(ctx, `UPDATE zasp_sa_multistep_prior.cleanups SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1; UPDATE zasp_security_agent_effects SET lease_expires_at=(SELECT lease_expires_at FROM zasp_sa_multistep_prior.cleanups WHERE run_id=$1) WHERE run_id=$1; UPDATE zasp_policy_deployment_work SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE organization_id=$2 AND state='leased'`, pgx.QueryExecModeSimpleProtocol, r, o); err != nil {
						t.Fatal(err)
					}
					q = orderedCleanupRequest(o, w, e, r, step, "reconcile", rv, 4, 2)
					got, reconcileErr := orderedCleanupRestartCall(ctx, action, q, keys)
					if reconcileErr != nil || got["state"] != "retryable" || got["reason"] != "unknown_call" || got["run_state"] != wantState || got["receipt_kind"] != "" {
						t.Fatal("unknown partial removal manufactured success", got, reconcileErr)
					}
					before = orderedCleanupSnapshot(t, ctx, owner, r)
					if _, err = orderedCleanupRestartCall(ctx, action, q, keys); err != nil || before != orderedCleanupSnapshot(t, ctx, owner, r) {
						t.Fatal("unknown partial removal replay changed evidence", err)
					}
					return
				}
				deployOrderedCleanup(t, ctx, owner, key, storedCleanup)
				if partialDeployment {
					outcome := "unknown_application_outcome"
					if strings.HasPrefix(boundary, "deployment_claim") {
						outcome = "no_external_call"
					}
					if err = owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(a.body->>'outcome'=$5
 AND (CASE WHEN $5='no_external_call' THEN a.body->'bundle'='null'::jsonb ELSE a.body->'bundle'=(SELECT to_jsonb(b) FROM zasp_runtime_gateway_policy_bundles b WHERE (b.organization_id,b.workspace_id,b.environment_id,b.device_id,b.sequence)=($1,$2,$3,a.body->>'device_id',(a.body->'work'->>'leased_sequence')::bigint)) END)
 AND (SELECT d.applied_generation>(a.body->'work'->>'leased_generation')::bigint AND b.sequence>(a.body->'work'->>'leased_sequence')::bigint FROM zasp_policy_deployment_work d JOIN zasp_runtime_gateway_policy_bundles b ON (b.organization_id,b.workspace_id,b.environment_id,b.device_id,b.envelope_digest)=(d.organization_id,d.workspace_id,d.environment_id,d.device_id,d.applied_envelope_digest) WHERE (d.organization_id,d.workspace_id,d.environment_id,d.device_id)=($1,$2,$3,a.body->>'device_id'))
 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(a.body->'audits') x WHERE NOT EXISTS(SELECT 1 FROM zasp_security_agent_audit p WHERE p.organization_id=$1 AND p.audit_id=x->>'audit_id' AND x->>'body_digest'=encode(digest(convert_to(p.body::text,'UTF8'),'sha256'),'hex'))))
 FROM zasp_security_agent_audit a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.event_kind)=($1,$2,$3,$4,'ordered_partial_deployment_handoff')`, o, w, e, r, outcome).Scan(&retained); err != nil || !retained {
						t.Fatal("application uncertainty or exact original evidence lost at handoff", retained, err)
					}
				}
				completeRequest := orderedCleanupRequest(o, w, e, r, step, "complete", rv, int(storedCleanup["effect_version"].(float64)), int(storedCleanup["version"].(float64)))
				completeRequest["lease_token"] = lease
				complete, err := orderedCleanupRestartCall(ctx, action, completeRequest, keys)
				if err != nil || complete["receipt_kind"] != "temporary_policy_partial_cleaned.v1" || complete["run_state"] != wantState || complete["state"] != "cleaned" {
					t.Fatal("partial cleanup has no conservative removal receipt", complete, err)
				}
				if boundary == "source_store" {
					orderedCleanupResponseRefusals(t, ctx, completeRequest, complete, keys)
					for _, mode := range []string{"remediated", "normal_kind", "missing_partial_digest"} {
						v := cloneOrderedApplicationRequest(t, complete)
						switch mode {
						case "remediated":
							v["run_state"] = "remediated"
						case "normal_kind":
							v["receipt_kind"] = "temporary_policy_cleaned.v1"
						case "missing_partial_digest":
							delete(v["receipt"].(map[string]any), "partial_application_digest")
						}
						v["receipt_digest"] = orderedCleanupDigest(mustJSON(t, v["receipt"]))
						db := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{`SELECT zasp_sa_multistep_prior.cleanup($1,$2,$3::jsonb)`: mustJSON(t, v)}}
						if _, err = (&securityAgentMultistepAdmissionRepository{database: db}).cleanup(ctx, mustJSON(t, completeRequest), keys); err == nil {
							t.Fatal("partial receipt decoder accepted " + mode)
						}
					}
				}
				before := orderedCleanupSnapshot(t, ctx, owner, r)
				if _, err = orderedCleanupRestartCall(ctx, action, completeRequest, keys); err != nil || before != orderedCleanupSnapshot(t, ctx, owner, r) {
					t.Fatal("partial completion replay changed durable evidence", err)
				}
				if handoffBefore != "" {
					var handoffAfter string
					if err = owner.QueryRow(ctx, `SELECT to_jsonb(a)::text FROM zasp_security_agent_audit a WHERE run_id=$1 AND event_kind='ordered_partial_deployment_handoff'`, r).Scan(&handoffAfter); err != nil || handoffBefore != handoffAfter {
						t.Fatal("cross-run cleanup rewrote historical no-call proof", err)
					}
					var bundleAfter string
					if err = owner.QueryRow(ctx, `SELECT to_jsonb(b)::text FROM zasp_security_agent_audit a JOIN zasp_runtime_gateway_policy_bundles b ON (b.organization_id,b.device_id,b.sequence)=(a.organization_id,a.body->>'device_id',(a.body->'work'->>'leased_sequence')::bigint) WHERE a.run_id=$1 AND a.event_kind='ordered_partial_deployment_handoff'`, r).Scan(&bundleAfter); err != nil || otherBundle != bundleAfter {
						t.Fatal("cross-run cleanup changed B's immutable bundle", err)
					}
				}
				if err = owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_receipts WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_controls WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4))`, o, w, e, r).Scan(&retained); err != nil || !retained {
					t.Fatal("partial removal fabricated application or successor success", retained, err)
				}
				if err = owner.QueryRow(ctx, `SELECT w.body=$4::jsonb AND EXISTS(SELECT 1 FROM zasp_policy_deployment_work d JOIN zasp_runtime_gateway_policy_bundles b ON (b.organization_id,b.workspace_id,b.environment_id,b.device_id,b.envelope_digest)=(d.organization_id,d.workspace_id,d.environment_id,d.device_id,d.applied_envelope_digest) WHERE (d.organization_id,d.workspace_id,d.environment_id)=($1,$2,$3) AND b.policies @> '[{"id":"retained-partial-persistent"}]') FROM zasp_workflow_records w WHERE (w.organization_id,w.workspace_id,w.environment_id,w.kind,w.id)=($1,$2,$3,'policy','retained-partial-persistent')`, o, w, e, body).Scan(&retained); err != nil || !retained {
					t.Fatal("partial removal lost persistent policy", retained, err)
				}
				if otherRun != "" {
					var after string
					if err = owner.QueryRow(ctx, `SELECT to_jsonb(t)::text FROM zasp_security_agent_temporary_policy_targets t WHERE run_id=$1`, otherRun).Scan(&after); err != nil || after != otherSource {
						t.Fatal("partial cleanup changed unrelated source", err)
					}
					if err = owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_policy_deployment_work d JOIN zasp_runtime_gateway_policy_bundles b ON (b.organization_id,b.workspace_id,b.environment_id,b.device_id,b.envelope_digest)=(d.organization_id,d.workspace_id,d.environment_id,d.device_id,d.applied_envelope_digest) WHERE (d.organization_id,d.workspace_id,d.environment_id)=($1,$2,$3) AND jsonb_array_length(b.policies)=3 AND b.policies @> '[{"id":"temporary-containment-http-v1"},{"id":"temporary-containment-mcp-v1"}]')`, o, w, e).Scan(&retained); err != nil || !retained {
						t.Fatal("partial cleanup omitted unrelated temporary policy", retained, err)
					}
				}
			})
		})
	}
}

// Stop the real deployment producer at a committed store/read boundary. Each
// operation reconstructs its connection and repository, as a restarted worker.
func release61PreflightPartialDeployment(t *testing.T, ctx context.Context, owner *pgx.Conn, key ed25519.PrivateKey, stored map[string]any, boundary string) map[string]any {
	t.Helper()
	connection := orderedApplicationDeploymentConnection(t, ctx, owner)
	config := connection.Config().Copy()
	connection.Close(ctx)
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
	q := orderedApplicationDeploymentRequest(stored["organization_id"].(string), stored["workspace_id"].(string), stored["environment_id"].(string), stored["run_id"].(string), stored["step_id"].(string), stored)
	q["lease_seconds"] = 30
	call := func() map[string]any {
		c, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close(ctx)
		got, err := orderedCompositionDeploymentCall(ctx, c, q, keys)
		if err != nil {
			t.Fatal("partial application deployment", q["operation"], err)
		}
		return got
	}
	got := call()
	if strings.HasPrefix(boundary, "deployment_claim") {
		return q
	}
	raw, _ := json.Marshal(got["result"])
	var claim orderedDeploymentClaim
	if err := json.Unmarshal(raw, &claim); err != nil {
		t.Fatal(err)
	}
	var composition orderedDeploymentComposition
	if err := json.Unmarshal(claim.Composition, &composition); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	expires, _ := time.Parse(time.RFC3339Nano, composition.ExpiresAt)
	envelope, err := policy.SignGatewayPolicyEnvelope(policy.GatewayPolicySigningInput{KeyID: "ordered-key-01", Binding: policy.GatewayPolicyBinding{OrganizationID: claim.OrganizationID, WorkspaceID: claim.WorkspaceID, EnvironmentID: claim.EnvironmentID, DeviceID: claim.DeviceID}, Sequence: uint64(claim.Sequence), PolicyVersion: uint64(claim.PolicyVersion), Now: now, IssuedAt: now, ExpiresAt: expires, FailureMode: "closed", Policies: composition.Policies}, key)
	if err != nil {
		t.Fatal(err)
	}
	q["operation"], q["sequence"], q["input_digest"], q["composition"], q["envelope"], q["digest"] = "store", claim.Sequence, claim.InputDigest, claim.Composition, envelope, orderedEnvelopeDigest(envelope)
	call()
	if boundary == "deployment_read" {
		q["operation"], q["envelope"], q["digest"] = "read", map[string]any{}, ""
		call()
	}
	return q
}

// Historical absence is immutable evidence, not permission to substitute a
// later producer's bundle/audit, even if a tamperer recomputes the audit hash.
func release61HistoricalHandoffRefusals(t *testing.T, ctx context.Context, owner, action *pgx.Conn, r, otherRun string, q map[string]any, keys policy.GatewayPolicyKeys) {
	t.Helper()
	for _, fault := range []struct{ name, mutation string }{
		{"handoff_digest", `event_digest=decode(repeat('ab',32),'hex')`},
		{"handoff_body", `body=jsonb_set(body,'{lease_token_digest}','"changed"')`},
		{"foreign_bundle", `body=jsonb_set(jsonb_set(body,'{bundle}',(SELECT to_jsonb(b) FROM zasp_runtime_gateway_policy_bundles b WHERE b.organization_id=a.organization_id AND b.sequence=(a.body->'work'->>'leased_sequence')::bigint)),'{outcome}','"unknown_application_outcome"')`},
		{"foreign_claim_audit", `body=jsonb_set(body,'{audits}',(SELECT jsonb_build_array(jsonb_build_object('audit_id',p.audit_id,'event_digest',encode(p.event_digest,'hex'),'body_digest',encode(digest(convert_to(p.body::text,'UTF8'),'sha256'),'hex'))) FROM zasp_security_agent_audit p WHERE p.run_id=$2 AND p.event_kind='ordered_delivery_claim' LIMIT 1))`},
	} {
		t.Run(fault.name, func(t *testing.T) {
			var original []byte
			if err := owner.QueryRow(ctx, `SELECT to_jsonb(a) FROM zasp_security_agent_audit a WHERE run_id=$1 AND event_kind='ordered_partial_deployment_handoff'`, r).Scan(&original); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_audit a SET body=x.body,event_digest=x.event_digest FROM jsonb_populate_record(NULL::zasp_security_agent_audit,$1::jsonb) x WHERE a.audit_id=x.audit_id`, original); err != nil {
					t.Fatal("restore historical proof fault", err)
				}
			}()
			args := []any{r}
			if fault.name == "foreign_claim_audit" {
				args = append(args, otherRun)
			}
			if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_audit a SET `+fault.mutation+` WHERE run_id=$1 AND event_kind='ordered_partial_deployment_handoff'`, args...); err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(fault.name, "foreign_") {
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_audit SET event_digest=digest(convert_to(body::text,'UTF8'),'sha256') WHERE run_id=$1 AND event_kind='ordered_partial_deployment_handoff'`, r); err != nil {
					t.Fatal(err)
				}
			}
			before := orderedCleanupSnapshot(t, ctx, owner, r)
			if _, err := orderedCleanupRestartCall(ctx, action, q, keys); err == nil || before != orderedCleanupSnapshot(t, ctx, owner, r) {
				t.Fatal("cleanup accepted historical proof substitution", fault.name, err)
			}
			if _, err := orderedProgressionCall(ctx, action, "cleanup", q); err == nil || before != orderedCleanupSnapshot(t, ctx, owner, r) {
				t.Fatal("private SQL accepted historical proof substitution", fault.name, err)
			}
		})
	}
}

func release61HandoffDriftRefusals(t *testing.T, ctx context.Context, owner, action *pgx.Conn, o, w, e, r, step string, rv int, keys policy.GatewayPolicyKeys) {
	t.Helper()
	for _, fault := range []struct{ name, table, where, mutation, restore string }{
		{"generation", "zasp_policy_deployment_work", "organization_id=$1", "leased_generation=leased_generation+1", "leased_generation=x.leased_generation"},
		{"credential", "zasp_policy_deployment_work", "organization_id=$1", "leased_credential_id='pid_8f000009-0000-4000-8000-000000000009'", "leased_credential_id=x.leased_credential_id"},
		{"lease", "zasp_policy_deployment_work", "organization_id=$1", "lease_token='wrong-expired-lease-token'", "lease_token=x.lease_token"},
		{"input", "zasp_policy_deployment_work", "organization_id=$1", "leased_input_digest=decode(repeat('ab',32),'hex')", "leased_input_digest=x.leased_input_digest"},
		{"bundle", "zasp_runtime_gateway_policy_bundles", "organization_id=$1", "signature=decode(repeat('ab',64),'hex')", "signature=x.signature"},
		{"issued_plus_microsecond", "zasp_runtime_gateway_policy_bundles", "organization_id=$1", "issued_at=issued_at+interval '1 microsecond'", "issued_at=x.issued_at"},
		{"issued_minus_microsecond", "zasp_runtime_gateway_policy_bundles", "organization_id=$1", "issued_at=issued_at-interval '1 microsecond'", "issued_at=x.issued_at"},
		{"expires_plus_microsecond", "zasp_runtime_gateway_policy_bundles", "organization_id=$1", "expires_at=expires_at+interval '1 microsecond'", "expires_at=x.expires_at"},
		{"expires_minus_microsecond", "zasp_runtime_gateway_policy_bundles", "organization_id=$1", "expires_at=expires_at-interval '1 microsecond'", "expires_at=x.expires_at"},
		{"bundle_key", "zasp_runtime_gateway_policy_bundles", "organization_id=$1", "key_id='changed-non-time-key'", "key_id=x.key_id"},
		{"audit", "zasp_security_agent_audit", "organization_id=$1 AND event_kind='ordered_delivery_store'", "body=jsonb_set(body,'{request,digest}','\"sha256:bad\"')", "body=x.body"},
		{"claim_audit", "zasp_security_agent_audit", "organization_id=$1 AND event_kind='ordered_delivery_claim'", "body=jsonb_set(body,'{request,source_digest}','\"sha256:bad\"')", "body=x.body"},
		{"missing_claim", "zasp_security_agent_audit", "organization_id=$1 AND event_kind='ordered_delivery_claim'", "event_kind='ordered_hidden_claim_fixture'", "event_kind=x.event_kind"},
		{"unexpected_bundle", "zasp_security_agent_audit", "organization_id=$1 AND event_kind='ordered_delivery_store'", "event_kind='ordered_hidden_store_fixture'", "event_kind=x.event_kind"},
	} {
		t.Run(fault.name, func(t *testing.T) {
			var original string
			if err := owner.QueryRow(ctx, "SELECT to_jsonb(t)::text FROM "+fault.table+" t WHERE "+fault.where, o).Scan(&original); errors.Is(err, pgx.ErrNoRows) {
				t.Skip("no stored deployment evidence at claim boundary")
			} else if err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, "UPDATE "+fault.table+" SET "+fault.mutation+" WHERE "+fault.where, o); err != nil {
				t.Fatal(err)
			}
			defer func() {
				where := "t.organization_id=$1"
				if fault.table == "zasp_security_agent_audit" {
					where += " AND t.audit_id=x.audit_id"
				}
				if _, err := owner.Exec(ctx, "UPDATE "+fault.table+" t SET "+fault.restore+" FROM jsonb_populate_record(NULL::"+fault.table+",$2::jsonb) x WHERE "+where, o, original); err != nil {
					t.Fatal("restore handoff fault", err)
				}
			}()
			if _, err := action.Exec(ctx, "BEGIN"); err != nil {
				t.Fatal(err)
			}
			_, err := orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, r, step, "claim", rv, 2, 0), keys)
			action.Exec(ctx, "ROLLBACK")
			if err == nil {
				t.Error("partial handoff accepted corrupted " + fault.name)
			}
		})
	}
}

func release61PartialDriftRefusals(t *testing.T, ctx context.Context, owner, action *pgx.Conn, o, w, e, r, step string, rv int, keys policy.GatewayPolicyKeys) {
	t.Helper()
	var original []byte
	if err := owner.QueryRow(ctx, `SELECT to_jsonb(t) FROM zasp_security_agent_temporary_policy_targets t WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=($1,$2,$3,$4,$5,'apply')`, o, w, e, r, step).Scan(&original); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"key_id='changed-key'", "payload_digest=decode(repeat('ba',32),'hex')", "desired_generation=desired_generation+1", "policy_version=policy_version+1", "action_key='isolate_session'"} {
		t.Run(mutation, func(t *testing.T) {
			if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_temporary_policy_targets SET `+mutation+` WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=($1,$2,$3,$4,$5,'apply')`, o, w, e, r, step); err != nil {
				var postgresError *pgconn.PgError
				if mutation == "action_key='isolate_session'" && errors.As(err, &postgresError) && postgresError.Code == "23503" {
					// This drift is already prevented by the exact scoped
					// effect FK, before partial-cleanup code can observe it.
					return
				}
				t.Fatal(err)
			}
			defer func() {
				_, err := owner.Exec(ctx, `UPDATE zasp_security_agent_temporary_policy_targets t SET key_id=x.key_id,payload_digest=x.payload_digest,desired_generation=x.desired_generation,policy_version=x.policy_version,action_key=x.action_key FROM jsonb_populate_record(NULL::zasp_security_agent_temporary_policy_targets,$6::jsonb) x WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.step_id,t.phase)=($1,$2,$3,$4,$5,'apply')`, o, w, e, r, step, original)
				if err != nil {
					t.Fatal("restore negative source fault", err)
				}
			}()
			if _, err := action.Exec(ctx, `BEGIN`); err != nil {
				t.Fatal(err)
			}
			_, err := orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, r, step, "claim", rv, 2, 0), keys)
			action.Exec(ctx, `ROLLBACK`)
			if err == nil {
				t.Error("partial cleanup accepted changed source authority", mutation)
			}
		})
	}
}

func release61PreflightPlan(t *testing.T, ctx context.Context, owner *pgx.Conn, binary, o, w, e, testID, actor string) (string, string) {
	t.Helper()
	r, binding := release61PreflightQueue(t, ctx, owner, o, w, e, testID, actor)
	release61PreflightInvokePlan(t, ctx, owner, binary, binding, r, testID)
	return r, binding
}

func release61PreflightQueue(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, testID, actor string) (string, string) {
	t.Helper()
	r := seedOrderedPlanningQueue(t, ctx, owner, o, w, e, testID, actor)
	config := owner.Config().Copy()
	config.User = "security_agent_v33_discovery_api_login"
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	if _, err = owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1; UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests"]' WHERE principal_id=$1`, pgx.QueryExecModeSimpleProtocol, actor); err != nil {
		t.Fatal(err)
	}
	q := orderedPricingAdminRequest(o, w, e, actor)
	p := q["policy"].(map[string]any)
	p["request_token_limit"], p["request_policy_version"] = 512, "security-agent-planner-v1"
	h := sha256.Sum256([]byte("sk-or-v1-test-token-1234567890"))
	p["credential_digest"] = "sha256:" + hex.EncodeToString(h[:])
	created, err := orderedPricingCall(ctx, admin, "pricing_admin", q)
	if err != nil {
		t.Fatal(err)
	}
	binding, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "account_profile": p["account_profile"], "credential_reference": p["credential_reference"], "policy_id": created["policy_id"], "policy_version": created["version"], "policy_digest": created["policy_digest"], "account_id": created["account_id"], "account_version": created["account_version"]})
	return r, string(binding)
}

func release61PreflightInvokePlan(t *testing.T, ctx context.Context, owner *pgx.Conn, binary, binding, r, testID string) {
	t.Helper()
	command := exec.Command(binary, "-test.run=^TestSecurityAgentMultistepPlanningOwnedPostgres$", "-test.v", "-test.timeout=90s")
	command.Dir = "../agentsec-worker"
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "ZASP_") && !strings.HasPrefix(entry, "PG") {
			command.Env = append(command.Env, entry)
		}
	}
	command.Env = append(command.Env, "ZASP_ORDERED_PLANNING_DSN="+owner.Config().ConnString(), "ZASP_ORDERED_PLANNING_BINDING="+binding, "ZASP_ORDERED_PLANNING_RUN="+r, "ZASP_ORDERED_PLANNING_TEST_ID="+testID, "ZASP_ORDERED_PLANNING_ARTIFACTS="+t.TempDir())
	output, err := runSandboxWorkerCommand(ctx, command)
	if err != nil || strings.Contains(string(output), "--- SKIP:") || !strings.Contains(string(output), "owned planning worker joined: provider_calls=1") {
		t.Fatalf("real private planning process: %v\n%s", err, output)
	}
	t.Log(string(output))
}

func release61PreflightOtherSource(t *testing.T, ctx context.Context, owner, api, action *pgx.Conn, binary, binding, o, w, e, first, testID, actor string, key ed25519.PrivateKey, keys policy.GatewayPolicyKeys) (string, map[string]any) {
	t.Helper()
	finding := "pid_8c300002-0000-4000-8000-000000000003"
	var run string
	if err := owner.QueryRow(ctx, `SELECT zasp_discovery_canonical_id($1,$2,$3,'security_agent_run',definition_id||chr(31)||$5||chr(31)||'1') FROM zasp_security_agent_runs WHERE run_id=$4`, o, w, e, first, finding).Scan(&run); err != nil {
		t.Fatal(err)
	}
	// Only a second queued input is seeded. Its planner and all source evidence
	// are produced through the same real private boundaries as the first run.
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$5,'posture','credential','Second queued trigger','high','open'); INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state,version,attempt) SELECT organization_id,workspace_id,environment_id,$6,definition_id,definition_version,$5,$7,'queued',1,0 FROM zasp_security_agent_runs WHERE run_id=$4; INSERT INTO zasp_security_agent_trigger_receipts(organization_id,workspace_id,environment_id,definition_id,trigger_id,trigger_kind,trigger_version,trigger_digest,run_id) SELECT organization_id,workspace_id,environment_id,definition_id,$5,'finding',1,decode(repeat('cd',32),'hex'),$6 FROM zasp_security_agent_runs WHERE run_id=$4`, pgx.QueryExecModeSimpleProtocol, o, w, e, first, finding, run, actor); err != nil {
		t.Fatal(err)
	}
	release61PreflightInvokePlan(t, ctx, owner, binary, binding, run, testID)
	var step string
	var rv int
	if err := owner.QueryRow(ctx, `SELECT s.step_id,r.version FROM zasp_security_agent_runs r JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1 AND s.step_index=0`, run).Scan(&step, &rv); err != nil {
		t.Fatal(err)
	}
	approved, err := orderedProgressionCall(ctx, api, "transition", orderedProgressionRequest(o, w, e, run, step, "approve", orderedProgressionApprover, rv))
	if err != nil {
		t.Fatal(err)
	}
	claim, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, run, step, "claim", int(approved["run_version"].(float64)), 0), keys)
	if err != nil {
		t.Fatal(err)
	}
	q := orderedApplicationStoreRequest(t, o, w, e, run, step, claim, key)
	q["run_version"] = claim["run_version"]
	stored, err := orderedApplicationCall(ctx, action, q, keys)
	if err != nil {
		t.Fatal(err)
	}
	return run, stored
}
