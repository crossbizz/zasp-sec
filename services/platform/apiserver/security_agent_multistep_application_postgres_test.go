package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// Unlike Task 7's consumer fixtures, every effect, reservation, target, control,
// deployment acknowledgement and application receipt below must be written by
// its production authority. Owner writes only seed configuration or inject faults.
func TestSecurityAgentMultistepApplicationClaimPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		for i, mode := range []string{"approved", "pending", "successor", "cross_tenant", "stale_version", "concurrent", "rollback"} {
			t.Run(mode, func(t *testing.T) {
				r, steps := seedOrderedApplicationRun(t, ctx, owner, worker, api, o, w, e, testID, actor, 700+i, mode != "pending")
				request := orderedApplicationRequest(o, w, e, r, steps[0], "claim", 4, 0)
				if mode == "pending" {
					request["run_version"] = 3
				}
				if mode == "successor" {
					request["step_id"] = steps[1]
				}
				if mode == "cross_tenant" {
					request["organization_id"] = orderedProgressionApprover
				}
				if mode == "stale_version" {
					request["run_version"] = 3
				}
				before := orderedApplicationSnapshot(t, ctx, owner, r)
				if mode == "rollback" || mode == "concurrent" {
					if _, err := action.Exec(ctx, `BEGIN`); err != nil {
						t.Fatal(err)
					}
					defer action.Exec(ctx, `ROLLBACK`)
				}
				got, err := orderedProgressionCall(ctx, action, "application", request)
				if mode == "pending" || mode == "successor" || mode == "cross_tenant" || mode == "stale_version" {
					if err == nil || orderedApplicationSnapshot(t, ctx, owner, r) != before {
						t.Fatal("unready claim changed authority", got, err)
					}
					return
				}
				if err != nil {
					t.Fatal("approved dependency-ready step has no claim authority", err)
				}
				if got["effect_state"] != "leased" || got["run_version"] != float64(5) || got["effect_version"] != float64(1) || got["attempt"] != float64(1) {
					t.Fatal("claim postconditions", got)
				}
				if mode == "rollback" {
					if _, err = action.Exec(ctx, `ROLLBACK`); err != nil {
						t.Fatal(err)
					}
					if orderedApplicationSnapshot(t, ctx, owner, r) != before {
						t.Fatal("claim escaped rollback")
					}
					return
				}
				if mode == "concurrent" {
					other, err := pgx.ConnectConfig(ctx, action.Config().Copy())
					if err != nil {
						t.Fatal(err)
					}
					defer other.Close(ctx)
					request["lease_token"] = "ordered-application-other-lease"
					done := make(chan error, 1)
					go func() { _, callErr := orderedProgressionCall(ctx, other, "application", request); done <- callErr }()
					waitOrderedProgressionBlocked(t, ctx, action, other)
					if _, err = action.Exec(ctx, `COMMIT`); err != nil {
						t.Fatal(err)
					}
					if err = <-done; err == nil {
						t.Fatal("second worker acquired current lease")
					}
					request["lease_token"] = "ordered-application-lease"
				}
				stable := orderedApplicationSnapshot(t, ctx, owner, r)
				restart, err := pgx.ConnectConfig(ctx, action.Config().Copy())
				if err != nil {
					t.Fatal(err)
				}
				defer restart.Close(ctx)
				replayed, err := orderedProgressionCall(ctx, restart, "application", request)
				if err != nil || replayed["reservation_id"] != got["reservation_id"] || orderedApplicationSnapshot(t, ctx, owner, r) != stable {
					t.Fatal("claim restart changed reservation", replayed, err)
				}
				assertOrderedApplicationCounts(t, ctx, owner, r, 1, 1, 0, 1)
			})
		}
	})
}

func TestSecurityAgentMultistepApplicationLeasePostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		r, steps := seedOrderedApplicationRun(t, ctx, owner, worker, api, o, w, e, testID, actor, 720, true)
		request := orderedApplicationRequest(o, w, e, r, steps[0], "claim", 4, 0)
		first, err := orderedProgressionCall(ctx, action, "application", request)
		if err != nil {
			t.Fatal(err)
		}
		heartbeat := orderedApplicationRequest(o, w, e, r, steps[0], "heartbeat", 5, 1)
		heartbeat["lease_seconds"] = 120
		beat, err := orderedProgressionCall(ctx, action, "application", heartbeat)
		if err != nil || beat["effect_version"] != float64(2) || beat["run_version"] != float64(5) {
			t.Fatal("heartbeat", beat, err)
		}
		if _, err = owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`, r); err != nil {
			t.Fatal(err)
		}
		if _, err = orderedProgressionCall(ctx, action, "application", heartbeat); err == nil {
			t.Fatal("expired heartbeat replay accepted")
		}
		recovery := orderedApplicationRequest(o, w, e, r, steps[0], "claim", 5, 2)
		recovery["lease_token"] = "ordered-application-recovery"
		got, err := orderedProgressionCall(ctx, action, "application", recovery)
		if err != nil || got["reservation_id"] != first["reservation_id"] || got["effect_version"] != float64(3) || got["attempt"] != float64(2) || got["run_version"] != float64(6) {
			t.Fatal("stable recovery", got, err)
		}
		old := orderedApplicationRequest(o, w, e, r, steps[0], "complete", 6, 3)
		before := orderedApplicationSnapshot(t, ctx, owner, r)
		if _, err = orderedProgressionCall(ctx, action, "application", old); err == nil || orderedApplicationSnapshot(t, ctx, owner, r) != before {
			t.Fatal("stale owner completed recovered work", err)
		}
		assertOrderedApplicationCounts(t, ctx, owner, r, 1, 1, 0, 1)
	})
}

func TestSecurityAgentMultistepApplicationReceiptPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		r, steps := seedOrderedApplicationRun(t, ctx, owner, worker, api, o, w, e, testID, actor, 730, true)
		claim, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, r, steps[0], "claim", 4, 0), policy.GatewayPolicyKeys{})
		if err != nil {
			t.Fatal(err)
		}
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys, err := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
		if err != nil {
			t.Fatal(err)
		}
		store := orderedApplicationStoreRequest(t, o, w, e, r, steps[0], claim, key)
		stored, err := orderedApplicationCall(ctx, action, store, keys)
		if err != nil || stored["effect_version"] != float64(2) {
			t.Fatal("source store", stored, err)
		}
		complete := orderedApplicationRequest(o, w, e, r, steps[0], "complete", 5, 2)
		before := orderedApplicationSnapshot(t, ctx, owner, r)
		if _, err = orderedApplicationCall(ctx, action, complete, keys); err == nil || orderedApplicationSnapshot(t, ctx, owner, r) != before {
			t.Fatal("unacknowledged deployment produced receipt", err)
		}
		deployOrderedApplication(t, ctx, owner, key, stored)
		before = orderedApplicationSnapshot(t, ctx, owner, r)
		// Provisional application, control, receipt and audit must roll back together.
		if _, err = action.Exec(ctx, `BEGIN`); err != nil {
			t.Fatal(err)
		}
		defer action.Exec(ctx, `ROLLBACK`)
		if _, err = orderedApplicationCall(ctx, action, complete, keys); err != nil {
			t.Fatal("atomic completion", err)
		}
		if _, err = action.Exec(ctx, `ROLLBACK`); err != nil {
			t.Fatal(err)
		}
		if orderedApplicationSnapshot(t, ctx, owner, r) != before {
			t.Fatal("application receipt escaped rollback")
		}
		got, err := orderedApplicationCall(ctx, action, complete, keys)
		if err != nil || got["effect_state"] != "cleanup_pending" || got["run_version"] != float64(6) || got["effect_version"] != float64(3) {
			t.Fatal("application receipt", got, err)
		}
		assertOrderedApplicationCounts(t, ctx, owner, r, 1, 1, 1, 1)
		stable := orderedApplicationSnapshot(t, ctx, owner, r)
		restart, err := pgx.ConnectConfig(ctx, action.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer restart.Close(ctx)
		replayed, err := orderedApplicationCall(ctx, restart, complete, keys)
		if err != nil || replayed["deployment_id"] != got["deployment_id"] || orderedApplicationSnapshot(t, ctx, owner, r) != stable {
			t.Fatal("completion restart duplicated receipt", replayed, err)
		}
		progress := orderedProgressionRequest(o, w, e, r, steps[1], "progress", "ordered-progress-worker", 6)
		ready, err := orderedProgressionCall(ctx, worker, "transition", progress)
		if err != nil || ready["outcome"] != "ready" {
			t.Fatal("produced receipt did not advance successor", ready, err)
		}
		if _, err = orderedProgressionCall(ctx, worker, "transition", progress); err != nil {
			t.Fatal("progression replay", err)
		}
		assertOrderedApplicationCounts(t, ctx, owner, r, 1, 1, 1, 2)
		if _, err = orderedApplicationCall(ctx, action, complete, keys); err == nil {
			t.Fatal("completion replay ignored changed parent post-state")
		}
	})
}

const orderedApplicationDevice = "pid_8f000001-0000-4000-8000-000000000001"

func seedOrderedApplicationGateway(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e string) {
	t.Helper()
	seedOrderedApplicationGatewayAt(t, ctx, owner, o, w, e, orderedApplicationDevice)
}

func seedOrderedApplicationGatewayAt(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, device string) {
	t.Helper()
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_gateway_devices(organization_id,workspace_id,environment_id,id,name,state) VALUES($1,$2,$3,$4,'Ordered application gateway','active');
 INSERT INTO zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,id,device_id,audience,salt,token_hash,expires_at) VALUES($1,$2,$3,$4,$4,'runtime-gateway-enroll',decode(repeat('01',16),'hex'),digest(convert_to($1||$4,'UTF8'),'sha256'),clock_timestamp()+interval '1 hour');
 INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at) VALUES($1,$2,$3,$4,$4,$4,decode(repeat('03',32),'hex'),'runtime-gateway','ref:gateway/public/gateway-device-key-01',decode(repeat('04',32),'hex'),clock_timestamp()+interval '1 hour',1,1,'gateway-device-key-01','Ed25519',clock_timestamp())`, pgx.QueryExecModeSimpleProtocol, o, w, e, device); err != nil {
		t.Fatal(err)
	}
}

func seedOrderedApplicationRun(t *testing.T, ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string, index int, approve bool) (string, []string) {
	t.Helper()
	request := seedOrderedAdmission(t, ctx, owner, o, w, e, testID, actor, index)
	r := request["run_id"].(string)
	admitted, err := orderedProgressionCall(ctx, worker, "admit", request)
	if err != nil {
		t.Fatal(err)
	}
	steps := []string{admitted["step_ids"].([]any)[0].(string), admitted["step_ids"].([]any)[1].(string)}
	if approve {
		if _, err = orderedProgressionCall(ctx, api, "transition", orderedProgressionRequest(o, w, e, r, steps[0], "approve", orderedProgressionApprover, 3)); err != nil {
			t.Fatal(err)
		}
	}
	return r, steps
}

func orderedApplicationRequest(o, w, e, r, s, operation string, runVersion, effectVersion int) map[string]any {
	return map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": r, "step_id": s, "operation": operation, "worker_id": "ordered-action-worker", "lease_token": "ordered-application-lease", "run_version": runVersion, "effect_version": effectVersion, "lease_seconds": 60, "envelope": map[string]any{}}
}

func assertOrderedApplicationCounts(t *testing.T, ctx context.Context, owner *pgx.Conn, r string, effects, reservations, receipts, approvals int) {
	t.Helper()
	var a, b, c, d int
	if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_effects WHERE run_id=$1),(SELECT count(*) FROM zasp_security_agent_step_reservations WHERE run_id=$1),(SELECT count(*) FROM zasp_sa_multistep_receipts WHERE run_id=$1),(SELECT count(*) FROM zasp_security_agent_approvals WHERE run_id=$1)`, r).Scan(&a, &b, &c, &d); err != nil || a != effects || b != reservations || c != receipts || d != approvals {
		t.Fatal("application authority counts", a, b, c, d, err)
	}
}

func orderedApplicationStoreRequest(t *testing.T, o, w, e, r, s string, claim map[string]any, key ed25519.PrivateKey) map[string]any {
	t.Helper()
	device := claim["targets"].([]any)[0].(map[string]any)
	target := TemporaryPolicyTarget{DeviceID: device["device_id"].(string), CredentialID: device["credential_id"].(string), Sequence: int64(device["sequence"].(float64)), PolicyVersion: int64(device["policy_version"].(float64))}
	compiled := make([]policy.CompiledPolicy, 0, 2)
	for _, definition := range []policy.Policy{{ID: "temporary-containment-http-v1", Trigger: "http_request", Conditions: []policy.Condition{{Field: "http.method", Operator: "present"}}, Action: policy.ActionBlock}, {ID: "temporary-containment-mcp-v1", Trigger: "tool_call", Conditions: []policy.Condition{{Field: "tool.name", Operator: "present"}}, Action: policy.ActionBlock}} {
		value, err := policy.Compile(definition)
		if err != nil {
			t.Fatal(err)
		}
		compiled = append(compiled, value)
	}
	now := time.Now().UTC().Truncate(time.Second)
	value := postgresTemporaryPolicyEnvelope(t, TemporaryPolicyEffectClaim{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, Phase: "apply"}, target, "ordered-key-01", key, now, now.Add(time.Duration(claim["ttl_seconds"].(float64))*time.Second), compiled)
	request := orderedApplicationRequest(o, w, e, r, s, "store", 5, 1)
	request["envelope"] = map[string]any{"device_id": target.DeviceID, "credential_id": target.CredentialID, "sequence": target.Sequence, "policy_version": target.PolicyVersion, "key_id": value.KeyID, "issued_at": value.IssuedAt.Format(time.RFC3339Nano), "expires_at": value.ExpiresAt.Format(time.RFC3339Nano), "failure_mode": value.FailureMode, "payload_digest": value.PayloadDigest, "policies": value.Policies, "signature": base64.StdEncoding.EncodeToString(value.Signature), "envelope_digest": value.EnvelopeDigest}
	return request
}

func deployOrderedApplication(t *testing.T, ctx context.Context, owner *pgx.Conn, key ed25519.PrivateKey, stored map[string]any, shortLifetime ...bool) {
	t.Helper()
	connection := orderedApplicationDeploymentConnection(t, ctx, owner)
	defer connection.Close(ctx)
	database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if repository, err := NewPolicyDeploymentRepository(database); !errors.Is(err, ErrRepositoryConfiguration) || repository != nil {
		t.Fatal("historical deployment constructor accepted release61", err)
	}
	keys, err := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	request := orderedApplicationDeploymentRequest(stored["organization_id"].(string), stored["workspace_id"].(string), stored["environment_id"].(string), stored["run_id"].(string), stored["step_id"].(string), stored)
	// Reconstruct the private repository and connection after each commit.
	call := func(input map[string]any) map[string]any {
		restart, connectErr := pgx.ConnectConfig(ctx, connection.Config().Copy())
		if connectErr != nil {
			t.Fatal(connectErr)
		}
		defer restart.Close(ctx)
		db, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: restart})
		repository := &securityAgentMultistepAdmissionRepository{database: db}
		raw, _ := json.Marshal(input)
		result, callErr := repository.deployment(ctx, raw, keys)
		if callErr != nil {
			t.Fatal("private deployment "+input["operation"].(string), callErr)
		}
		var got map[string]any
		if decodeErr := json.Unmarshal(result, &got); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		return got
	}
	claimed := call(request)
	if replay := call(request); replay["work_id"] != claimed["work_id"] {
		t.Fatal("claim restart changed identity")
	}
	rawClaim, _ := json.Marshal(claimed["result"])
	var claim orderedDeploymentClaim
	if err = json.Unmarshal(rawClaim, &claim); err != nil {
		t.Fatal(err)
	}
	var composition orderedDeploymentComposition
	if err = json.Unmarshal(claim.Composition, &composition); err != nil {
		t.Fatal(err)
	}
	if len(composition.TemporarySources) != 1 || len(composition.TemporarySources[0].Policies) != 2 {
		t.Fatal("scoped deployment omitted containment", claim)
	}
	compiled := composition.Policies
	now := time.Now().UTC().Truncate(time.Second)
	expires, err := time.Parse(time.RFC3339Nano, composition.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if len(shortLifetime) > 0 && shortLifetime[0] {
		expires = now.Add(time.Minute)
	}
	envelope, err := policy.SignGatewayPolicyEnvelope(policy.GatewayPolicySigningInput{KeyID: "ordered-key-01", Binding: policy.GatewayPolicyBinding{OrganizationID: claim.OrganizationID, WorkspaceID: claim.WorkspaceID, EnvironmentID: claim.EnvironmentID, DeviceID: claim.DeviceID}, Sequence: uint64(claim.Sequence), PolicyVersion: uint64(claim.PolicyVersion), Now: now, IssuedAt: now, ExpiresAt: expires, FailureMode: "closed", Policies: compiled}, key)
	if err != nil {
		t.Fatal(err)
	}
	request["operation"] = "store"
	request["sequence"] = claim.Sequence
	request["input_digest"] = claim.InputDigest
	request["composition"] = claim.Composition
	request["envelope"] = envelope
	request["digest"] = orderedEnvelopeDigest(envelope)
	call(request)
	call(request)
	digest := request["digest"]
	request["operation"] = "read"
	request["envelope"] = map[string]any{}
	request["digest"] = ""
	read := call(request)
	rawRead, _ := json.Marshal(read["result"])
	var readback policy.GatewayPolicyEnvelope
	if err = json.Unmarshal(rawRead, &readback); err != nil {
		t.Fatal(err)
	}
	if _, err = policy.VerifyGatewayPolicyEnvelope(readback, keys, policy.GatewayPolicyBinding{OrganizationID: claim.OrganizationID, WorkspaceID: claim.WorkspaceID, EnvironmentID: claim.EnvironmentID, DeviceID: claim.DeviceID}, now); err != nil {
		t.Fatal(err)
	}
	request["operation"] = "finish"
	request["digest"] = digest
	call(request)
	call(request)
}

func orderedApplicationCall(ctx context.Context, connection *pgx.Conn, request map[string]any, keys policy.GatewayPolicyKeys) (map[string]any, error) {
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		return nil, err
	}
	repository := &securityAgentMultistepAdmissionRepository{database: database}
	raw, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	response, err := repository.application(ctx, raw, keys)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	err = json.Unmarshal(response, &result)
	return result, err
}
