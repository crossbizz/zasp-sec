package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

const recoveryOrg = "pid_6a000001-0000-4000-8000-000000000001"
const recoveryWS = "pid_6a000002-0000-4000-8000-000000000002"
const recoveryEnv = "pid_6a000003-0000-4000-8000-000000000003"
const recoveryDevice = "pid_6a000060-0000-4000-8000-000000000060"
const recoveryCredential = "pid_6a000062-0000-4000-8000-000000000062"
const recoverySession = "pid_6a000080-0000-4000-8000-000000000080"

func recoveryVerificationTime(now time.Time) time.Time { return now.UTC().Truncate(time.Second) }

func recoveryPolicyAgreement(action string, source json.RawMessage, published []policy.CompiledPolicy) bool {
	// Independent intended definitions, not the action worker's policy builder.
	definitions := []policy.Policy{
		{ID: "temporary-containment-http-v1", Trigger: "http_request", Action: policy.ActionBlock, Conditions: []policy.Condition{{Field: "http.method", Operator: "present"}}},
		{ID: "temporary-containment-mcp-v1", Trigger: "tool_call", Action: policy.ActionBlock, Conditions: []policy.Condition{{Field: "tool.name", Operator: "present"}}},
	}
	if action == "isolate_session" {
		definitions[0].ID, definitions[1].ID = "session-isolation-http-v1", "session-isolation-mcp-v1"
		for i := range definitions {
			definitions[i].Conditions = append(definitions[i].Conditions, policy.Condition{Field: "session_id", Operator: "equals", Value: recoverySession})
		}
	} else if action != "create_temporary_policy" {
		return false
	}
	want := make([]policy.CompiledPolicy, len(definitions))
	for i, definition := range definitions {
		var err error
		want[i], err = policy.Compile(definition)
		if err != nil {
			return false
		}
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		return false
	}
	publishedJSON, err := json.Marshal(published)
	if err != nil {
		return false
	}
	// Generic decoding preserves unexpected keys while normalizing object key
	// order. Arrays retain the canonical policy/condition order from compilation.
	var expected, stored, delivered any
	if json.Unmarshal(wantJSON, &expected) != nil || json.Unmarshal(source, &stored) != nil || json.Unmarshal(publishedJSON, &delivered) != nil {
		return false
	}
	return reflect.DeepEqual(expected, stored) && reflect.DeepEqual(expected, delivered)
}

func recoveryExpectedFinish(claim apiserver.TemporaryPolicyEffectClaim, sourceDigest string) (string, string, error) {
	// One-target form of SQL0024's raw input || ordered source-envelope digest.
	decode := func(value string) ([]byte, error) {
		if !strings.HasPrefix(value, "sha256:") {
			return nil, errors.New("noncanonical fixture digest")
		}
		raw, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
		if err != nil || len(raw) != 32 {
			return nil, errors.New("invalid fixture digest")
		}
		return raw, nil
	}
	input, err := decode(claim.InputDigest)
	if err != nil {
		return "", "", err
	}
	source, err := decode(sourceDigest)
	if err != nil {
		return "", "", err
	}
	result := sha256.Sum256(append(input, source...))
	identity := sha256.Sum256([]byte(strings.Join([]string{claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, "security_agent_effect", claim.RunID, claim.StepID, claim.Phase}, "\x1f")))
	value := hex.EncodeToString(identity[:])
	outcome := "pid_" + value[:8] + "-" + value[8:12] + "-4" + value[13:16] + "-8" + value[17:20] + "-" + value[20:32]
	return hex.EncodeToString(result[:]), outcome, nil
}

func TestSecurityAgentActionRecoveryExactPolicies(t *testing.T) {
	for _, action := range []string{"create_temporary_policy", "isolate_session"} {
		t.Run(action, func(t *testing.T) {
			session := ""
			if action == "isolate_session" {
				session = recoverySession
			}
			actual, err := temporaryContainmentPolicies(action, session, "apply")
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(actual)
			if err != nil {
				t.Fatal(err)
			}
			if !recoveryPolicyAgreement(action, raw, actual) {
				t.Fatal("intended policy fixture rejected")
			}
			// The old POST/shell spot checks still pass when present becomes
			// equals POST. Compile a valid changed policy, not corrupt bytes.
			changed := append([]policy.CompiledPolicy(nil), actual...)
			conditions := append([]policy.Condition(nil), changed[0].Conditions...)
			conditions[0].Operator, conditions[0].Value = "equals", "POST"
			changed[0], err = policy.Compile(policy.Policy{ID: changed[0].ID, Trigger: changed[0].Trigger, Conditions: conditions, Action: changed[0].Action})
			if err != nil {
				t.Fatal(err)
			}
			changedRaw, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			for _, candidate := range []struct {
				name      string
				source    json.RawMessage
				published []policy.CompiledPolicy
			}{
				{"source_only", changedRaw, actual}, {"published_only", raw, changed}, {"both_changed", changedRaw, changed},
				{"extra_field", json.RawMessage(strings.Replace(string(raw), `"id":`, `"unexpected":true,"id":`, 1)), actual},
			} {
				if recoveryPolicyAgreement(action, candidate.source, candidate.published) {
					t.Errorf("accepted %s policy drift", candidate.name)
				}
			}
		})
	}
}

func TestSecurityAgentActionRecoveryFinishVector(t *testing.T) {
	claim := apiserver.TemporaryPolicyEffectClaim{OrganizationID: recoveryOrg, WorkspaceID: recoveryWS, EnvironmentID: recoveryEnv, RunID: "pid_6a000040-0000-4000-8000-000000000040", StepID: "pid_6a000041-0000-4000-8000-000000000041", Phase: "apply", InputDigest: "sha256:" + strings.Repeat("aa", 32)}
	source := "sha256:" + strings.Repeat("bb", 32)
	digest, outcome, err := recoveryExpectedFinish(claim, source)
	// Literal vectors calculated independently of the worker/SQL helpers.
	if err != nil || digest != "e2d80f78d79027556d6619a1400605abbdca6bb6eb24e0831e33ecd5466fa5f6" || outcome != "pid_2b3701c0-5969-41c5-8a16-974b05adceac" {
		t.Fatalf("finish vector digest=%s outcome=%s err=%v", digest, outcome, err)
	}
	changed, _, err := recoveryExpectedFinish(claim, "sha256:"+strings.Repeat("bc", 32))
	if err != nil || changed == digest {
		t.Fatal("source digest not bound")
	}
	claim.InputDigest = "sha256:" + strings.Repeat("ac", 32)
	changed, _, err = recoveryExpectedFinish(claim, source)
	if err != nil || changed == digest {
		t.Fatal("input digest not bound")
	}
	claim.Phase = "cleanup"
	_, changedOutcome, err := recoveryExpectedFinish(claim, source)
	if err != nil || changedOutcome == outcome {
		t.Fatal("phase not bound to outcome")
	}
	if _, _, err := recoveryExpectedFinish(claim, "bad digest"); err == nil {
		t.Fatal("malformed source digest accepted")
	}
}

// The proof's wall clock has subsecond precision; production signature
// verification deliberately accepts only canonical whole-second UTC times.
func TestSecurityAgentActionRecoveryVerificationClock(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	claim := apiserver.TemporaryPolicyEffectClaim{OrganizationID: recoveryOrg, WorkspaceID: recoveryWS, EnvironmentID: recoveryEnv, Phase: "apply"}
	target := apiserver.TemporaryPolicyTarget{DeviceID: recoveryDevice, CredentialID: recoveryCredential, Sequence: 2, PolicyVersion: 2}
	compiled, err := temporaryContainmentPolicies("create_temporary_policy", "", "apply")
	if err != nil {
		t.Fatal(err)
	}
	binding := policy.GatewayPolicyBinding{OrganizationID: recoveryOrg, WorkspaceID: recoveryWS, EnvironmentID: recoveryEnv, DeviceID: recoveryDevice}
	envelope, err := policy.SignGatewayPolicyEnvelope(policy.GatewayPolicySigningInput{KeyID: "gateway-key-01", Binding: binding, Sequence: 2, PolicyVersion: 2, Now: now, IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute), FailureMode: "closed", Policies: compiled}, private)
	if err != nil {
		t.Fatal(err)
	}
	source, err := temporaryPolicyRepositoryEnvelope(target, "apply", envelope)
	if err != nil {
		t.Fatal(err)
	}
	processor := &securityAgentActionProcessor{config: securityAgentActionProcessorConfig{PrivateKey: private, KeyID: "gateway-key-01"}}
	keys, err := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-01": public})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.verifyReadback(claim, source, now); err != nil {
		t.Fatalf("canonical source fixture rejected: %v", err)
	}
	fractional := now.Add(123456789 * time.Nanosecond)
	if err := processor.verifyReadback(claim, source, fractional); err == nil {
		t.Fatal("production source verifier accepted a noncanonical clock")
	}
	if _, err := policy.VerifyGatewayPolicyEnvelope(envelope, keys, binding, fractional); err == nil {
		t.Fatal("production gateway verifier accepted a noncanonical clock")
	}
	proofClock := recoveryVerificationTime(fractional)
	if err := processor.verifyReadback(claim, source, proofClock); err != nil {
		t.Errorf("proof source verification: %v", err)
	}
	if _, err := policy.VerifyGatewayPolicyEnvelope(envelope, keys, binding, proofClock); err != nil {
		t.Errorf("proof gateway verification: %v", err)
	}
}

// Only observes real repository calls. Successful store invokes the actual
// deployment processor synchronously, isolating reclaim from a second race.
type recoveryActionAuthority struct {
	*apiserver.SecurityAgentActionRepository
	onClaim                       func(apiserver.TemporaryPolicyEffectClaim, string)
	deploy                        workerProcessor
	stores, finishes, emptyClaims int
	storeErrors                   []error
	claims                        []apiserver.TemporaryPolicyEffectClaim
	tokens                        []string
}

func (a *recoveryActionAuthority) ClaimTemporaryPolicyEffects(ctx context.Context, worker, token string, seconds, limit int) ([]apiserver.TemporaryPolicyEffectClaim, error) {
	claims, err := a.SecurityAgentActionRepository.ClaimTemporaryPolicyEffects(ctx, worker, token, seconds, limit)
	if err == nil && len(claims) == 0 {
		a.emptyClaims++
	}
	for _, claim := range claims {
		a.claims = append(a.claims, claim)
		a.tokens = append(a.tokens, token)
		a.onClaim(claim, token)
	}
	return claims, err
}

func (a *recoveryActionAuthority) StoreTemporaryPolicyTarget(ctx context.Context, claim apiserver.TemporaryPolicyEffectClaim, worker, token string, envelope apiserver.TemporaryPolicyTargetEnvelope) error {
	a.stores++
	err := a.SecurityAgentActionRepository.StoreTemporaryPolicyTarget(ctx, claim, worker, token, envelope)
	if err != nil {
		a.storeErrors = append(a.storeErrors, err)
		return err
	}
	return a.deploy.RunOnce(ctx)
}

func (a *recoveryActionAuthority) FinishTemporaryPolicyEffect(ctx context.Context, claim apiserver.TemporaryPolicyEffectClaim, worker, token, digest, audit, correlation string) (apiserver.TemporaryPolicyFinishResult, error) {
	a.finishes++
	return a.SecurityAgentActionRepository.FinishTemporaryPolicyEffect(ctx, claim, worker, token, digest, audit, correlation)
}

func TestSecurityAgentActionNaturalRecoveryOwnedPostgres(t *testing.T) {
	dsn := os.Getenv("ZASP_ACTION_RECOVERY_DSN")
	if dsn == "" {
		t.Skip("requires parent-owned current55 recovery fixture")
	}
	actionKey, lockKind := os.Getenv("ZASP_ACTION_RECOVERY_ACTION"), os.Getenv("ZASP_ACTION_RECOVERY_LOCK")
	if actionKey != "create_temporary_policy" && actionKey != "isolate_session" || lockKind != "work" && lockKind != "fairness" {
		t.Fatal("invalid recovery scenario")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid recovery DSN")
	}
	local := func(host string) bool { ip := net.ParseIP(host); return ip != nil && ip.IsLoopback() }
	if !local(cfg.Host) || cfg.User != "zasp_e2e" || cfg.Database != "postgres" {
		t.Fatal("requires owned loopback fixture")
	}
	for _, fallback := range cfg.Fallbacks {
		if !local(fallback.Host) {
			t.Fatal("nonlocal fallback refused")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
	defer cancel()
	owner, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	execSQL := func(sql string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	var releaseOK bool
	if err := owner.QueryRow(ctx, `SELECT max(version)=55 AND zasp_production_security_agent_existing_tests_readiness($1,$2) FROM zasp_schema_versions`, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&releaseOK); err != nil || !releaseOK {
		t.Fatalf("registered current55 readiness=%t err=%v", releaseOK, err)
	}
	execSQL(`CREATE ROLE recovery_action_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE recovery_deployment_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE recovery_coordinator_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE recovery_archive_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE recovery_index_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE recovery_correlation_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE recovery_projection_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE recovery_gateway_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`)
	for _, sql := range []string{`SELECT zasp_security_agent_register_action_principal(session_user,'recovery_action_login')`, `SELECT zasp_policy_deployment_register_principal(session_user,'recovery_deployment_login')`, `SELECT zasp_runtime_register_principals(session_user,'recovery_coordinator_login','recovery_archive_login','recovery_index_login','recovery_correlation_login','recovery_projection_login','recovery_gateway_login')`} {
		var ready bool
		if err := owner.QueryRow(ctx, sql).Scan(&ready); err != nil || !ready {
			t.Fatalf("register=%t err=%v", ready, err)
		}
	}
	trace := &combinedE2EPostgresTrace{}
	databaseFor := func(user string, traced bool) apiserver.JSONDatabase {
		t.Helper()
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		u.User = url.User(user)
		pool, err := pgxpool.New(ctx, u.String())
		if err != nil {
			t.Fatal(err)
		}
		var driver apiserver.PostgresDriver = &workerPostgresDriver{pool: pool}
		if traced {
			driver = &combinedE2EPostgresDriver{delegate: driver, trace: trace}
		}
		db, err := apiserver.NewPostgresJSONDatabase(driver)
		if err != nil {
			pool.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	planner, err := apiserver.NewSecurityAgentWorkerRepository(databaseFor("security_agent_v33_worker_login", false))
	if err != nil {
		t.Fatal(err)
	}
	action, err := apiserver.NewSecurityAgentActionRepository(databaseFor("recovery_action_login", true))
	if err != nil {
		t.Fatal(err)
	}
	deployment, err := apiserver.NewPolicyDeploymentRepository(databaseFor("recovery_deployment_login", false))
	if err != nil {
		t.Fatal(err)
	}
	gateway := databaseFor("recovery_gateway_login", false)
	readyJSON, err := gateway.QueryJSON(ctx, `SELECT to_jsonb(zasp_runtime_principal_ready('zasp_gateway_control'))`)
	if err != nil || string(readyJSON) != "true" {
		t.Fatalf("gateway principal preflight ready=%s err=%v", readyJSON, err)
	}
	execSQL(`UPDATE zasp_risk_attack_paths SET state='verified',version=version+1 WHERE organization_id=$1`, recoveryOrg)
	execSQL(`INSERT INTO zasp_gateway_devices(organization_id,workspace_id,environment_id,id,name,state) VALUES($1,$2,$3,$4,'Recovery fixture gateway','active')`, recoveryOrg, recoveryWS, recoveryEnv, recoveryDevice)
	execSQL(`INSERT INTO zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,id,device_id,audience,salt,token_hash,expires_at) VALUES($1,$2,$3,'pid_6a000061-0000-4000-8000-000000000061',$4,'runtime-gateway-enroll',decode(repeat('01',16),'hex'),decode(repeat('02',32),'hex'),clock_timestamp()+interval '1 hour')`, recoveryOrg, recoveryWS, recoveryEnv, recoveryDevice)
	execSQL(`INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at) VALUES($1,$2,$3,$4,$5,'pid_6a000061-0000-4000-8000-000000000061',decode(repeat('03',32),'hex'),'runtime-gateway','ref:gateway/public/gateway-device-key-01',decode(repeat('04',32),'hex'),clock_timestamp()+interval '1 hour',1,1,'gateway-device-key-01','Ed25519',clock_timestamp())`, recoveryOrg, recoveryWS, recoveryEnv, recoveryCredential, recoveryDevice)
	if actionKey == "isolate_session" {
		// Same real runtime-evidence fixture as budget apply tests. Never relabel
		// an existing effect; the planner must create the isolation plan itself.
		execSQL(`UPDATE zasp_security_agent_definitions SET body=body || '{"trigger_kind":"runtime_decision","trigger_source":"gateway","allowed_actions":["isolate_session"],"verification_kind":"gateway_decision"}'::jsonb WHERE organization_id=$1`, recoveryOrg)
		execSQL(`UPDATE zasp_security_agent_kill_switches SET action_key='isolate_session' WHERE organization_id=$1 AND action_key='create_temporary_policy'`, recoveryOrg)
		for i := 1; i <= 3; i++ {
			execSQL(`INSERT INTO zasp_runtime_gateway_events(organization_id,workspace_id,environment_id,device_id,credential_id,event_id,sequence,request_digest,policy_version,decision,action_kind,classification,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7,digest(convert_to($6,'UTF8'),'sha256'),1,'block','http',jsonb_build_object('category','security','route_class','runtime','resource_class','session','outcome','gateway','session_id',$8::text),clock_timestamp())`, recoveryOrg, recoveryWS, recoveryEnv, recoveryDevice, recoveryCredential, fmt.Sprintf("pid_6a00008%d-0000-4000-8000-00000000008%d", i, i), i, recoverySession)
		}
	}
	const plannerID, plannerToken = "recovery-planner", "recovery-planner-lease"
	if count, err := planner.ScheduleSecurityAgentTriggers(ctx, plannerID, 1); err != nil || count != 1 {
		t.Fatalf("schedule=%d err=%v", count, err)
	}
	claimRun := func() apiserver.SecurityAgentRunClaim {
		t.Helper()
		claims, err := planner.ClaimSecurityAgentRuns(ctx, plannerID, plannerToken, 60, 1)
		if err != nil || len(claims) != 1 {
			t.Fatalf("planner claims=%d err=%v", len(claims), err)
		}
		return claims[0]
	}
	current := claimRun()
	if result, err := planner.PrepareSecurityAgentRun(ctx, current, plannerID, plannerToken, "pid_6a000030-0000-4000-8000-000000000030", time.Now().UTC().Add(10*time.Minute), "pid_6a000031-0000-4000-8000-000000000031", "pid_6a000032-0000-4000-8000-000000000032"); err != nil || result.State != "waiting_approval" {
		t.Fatalf("prepare=%+v err=%v", result, err)
	}
	// Controlled approval fixture, not fresh-auth API acceptance.
	execSQL(`UPDATE zasp_security_agent_approvals SET state='approved',approver_id='pid_6a000033-0000-4000-8000-000000000033',fresh_auth_at=clock_timestamp(),decided_at=clock_timestamp(),version=version+1 WHERE organization_id=$1`, recoveryOrg)
	execSQL(`UPDATE zasp_security_agent_steps SET state='authorized',version=version+1 WHERE organization_id=$1`, recoveryOrg)
	execSQL(`UPDATE zasp_security_agent_runs SET state='queued',version=version+1 WHERE organization_id=$1`, recoveryOrg)
	current = claimRun()
	if result, err := planner.ExecuteSecurityAgentRun(ctx, current, plannerID, plannerToken, "pid_6a000034-0000-4000-8000-000000000034", "pid_6a000035-0000-4000-8000-000000000035"); err != nil || result.State != "running" {
		t.Fatalf("dispatch=%+v err=%v", result, err)
	}
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	deployer, err := newPolicyDeploymentProcessor(policyDeploymentProcessorConfig{Authority: deployment, WorkerID: "recovery-deployment", LeaseSeconds: 30, BatchSize: 1, HeartbeatInterval: 10 * time.Second, KeyID: "gateway-key-01", PrivateKey: key, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: newWorkerLeaseToken})
	if err != nil {
		t.Fatal(err)
	}
	defer deployer.Close()
	// Drain the registration generation first. Later exactly one new source
	// generation and one additional signed publication are permitted.
	if err := deployer.RunOnce(ctx); err != nil {
		t.Fatal("baseline deployment", err)
	}
	// Exercise the same authenticated read used by the final oracle before any
	// 30-second lease wait, so principal/credential setup errors fail promptly.
	baselineRaw, err := gateway.QueryJSON(ctx, `SELECT zasp_runtime_gateway_policy_bundle($1,$2)`, recoveryCredential, int64(0))
	if err != nil {
		t.Fatal("gateway bundle preflight", err)
	}
	var baseline policy.GatewayPolicyEnvelope
	if err := json.Unmarshal(baselineRaw, &baseline); err != nil || baseline.Sequence != 1 {
		t.Fatalf("gateway bundle preflight sequence=%d err=%v", baseline.Sequence, err)
	}
	var initialGeneration int64
	var initialBundles int
	if err := owner.QueryRow(ctx, `SELECT desired_generation,(SELECT count(*) FROM zasp_runtime_gateway_policy_bundles WHERE organization_id=$1) FROM zasp_policy_deployment_work WHERE organization_id=$1 AND device_id=$2 AND applied_generation=desired_generation`, recoveryOrg, recoveryDevice).Scan(&initialGeneration, &initialBundles); err != nil || initialBundles != 1 {
		t.Fatalf("baseline generation=%d bundles=%d err=%v", initialGeneration, initialBundles, err)
	}
	snapshot := func() string {
		t.Helper()
		var value string
		if err := owner.QueryRow(ctx, recoverySnapshotSQL, recoveryOrg).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	identity := func() string {
		t.Helper()
		var value string
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('effect',(SELECT jsonb_agg(jsonb_build_array(organization_id,workspace_id,environment_id,run_id,step_id,action_key,encode(input_digest,'hex'))) FROM zasp_security_agent_effects WHERE organization_id=$1),'reservations',(SELECT jsonb_agg(to_jsonb(s)) FROM zasp_security_agent_step_reservations s WHERE organization_id=$1))::text`, recoveryOrg).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	initialIdentity := identity()
	blocker, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close(context.Background())
	held, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Rollback(context.Background())
	lockSQL := `SELECT 1 FROM zasp_policy_deployment_work WHERE organization_id=$1 AND device_id=$2 FOR UPDATE`
	lockArgs := []any{recoveryOrg, recoveryDevice}
	if lockKind == "fairness" {
		lockSQL = `SELECT 1 FROM zasp_policy_deployment_fairness WHERE organization_id=$1 FOR UPDATE`
		lockArgs = []any{recoveryOrg}
	}
	var locked int
	if err := held.QueryRow(ctx, lockSQL, lockArgs...).Scan(&locked); err != nil || locked != 1 {
		t.Fatalf("exact row lock=%d err=%v", locked, err)
	}
	var claimedSnapshot string
	var firstAttempt int64
	var firstExpiry time.Time
	instrument := &recoveryActionAuthority{SecurityAgentActionRepository: action, deploy: deployer}
	instrument.onClaim = func(claim apiserver.TemporaryPolicyEffectClaim, token string) {
		if len(claim.Targets) != 1 || claim.ActionKey != actionKey || claim.Phase != "apply" || claim.RunID != current.RunID {
			t.Fatalf("wrong recovery claim: %+v", claim)
		}
		if actionKey == "isolate_session" && claim.SessionID != recoverySession {
			t.Fatal("isolation session not bound")
		}
		var attempt int64
		var expires, timeNow time.Time
		var durableToken string
		if err := owner.QueryRow(ctx, `SELECT attempt,lease_expires_at,lease_token,clock_timestamp() FROM zasp_security_agent_effects WHERE organization_id=$1 AND run_id=$2 AND step_id=$3`, recoveryOrg, claim.RunID, claim.StepID).Scan(&attempt, &expires, &durableToken, &timeNow); err != nil {
			t.Fatal(err)
		}
		if durableToken != token {
			t.Fatal("claim token differs from durable lease")
		}
		if len(instrument.claims) == 1 {
			firstAttempt, firstExpiry = attempt, expires
			claimedSnapshot = snapshot()
			return
		}
		if len(instrument.claims) != 2 || attempt != firstAttempt+1 || token == instrument.tokens[0] || timeNow.Before(firstExpiry) || !expires.After(firstExpiry) {
			t.Fatalf("reclaim wasn't natural: claims=%d attempt=%d first=%d first_expiry=%s now=%s", len(instrument.claims), attempt, firstAttempt, firstExpiry, timeNow)
		}
	}
	processor, err := newSecurityAgentActionProcessor(securityAgentActionProcessorConfig{Authority: instrument, WorkerID: "recovery-action", LeaseSeconds: 30, BatchSize: 1, HeartbeatInterval: 10 * time.Second, KeyID: "gateway-key-01", PrivateKey: key, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: newWorkerLeaseToken, NewProductID: sequentialActionProductIDs()})
	if err != nil {
		t.Fatal(err)
	}
	defer processor.Close()
	firstCtx, firstCancel := context.WithTimeout(ctx, 5*time.Second)
	firstErr := processor.RunOnce(firstCtx)
	firstCancel()
	if firstErr != errWorkerExecution || len(instrument.claims) != 1 || instrument.stores != 1 || instrument.finishes != 0 || len(instrument.storeErrors) != 1 || !errors.Is(instrument.storeErrors[0], apiserver.ErrRepositoryConflict) || !strings.Contains(trace.String(), ":40001:policy deployment authority busy") || !strings.Contains(trace.String(), ":P0002:session policy target missing") {
		t.Fatalf("refused attempt err=%v stores=%d finishes=%d errors=%v trace=%s", firstErr, instrument.stores, instrument.finishes, instrument.storeErrors, trace.String())
	}
	if after := snapshot(); claimedSnapshot == "" || after != claimedSnapshot {
		t.Fatalf("refused attempt changed durable state\nbefore=%s\nafter=%s", claimedSnapshot, after)
	}
	// Release only after both the real SQL error and unchanged state are proven.
	if err := held.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("observed real busy refusal action=%s lock=%s; unchanged snapshot; awaiting natural lease expiry %s", actionKey, lockKind, firstExpiry.Format(time.RFC3339Nano))
	for {
		if err := processor.RunOnce(ctx); err != nil {
			t.Fatalf("unexpected recovery poll error=%v trace=%s", err, trace.String())
		}
		var complete bool
		if err := owner.QueryRow(ctx, recoveryCompleteSQL, recoveryOrg, current.RunID, initialGeneration+1, initialBundles+1).Scan(&complete); err != nil {
			t.Fatal(err)
		}
		if complete {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("no durable completion: %v; snapshot=%s", ctx.Err(), snapshot())
		case <-time.After(100 * time.Millisecond):
		}
	}
	if len(instrument.claims) != 2 || instrument.emptyClaims < 1 || instrument.stores != 2 || instrument.finishes != 1 || len(instrument.storeErrors) != 1 || identity() != initialIdentity {
		t.Fatalf("recovery identities/counts changed: claims=%d empty=%d stores=%d finishes=%d errors=%v", len(instrument.claims), instrument.emptyClaims, instrument.stores, instrument.finishes, instrument.storeErrors)
	}
	claim := instrument.claims[1]
	source, err := action.ReadTemporaryPolicyTarget(ctx, claim, claim.Targets[0])
	verificationErr := processor.verifyReadback(claim, source, recoveryVerificationTime(time.Now()))
	if err != nil || source.State != "verified" || verificationErr != nil {
		t.Fatalf("source verification=%s read_err=%v verification_err=%v", source.State, err, verificationErr)
	}
	raw, err := gateway.QueryJSON(ctx, `SELECT zasp_runtime_gateway_policy_bundle($1,$2)`, recoveryCredential, int64(0))
	if err != nil {
		t.Fatal(err)
	}
	var envelope policy.GatewayPolicyEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	keys, err := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-01": key.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := policy.VerifyGatewayPolicyEnvelope(envelope, keys, policy.GatewayPolicyBinding{OrganizationID: recoveryOrg, WorkspaceID: recoveryWS, EnvironmentID: recoveryEnv, DeviceID: recoveryDevice}, recoveryVerificationTime(time.Now()))
	if err != nil || envelope.Sequence != 2 || envelope.PolicyVersion != 2 || envelope.FailureMode != "closed" || len(verified.Policies) != 2 {
		t.Fatalf("gateway signed envelope seq=%d policies=%d err=%v", envelope.Sequence, len(verified.Policies), err)
	}
	if !recoveryPolicyAgreement(actionKey, source.Policies, verified.Policies) || !envelope.ExpiresAt.Equal(source.ExpiresAt) {
		t.Fatal("intended, stored and published canonical policies/expiry disagree")
	}
	expectedDigest, expectedOutcome, err := recoveryExpectedFinish(claim, source.EnvelopeDigest)
	if err != nil {
		t.Fatal(err)
	}
	expectedBody, err := json.Marshal(map[string]string{"run_id": claim.RunID, "step_id": claim.StepID, "action": actionKey, "phase": "apply", "outcome_id": expectedOutcome, "result_digest": "sha256:" + expectedDigest})
	if err != nil {
		t.Fatal(err)
	}
	var finishBound bool
	if err := owner.QueryRow(ctx, `SELECT EXISTS(
 SELECT 1 FROM zasp_security_agent_effects e JOIN zasp_security_agent_audit a
 ON (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.step_id)=(e.organization_id,e.workspace_id,e.environment_id,e.run_id,e.step_id)
 WHERE (e.organization_id,e.workspace_id,e.environment_id,e.run_id,e.step_id,e.action_key,e.state)=($1,$2,$3,$4,$5,$6,'cleanup_pending')
 AND e.result_digest=decode($7,'hex') AND e.outcome_id=$8
 AND a.event_kind='effect_verified' AND a.event_digest=decode($7,'hex') AND a.body=$9::jsonb
 AND a.actor_id='recovery-action' AND a.audit_id='pid_78000008-0000-4000-8000-000000000008'
 AND a.correlation_id='pid_78000009-0000-4000-8000-000000000009')`, claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, claim.StepID, actionKey, expectedDigest, expectedOutcome, string(expectedBody)).Scan(&finishBound); err != nil || !finishBound {
		t.Fatalf("exact effect/outcome/audit binding=%t err=%v", finishBound, err)
	}
	for _, compiled := range verified.Policies {
		input := map[string]string{"session_id": recoverySession}
		expectedID := "temporary-containment-http-v1"
		if actionKey == "isolate_session" {
			expectedID = "session-isolation-http-v1"
		}
		if compiled.Trigger == "tool_call" {
			input["tool.name"] = "shell"
			expectedID = strings.Replace(expectedID, "http", "mcp", 1)
		} else if compiled.Trigger == "http_request" {
			input["http.method"] = "POST"
		} else {
			t.Fatal("unexpected policy trigger")
		}
		if compiled.ID != expectedID {
			t.Fatalf("policy id=%s want=%s", compiled.ID, expectedID)
		}
		result, err := policy.Evaluate(ctx, compiled, input)
		if err != nil || !result.Matched || result.Action != policy.ActionBlock {
			t.Fatalf("target wasn't blocked: %+v err=%v", result, err)
		}
		input["session_id"] = "pid_6a000090-0000-4000-8000-000000000090"
		other, err := policy.Evaluate(ctx, compiled, input)
		if err != nil || other.Matched != (actionKey == "create_temporary_policy") {
			t.Fatalf("unrelated session semantics: %+v err=%v", other, err)
		}
	}
	completedSnapshot := snapshot()
	if err := processor.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if err := deployer.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if snapshot() != completedSnapshot {
		t.Fatal("extra empty polls duplicated or changed durable result")
	}
	t.Logf("natural recovery durable proof: action=%s lock=%s claims=2 attempt=%d->%d token_changed=true empty_polls=%d generation=%d->%d signed_publications=1 final_outcomes=1", actionKey, lockKind, firstAttempt, firstAttempt+1, instrument.emptyClaims, initialGeneration, initialGeneration+1)
}

const recoverySnapshotSQL = `SELECT jsonb_build_object(
 'runs',(SELECT jsonb_agg(to_jsonb(r)) FROM zasp_security_agent_runs r WHERE organization_id=$1),
 'budgets',(SELECT jsonb_agg(to_jsonb(b)) FROM zasp_security_agent_run_budgets b WHERE organization_id=$1),
 'effects',(SELECT jsonb_agg(to_jsonb(e)) FROM zasp_security_agent_effects e WHERE organization_id=$1),
 'reservations',(SELECT jsonb_agg(to_jsonb(s)) FROM zasp_security_agent_step_reservations s WHERE organization_id=$1),
 'targets',(SELECT jsonb_agg(to_jsonb(t)) FROM zasp_security_agent_temporary_policy_targets t WHERE organization_id=$1),
 'work',(SELECT jsonb_agg(to_jsonb(w)) FROM zasp_policy_deployment_work w WHERE organization_id=$1),
 'bundles',(SELECT jsonb_agg(to_jsonb(p) ORDER BY p.sequence) FROM zasp_runtime_gateway_policy_bundles p WHERE organization_id=$1),
 'audits',(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.audit_id) FROM zasp_security_agent_audit a WHERE organization_id=$1))::text`

const recoveryCompleteSQL = `SELECT
 EXISTS(SELECT 1 FROM zasp_security_agent_runs WHERE organization_id=$1 AND run_id=$2 AND state='contained')
 AND (SELECT count(*) FROM zasp_security_agent_effects WHERE organization_id=$1)=1
 AND EXISTS(SELECT 1 FROM zasp_security_agent_effects WHERE organization_id=$1 AND run_id=$2 AND state='cleanup_pending' AND attempt=2 AND outcome_id IS NOT NULL AND result_digest IS NOT NULL AND lease_token IS NULL)
 AND (SELECT count(*) FROM zasp_security_agent_steps WHERE organization_id=$1 AND run_id=$2 AND state='succeeded')=1
 AND (SELECT count(*) FROM zasp_security_agent_step_reservations WHERE organization_id=$1 AND run_id=$2)=1
 AND (SELECT count(*) FROM zasp_security_agent_temporary_policy_targets WHERE organization_id=$1)=1
 AND EXISTS(SELECT 1 FROM zasp_security_agent_temporary_policy_targets WHERE organization_id=$1 AND run_id=$2 AND phase='apply' AND state='verified' AND desired_generation=$3)
 AND EXISTS(SELECT 1 FROM zasp_policy_deployment_work WHERE organization_id=$1 AND desired_generation=$3 AND applied_generation=$3 AND state='scheduled' AND lease_token IS NULL)
 AND (SELECT count(*) FROM zasp_runtime_gateway_policy_bundles WHERE organization_id=$1)=$4
 AND (SELECT count(*) FROM zasp_security_agent_audit WHERE organization_id=$1 AND run_id=$2 AND event_kind='effect_verified')=1
 AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_audit WHERE organization_id=$1 AND run_id=$2 AND event_kind='effect_cleaned')
 AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_run_budgets WHERE organization_id=$1 AND run_id=$2 AND stop_reason IS NOT NULL)`
