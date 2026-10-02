package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// This is a local approval-ceiling component test, not provider pricing or a
// planning submission. Only identity/scope are fixture-seeded; policy writes
// must use the restricted admin authority.
func TestSecurityAgentMultistepPricingPolicyPostgres(t *testing.T) {
	runOrderedPricingFixture(t, func(ctx context.Context, owner, admin, worker *pgx.Conn, o, w, e, actor string) {
		req := orderedPricingAdminRequest(o, w, e, actor)
		var pid, aid string
		if err := owner.QueryRow(ctx, `SELECT zasp_discovery_canonical_id($1,$2,$3,'security_agent_pricing_policy','openrouter'||chr(31)||'openai/gpt-5-mini'||chr(31)||'local-controlled-account'),zasp_discovery_canonical_id($1,$2,$3,'security_agent_pricing_account','openrouter'||chr(31)||'local-controlled-account')`, o, w, e).Scan(&pid, &aid); err != nil {
			t.Fatal(err)
		}
		absent := map[string]any{"policy_id": pid, "account_id": aid, "version": 1, "account_version": 1, "policy_digest": "sha256:" + strings.Repeat("ab", 32)}
		before := orderedPricingSnapshot(t, ctx, owner)
		if _, err := orderedPricingCall(ctx, worker, "pricing_lookup", orderedPricingLookupRequest(o, w, e, req["policy"].(map[string]any), absent)); err == nil || orderedPricingSnapshot(t, ctx, owner) != before {
			t.Fatal("absent pricing authority did not fail closed without mutation", err)
		}
		created, err := orderedPricingCall(ctx, admin, "pricing_admin", req)
		if err != nil {
			t.Fatal("private release61 policy create unavailable", err)
		}
		if created["version"] != float64(1) || created["account_version"] != float64(1) || created["disabled"] != false || created["contract_version"] != float64(61) {
			t.Fatal("create identity/state", created)
		}
		before = orderedPricingSnapshot(t, ctx, owner)
		replayed, err := orderedPricingCall(ctx, admin, "pricing_admin", req)
		if err != nil || !jsonEqualMaps(created, replayed) || orderedPricingSnapshot(t, ctx, owner) != before {
			t.Fatal("immutable admin replay changed authority", err, replayed)
		}
		lookup := orderedPricingLookupRequest(o, w, e, req["policy"].(map[string]any), created)
		bound, err := orderedPricingCall(ctx, worker, "pricing_lookup", lookup)
		if err != nil || bound["maximum_tokens"] != float64(1000) || bound["maximum_cost_nano_credits"] != float64(2000000) || bound["body_digest"] != lookup["body_digest"] || bound["policy_digest"] != created["policy_digest"] || bound["policy_version"] != float64(1) {
			t.Fatal("exact prepared request did not resolve approval ceiling", err, bound)
		}
		if again, err := orderedPricingCall(ctx, worker, "pricing_lookup", lookup); err != nil || !jsonEqualMaps(again, bound) || orderedPricingSnapshot(t, ctx, owner) != before {
			t.Fatal("lookup replay mutated authority", err, again)
		}
		var unrelated bool
		if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_security_agent_provider_reservations) AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.admissions) AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_runs)`).Scan(&unrelated); err != nil || !unrelated {
			t.Fatal("pricing lookup performed planning work", unrelated, err)
		}
	})
}

func runOrderedPricingFixture(t *testing.T, exercise func(context.Context, *pgx.Conn, *pgx.Conn, *pgx.Conn, string, string, string, string)) {
	t.Helper()
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, _ *pgx.Conn, o, w, e, _, actor string) {
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($4,$1,'pricing-local-org','pricing-local-admin','organization_admin') ON CONFLICT(organization_id,principal_id) DO UPDATE SET role='organization_admin',active=true;
 INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Pricing approval','["view","manage_identity"]') ON CONFLICT(principal_id,organization_id,workspace_id,environment_id) DO UPDATE SET permissions=EXCLUDED.permissions`, pgx.QueryExecModeSimpleProtocol, o, w, e, actor); err != nil {
			t.Fatal(err)
		}
		config := owner.Config().Copy()
		config.User = "security_agent_v33_discovery_api_login"
		admin, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer admin.Close(context.Background())
		exercise(ctx, owner, admin, worker, o, w, e, actor)
	})
}

func orderedPricingAdminRequest(o, w, e, actor string) map[string]any {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "actor_id": actor, "fresh_auth_at": now.Format("2006-01-02T15:04:05.000000Z"), "operation": "create", "idempotency_key": "local-pricing-policy-0001", "expected_version": 0, "expected_account_version": 0,
		"policy": map[string]any{"provider": "openrouter", "model": "openai/gpt-5-mini", "account_profile": "local-controlled-account", "cost_unit": "openrouter_credit", "maximum_tokens": 1000, "maximum_cost_nano_credits": 2000000, "request_policy_version": "ordered-planner-v1", "request_token_limit": 256, "credential_reference": "secret_ref_planner/" + o + "/" + w + "/" + e + "/local-credential", "credential_digest": "sha256:" + strings.Repeat("ab", 32), "effective_at": now.Add(-time.Second).Format("2006-01-02T15:04:05.000000Z"), "expires_at": now.Add(time.Hour).Format("2006-01-02T15:04:05.000000Z")}}
}

func orderedPricingLookupRequest(o, w, e string, policy, created map[string]any) map[string]any {
	body := `{"model":"openai/gpt-5-mini","max_tokens":256,"messages":[{"role":"system","content":"fixed"},{"role":"user","content":"closed context"}],"provider":{"data_collection":"deny","require_parameters":true},"response_format":{"type":"json_schema","json_schema":{"name":"security_response_plan","strict":true,"schema":{"type":"object"}}}}`
	digest := sha256.Sum256([]byte(body))
	return map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "provider": policy["provider"], "model": policy["model"], "account_profile": policy["account_profile"], "cost_unit": policy["cost_unit"], "credential_reference": policy["credential_reference"], "credential_digest": policy["credential_digest"], "request_policy_version": policy["request_policy_version"], "request_token_limit": policy["request_token_limit"], "body": body, "body_digest": "sha256:" + hex.EncodeToString(digest[:]), "policy_id": created["policy_id"], "policy_version": created["version"], "policy_digest": created["policy_digest"], "account_id": created["account_id"], "account_version": created["account_version"]}
}

func orderedPricingCall(ctx context.Context, connection *pgx.Conn, function string, request map[string]any) (map[string]any, error) {
	raw, _ := json.Marshal(request)
	var response []byte
	err := connection.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.`+function+`($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), raw).Scan(&response)
	var result map[string]any
	if err == nil {
		err = json.Unmarshal(response, &result)
	}
	return result, err
}

func orderedPricingSnapshot(t *testing.T, ctx context.Context, owner *pgx.Conn) string {
	t.Helper()
	var value string
	if err := owner.QueryRow(ctx, `SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(p) ORDER BY policy_id,version) FROM zasp_sa_multistep_prior.pricing_policies p),(SELECT jsonb_agg(to_jsonb(a) ORDER BY account_id,version) FROM zasp_sa_multistep_prior.pricing_accounts a),(SELECT jsonb_agg(to_jsonb(m) ORDER BY mutation_id) FROM zasp_sa_multistep_prior.pricing_mutations m),(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM zasp_admin_audit a WHERE action LIKE 'security_agent.pricing.%'))::text`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func jsonEqualMaps(a, b map[string]any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
