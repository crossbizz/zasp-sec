package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/multisteppricing"
)

type pricingBoundDatabase struct {
	response json.RawMessage
	mutate   func()
	queries  []string
}

func (d *pricingBoundDatabase) QueryJSON(_ context.Context, q string, args ...any) (json.RawMessage, error) {
	d.queries = append(d.queries, q)
	if strings.Contains(q, "pricing_ready") {
		return json.RawMessage(`{"release":true,"principal":true}`), nil
	}
	if d.mutate != nil {
		d.mutate()
	}
	return d.response, nil
}

func TestSecurityAgentMultistepPricingPreparedBinding(t *testing.T) {
	for _, mode := range []string{"exact", "scope", "profile", "reference", "consumed", "body", "model", "policy", "tokens", "closed", "credential_wait", "model_wait", "cancel_wait", "wrong_body_response", "zero_usage_ceiling"} {
		t.Run(mode, func(t *testing.T) {
			transport := orderedBindingResponseTransport()
			planner := orderedRequestBindingPlanner(t, transport)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			prepared, err := orderedPreparedPlanFixture(ctx, planner, orderedContextFixture().Context)
			if err != nil {
				t.Fatal(err)
			}
			binding, response := orderedPricingWorkerFixture(t, prepared)
			db := &pricingBoundDatabase{response: response}
			switch mode {
			case "scope":
				binding.EnvironmentID = binding.WorkspaceID
			case "profile":
				binding.AccountProfile = "other"
			case "reference":
				binding.CredentialReference = "secret_ref_planner/global"
			case "consumed":
				prepared.consumed.Store(true)
			case "body":
				prepared.body += " "
			case "model":
				planner.model = "other/model"
			case "policy":
				planner.policyVersion = "other-v1"
			case "tokens":
				planner.maximumTokens++
			case "closed":
				planner.Close()
			case "credential_wait":
				db.mutate = func() {
					planner.mu.Lock()
					planner.token = []byte("sk-or-v1-rotated-test-credential")
					planner.mu.Unlock()
				}
			case "model_wait":
				db.mutate = func() { planner.mu.Lock(); planner.model = "other/model"; planner.mu.Unlock() }
			case "cancel_wait":
				db.mutate = cancel
			case "wrong_body_response":
				var v map[string]any
				json.Unmarshal(response, &v)
				v["body_digest"] = "sha256:" + strings.Repeat("cd", 32)
				db.response, _ = json.Marshal(v)
			case "zero_usage_ceiling":
				var v map[string]any
				json.Unmarshal(response, &v)
				v["maximum_cost_nano_credits"] = 0
				db.response, _ = json.Marshal(v)
			}
			bound, err := lookupSecurityAgentMultistepCost(ctx, db, prepared, binding)
			if mode == "exact" {
				if err != nil || bound == nil {
					t.Fatal("verified approval ceiling absent", err)
				}
				if !bound.validFor(prepared.identity, binding.AccountProfile, time.Now()) || bound.maximumTokens != 1000 || bound.maximumCostNanoCredits != 2000000 || bound.policyVersion == "" {
					t.Fatal("wrong ceiling", bound)
				}
			} else if err == nil || bound != nil {
				t.Fatal("stale or unbound request received authority", bound, err)
			}
			if transport.calls != 0 {
				t.Fatal("pricing lookup called provider")
			}
		})
	}
}

func orderedPricingWorkerFixture(t *testing.T, p *securityAgentOrderedPreparedPlan) (securityAgentMultistepPricingBinding, json.RawMessage) {
	t.Helper()
	c := p.contextValue
	s := multisteppricing.Scope{OrganizationID: c.OrganizationID, WorkspaceID: c.WorkspaceID, EnvironmentID: c.EnvironmentID}
	o, _ := domain.ParseProductID(c.OrganizationID)
	w, _ := domain.ParseProductID(c.WorkspaceID)
	e, _ := domain.ParseProductID(c.EnvironmentID)
	scope, _ := domain.NewScope(o, w, e)
	pid, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_pricing_policy", "openrouter\x1f"+p.identity.Model+"\x1flocal-controlled-account")
	aid, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_pricing_account", "openrouter\x1flocal-controlled-account")
	h := sha256.Sum256(p.planner.token)
	now := time.Now().UTC().Truncate(time.Microsecond)
	policy := map[string]any{"provider": "openrouter", "model": p.identity.Model, "account_profile": "local-controlled-account", "cost_unit": "openrouter_credit", "maximum_tokens": 1000, "maximum_cost_nano_credits": 2000000, "request_policy_version": p.identity.PolicyVersion, "request_token_limit": p.identity.MaximumTokens, "credential_reference": "secret_ref_planner/" + c.OrganizationID + "/" + c.WorkspaceID + "/" + c.EnvironmentID + "/credential", "credential_digest": "sha256:" + hex.EncodeToString(h[:]), "effective_at": now.Add(-time.Second).Format(multisteppricing.TimeFormat), "expires_at": now.Add(time.Hour).Format(multisteppricing.TimeFormat)}
	digestFields := map[string]any{"organization_id": s.OrganizationID, "workspace_id": s.WorkspaceID, "environment_id": s.EnvironmentID, "policy_id": pid, "version": 1, "account_id": aid, "account_version": 1, "disabled": false, "policy": policy}
	bytes, _ := json.Marshal(digestFields)
	h = sha256.Sum256(bytes)
	pin := "sha256:" + hex.EncodeToString(h[:])
	response, _ := json.Marshal(map[string]any{"contract_version": 61, "organization_id": s.OrganizationID, "workspace_id": s.WorkspaceID, "environment_id": s.EnvironmentID, "policy_id": pid, "policy_version": 1, "policy_digest": pin, "account_id": aid, "account_version": 1, "body_digest": p.identity.BodyDigest, "policy": policy, "maximum_tokens": 1000, "maximum_cost_nano_credits": 2000000, "cost_policy_version": "pricing61-1-" + pin[7:39]})
	return securityAgentMultistepPricingBinding{Scope: s, AccountProfile: "local-controlled-account", CredentialReference: policy["credential_reference"].(string), PolicyID: pid, PolicyVersion: 1, PolicyDigest: pin, AccountID: aid, AccountVersion: 1}, response
}

// The apiserver test owns and joins this helper. Its controlled token only
// establishes local credential binding; no transport dispatch is authorized.
func TestSecurityAgentMultistepPricingOwnedPostgres(t *testing.T) {
	dsn := os.Getenv("ZASP_ORDERED_PRICING_TEST_DSN")
	if dsn == "" {
		t.Skip("requires parent-owned pricing database")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil || config.User != "zasp_e2e" || config.Database != "postgres" || net.ParseIP(config.Host) == nil || !net.ParseIP(config.Host).IsLoopback() {
		t.Fatal("requires owned loopback database")
	}
	for _, fallback := range config.Fallbacks {
		if net.ParseIP(fallback.Host) == nil || !net.ParseIP(fallback.Host).IsLoopback() {
			t.Fatal("foreign fallback")
		}
	}
	var binding securityAgentMultistepPricingBinding
	if json.Unmarshal([]byte(os.Getenv("ZASP_ORDERED_PRICING_BINDING")), &binding) != nil {
		t.Fatal("invalid parent binding")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	config.User = "security_agent_v33_worker_login"
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("worker connect", err)
	}
	defer conn.Close(context.Background())
	db := &orderedPricingWorkerPG{conn: conn}
	transport := orderedBindingResponseTransport()
	planner := orderedRequestBindingPlanner(t, transport)
	c := orderedContextFixture().Context
	c.OrganizationID = binding.OrganizationID
	c.WorkspaceID = binding.WorkspaceID
	c.EnvironmentID = binding.EnvironmentID
	p, err := orderedPreparedPlanFixture(ctx, planner, c)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := lookupSecurityAgentMultistepCost(ctx, db, p, binding)
	refuse := os.Getenv("ZASP_ORDERED_PRICING_MODE") == "refuse"
	if refuse {
		if err == nil || bound != nil {
			t.Fatal("revoked policy resolved")
		}
	} else if err != nil || bound == nil || !bound.validFor(p.identity, binding.AccountProfile, time.Now()) || bound.maximumCostNanoCredits != 2000000 {
		t.Fatal("exact current policy did not bind", err)
	}
	if transport.calls != 0 {
		t.Fatal("pricing component sent provider request")
	}
	fmt.Println("owned ordered pricing worker joined: provider_calls=0")
}

type orderedPricingWorkerPG struct{ conn *pgx.Conn }

func (d *orderedPricingWorkerPG) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	var raw []byte
	err := d.conn.QueryRow(ctx, q, args...).Scan(&raw)
	return raw, err
}
