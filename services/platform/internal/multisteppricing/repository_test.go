package multisteppricing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

type wireDatabase struct {
	response json.RawMessage
	calls    []string
	ready    json.RawMessage
}

func (d *wireDatabase) QueryJSON(_ context.Context, q string, _ ...any) (json.RawMessage, error) {
	d.calls = append(d.calls, q)
	if strings.Contains(q, "pricing_ready") {
		if d.ready != nil {
			return d.ready, nil
		}
		return json.RawMessage(`{"release":true,"principal":true}`), nil
	}
	return d.response, nil
}

// Literal canonical IDs were independently calculated from the documented
// tenant/kind/native-ID recipe. The SQL integration tests check the other side.
func pricingWireFixture() (map[string]any, map[string]any, map[string]any, map[string]any) {
	o, w, e, actor := "pid_71000001-0000-4000-8000-000000000001", "pid_71000002-0000-4000-8000-000000000002", "pid_71000003-0000-4000-8000-000000000003", "pid_71000004-0000-4000-8000-000000000004"
	now := time.Now().UTC().Truncate(time.Microsecond)
	p := map[string]any{"provider": "openrouter", "model": "openai/gpt-5-mini", "account_profile": "local-controlled-account", "cost_unit": "openrouter_credit", "maximum_tokens": 1000, "maximum_cost_nano_credits": 2000000, "request_policy_version": "ordered-planner-v1", "request_token_limit": 256, "credential_reference": "secret_ref_planner/" + o + "/" + w + "/" + e + "/credential", "credential_digest": "sha256:" + strings.Repeat("ab", 32), "effective_at": now.Add(-time.Second).Format("2006-01-02T15:04:05.000000Z"), "expires_at": now.Add(time.Hour).Format("2006-01-02T15:04:05.000000Z")}
	admin := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "actor_id": actor, "fresh_auth_at": now.Format("2006-01-02T15:04:05.000000Z"), "operation": "create", "idempotency_key": "local-pricing-policy-0001", "expected_version": 0, "expected_account_version": 0, "policy": p}
	response := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "policy_id": "pid_62c591fd-f6e0-4793-8aa2-16aa29135f31", "version": 1, "account_id": "pid_56b04655-ade6-465b-8ddd-d53b93412312", "account_version": 1, "disabled": false, "policy": p}
	raw, _ := json.Marshal(response)
	sum := sha256.Sum256(raw)
	response["policy_digest"] = "sha256:" + hex.EncodeToString(sum[:])
	response["contract_version"] = 61
	response["mutation_id"] = "pid_de5647b3-457e-4aa7-81eb-ee5a0e1f5178"
	body := `{"model":"openai/gpt-5-mini","max_tokens":256,"messages":[{"role":"system","content":"fixed"},{"role":"user","content":"closed context"}],"provider":{"data_collection":"deny","require_parameters":true},"response_format":{"type":"json_schema","json_schema":{"name":"security_response_plan","strict":true,"schema":{"type":"object"}}}}`
	sum = sha256.Sum256([]byte(body))
	lookup := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "provider": p["provider"], "model": p["model"], "account_profile": p["account_profile"], "cost_unit": p["cost_unit"], "credential_reference": p["credential_reference"], "credential_digest": p["credential_digest"], "request_policy_version": p["request_policy_version"], "request_token_limit": 256, "body": body, "body_digest": "sha256:" + hex.EncodeToString(sum[:]), "policy_id": response["policy_id"], "policy_version": 1, "policy_digest": response["policy_digest"], "account_id": response["account_id"], "account_version": 1}
	bound := map[string]any{"contract_version": 61, "organization_id": o, "workspace_id": w, "environment_id": e, "policy_id": response["policy_id"], "policy_version": 1, "policy_digest": response["policy_digest"], "account_id": response["account_id"], "account_version": 1, "body_digest": lookup["body_digest"], "policy": p, "maximum_tokens": 1000, "maximum_cost_nano_credits": 2000000, "cost_policy_version": "pricing61-1-" + response["policy_digest"].(string)[7:39]}
	return admin, response, lookup, bound
}

func TestPricingRepositoryClosedResponses(t *testing.T) {
	for _, kind := range []string{"admin", "worker"} {
		for _, mode := range []string{"exact", "unknown", "missing", "zero", "negative", "large", "canonical_id", "account_id", "scope", "digest", "policy", "disabled", "cost_pin", "duplicate", "null", "oversize", "ready_false", "ready_extra"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				a, response, q, bound := pricingWireFixture()
				version := "version"
				if kind == "worker" {
					response = bound
					a = q
					version = "policy_version"
				}
				db := &wireDatabase{}
				switch mode {
				case "unknown":
					response["verified"] = true
				case "missing":
					delete(response, version)
				case "zero":
					response[version] = 0
				case "negative":
					response[version] = -1
				case "large":
					response[version] = 1000001
				case "canonical_id":
					response["policy_id"] = a["actor_id"]
					if kind == "worker" {
						response["policy_id"] = a["environment_id"]
					}
				case "account_id":
					response["account_id"] = a["environment_id"]
				case "scope":
					response["environment_id"] = a["workspace_id"]
				case "digest":
					response["policy_digest"] = "sha256:" + strings.Repeat("ef", 32)
				case "policy":
					response["policy"].(map[string]any)["maximum_tokens"] = 1001
				case "disabled":
					response["disabled"] = true
				case "cost_pin":
					response["cost_policy_version"] = "unreviewed"
				case "null":
					response[version] = nil
				case "ready_false":
					db.ready = json.RawMessage(`{"release":false,"principal":true}`)
				case "ready_extra":
					db.ready = json.RawMessage(`{"release":true,"principal":true,"stale":false}`)
				}
				db.response, _ = json.Marshal(response)
				if mode == "duplicate" {
					db.response = append([]byte(`{"contract_version":60,`), db.response[1:]...)
				}
				if mode == "oversize" {
					db.response = append(db.response, []byte(strings.Repeat(" ", 8193))...)
				}
				repo, err := New(db, kind)
				if err == nil {
					raw, _ := json.Marshal(a)
					if kind == "admin" {
						_, err = repo.Admin(context.Background(), raw)
					} else {
						_, err = repo.Lookup(context.Background(), raw)
					}
				}
				if mode == "exact" {
					if err != nil {
						t.Fatal("exact SQL response refused", err)
					}
				} else if err == nil {
					t.Fatal("fabricated response accepted")
				}
			})
		}
	}
}

func TestPricingRepositoryRejectsInputBeforeSQL(t *testing.T) {
	for _, kind := range []string{"admin", "worker"} {
		for _, mode := range []string{"unknown", "duplicate", "zero_token", "bad_body", "wrong_digest", "credential_scope", "invalid_utf8", "oversize"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				a, _, q, _ := pricingWireFixture()
				if kind == "worker" {
					a = q
				}
				switch mode {
				case "unknown":
					a["unreviewed"] = true
				case "zero_token":
					if kind == "admin" {
						a["policy"].(map[string]any)["maximum_tokens"] = 0
					} else {
						a["request_token_limit"] = 0
					}
				case "credential_scope":
					if kind == "admin" {
						a["policy"].(map[string]any)["credential_reference"] = "secret_ref_planner/global"
					} else {
						a["credential_reference"] = "secret_ref_planner/global"
					}
				case "bad_body":
					if kind == "worker" {
						a["body"] = "not-json"
					} else {
						a["policy"] = "not-object"
					}
				case "wrong_digest":
					if kind == "worker" {
						a["body_digest"] = "sha256:" + strings.Repeat("cd", 32)
					} else {
						a["policy"].(map[string]any)["credential_digest"] = "bad"
					}
				}
				raw, _ := json.Marshal(a)
				if mode == "duplicate" {
					raw = append([]byte(`{"organization_id":"ignored",`), raw[1:]...)
				}
				if mode == "invalid_utf8" {
					raw = append(raw, 0xff)
				}
				if mode == "oversize" {
					raw = append(raw, []byte(strings.Repeat(" ", 524289))...)
				}
				db := &wireDatabase{}
				repo, err := New(db, kind)
				if err != nil {
					t.Fatal(err)
				}
				calls := append([]string{}, db.calls...)
				if kind == "admin" {
					_, err = repo.Admin(context.Background(), raw)
				} else {
					_, err = repo.Lookup(context.Background(), raw)
				}
				if err == nil || !reflect.DeepEqual(calls, db.calls) {
					t.Fatal("invalid input reached SQL", err, db.calls)
				}
			})
		}
	}
}

func TestLookupIdentityValidationMatchesRepositoryRulesWithoutIO(t *testing.T) {
	_, _, lookup, _ := pricingWireFixture()
	raw, _ := json.Marshal(lookup)
	var request LookupRequest
	if json.Unmarshal(raw, &request) != nil || !ValidLookupIdentity(request) {
		t.Fatal("valid lookup identity rejected")
	}
	for name, mutate := range map[string]func(*LookupRequest){
		"organization":         func(q *LookupRequest) { q.OrganizationID = "bad" },
		"workspace":            func(q *LookupRequest) { q.WorkspaceID = "bad" },
		"environment":          func(q *LookupRequest) { q.EnvironmentID = "bad" },
		"provider":             func(q *LookupRequest) { q.Provider = "other" },
		"model":                func(q *LookupRequest) { q.Model = "" },
		"account profile":      func(q *LookupRequest) { q.AccountProfile = "" },
		"cost unit":            func(q *LookupRequest) { q.CostUnit = "usd" },
		"credential reference": func(q *LookupRequest) { q.CredentialReference = "secret_ref_planner/global" },
		"credential digest":    func(q *LookupRequest) { q.CredentialDigest = "bad" },
		"request policy":       func(q *LookupRequest) { q.RequestPolicyVersion = "" },
		"request token limit":  func(q *LookupRequest) { q.RequestTokenLimit = 0 },
		"policy id canonical":  func(q *LookupRequest) { q.PolicyID = q.AccountID },
		"policy version":       func(q *LookupRequest) { q.PolicyVersion = 0 },
		"policy digest":        func(q *LookupRequest) { q.PolicyDigest = "bad" },
		"account id canonical": func(q *LookupRequest) { q.AccountID = q.PolicyID },
		"account version":      func(q *LookupRequest) { q.AccountVersion = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := request
			mutate(&candidate)
			if ValidLookupIdentity(candidate) {
				t.Fatal("malformed identity accepted")
			}
		})
	}
}

func TestPricingRepositoryRevisionCeiling(t *testing.T) {
	for _, tc := range []struct {
		name, kind, operation        string
		version, account, gotAccount int64
		want                         bool
	}{
		{"account_version", "admin", "version", 2, 1000000, 1000000, true},
		{"account_disable", "admin", "disable", 2, 1000000, 1000000, true},
		{"account_rotation_overflow", "admin", "version", 2, 1000000, 1000001, false},
		{"account_zero_disable", "admin", "disable", 2, 0, 0, false},
		{"active_final_policy", "admin", "version", 1000000, 1, 1, false},
		{"final_disable", "admin", "disable", 1000000, 1, 1, true},
		{"lookup_account_ceiling", "worker", "", 1, 1000000, 1000000, true},
		{"lookup_reserved_policy", "worker", "", 1000000, 1, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, response, lookup, bound := pricingWireFixture()
			q["operation"], q["expected_version"], q["expected_account_version"] = tc.operation, tc.version-1, tc.account
			response["version"], response["account_version"], response["disabled"] = tc.version, tc.gotAccount, tc.operation == "disable"
			// Build the documented digest payload from fixture fields, without
			// calling the production digest or canonical identity helpers.
			payload := map[string]any{}
			for _, k := range []string{"organization_id", "workspace_id", "environment_id", "policy_id", "version", "account_id", "account_version", "disabled", "policy"} {
				payload[k] = response[k]
			}
			digestRaw, _ := json.Marshal(payload)
			sum := sha256.Sum256(digestRaw)
			response["policy_digest"] = "sha256:" + hex.EncodeToString(sum[:])
			if tc.kind == "worker" {
				lookup["policy_version"], lookup["account_version"], lookup["policy_digest"] = tc.version, tc.account, response["policy_digest"]
				bound["policy_version"], bound["account_version"], bound["policy_digest"] = tc.version, tc.gotAccount, response["policy_digest"]
				prefix := "pricing61-1-"
				if tc.version == 1000000 {
					prefix = "pricing61-1000000-"
				}
				bound["cost_policy_version"] = prefix + response["policy_digest"].(string)[7:39]
				q, response = lookup, bound
			}
			db := &wireDatabase{}
			db.response, _ = json.Marshal(response)
			repo, err := New(db, tc.kind)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(q)
			if tc.kind == "admin" {
				_, err = repo.Admin(context.Background(), raw)
			} else {
				_, err = repo.Lookup(context.Background(), raw)
			}
			if (err == nil) != tc.want {
				t.Fatalf("revision ceiling accepted=%v want=%v err=%v", err == nil, tc.want, err)
			}
		})
	}
}

func TestPricingAdminReplayTimeChecks(t *testing.T) {
	for _, mode := range []string{"saved_replay", "stale_auth", "expired"} {
		t.Run(mode, func(t *testing.T) {
			q, response, _, _ := pricingWireFixture()
			now := time.Now().UTC()
			q["policy"].(map[string]any)["effective_at"] = now.Add(-6 * time.Minute).Format(TimeFormat)
			if mode == "stale_auth" {
				q["fresh_auth_at"] = now.Add(-6 * time.Minute).Format(TimeFormat)
			}
			if mode == "expired" {
				q["policy"].(map[string]any)["expires_at"] = now.Add(-time.Second).Format(TimeFormat)
			}
			payload := map[string]any{}
			for _, k := range []string{"organization_id", "workspace_id", "environment_id", "policy_id", "version", "account_id", "account_version", "disabled", "policy"} {
				payload[k] = response[k]
			}
			digestRaw, _ := json.Marshal(payload)
			sum := sha256.Sum256(digestRaw)
			response["policy_digest"] = "sha256:" + hex.EncodeToString(sum[:])
			db := &wireDatabase{}
			db.response, _ = json.Marshal(response)
			repo, err := New(db, "admin")
			if err != nil {
				t.Fatal(err)
			}
			calls := len(db.calls)
			raw, _ := json.Marshal(q)
			_, err = repo.Admin(context.Background(), raw)
			if mode == "saved_replay" {
				if err != nil {
					t.Fatal("valid saved replay refused by new-mutation time check", err)
				}
			} else if err == nil || len(db.calls) != calls {
				t.Fatal("current freshness/expiry refusal changed", err)
			}
		})
	}
}
