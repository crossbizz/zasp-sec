package apiserver

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const existingTestPublicDefinition = "pid_78000005-0000-4000-8000-000000000005"
const existingTestPublicRun = "pid_78000009-0000-4000-8000-000000000009"
const existingTestPublicBefore = "pid_78000008-0000-4000-8000-000000000008"

func existingTestPublicProof() map[string]any {
	artifact := func() map[string]any {
		return map[string]any{"reference_digest": strings.Repeat("a", 64), "version_id": "immutable-version", "sha256": strings.Repeat("b", 64), "size_bytes": 128}
	}
	attempt := func(id string) map[string]any {
		return map[string]any{"run_id": id, "attempt": 1, "input_digest": strings.Repeat("d", 64), "input_artifact": artifact(), "output_artifact": artifact()}
	}
	return map[string]any{"definition_id": existingTestPublicDefinition, "definition_version": 1, "test_run_id": existingTestPublicRun, "state": "settled", "cancellation_outcome": nil,
		"verification": map[string]any{"outcome": "remediated", "reason": "test_condition_changed", "proof_digest": "sha256:" + strings.Repeat("c", 64), "before": attempt(existingTestPublicBefore), "after": attempt(existingTestPublicRun), "checks": []any{map[string]any{"category": "prompt_injection", "check_id": "zasp.curated.prompt_injection.v1", "prompt_digest": strings.Repeat("e", 64), "assertion_digest": strings.Repeat("f", 64), "before_protected": false, "after_protected": true, "before_http_status": 200, "after_http_status": 200}}}}
}

func existingTestPublicFixture(t *testing.T, proof any) (json.RawMessage, SecurityAgentRunDetail) {
	t.Helper()
	return actionProjectionFixture(t, "run_test", "succeeded", [2]int{}, [2]int{}, func(_, s map[string]any) {
		s["arguments"] = map[string]any{"target_id": existingTestPublicDefinition, "expected_version": 1}
		if proof != nil {
			s["existing_test"] = proof
		}
	})
}

func TestSecurityAgentExistingTestPublicAcceptsBoundProof(t *testing.T) {
	for _, pair := range [][2]string{{"remediated", "test_condition_changed"}, {"needs_human", "test_baseline_unavailable"}, {"needs_human", "test_condition_persists"}, {"inconclusive", "test_outcome_unknown"}, {"inconclusive", "test_evidence_unavailable"}, {"inconclusive", "test_evaluation_inconclusive"}, {"failed", "test_run_failed"}, {"cancelled", "test_run_cancelled"}, {"pending", ""}} {
		t.Run(pair[1]+pair[0], func(t *testing.T) {
			proof := existingTestPublicProof()
			v := proof["verification"].(map[string]any)
			v["outcome"], v["reason"] = pair[0], pair[1]
			if pair[0] != "remediated" {
				v["checks"], v["before"] = []any{}, nil
			}
			if pair[0] != "remediated" && pair[0] != "needs_human" {
				v["after"] = nil
			}
			if pair[0] == "pending" {
				proof["state"], proof["verification"] = "pending", nil
			}
			raw, detail := existingTestPublicFixture(t, proof)
			got, err := decodeSecurityAgentActionDetails(raw, detail)
			if err != nil || len(got) != 1 {
				t.Fatalf("valid bound proof rejected: %v", err)
			}
			encoded, err := json.Marshal(got[0])
			if err != nil || !strings.Contains(string(encoded), `"existing_test":`) || !strings.Contains(string(encoded), `"test_run_id":"`+existingTestPublicRun+`"`) {
				t.Fatal("bound proof was dropped")
			}
			detail.ActionDetails = got
			if !validSecurityAgentActionDetails(detail) {
				t.Fatal("public validator rejected valid proof")
			}
		})
	}
}

func TestSecurityAgentExistingTestPublicAbsentCompatibility(t *testing.T) {
	raw, detail := existingTestPublicFixture(t, nil)
	got, err := decodeSecurityAgentActionDetails(raw, detail)
	if err != nil {
		t.Fatal(err)
	}
	detail.ActionDetails = got
	encoded, _ := json.Marshal(got)
	if !validSecurityAgentActionDetails(detail) || strings.Contains(string(encoded), "existing_test") {
		t.Fatal("older-server absence changed")
	}
}

func TestSecurityAgentExistingTestPublicEffectIdentityIsSeparate(t *testing.T) {
	raw, detail := existingTestPublicFixture(t, existingTestPublicProof())
	var envelope map[string]any
	if json.Unmarshal(raw, &envelope) != nil {
		t.Fatal("fixture envelope")
	}
	step := envelope["steps"].([]any)[0].(map[string]any)
	effectID := "pid_78000007-0000-4000-8000-000000000007"
	step["effect"].(map[string]any)["outcome_id"] = effectID
	detail.Execution[0].OutcomeID = effectID
	raw, _ = json.Marshal(envelope)
	got, err := decodeSecurityAgentActionDetails(raw, detail)
	if err != nil || len(got) != 1 {
		t.Fatal("effect identity was confused with linked test run", err)
	}
	detail.ActionDetails = got
	if !validSecurityAgentActionDetails(detail) {
		t.Fatal("public validator confused the effect and test run identities")
	}
}

func TestSecurityAgentExistingTestPublicRejectsMalformedProof(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(map[string]any, map[string]any)
	}{
		{"wrong definition", func(p, v map[string]any) { p["definition_id"] = existingTestPublicBefore }},
		{"wrong version", func(p, v map[string]any) { p["definition_version"] = 2 }},
		{"version zero", func(p, v map[string]any) { p["definition_version"] = 0 }},
		{"version overflow", func(p, v map[string]any) { p["definition_version"] = 1000001 }},
		{"wrong run", func(p, v map[string]any) { p["test_run_id"] = existingTestPublicBefore }},
		{"private field", func(p, v map[string]any) { p["worker"] = "secret-sentinel" }},
		{"missing cancellation", func(p, v map[string]any) { delete(p, "cancellation_outcome") }},
		{"unknown cancellation", func(p, v map[string]any) { p["cancellation_outcome"] = "unknown" }},
		{"unknown cannot remediate", func(p, v map[string]any) { p["cancellation_outcome"] = "outcome_unknown" }},
		{"unknown state", func(p, v map[string]any) { p["state"] = "leased" }},
		{"pending verification", func(p, v map[string]any) { p["state"] = "pending" }},
		{"settled missing verification", func(p, v map[string]any) { delete(p, "verification") }},
		{"settled null verification", func(p, v map[string]any) { p["verification"] = nil }},
		{"mismatched digest", func(p, v map[string]any) { v["proof_digest"] = "sha256:" + strings.Repeat("a", 64) }},
		{"bad pair", func(p, v map[string]any) { v["reason"] = "test_condition_persists" }},
		{"null checks", func(p, v map[string]any) { v["checks"] = nil }},
		{"empty checks", func(p, v map[string]any) { v["checks"] = []any{} }},
		{"duplicate checks", func(p, v map[string]any) { c := v["checks"].([]any)[0]; v["checks"] = []any{c, c} }},
		{"too many checks", func(p, v map[string]any) { c := v["checks"].([]any)[0]; v["checks"] = []any{c, c, c, c, c, c, c} }},
		{"missing baseline", func(p, v map[string]any) { v["before"] = nil }},
		{"missing after", func(p, v map[string]any) { v["after"] = nil }},
		{"same attempts", func(p, v map[string]any) { v["before"].(map[string]any)["run_id"] = existingTestPublicRun }},
		{"foreign after", func(p, v map[string]any) { v["after"].(map[string]any)["run_id"] = existingTestPublicBefore }},
		{"needs human missing after", func(p, v map[string]any) {
			v["outcome"], v["reason"], v["checks"], v["after"] = "needs_human", "test_baseline_unavailable", []any{}, nil
		}},
		{"nonremediated checks", func(p, v map[string]any) { v["outcome"], v["reason"] = "needs_human", "test_baseline_unavailable" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := existingTestPublicProof()
			tc.change(p, p["verification"].(map[string]any))
			raw, detail := existingTestPublicFixture(t, p)
			got, err := decodeSecurityAgentActionDetails(raw, detail)
			if err != ErrRepositoryUnavailable || got != nil {
				t.Fatal("malformed proof accepted")
			}
		})
	}
}

func TestSecurityAgentExistingTestPublicNestedExactFields(t *testing.T) {
	// This catches missing, duplicate, null and private nested fields, including
	// false-valued booleans that ordinary json.Unmarshal cannot distinguish.
	for _, path := range []string{"proof", "verification", "after", "input_artifact", "check"} {
		for _, change := range []string{"missing", "duplicate", "extra", "null"} {
			t.Run(path+"/"+change, func(t *testing.T) {
				p := existingTestPublicProof()
				v := p["verification"].(map[string]any)
				a := v["after"].(map[string]any)
				object, field := p, "definition_id"
				switch path {
				case "verification":
					object, field = v, "outcome"
				case "after":
					object, field = a, "attempt"
				case "input_artifact":
					object, field = a["input_artifact"].(map[string]any), "reference_digest"
				case "check":
					object, field = v["checks"].([]any)[0].(map[string]any), "before_protected"
				}
				if change == "missing" {
					delete(object, field)
				}
				if change == "extra" {
					object["secret"] = "secret-sentinel"
				}
				if change == "null" {
					object[field] = nil
				}
				raw, detail := existingTestPublicFixture(t, p)
				if change == "duplicate" {
					encoded, _ := json.Marshal(object[field])
					key := `"` + field + `":` + string(encoded)
					raw = []byte(strings.Replace(string(raw), key, key+","+key, 1))
				}
				if got, err := decodeSecurityAgentActionDetails(raw, detail); err != ErrRepositoryUnavailable || got != nil {
					t.Fatal("ambiguous nested proof accepted")
				}
			})
		}
	}
}

func TestSecurityAgentExistingTestPublicStructValidation(t *testing.T) {
	for _, field := range []string{"definition_id", "definition_version", "test_run_id", "state", "verification"} {
		t.Run(field, func(t *testing.T) {
			raw, detail := existingTestPublicFixture(t, nil)
			actions, err := decodeSecurityAgentActionDetails(raw, detail)
			if err != nil {
				t.Fatal(err)
			}
			p := existingTestPublicProof()
			switch field {
			case "definition_id", "test_run_id":
				p[field] = existingTestPublicBefore
			case "definition_version":
				p[field] = 2
			case "state":
				p[field] = "pending"
			case "verification":
				p[field] = nil
			}
			encoded, _ := json.Marshal(actions[0])
			var object map[string]any
			if json.Unmarshal(encoded, &object) != nil {
				t.Fatal("fixture")
			}
			object["existing_test"] = p
			encoded, _ = json.Marshal(object)
			if json.Unmarshal(encoded, &actions[0]) != nil {
				t.Fatal("fixture proof")
			}
			detail.ActionDetails = actions
			if validSecurityAgentActionDetails(detail) {
				t.Fatal("public authority adapter bypassed proof validation")
			}
		})
	}
}

func TestSecurityAgentExistingTestPublicBounds(t *testing.T) {
	for _, tc := range []struct {
		path, field string
		value       any
	}{
		{"after", "attempt", 0}, {"after", "attempt", 6}, {"after", "attempt", 1.5},
		{"after", "run_id", "PID_78000009-0000-4000-8000-000000000009"},
		{"after", "input_digest", strings.Repeat("0", 64)}, {"after", "input_digest", strings.Repeat("A", 64)},
		{"input", "reference_digest", "s3://secret-bucket/private-key"}, {"input", "reference_digest", strings.Repeat("0", 64)},
		{"input", "sha256", strings.Repeat("0", 64)}, {"input", "sha256", strings.Repeat("a", 63)},
		{"input", "version_id", ""}, {"input", "version_id", strings.Repeat("v", 513)}, {"input", "version_id", "a b"}, {"input", "version_id", "a\x7fb"}, {"input", "version_id", "a\u00a0b"},
		{"input", "size_bytes", 0}, {"input", "size_bytes", 65537}, {"output", "size_bytes", 16777217},
		{"check", "category", "private-category"}, {"check", "check_id", "zasp.curated.tool_abuse.v1"},
		{"check", "prompt_digest", strings.Repeat("0", 64)}, {"check", "assertion_digest", strings.Repeat("A", 64)},
		{"check", "before_protected", true}, {"check", "after_protected", false}, {"check", "before_http_status", 201}, {"check", "after_http_status", 500},
	} {
		t.Run(tc.path+"/"+tc.field+"/"+stringMustJSON(t, tc.value), func(t *testing.T) {
			p := existingTestPublicProof()
			v := p["verification"].(map[string]any)
			a := v["after"].(map[string]any)
			object := a
			switch tc.path {
			case "input":
				object = a["input_artifact"].(map[string]any)
			case "output":
				object = a["output_artifact"].(map[string]any)
			case "check":
				object = v["checks"].([]any)[0].(map[string]any)
			}
			object[tc.field] = tc.value
			raw, detail := existingTestPublicFixture(t, p)
			if got, err := decodeSecurityAgentActionDetails(raw, detail); err != ErrRepositoryUnavailable || got != nil {
				t.Fatal("out of bounds proof accepted")
			}
			// An adapter constructing public values must not bypass these checks.
			raw, detail = existingTestPublicFixture(t, nil)
			actions, err := decodeSecurityAgentActionDetails(raw, detail)
			if err != nil {
				t.Fatal(err)
			}
			var public map[string]any
			encoded, _ := json.Marshal(actions[0])
			json.Unmarshal(encoded, &public)
			public["existing_test"] = p
			encoded, _ = json.Marshal(public)
			if json.Unmarshal(encoded, &actions[0]) == nil {
				detail.ActionDetails = actions
				if validSecurityAgentActionDetails(detail) {
					t.Fatal("public struct bounds bypassed")
				}
			}
		})
	}
}

func stringMustJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestSecurityAgentExistingTestPublicApplicability(t *testing.T) {
	for _, action := range []string{"run_test", "rerun_test", "update_finding_response"} {
		for _, present := range []bool{false, true} {
			t.Run(action+stringMustJSON(t, present), func(t *testing.T) {
				raw, detail := actionProjectionFixture(t, action, "", [2]int{}, [2]int{}, func(_, s map[string]any) {
					if action != "update_finding_response" {
						s["arguments"] = map[string]any{"target_id": existingTestPublicDefinition, "expected_version": 1}
					}
					if present {
						s["existing_test"] = existingTestPublicProof()
					}
				})
				got, err := decodeSecurityAgentActionDetails(raw, detail)
				if present {
					if err != ErrRepositoryUnavailable || got != nil {
						t.Fatal("pre-dispatch or unrelated proof accepted")
					}
				} else if err != nil {
					t.Fatal("absent proof rejected", err)
				}
			})
		}
	}
	for _, literal := range []string{"null", "{}", "[]"} {
		raw, detail := existingTestPublicFixture(t, json.RawMessage(literal))
		if got, err := decodeSecurityAgentActionDetails(raw, detail); err != ErrRepositoryUnavailable || got != nil {
			t.Fatal("malformed present proof accepted")
		}
	}
	// Duplicate top-level optional fields must not be silently collapsed.
	raw, detail := existingTestPublicFixture(t, existingTestPublicProof())
	raw = []byte(strings.Replace(string(raw), `"existing_test":`, `"existing_test":null,"existing_test":`, 1))
	if got, err := decodeSecurityAgentActionDetails(raw, detail); err != ErrRepositoryUnavailable || got != nil {
		t.Fatal("duplicate optional proof accepted")
	}
}

func TestSecurityAgentExistingTestPublicBoundarySuccess(t *testing.T) {
	p := existingTestPublicProof()
	p["definition_version"] = 1000000
	v := p["verification"].(map[string]any)
	checks := []any{}
	for i, category := range []string{"prompt_injection", "tool_abuse", "data_leakage", "authorization_bypass", "excessive_agency", "sensitive_information"} {
		checks = append(checks, map[string]any{"category": category, "check_id": "zasp.curated." + category + ".v1", "prompt_digest": strings.Repeat("a", 64), "assertion_digest": strings.Repeat("b", 64), "before_protected": i > 0, "after_protected": true, "before_http_status": 200, "after_http_status": 200})
	}
	v["checks"] = checks
	for _, side := range []string{"before", "after"} {
		a := v[side].(map[string]any)
		a["attempt"] = 5
		a["input_artifact"].(map[string]any)["size_bytes"] = 65536
		a["output_artifact"].(map[string]any)["size_bytes"] = 16777216
		a["input_artifact"].(map[string]any)["version_id"] = strings.Repeat("v", 512)
	}
	raw, detail := actionProjectionFixture(t, "rerun_test", "succeeded", [2]int{}, [2]int{}, func(_, s map[string]any) {
		s["arguments"] = map[string]any{"target_id": existingTestPublicDefinition, "expected_version": 1000000}
		s["existing_test"] = p
	})
	// A stopped parent keeps its state even when its saved proof shows improvement.
	detail.Run.State = "cancelled"
	got, err := decodeSecurityAgentActionDetails(raw, detail)
	if err != nil {
		t.Fatal("valid bounded historical proof rejected", err)
	}
	detail.ActionDetails = got
	if !validSecurityAgentActionDetails(detail) {
		t.Fatal("public bounds or stopped parent rejected")
	}
	encoded, _ := json.Marshal(got)
	for _, private := range []string{"s3://", `"reference":`, `"key":`, "proof_hex", "snapshot", "worker", "generation", "token"} {
		if strings.Contains(string(encoded), private) {
			t.Fatal("private authority exposed", private)
		}
	}
}

func TestSecurityAgentExistingTestPublicCancellationAndPending(t *testing.T) {
	for _, cancellation := range []any{nil, "cancelled_before_execution", "cancelled_after_partial_execution", "outcome_unknown"} {
		for _, state := range []string{"pending", "settled"} {
			t.Run(state+stringMustJSON(t, cancellation), func(t *testing.T) {
				p := existingTestPublicProof()
				p["state"], p["cancellation_outcome"] = state, cancellation
				v := p["verification"].(map[string]any)
				v["outcome"], v["reason"], v["before"], v["after"], v["checks"] = "cancelled", "test_run_cancelled", nil, nil, []any{}
				if cancellation == "outcome_unknown" {
					v["outcome"], v["reason"] = "inconclusive", "test_outcome_unknown"
				}
				if state == "pending" {
					p["verification"] = nil
				}
				raw, detail := existingTestPublicFixture(t, p)
				if state == "pending" {
					raw = []byte(strings.Replace(string(raw), `"state":"succeeded"`, `"state":"leased"`, 1))
				}
				got, err := decodeSecurityAgentActionDetails(raw, detail)
				if err != nil {
					t.Fatal("valid cancellation/pending proof rejected", err)
				}
				detail.ActionDetails = got
				if !validSecurityAgentActionDetails(detail) {
					t.Fatal("public cancellation/pending proof rejected")
				}
			})
		}
	}
}

func TestSecurityAgentExistingTestPublicHTTPBoundary(t *testing.T) {
	for _, headers := range [][]string{nil, {"v1"}} {
		raw, detail := existingTestPublicFixture(t, existingTestPublicProof())
		var err error
		detail.ActionDetails, err = decodeSecurityAgentActionDetails(raw, detail)
		if err != nil {
			t.Fatal(err)
		}
		response := actionDetailHTTP(t, detail, headers, false)
		if response.Code != http.StatusOK || strings.Contains(response.Body.String(), `"existing_test"`) != (len(headers) == 1) {
			t.Fatal("proof header negotiation changed")
		}
		detail.ActionDetails[0].ExistingTest.Verification.After.InputArtifact.ReferenceDigest = "secret-sentinel"
		response = actionDetailHTTP(t, detail, headers, false)
		if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "secret-sentinel") {
			t.Fatal("unsafe proof bypassed validation before header filtering")
		}
	}
}
