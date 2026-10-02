package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestSecurityAgentMultistepPlanningResultPostgres(t *testing.T) {
	runOrderedPlanningFixture(t, func(ctx context.Context, owner, worker *pgx.Conn, q map[string]any, selection map[string]any, rawResult string) {
		if _, err := orderedPlanningCall(ctx, worker, q); err != nil {
			t.Fatal(err)
		}
		q["operation"] = "prepare"
		q["payload"] = map[string]any{"pricing": selection, "input_version": "controlled-input-version"}
		if _, err := orderedPlanningCall(ctx, worker, q); err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"exact", "valid_v_summary", "unknown_field", "wrong_action", "wrong_target", "wrong_order", "extra_step", "summary_large", "summary_space", "summary_unicode_space", "null_usage", "wrong_model", "tokens", "cost", "negative_subnano", "duplicate_outer", "duplicate_candidate", "version_decimal", "index_decimal"} {
			t.Run(mode, func(t *testing.T) {
				if _, err := worker.Exec(ctx, `BEGIN`); err != nil {
					t.Fatal(err)
				}
				defer worker.Exec(ctx, `ROLLBACK`)
				q["operation"] = "start"
				q["payload"] = map[string]any{}
				if _, err := orderedPlanningCall(ctx, worker, q); err != nil {
					t.Fatal(err)
				}
				var outer map[string]json.RawMessage
				json.Unmarshal([]byte(rawResult), &outer)
				var choices []struct {
					Index        int    `json:"index"`
					FinishReason string `json:"finish_reason"`
					Message      struct {
						Role    string `json:"role"`
						Content string `json:"content"`
					} `json:"message"`
				}
				json.Unmarshal(outer["choices"], &choices)
				content := choices[0].Message.Content
				switch mode {
				case "valid_v_summary":
					content = strings.Replace(content, "Contain and retest", "verify", 1)
				case "unknown_field":
					content = strings.Replace(content, `"version":1`, `"version":1,"approved":true`, 1)
				case "wrong_action":
					content = strings.Replace(content, "run_test", "rerun_test", 1)
				case "wrong_target":
					content = strings.Replace(content, q["environment_id"].(string), q["run_id"].(string), 1)
				case "wrong_order":
					content = strings.Replace(content, `"index":1`, `"index":0`, 1)
				case "extra_step":
					content = strings.Replace(content, `],"summary"`, ` ,{"index":2,"action":"run_test","target_id":"forged"}],"summary"`, 1)
				case "summary_large":
					content = strings.Replace(content, "Contain and retest", strings.Repeat("x", 501), 1)
				case "summary_space":
					content = strings.Replace(content, "Contain and retest", " Contain and retest", 1)
				case "summary_unicode_space":
					content = strings.Replace(content, "Contain and retest", "\u00a0Contain and retest", 1)
				case "null_usage":
					outer["usage"] = json.RawMessage("null")
				case "wrong_model":
					outer["model"] = json.RawMessage(`"different/model"`)
				case "tokens":
					outer["usage"] = json.RawMessage(`{"prompt_tokens":1000,"completion_tokens":1,"total_tokens":1001,"cost":0.0000005}`)
				case "cost":
					outer["usage"] = json.RawMessage(`{"prompt_tokens":50,"completion_tokens":50,"total_tokens":100,"cost":0.003}`)
				case "negative_subnano":
					outer["usage"] = json.RawMessage(`{"prompt_tokens":50,"completion_tokens":50,"total_tokens":100,"cost":-0.0000000001}`)
				case "duplicate_candidate":
					content = strings.Replace(content, `"version":1`, `"version":2,"version":1`, 1)
				case "version_decimal":
					content = strings.Replace(content, `"version":1`, `"version":1.0`, 1)
				case "index_decimal":
					content = strings.Replace(content, `"index":0`, `"index":0.0`, 1)
				}
				choices[0].Message.Content = content
				outer["choices"], _ = json.Marshal(choices)
				raw, _ := json.Marshal(outer)
				if mode == "duplicate_outer" {
					raw = []byte(strings.Replace(string(raw), `"model":"openai/gpt-5-mini"`, `"model":"different/model","model":"openai/gpt-5-mini"`, 1))
				}
				q["operation"] = "result"
				q["payload"] = map[string]any{"raw": string(raw)}
				job, err := orderedPlanningCall(ctx, worker, q)
				if err != nil || job["raw_result"] != string(raw) {
					t.Fatal("raw result lost", err)
				}
				q["operation"] = "settle"
				q["payload"] = map[string]any{}
				job, err = orderedPlanningCall(ctx, worker, q)
				if err != nil {
					t.Fatal("accounting rejected retained bytes", err)
				}
				want := "needs_human"
				if mode == "exact" || mode == "valid_v_summary" {
					want = "settled"
				}
				if job["state"] != want {
					t.Fatal("malformed/overbudget result accepted", mode, job["state"])
				}
				q["operation"] = "admit"
				if _, err = orderedPlanningCall(ctx, worker, q); err == nil {
					t.Fatal("result without artifact authority admitted")
				}
			})
		}
	})
}
