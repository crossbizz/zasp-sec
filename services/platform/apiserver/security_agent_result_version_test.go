package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSecurityAgentWorkerResultVersionsAfterHeartbeat(t *testing.T) {
	for _, operation := range []string{"accept", "accept_stop", "fail", "prepare", "prepare_stop", "execute", "execute_stop"} {
		for _, version := range []int64{0, 2, 3, 5, 1000000, 1000001} {
			t.Run(fmt.Sprintf("%s/%d", operation, version), func(t *testing.T) {
				claim := budgetRepositoryClaim()
				id := "pid_78000004-0000-4000-8000-000000000004"
				hash := "sha256:" + strings.Repeat("a", 64)
				fields := map[string]any{"run_id": claim.RunID, "version": version}
				switch operation {
				case "accept", "accept_stop", "prepare", "prepare_stop":
					fields["state"], fields["approval_id"], fields["step_id"], fields["plan_hash"] = "waiting_approval", id, id, hash
					if strings.HasSuffix(operation, "_stop") {
						fields["state"], fields["approval_id"], fields["step_id"], fields["plan_hash"] = "needs_human", "", "", ""
					}
					if strings.HasPrefix(operation, "accept") {
						fields["planner_outcome"], fields["planner_summary"], fields["replayed"] = "accepted", "Review safely", false
						if operation == "accept_stop" {
							fields["planner_outcome"] = "budget_stopped"
						}
					}
				case "fail":
					fields["state"], fields["error_code"], fields["replayed"] = "failed", "planner_unavailable", false
				case "execute", "execute_stop":
					claim.Prepared = true
					fields["state"], fields["step_id"], fields["effect_state"], fields["outcome_id"], fields["result_digest"] = "remediated", id, "verified", id, hash
					if operation == "execute_stop" {
						fields["state"], fields["step_id"], fields["effect_state"], fields["outcome_id"], fields["result_digest"] = "needs_human", "", "", "", ""
					}
				}
				payload, err := json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
				db := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{"fixture-operation": payload}}
				r := &SecurityAgentWorkerRepository{database: db, acceptPlannerSQL: "fixture-operation", failPlannerSQL: "fixture-operation", prepareSQL: "fixture-operation", executeSQL: "fixture-operation"}
				ctx := context.Background()
				switch operation {
				case "accept", "accept_stop":
					_, err = r.AcceptSecurityAgentPlannerCandidate(ctx, claim, "worker-1", "worker-lease-00000001", SecurityAgentPlannerSubmission{InputDigest: hash, OutputDigest: hash, Model: "fixture-model", PolicyVersion: "fixture-policy", Summary: "Review safely", Action: "update_finding_response", TargetID: claim.TriggerID}, id, time.Now().UTC().Add(time.Minute), id, id)
				case "fail":
					_, err = r.FailSecurityAgentPlanner(ctx, claim, "worker-1", "worker-lease-00000001", SecurityAgentPlannerFailure{InputDigest: hash, Model: "fixture-model", PolicyVersion: "fixture-policy", ErrorCode: "planner_unavailable"}, id, id)
				case "prepare", "prepare_stop":
					_, err = r.PrepareSecurityAgentRun(ctx, claim, "worker-1", "worker-lease-00000001", id, time.Now().UTC().Add(time.Minute), id, id)
				case "execute", "execute_stop":
					_, err = r.ExecuteSecurityAgentRun(ctx, claim, "worker-1", "worker-lease-00000001", id, id)
				}
				wantOK := version == 3 || version == 5 || version == 1000000
				if (err == nil) != wantOK {
					t.Fatalf("version=%d accepted=%v want=%v err=%v", version, err == nil, wantOK, err)
				}
			})
		}
	}
}
