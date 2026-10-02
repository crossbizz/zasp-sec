package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestSecurityAgentMultistepCleanupWirePostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		for kind, limit := range map[string]int{"request": 32768, "response": 262144, "receipt": 131072} {
			for _, delta := range []int{-1, 0, 1} {
				// PostgreSQL's actual spaced jsonb wire bytes, not a compact
				// input estimate. Closed decoding uses the same exact byte cap.
				var raw []byte
				var valid bool
				if err := owner.QueryRow(ctx, `SELECT v::text,zasp_sa_multistep_prior.cleanup_wire(v,$1) FROM (SELECT jsonb_build_object('x',repeat('x',$2-9)) v) x`, kind, limit+delta).Scan(&raw, &valid); err != nil {
					t.Fatal("cleanup byte-bound authority absent", err)
				}
				_, goValid := orderedDeploymentClosedObject(raw, limit, "x")
				if len(raw) != limit+delta || valid != (delta <= 0) || goValid != valid {
					t.Fatal("cleanup SQL/Go wire mismatch", kind, delta, len(raw), valid, goValid)
				}
			}
		}
		var valid bool
		if err := owner.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.cleanup_wire('{}','unknown') OR zasp_sa_multistep_prior.cleanup_wire('[]','request') OR zasp_sa_multistep_prior.cleanup_wire(NULL,'receipt')`).Scan(&valid); err != nil || valid {
			t.Fatal("cleanup wire kind/shape refusal", valid, err)
		}
	})
}

func orderedCleanupRequestBounds(t *testing.T, ctx context.Context, q, result map[string]any) {
	t.Helper()
	body, _ := json.Marshal(result)
	db := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{`SELECT zasp_sa_multistep_prior.cleanup($1,$2,$3::jsonb)`: body}}
	repo := &securityAgentMultistepAdmissionRepository{database: db}
	raw, _ := json.Marshal(q)
	for _, delta := range []int{-1, 0, 1} {
		padded := append(append([]byte{}, raw...), []byte(strings.Repeat(" ", 32768+delta-len(raw)))...)
		if _, err := repo.cleanup(ctx, padded, policy.GatewayPolicyKeys{}); (err == nil) != (delta <= 0) {
			t.Fatal("cleanup request byte boundary", delta, err)
		}
	}
}

func orderedCleanupMaximumResponse(t *testing.T, ctx context.Context, q, result map[string]any) {
	t.Helper()
	scope, valid := orderedApplicationScope(q["organization_id"].(string), q["workspace_id"].(string), q["environment_id"].(string), q["run_id"].(string), q["step_id"].(string))
	if !valid {
		t.Fatal("cleanup response bound scope")
	}
	r, s := q["run_id"].(string), q["step_id"].(string)
	request, _ := json.Marshal(q)
	for _, count := range []int{100, 101} {
		v := cloneOrderedApplicationRequest(t, result)
		receipt := v["receipt"].(map[string]any)
		var targets, acks []any
		for i := 0; i < count; i++ {
			device := fmt.Sprintf("pid_8f%06d-0000-4000-8000-%012d", i, i)
			target := map[string]any{"device_id": device, "credential_id": device, "sequence": 999999999, "policy_version": 999999999, "state": "verified", "desired_generation": 999999999, "envelope_digest": "sha256:" + strings.Repeat("b", 64)}
			sourceID := func(seq, digest string) string {
				x, _ := CanonicalDiscoveryID(scope, "security_agent_ordered_source", strings.Join([]string{r, s, device, seq, digest}, "\x1f"))
				return x
			}
			ack := map[string]any{"device_id": device, "credential_id": device, "removed_source_id": sourceID("999999998", "sha256:"+strings.Repeat("a", 64)), "removed_source_digest": "sha256:" + strings.Repeat("a", 64), "removed_sequence": 999999998, "cleanup_source_id": sourceID("999999999", target["envelope_digest"].(string)), "cleanup_source_digest": target["envelope_digest"], "cleanup_sequence": 999999999, "desired_generation": 999999999, "deployment_sequence": 999999999, "deployment_digest": "sha256:" + strings.Repeat("c", 64), "composition_digest": "sha256:" + strings.Repeat("d", 64)}
			ackBody, _ := json.Marshal(ack)
			ack["acknowledgement_id"], _ = CanonicalDiscoveryID(scope, "security_agent_ordered_cleanup_acknowledgement", r+"\x1f"+s+"\x1f"+strings.TrimPrefix(orderedCleanupDigest(ackBody), "sha256:"))
			targets = append(targets, target)
			acks = append(acks, ack)
		}
		v["targets"], receipt["targets"] = targets, acks
		ackBody, _ := json.Marshal(acks)
		receipt["cleanup_deployment_digest"] = strings.TrimPrefix(orderedCleanupDigest(ackBody), "sha256:")
		receiptBody, _ := json.Marshal(receipt)
		v["receipt_digest"] = orderedCleanupDigest(receiptBody)
		body, _ := json.Marshal(v)
		if count == 100 && (len(ackBody) > 120000 || len(receiptBody) > 131072 || len(body) > 262144) {
			t.Fatal("100-target wire budgets cannot represent domain", len(ackBody), len(receiptBody), len(body))
		}
		db := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{`SELECT zasp_sa_multistep_prior.cleanup($1,$2,$3::jsonb)`: body}}
		if _, err := (&securityAgentMultistepAdmissionRepository{database: db}).cleanup(ctx, request, policy.GatewayPolicyKeys{}); (err == nil) != (count == 100) {
			t.Fatal("cleanup decoder target bound", count, err)
		}
		if count == 100 {
			t.Logf("100-target closed decoder evidence only: acknowledgements=%d receipt=%d response=%d bytes", len(ackBody), len(receiptBody), len(body))
		}
	}
}
