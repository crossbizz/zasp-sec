package main

import (
	"context"
	"crypto/ed25519"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// Calls the shipped serial policy loop, not an equivalent fixture loop. The
// repository verifies each stored envelope before its real native ack. This
// does not claim downstream gateway network consumption or enforcement.
func assertOrderedMaximumProductPolicy(t *testing.T, ctx context.Context, owner *pgxpool.Pool, product *temporalSecurityAgentProduct, start orchestration.StartRequest, trace *orderedCapacityTrace, prefix ...func(string, func() int32)) {
	t.Helper()
	if !orderedCapacityPrefixCallbackValid(os.Getenv("ZASP_P7_ORDERED_POLICY_PREFIX"), prefix) {
		t.Fatal("invalid capacity prefix callback")
	}
	directory := os.Getenv("ZASP_P7_ORDERED_POLICY_KEYS")
	if !filepath.IsAbs(directory) {
		t.Fatal("owned policy key directory required")
	}
	read := func(name string, size int) []byte {
		p := filepath.Join(directory, name)
		info, err := os.Lstat(p)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0400 || info.Size() != int64(size) {
			t.Fatal("owned policy key file shape")
		}
		b, err := os.ReadFile(p)
		if err != nil || len(b) != size {
			t.Fatal("owned policy key file read")
		}
		return b
	}
	public := read("public", ed25519.PublicKeySize)
	keys, err := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": public})
	if err != nil {
		t.Fatal("actual fixture public verifier")
	}
	var calls atomic.Int32
	product.orderedPolicyKeyID, product.orderedPolicyKeys = "ordered-key-01", keys
	product.orderedPolicySigner = func(c context.Context, input policy.GatewayPolicySigningInput) (policy.GatewayPolicyEnvelope, error) {
		calls.Add(1)
		secret := read("private", ed25519.PrivateKeySize)
		defer clear(secret)
		return policy.SignGatewayPolicyEnvelope(input, ed25519.PrivateKey(secret))
	}
	product.signing = func() (string, ed25519.PrivateKey, policy.GatewayPolicyKeys, error) {
		t.Fatal("named capacity called legacy signer")
		return "", nil, policy.GatewayPolicyKeys{}, nil
	}
	var step string
	var exact bool
	if err := owner.QueryRow(ctx, `SELECT step_id,jsonb_array_length(snapshot->'targets')=100 AND state='started' FROM zasp_temporal68.effects WHERE run_id=$1 AND action_key='create_temporary_policy'`, start.Ref.RunID).Scan(&step, &exact); err != nil || !exact {
		t.Fatal("actual maximum started effect required")
	}
	if len(prefix) == 1 {
		prefix[0](step, calls.Load)
		return
	}
	began := time.Now()
	// The real Temporal server owns production20m attempts/1h scheduling and
	// five retries. This is Apply activity integration, not full workflow E2E.
	err = runOrderedCapacityApplyActivity(t, ctx, owner, product, start, trace)
	t.Log("actual maximum Apply activity elapsed_ms", time.Since(began).Milliseconds(), "signer_calls", calls.Load(), "class", orderedCapacityClass(err), "last_phase", trace.lastPhase())
	var stored, sources, deliveries, receipts int
	if queryErr := owner.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$1 AND step_id=$2 AND phase='apply' AND state='stored'),
 (SELECT count(*) FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$1 AND step_id=$2 AND phase='apply' AND state='verified'),
 (SELECT count(*) FROM zasp_temporal68.deliveries WHERE run_id=$1 AND step_id=$2 AND phase='apply' AND state='acknowledged' AND read_at IS NOT NULL AND acknowledged_at IS NOT NULL),
 (SELECT count(*) FROM zasp_sa_multistep_receipts WHERE run_id=$1 AND step_id=$2 AND receipt_kind='temporary_policy_applied.v1')`, start.Ref.RunID, step).Scan(&stored, &sources, &deliveries, &receipts); queryErr != nil {
		t.Fatal("maximum progress read unavailable")
	}
	t.Log("actual maximum progress stored_sources", stored, "verified_sources", sources, "acknowledged_deliveries", deliveries, "application_receipts", receipts)
	if err != nil {
		t.Fatal("actual maximum Apply activity failed under production retry contract")
	}
	if calls.Load() != 200 || sources != 100 || deliveries != 100 || receipts != 1 {
		t.Fatal("incomplete maximum product consumption")
	}
	if err := owner.QueryRow(ctx, `SELECT
 (SELECT count(*)=1 FROM zasp_security_agent_controls WHERE run_id=$1 AND step_id=$2 AND state='active')
 AND (SELECT count(*)=100 AND bool_and(expires_at>clock_timestamp()) FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$1 AND step_id=$2 AND phase='apply')
 AND NOT zasp_authorization80_worker.runtime_ready()`, start.Ref.RunID, step).Scan(&exact); err != nil || !exact {
		t.Fatal("maximum receipt/current expiry/control boundary")
	}
}
