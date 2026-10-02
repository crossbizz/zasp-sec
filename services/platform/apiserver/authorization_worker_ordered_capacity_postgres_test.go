package apiserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Full shipped policy-loop capacity is separate from the maximum proof-set
// boundary. No engine, paid provider, fabricated ack, or modified TTL is used.
func TestP7Ordered68MaximumProductPolicy(t *testing.T) {
	runOrdered68CapacityProduct(t, "")
}

// This is a measured real prefix, not Temporal retry or full100 acceptance.
func TestP7Ordered68PolicyPrefixProfile(t *testing.T) {
	if os.Getenv("ZASP_ORDERED_POLICY_PREFIX") != "1" {
		t.Skip("explicit prefix profile opt-in required")
	}
	runOrdered68CapacityProduct(t, "1")
}

func TestP7Ordered68PolicyThreeTargetProfile(t *testing.T) {
	if os.Getenv("ZASP_ORDERED_POLICY_PREFIX") != "3" {
		t.Skip("explicit three-target profile opt-in required")
	}
	runOrdered68CapacityProduct(t, "3")
}

func runOrdered68CapacityProduct(t *testing.T, prefix string) {
	t.Helper()
	if prefix != "" && prefix != "1" && prefix != "3" {
		t.Fatal("invalid capacity diagnostic mode")
	}
	if os.Getenv("ZASP_ORDERED_POLICY_CAPACITY") != "100" {
		t.Skip("explicit full100 product-loop opt-in required")
	}
	binary := filepath.Join(t.TempDir(), "worker-capacity")
	buildCtx, stopBuild := context.WithTimeout(context.Background(), 2*time.Minute)
	build := exec.CommandContext(buildCtx, "go", "test", "-p=1", "-c", "-o", binary, "../agentsec-worker")
	output, err := build.CombinedOutput()
	stopBuild()
	if err != nil {
		t.Fatalf("capacity test build failed: diagnostic_bytes=%d", len(output))
	}
	consumed := false
	runOrdered68PolicyAcceptance(t, false, false, false, &ordered68PolicyAcceptance{
		capacity: true,
		prepare: func(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e string) {
			for i := 1; i <= 99; i++ {
				seedOrderedApplicationGatewayAt(t, ctx, owner, o, w, e, ordered68MaximumDevice(i))
			}
		},
		consume: func(f ordered68PolicyAcceptanceContext) {
			consumed = true
			worker := f.newWorker(f.checker)
			f.start(worker)
			// Existing registered compensation login and a distinct purpose key;
			// this is key registration, never a product authorization/effect receipt.
			key, keyErr := authorization.NewWorkerKey(authorization.CapturedCompensation, bytes.Repeat([]byte{92}, 32))
			if keyErr != nil {
				t.Fatal("capacity compensation key")
			}
			if _, err := f.owner.Exec(f.ctx, `SELECT zasp_authorization80_worker.register_verifier($1,$2,$3)`, string(authorization.CapturedCompensation), key.Version(), key.Verifier()); err != nil {
				t.Fatal("capacity verifier registration", ordered68ErrorClass(err))
			}
			var identity json.RawMessage
			if err := f.owner.QueryRow(f.ctx, `SELECT jsonb_build_object('organization_id',r.organization_id,'workspace_id',r.workspace_id,'environment_id',r.environment_id,'run_id',r.run_id,'definition_version',r.definition_version,'input_digest',c.input_digest) FROM zasp_security_agent_runs r JOIN zasp_temporal65.commands c USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1 AND c.kind='start'`, f.run).Scan(&identity); err != nil {
				t.Fatal("actual capacity start identity", ordered68ErrorClass(err))
			}
			settings, err := json.Marshal(f.config)
			if err != nil {
				t.Fatal("capacity settings")
			}
			keys := t.TempDir()
			if os.WriteFile(filepath.Join(keys, "private"), f.private, 0400) != nil || os.WriteFile(filepath.Join(keys, "public"), f.private.Public().(ed25519.PublicKey), 0400) != nil {
				t.Fatal("capacity owned key files")
			}
			timeout := "63m"
			if prefix != "" {
				timeout = "4m"
			}
			child := exec.CommandContext(f.ctx, binary, "-test.run=^TestP7OrderedActualRunnerNative$", "-test.v", "-test.timeout="+timeout)
			child.Dir = "../agentsec-worker"
			child.WaitDelay = 5 * time.Second
			child.Env = append(orderedRunnerChildEnvironment(t.TempDir()), "ZASP_P7_ORDERED_OWNER_DSN="+f.owner.Config().ConnString(), "ZASP_P7_ORDERED_CONFIG="+string(settings), "ZASP_P7_ORDERED_START="+string(identity), "ZASP_P7_ORDERED_EXECUTOR="+f.login, "ZASP_P7_ORDERED_POLICY_CAPACITY=100", "ZASP_P7_ORDERED_POLICY_KEYS="+keys)
			if prefix != "" {
				child.Env = append(child.Env, "ZASP_P7_ORDERED_POLICY_PREFIX="+prefix)
			}
			output, err := orderedRunnerChildOutput(child)
			if err != nil || !bytes.Contains(output, []byte("--- PASS: TestP7OrderedActualRunnerNative")) || bytes.Contains(output, []byte("--- SKIP:")) {
				t.Fatalf("actual maximum policy child failed; diagnostic_bytes=%d\n%s", len(output), output)
			}
			t.Log(string(output))
		},
	})
	if !t.Failed() && !consumed {
		t.Fatal("maximum product consumer not reached")
	}
}
