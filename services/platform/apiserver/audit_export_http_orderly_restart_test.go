//go:build darwin || linux

package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"
)

// The same live map and provider must survive both API lifetimes and replay.
// Hash one object's metadata and body digest at a time, never copy the export.
type auditHTTPOrderlyInventory struct {
	Identity, Digest string
	Puts, Repeats    int
}

func auditHTTPOrderlyInventorySnapshot(t *testing.T, ctx context.Context, p *auditHTTPSizeProvider) auditHTTPOrderlyInventory {
	t.Helper()
	select {
	case p.gate <- struct{}{}:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer func() { <-p.gate }()
	keys := make([]string, 0, len(p.objects))
	for key := range p.objects {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, key := range keys {
		object := p.objects[key]
		sum := sha256.Sum256(object.Body)
		if err := json.NewEncoder(h).Encode([]any{key, object.Version, len(object.Body), hex.EncodeToString(sum[:]), object.Headers}); err != nil {
			t.Fatal(err)
		}
	}
	return auditHTTPOrderlyInventory{fmt.Sprintf("%p/%p", p, p.objects), hex.EncodeToString(h.Sum(nil)), p.counts["worker-PUT"], p.counts["worker-repeat-PUT"]}
}

// Missing process replacement, ready-worker replay or a numeric API lifetime
// bound must fail this full durable HTTP path, even if all pages are correct.
func TestAuditExportHTTPOrderlyRestartPostgres(t *testing.T) {
	mode := os.Getenv("ZASP_AUDIT_HTTP_SIZE_BUILD")
	root, binaries, retain := auditHTTPSizeBuildChildren(t, mode)
	r := auditHTTPSizeCompositionCase(t, binaries, root, auditHTTPSizeFixture{Rows: 100001, OrderlyRestart: true}, retain)
	pids := map[int]bool{os.Getpid(): true}
	for name, child := range map[string]auditHTTPSizeChildResult{"API A": r.APIA, "API B": r.API, "publisher": r.Publisher, "executor": r.Executor, "ready replay executor": r.Replay} {
		if !child.Joined || child.PID <= 0 || pids[child.PID] || child.PeakRSSBytes <= 0 {
			t.Fatalf("missing independent joined %s lifetime: pid=%d joined=%v peak=%d", name, child.PID, child.Joined, child.PeakRSSBytes)
		}
		pids[child.PID] = true
		if mode == "" && (name == "API A" || name == "API B") && child.PeakRSSBytes > 192<<20 {
			t.Fatalf("%s absolute RSS=%d exceeds unchanged 201326592-byte bound", name, child.PeakRSSBytes)
		}
	}
	t.Logf("orderly restart accepted mode=%q parent=%d API_A=%d API_B=%d publisher=%d executor=%d replay=%d; full uninterrupted memory pairs and crash gates stay separate", mode, os.Getpid(), r.APIA.PID, r.API.PID, r.Publisher.PID, r.Executor.PID, r.Replay.PID)
}
