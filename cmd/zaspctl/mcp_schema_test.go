package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMCPCLIReviewCycle(t *testing.T) {
	baseline := filepath.Join(t.TempDir(), "tool-contract.json")
	scope := []string{"--environment", "pid_10000000-0000-4000-8000-000000000001", "--server", "pid_20000000-0000-4000-8000-000000000001", "--view", "registry-pilot", "--json"}
	pages := `{"request":{"jsonrpc":"2.0","id":"a","method":"tools/list"},"response":{"jsonrpc":"2.0","id":"a","result":{"tools":[{"name":"check","description":"private note","inputSchema":{"type":"object"}}]}}}`
	call := func(want int, data string, args ...string) map[string]any {
		t.Helper()
		var out, diag bytes.Buffer
		cmd := append([]string{args[0]}, scope...)
		cmd = append(cmd, args[1:]...)
		code := mcpSchema(cmd, strings.NewReader(data), &out, &diag)
		if code != want {
			t.Fatalf("exit %d wanted %d: %s", code, want, diag.String())
		}
		if strings.Contains(out.String()+diag.String(), "private note") {
			t.Fatal("supplier data leaked")
		}
		if out.Len() == 0 {
			return nil
		}
		var result map[string]any
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	saved := call(0, pages, "snapshot", "--out", baseline)
	if saved["status"] != "snapshot_saved" {
		t.Fatalf("unexpected %v", saved)
	}
	file, err := os.Stat(baseline)
	if err != nil || runtime.GOOS != "windows" && file.Mode().Perm()&0077 != 0 {
		t.Fatal("unsafe snapshot file")
	}
	call(2, pages, "snapshot", "--out", baseline)
	hash := saved["snapshot_sha256"].(string)
	args := []string{"rescan", "--baseline", baseline, "--baseline-sha256", hash, "--fail-on-change"}
	if res := call(0, pages, args...); res["status"] != "unchanged" {
		t.Fatal(res)
	}
	if res := call(10, strings.Replace(pages, "private note", "new private value", 1), args...); res["status"] != "review_needed" {
		t.Fatal(res)
	}
	call(3, strings.Replace(pages, `"tools":[`, `"nextCursor":"missing","tools":[`, 1), args...)
	if _, err := os.Stat(baseline); err != nil {
		t.Fatal("rescan changed baseline")
	}
}
