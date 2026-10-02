//go:build darwin || linux

package apiserver

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/internal/testprocess"
)

// Dropping either gate or accepting a missing kernel sample must fail these
// literal cases; expected values don't reuse the normalization/gate logic.
func TestAuditHTTPSizeMemoryGate(t *testing.T) {
	for _, c := range []struct {
		small, full int64
		refuse      bool
	}{
		{144 << 20, 192 << 20, false}, {144 << 20, (192 << 20) + 1, true},
		{100 << 20, 148 << 20, false}, {100 << 20, (148 << 20) + 1, true},
		{192 << 20, 192 << 20, false}, {192 << 20, 1, false},
		{0, 1, true}, {1, 0, true}, {-1, 1, true}, {1, -1, true},
	} {
		if err := auditHTTPSizeMemoryGate(c.small, c.full); (err != nil) != c.refuse {
			t.Errorf("small=%d full=%d refusal=%v want=%v", c.small, c.full, err, c.refuse)
		}
	}
	for _, c := range []struct {
		os        string
		raw, want int64
		refuse    bool
	}{
		{"darwin", 1234, 1234, false}, {"linux", 1234, 1263616, false},
		{"darwin", 0, 0, true}, {"linux", -1, 0, true}, {"windows", 1, 0, true},
		{"linux", math.MaxInt64, 0, true}, {"darwin", math.MaxInt64, math.MaxInt64, false},
	} {
		n, err := auditHTTPSizeNormalizeRSS(c.os, c.raw)
		if (err != nil) != c.refuse || n != c.want {
			t.Errorf("OS=%s raw=%d got=%d err=%v want=%d refuse=%v", c.os, c.raw, n, err, c.want, c.refuse)
		}
	}
}

func auditHTTPSizeMemoryGate(small, full int64) error {
	if small <= 0 || full <= 0 {
		return errors.New("missing positive kernel peaks")
	}
	growth := max(int64(0), full-small)
	if full > 192<<20 || growth > 48<<20 {
		return fmt.Errorf("RSS gate refused: small=%d full=%d growth=%d limits=201326592/50331648", small, full, growth)
	}
	return nil
}
func auditHTTPSizeNormalizeRSS(goos string, maximum int64) (int64, error) {
	if maximum <= 0 {
		return 0, errors.New("missing positive Maxrss")
	}
	switch goos {
	case "darwin":
		return maximum, nil
	case "linux":
		if maximum <= math.MaxInt64/1024 {
			return maximum * 1024, nil
		}
	}
	return 0, errors.New("unsupported or overflowing Maxrss")
}

func TestAuditHTTPSizeMemoryKernelExit(t *testing.T) {
	if _, err := auditHTTPSizePeak(nil); err == nil {
		t.Fatal("missing process state accepted")
	}
	for _, script := range []string{"exit 0", "exit 7", "kill -TERM $$"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.Command("/bin/sh", "-c", script)
		_, runErr := testprocess.Run(ctx, cmd)
		cancel()
		// The failure branches aren't inspected by real launchers. This focused
		// unit exercises Peak's own defensive exit validation after Run returns.
		peak, err := auditHTTPSizePeak(cmd.ProcessState)
		if script == "exit 0" {
			if runErr != nil || err != nil || peak <= 0 {
				t.Fatal(runErr, err, peak)
			}
		} else if err == nil {
			t.Fatal("failed/signaled exit accepted")
		}
	}
}
func TestAuditHTTPSizeMemoryBuildIdentity(t *testing.T) {
	for _, mode := range []string{"", "race"} {
		info := &debug.BuildInfo{GoVersion: "go1.25.6", Settings: []debug.BuildSetting{{Key: "GOOS", Value: runtime.GOOS}, {Key: "GOARCH", Value: runtime.GOARCH}}}
		if mode == "race" {
			info.Settings = append(info.Settings, debug.BuildSetting{Key: "-race", Value: "true"})
		}
		if err := auditHTTPSizeBuildIdentity(info, mode); err != nil {
			t.Fatal(err)
		}
		info.GoVersion = "go1.25.5"
		if auditHTTPSizeBuildIdentity(info, mode) == nil {
			t.Fatal("unpinned build accepted")
		}
	}
	for _, c := range []struct{ mode, key, value string }{{"", "-race", "true"}, {"race", "-race", "false"}, {"", "GOOS", "wrong"}, {"", "GOARCH", "wrong"}, {"bad", "GOOS", runtime.GOOS}} {
		info := &debug.BuildInfo{GoVersion: "go1.25.6", Settings: []debug.BuildSetting{{Key: "GOOS", Value: runtime.GOOS}, {Key: "GOARCH", Value: runtime.GOARCH}, {Key: c.key, Value: c.value}}}
		if auditHTTPSizeBuildIdentity(info, c.mode) == nil {
			t.Fatal("build mismatch accepted", c)
		}
	}
	for _, key := range []string{"GOFLAGS", "GOENV", "GOTOOLCHAIN", "GOEXPERIMENT", "GOOS", "GOARCH"} {
		t.Setenv(key, "ambient-fixture")
	}
	for _, entry := range auditHTTPSizeBuildEnvironment() {
		if strings.HasSuffix(entry, "=ambient-fixture") {
			t.Fatal("ambient build input survived", entry)
		}
	}
}
func TestAuditHTTPSizeMemoryAPIRetention(t *testing.T) {
	retain := new(auditHTTPSizeRetained)
	handler := retain.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/denied" {
			w.WriteHeader(403)
		}
		_, _ = w.Write([]byte("abc"))
		_, _ = w.Write([]byte("def"))
	}))
	for _, c := range []struct {
		method, path string
		want         int64
	}{{"GET", "/ok", 6}, {"POST", "/ok", 6}, {"GET", "/denied", 6}, {"GET", "/ok", 12}} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(c.method, c.path, nil))
		if w.Body.String() != "abcdef" || retain.Bytes() != c.want {
			t.Fatal("GET retention changed traffic or copied wrong status", retain.Bytes(), c.want)
		}
	}
}
func auditHTTPSizePeak(state *os.ProcessState) (int64, error) {
	if state == nil || !state.Success() || !state.Exited() {
		return 0, errors.New("normal child exit required")
	}
	usage, ok := state.SysUsage().(*syscall.Rusage)
	if !ok || usage == nil {
		return 0, errors.New("kernel rusage missing")
	}
	return auditHTTPSizeNormalizeRSS(runtime.GOOS, usage.Maxrss)
}
func auditHTTPSizeBuildIdentity(info *debug.BuildInfo, mode string) error {
	if info == nil || info.GoVersion != "go1.25.6" || mode != "" && mode != "race" {
		return errors.New("unpinned build/mode")
	}
	settings := map[string]string{}
	for _, s := range info.Settings {
		if _, exists := settings[s.Key]; exists {
			return errors.New("duplicate build setting")
		}
		settings[s.Key] = s.Value
	}
	if settings["GOOS"] != runtime.GOOS || settings["GOARCH"] != runtime.GOARCH || (settings["-race"] == "true") != (mode == "race") {
		return errors.New("build OS/architecture/race mismatch")
	}
	return nil
}
func auditHTTPSizeBuildEnvironment() []string {
	var result []string
	for _, entry := range auditHTTPSizeEnvironment() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "GO") || strings.HasPrefix(key, "CGO") {
			continue
		}
		result = append(result, entry)
	}
	return append(result, "GOENV=off", "GOTOOLCHAIN=local", "GOGC=100", "GOMEMLIMIT=off", "GOMAXPROCS=2")
}

func auditHTTPSizeToolchain(ctx context.Context) (string, error) {
	binary, err := exec.LookPath("go")
	if err != nil {
		return "", err
	}
	cmd := exec.Command(binary, "env", "GOVERSION", "GOOS", "GOARCH")
	cmd.Env = auditHTTPSizeBuildEnvironment()
	out, err := testprocess.Run(ctx, cmd)
	if err != nil || string(bytes.TrimSpace(out)) != "go1.25.6\n"+runtime.GOOS+"\n"+runtime.GOARCH {
		return "", fmt.Errorf("available Go is not pinned go1.25.6 %s/%s: %v", runtime.GOOS, runtime.GOARCH, err)
	}
	return binary, nil
}
func auditHTTPSizeVerifyBinary(path, mode string) error {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return err
	}
	return auditHTTPSizeBuildIdentity(info, mode)
}

type auditHTTPSizeRetained struct {
	mu     sync.Mutex
	chunks [][]byte
	count  int64
}

func (r *auditHTTPSizeRetained) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			next.ServeHTTP(w, request)
			return
		}
		next.ServeHTTP(&auditHTTPSizeRetainingWriter{ResponseWriter: w, retained: r}, request)
	})
}
func (r *auditHTTPSizeRetained) Bytes() int64 { r.mu.Lock(); defer r.mu.Unlock(); return r.count }

type auditHTTPSizeRetainingWriter struct {
	http.ResponseWriter
	retained *auditHTTPSizeRetained
	status   int
}

func (w *auditHTTPSizeRetainingWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *auditHTTPSizeRetainingWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(p)
	if w.status >= 200 && w.status < 300 && n > 0 {
		w.retained.mu.Lock()
		w.retained.chunks = append(w.retained.chunks, append([]byte(nil), p[:n]...))
		w.retained.count += int64(n)
		w.retained.mu.Unlock()
	}
	return n, err
}

func auditHTTPSizePair(t *testing.T, binaries map[string]string, root string, retain *bool, control string, diagnostics bool, numeric bool) [2]auditHTTPSizeCaseResult {
	t.Helper()
	var results [2]auditHTTPSizeCaseResult
	for i, name := range []string{"small", "full"} {
		rows := 1000
		if i == 1 {
			rows = 100001
		}
		if !t.Run(name, func(t *testing.T) {
			results[i] = auditHTTPSizeCompositionCase(t, binaries, root, auditHTTPSizeFixture{Rows: rows, Control: control, Diagnostics: diagnostics}, retain)
		}) {
			t.Fatal("pair incomplete; memory evidence refused")
		}
	}
	for _, role := range []string{"api", "executor", "publisher"} {
		small, full := results[0].API, results[1].API
		if role == "executor" {
			small, full = results[0].Executor, results[1].Executor
		}
		if role == "publisher" {
			small, full = results[0].Publisher, results[1].Publisher
		}
		if small.PeakRSSBytes <= 0 || full.PeakRSSBytes <= 0 {
			t.Fatal("missing pair kernel peaks")
		}
		if diagnostics != (small.SelfRSSBytes > 0 && full.SelfRSSBytes > 0) {
			t.Fatal("diagnostic mode not observed")
		}
		accumulation := role == "api" && control == "api-retain" || role == "executor" && control == "worker-retain"
		if accumulation {
			if small.RetainedBytes < results[0].Summary.ChunkBytes || full.RetainedBytes < results[1].Summary.ChunkBytes {
				t.Fatal("control did not retain verified actual traffic", role)
			}
		} else if small.RetainedBytes != 0 || full.RetainedBytes != 0 {
			t.Fatal("normal child retained traffic", role)
		}
		gate := auditHTTPSizeMemoryGate(small.PeakRSSBytes, full.PeakRSSBytes)
		t.Logf("PAIR role=%s numeric=%v control=%q diagnostics=%v smallPID=%d fullPID=%d smallRSS=%d fullRSS=%d growth=%d smallRetained=%d fullRetained=%d gate=%v", role, numeric, control, diagnostics, small.PID, full.PID, small.PeakRSSBytes, full.PeakRSSBytes, max(int64(0), full.PeakRSSBytes-small.PeakRSSBytes), small.RetainedBytes, full.RetainedBytes, gate)
		if numeric && role != "publisher" {
			if accumulation && gate == nil {
				t.Fatal("sensitivity failure: unchanged memory gate accepted actual accumulation", role)
			}
			if !accumulation && gate != nil {
				t.Fatal(gate)
			}
		}
	}
	return results
}

func TestAuditExportHTTPSizeMemorySensitivityPostgres(t *testing.T) {
	if os.Getenv("ZASP_AUDIT_HTTP_SIZE_BUILD") != "" {
		t.Fatal("sensitivity requires explicit non-race child build")
	}
	root, binaries, retain := auditHTTPSizeBuildChildren(t, "")
	for _, control := range []string{"api-retain", "worker-retain"} {
		t.Run(control, func(t *testing.T) { auditHTTPSizePair(t, binaries, root, retain, control, false, true) })
	}
}

func TestAuditExportHTTPSizeProcessPostgres(t *testing.T) {
	mode := os.Getenv("ZASP_AUDIT_HTTP_SIZE_BUILD")
	root, binaries, retain := auditHTTPSizeBuildChildren(t, mode)
	if mode == "race" {
		t.Run("functional-race", func(t *testing.T) { auditHTTPSizePair(t, binaries, root, retain, "", false, false) })
		return
	}
	var pairs [3][2]auditHTTPSizeCaseResult
	// N2/N3 are also the diagnostics-off/on perturbation comparison. These are
	// precisely three fresh serial normal pairs, with no extra calibration run.
	for i, name := range []string{"N1-off", "N2-off", "N3-on"} {
		if !t.Run(name, func(t *testing.T) { pairs[i] = auditHTTPSizePair(t, binaries, root, retain, "", i == 2, true) }) {
			t.Fatal("normal pair refused")
		}
	}
	for i, size := range []string{"small", "full"} {
		off, on := pairs[1][i], pairs[2][i]
		if off.API.PeakRSSBytes == 0 || on.API.PeakRSSBytes == 0 {
			continue
		} // a selected single pair has no perturbation claim
		t.Logf("PERTURBATION N2-off/N3-on size=%s separate-lifetimes API=%d/%d delta=%d executor=%d/%d delta=%d publisher=%d/%d delta=%d", size, off.API.PID, on.API.PID, on.API.PeakRSSBytes-off.API.PeakRSSBytes, off.Executor.PID, on.Executor.PID, on.Executor.PeakRSSBytes-off.Executor.PeakRSSBytes, off.Publisher.PID, on.Publisher.PID, on.Publisher.PeakRSSBytes-off.Publisher.PeakRSSBytes)
	}
}
