//go:build darwin || linux

package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/audit"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type auditBrowserCommand struct {
	Action    string `json:"action"`
	ExportID  string `json:"export_id,omitempty"`
	Directory string `json:"directory,omitempty"`
}

// The parent creates the private directory and owned cluster. No ambient DSN,
// provider endpoint, or pre-completed export can satisfy this process contract.
func TestAuditBrowserProviderProcess(t *testing.T) {
	if os.Getenv("ZASP_AUDIT_BROWSER_PROVIDER") != "true" {
		t.Skip("owned browser provider not selected")
	}
	root := os.Getenv("ZASP_AUDIT_BROWSER_PROVIDER_ROOT")
	destination := os.Getenv("ZASP_AUDIT_BROWSER_DESTINATION_ROOT")
	for _, directory := range []string{root, destination} {
		info, err := os.Lstat(directory)
		if err != nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || !info.IsDir() || info.Mode().Perm() != 0700 {
			t.Fatal("private owned directory required")
		}
	}
	deadline, err := time.Parse(time.RFC3339Nano, os.Getenv("ZASP_AUDIT_BROWSER_DEADLINE"))
	if err != nil || time.Until(deadline) < 30*time.Second || time.Until(deadline) > 35*time.Minute {
		t.Fatal("bounded provider deadline required")
	}
	port, err := strconv.Atoi(os.Getenv("ZASP_AUDIT_BROWSER_PG_PORT"))
	if err != nil || port < 1024 || port > 65535 {
		t.Fatal("owned PostgreSQL port required")
	}
	config, err := pgx.ParseConfig(os.Getenv("ZASP_AUDIT_BROWSER_PROVIDER_DSN"))
	if err != nil || config.Host != "127.0.0.1" || config.Port != uint16(port) || config.User != "zasp_e2e" || config.Database != "postgres" || config.Password != "" || config.TLSConfig != nil || len(config.Fallbacks) != 0 {
		t.Fatal("owned PostgreSQL observer required")
	}
	signaled, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithDeadline(signaled, deadline)
	defer cancel()
	var connections []*pgx.Conn
	connect := func(worker bool) *pgx.Conn {
		selected := config.Copy()
		if worker {
			selected.User = "audit_export_worker_fixture"
		}
		conn, err := pgx.ConnectConfig(ctx, selected)
		if err != nil {
			t.Fatal("owned connection failed", err)
		}
		connections = append(connections, conn)
		return conn
	}
	observer, queueObserver, worker, source, savedSource := connect(false), connect(false), connect(true), connect(false), connect(false)
	defer func() {
		c, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		for _, conn := range connections {
			if err := conn.Close(c); err != nil {
				t.Error(err)
			}
		}
	}()
	policy := migrations.AuditExportConfiguration{PolicyID: "pid_7b000001-0000-4000-8000-000000000001", Bucket: "owned-audit-browser-fixture", ExpectedBucketOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/7b000002-0000-4000-8000-000000000002", MaximumExportBytes: 1073741824, MaximumRetainedBytes: 10737418240, MaximumInflight: 2, CaptureTimeoutSeconds: 120}
	storage, err := newAuditHTTPSizeProvider(ctx, observer, policy)
	if err != nil {
		t.Fatal(err)
	}
	storage.browserReader = true
	bridge := newAuditHTTPSizeBridge(ctx)
	front := httptest.NewTLSServer(bridge)
	defer front.Close()
	var original, saved *auditHTTPSizeExpected
	defer func() {
		c, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if err := bridge.Close(c); err != nil {
			t.Error(err)
		}
		if err := storage.Close(c); err != nil {
			t.Error(err)
		}
		for _, oracle := range []*auditHTTPSizeExpected{original, saved} {
			if oracle != nil {
				if err := oracle.Close(c); err != nil {
					t.Error(err)
				}
			}
		}
	}()
	writePrivate := func(name string, data []byte) {
		f, err := os.OpenFile(filepath.Join(root, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := f.Write(data)
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatal("private file write failed", writeErr, closeErr)
		}
	}
	writePrivate("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: front.Certificate().Raw}))
	writePrivate("token", []byte(auditExportProcessToken))
	listener, err := net.Listen("unix", filepath.Join(root, "control.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "control.sock"), 0600); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	var gate sync.Mutex
	control := &http.Server{ReadHeaderTimeout: time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Minute}
	control.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/" || r.URL.RawQuery != "" {
			http.Error(w, "closed control route", 400)
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		if err != nil {
			http.Error(w, "control too large", 400)
			return
		}
		command, err := auditBrowserReadCommand(raw)
		if err != nil {
			http.Error(w, "control refused", 400)
			return
		}
		gate.Lock()
		defer gate.Unlock()
		var result any = map[string]bool{"ok": true}
		switch command.Action {
		case "stop":
			cancel()
		case "bind":
			if original != nil {
				http.Error(w, "already bound", 409)
				return
			}
			var org, workspace, environment string
			err = observer.QueryRow(ctx, `SELECT organization_id,workspace_id,environment_id FROM zasp_audit_export_jobs WHERE id=$1 AND policy_id=$2 AND organization_id='pid_10000001-0000-4000-8000-000000000001' AND workspace_id='pid_10000002-0000-4000-8000-000000000002' AND environment_id='pid_10000003-0000-4000-8000-000000000003' AND status='queued' AND NOT captured`, command.ExportID, policy.PolicyID).Scan(&org, &workspace, &environment)
			if err == nil {
				original, err = newAuditBrowserMixedExpected(ctx, source, org)
			}
			if err == nil {
				saved, err = newAuditBrowserMixedExpected(ctx, savedSource, org)
			}
			args := make([]any, 13)
			args[0], args[1], args[2], args[7] = org, workspace, environment, command.ExportID
			args[11], args[12] = migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint()
			if err == nil {
				err = storage.Bind(args, original)
			}
			if err == nil {
				provider := &auditExportProcessProvider{observer: queueObserver, worker: worker, args: args, objects: map[string]auditExportProcessObject{}, identities: map[string]int{}, assumes: map[string]int{}, policy: policy, forwardS3: storage}
				handler, _ := auditBrowserReaderSTS(http.HandlerFunc(provider.serve))
				err = bridge.Install(handler)
			}
		case "verify":
			if saved == nil {
				http.Error(w, "not bound", 409)
				return
			}
			binding := storage.binding
			err = observer.QueryRow(ctx, `SELECT capture_id FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2 AND status='ready'`, binding.OrganizationID, binding.ExportID).Scan(&binding.CaptureID)
			if err == nil {
				result, err = auditBrowserVerifySaved(ctx, filepath.Join(destination, command.Directory), saved, binding)
			}
			if err == nil {
				summary := result.(auditHTTPSizeSummary)
				var exact bool
				err = queueObserver.QueryRow(ctx, `SELECT status='ready' AND captured AND event_count=$3 AND chunk_count=$4 AND chunk_bytes=$5 AND encode(chain_root,'hex')=$6 AND encode(digest(manifest_bytes,'sha256'),'hex')=$7 AND (SELECT count(*) FROM zasp_audit_export_receipts r WHERE r.organization_id=j.organization_id AND r.export_id=j.id)=$4+1 AND NOT EXISTS(SELECT 1 FROM zasp_audit_export_receipts r JOIN zasp_audit_export_intents i USING(organization_id,export_id,kind,ordinal) WHERE r.organization_id=j.organization_id AND r.export_id=j.id AND (r.sha256<>i.sha256 OR r.size_bytes<>i.size_bytes OR r.version_id='')) FROM zasp_audit_export_jobs j WHERE organization_id=$1 AND id=$2`, binding.OrganizationID, binding.ExportID, summary.Events, summary.Chunks, summary.ChunkBytes, summary.ChainRoot, summary.ManifestSHA256).Scan(&exact)
				if err == nil && !exact {
					err = errors.New("registered SQL receipts differ from independently saved snapshot")
				}
				if err == nil {
					err = storage.Check()
				}
			}
		}
		if err != nil {
			t.Log("owned provider control failed", command.Action, err)
			http.Error(w, "owned provider control failed", 409)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})
	joined := make(chan error, 1)
	go func() { joined <- control.Serve(listener) }()
	ready := struct {
		Schema  string `json:"schema"`
		PID     int    `json:"pid"`
		Address string `json:"address"`
		Control string `json:"control"`
		CA      string `json:"ca"`
		Token   string `json:"token"`
	}{"audit-browser-provider-v1", os.Getpid(), front.Listener.Addr().String(), filepath.Join(root, "control.sock"), filepath.Join(root, "ca.pem"), filepath.Join(root, "token")}
	raw, _ := json.Marshal(ready)
	writePrivate("ready.json", append(raw, '\n'))
	<-ctx.Done()
	shutdown, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	if err := control.Shutdown(shutdown); err != nil {
		_ = control.Close()
		t.Error(err)
	}
	if err := <-joined; err != http.ErrServerClosed {
		t.Error(err)
	}
	t.Log("owned provider listener and control joined")
}

func auditBrowserVerifySaved(ctx context.Context, directory string, expected *auditHTTPSizeExpected, binding audit.ExportBinding) (auditHTTPSizeSummary, error) {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return auditHTTPSizeSummary{}, errors.New("owned real directory required")
	}
	if err := expected.Reset(ctx, binding); err != nil {
		return auditHTTPSizeSummary{}, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return auditHTTPSizeSummary{}, err
	}
	defer root.Close()
	compare := func(name string, want []byte) error {
		info, err := root.Lstat(name)
		if err != nil || !info.Mode().IsRegular() || info.Size() != int64(len(want)) {
			return errors.New("saved file size/type mismatch")
		}
		f, err := root.Open(name)
		if err != nil {
			return err
		}
		actual, readErr := io.ReadAll(io.LimitReader(f, audit.ExportMaximumChunkBytes+1))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil || !bytes.Equal(actual, want) {
			return errors.New("saved canonical bytes differ from original raw source")
		}
		return nil
	}
	for index := 1; ; index++ {
		chunk, err := expected.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			return auditHTTPSizeSummary{}, err
		}
		if err := compare(fmt.Sprintf("chunk-%06d.json", index), chunk); err != nil {
			return auditHTTPSizeSummary{}, err
		}
	}
	manifest, summary, err := expected.Manifest()
	if err == nil {
		err = compare("manifest.json", manifest)
	}
	if err == nil {
		directoryFile, openErr := root.Open(".")
		if openErr != nil {
			return summary, openErr
		}
		defer directoryFile.Close()
		var files int64
		for {
			names, readErr := directoryFile.Readdirnames(1)
			files += int64(len(names))
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return summary, readErr
			}
			if files > summary.Chunks+1 {
				return summary, errors.New("unaccounted saved file")
			}
		}
		if files != summary.Chunks+1 {
			return summary, errors.New("saved inventory mismatch")
		}
	}
	return summary, err
}

func auditBrowserReadCommand(raw []byte) (auditBrowserCommand, error) {
	var command auditBrowserCommand
	if len(raw) == 0 || len(raw) > 4096 || json.Unmarshal(raw, &command) != nil {
		return command, errors.New("bounded control required")
	}
	canonical, _ := json.Marshal(command)
	if !bytes.Equal(raw, canonical) {
		return command, errors.New("canonical control required")
	}
	switch command.Action {
	case "bind":
		if _, err := domain.ParseProductID(command.ExportID); err == nil && command.Directory == "" {
			return command, nil
		}
	case "verify":
		if command.ExportID == "" && strings.HasPrefix(command.Directory, "audit-export-") && filepath.Base(command.Directory) == command.Directory && !strings.ContainsAny(command.Directory, "\\\x00\r\n") {
			return command, nil
		}
	case "stop":
		if command.ExportID == "" && command.Directory == "" {
			return command, nil
		}
	}
	return command, errors.New("closed control command required")
}

func TestAuditHTTPSizeProviderBrowserControlRejectsMalformedCommands(t *testing.T) {
	for _, raw := range []string{`{"action":"bind","export_id":"pid_10000004-0000-4000-8000-000000000004"}`, `{"action":"stop"}`, `{"action":"verify","directory":"audit-export-owned"}`} {
		if _, err := auditBrowserReadCommand([]byte(raw)); err != nil {
			t.Fatal("valid closed command refused", err)
		}
	}
	for _, raw := range []string{`{"action":"bind","export_id":"foreign"}`, `{"action":"bind","action":"stop"}`, `{"action":"stop","extra":true}`, `{"action":"verify","directory":"../foreign"}`, `{"action":"verify","directory":"/tmp/foreign"}`, `{"action":"bind"}`, `{"action":"other"}`, `{"action":"stop"} {}`} {
		if _, err := auditBrowserReadCommand([]byte(raw)); err == nil {
			t.Fatal("malformed control admitted", raw)
		}
	}
}

// A completed-looking manifest must not hide unrelated or substituted local
// files. This exercises the real bounded filesystem verifier, not a writer.
func TestAuditHTTPSizeProviderBrowserSavedVerifierRejectsUnaccountedFiles(t *testing.T) {
	for _, change := range []string{"exact", "extra", "corrupt", "symlink", "directory-symlink"} {
		t.Run(change, func(t *testing.T) {
			ctx := context.Background()
			fixture := auditHTTPSizeTestOracle(t, 1, auditHTTPSizeTestRow)
			chunk, err := fixture.Next(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.Next(ctx); err != io.EOF {
				t.Fatal(err)
			}
			manifest, _, err := fixture.Manifest()
			if err != nil {
				t.Fatal(err)
			}
			directory := t.TempDir()
			for name, body := range map[string][]byte{"chunk-000001.json": chunk, "manifest.json": manifest} {
				if err := os.WriteFile(filepath.Join(directory, name), body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch change {
			case "directory-symlink":
				link := filepath.Join(t.TempDir(), "audit-export-link")
				if err := os.Symlink(directory, link); err != nil {
					t.Fatal(err)
				}
				directory = link
			case "extra":
				if err := os.WriteFile(filepath.Join(directory, "chunk-000002.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				chunk[0] = '['
				if err := os.WriteFile(filepath.Join(directory, "chunk-000001.json"), chunk, 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				external := t.TempDir()
				if err := os.WriteFile(filepath.Join(external, "manifest.json"), manifest, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(filepath.Join(directory, "manifest.json"), filepath.Join(directory, "manifest-original.json")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(external, "manifest.json"), filepath.Join(directory, "manifest.json")); err != nil {
					t.Fatal(err)
				}
			}
			independent := auditHTTPSizeTestOracle(t, 1, auditHTTPSizeTestRow)
			summary, err := auditBrowserVerifySaved(ctx, directory, independent, auditHTTPSizeTestBinding())
			if change == "exact" {
				if err != nil || summary.Events != 1 || summary.Chunks != 1 {
					t.Fatal("exact saved bytes refused", summary, err)
				}
			} else if err == nil {
				t.Fatal("unaccounted or substituted file accepted", change)
			}
		})
	}
}
