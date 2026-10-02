//go:build darwin || linux

package main

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/auditexportconfig"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/testprocess"
	"golang.org/x/sys/unix"
)

// An inherited blocking FD must not keep a successful child alive while its
// parent still owns the writer. os.Pipe alone does not exercise ExtraFiles.
func TestAuditExportLocalStackChildInheritedNormalClose(t *testing.T) {
	if os.Getenv("ZASP_AUDIT_LOCALSTACK_LIVENESS_CHILD") == "true" {
		reader, err := auditLocalstackInheritedLiveness()
		if err != nil {
			t.Fatal(err)
		}
		_, closeLife := auditLocalstackChildLifetime(context.Background(), reader)
		// Allow the inherited reader to enter Read while the writer stays open.
		time.Sleep(100 * time.Millisecond)
		if err := closeLife(); err != nil {
			t.Fatal(err)
		}
		t.Log("inherited liveness reader joined with parent writer open")
		return
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	command := exec.Command(os.Args[0], "-test.run=^TestAuditExportLocalStackChildInheritedNormalClose$", "-test.v")
	command.Env = []string{"ZASP_AUDIT_LOCALSTACK_LIVENESS_CHILD=true"}
	command.ExtraFiles = []*os.File{reader}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	output, err := testprocess.Run(ctx, command)
	if err != nil {
		t.Fatalf("inherited normal-close child did not join: %v\n%s", err, output)
	}
}

func TestAuditExportLocalStackChildLiveness(t *testing.T) {
	for _, data := range []bool{false, true} {
		t.Run(map[bool]string{false: "EOF", true: "data-refused"}[data], func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			ctx, closeLife := auditLocalstackChildLifetime(context.Background(), reader)
			if data {
				if _, err := writer.Write([]byte("x")); err != nil {
					t.Fatal(err)
				}
			} else {
				writer.Close()
			}
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("parent loss did not cancel child")
			}
			if err := closeLife(); (err != nil) != data {
				t.Fatal("liveness protocol outcome", err)
			}
		})
	}
}

func auditLocalstackChildLifetime(parent context.Context, reader *os.File) (context.Context, func() error) {
	ctx, cancel := context.WithCancel(parent)
	var closing atomic.Bool
	done := make(chan error, 1)
	go func() {
		var one [1]byte
		n, err := reader.Read(one[:])
		if n != 0 {
			err = errors.New("parent liveness stream contained data")
		} else if err == io.EOF || closing.Load() && errors.Is(err, os.ErrClosed) {
			err = nil
		}
		cancel()
		done <- err
	}()
	return ctx, func() error { closing.Store(true); reader.Close(); cancel(); return <-done }
}

// Dedicated entry point; the controlled-provider child's fixed policy contract
// remains unchanged. Publisher never reads the storage policy or constructs S3.
func TestAuditExportLocalStackProcessWorkerPostgres(t *testing.T) {
	dsn := os.Getenv("ZASP_AUDIT_EXPORT_LOCALSTACK_DSN")
	if dsn == "" {
		t.Skip("requires owned LocalStack parent")
	}
	signalCtx, stopSignal := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignal()
	life, err := auditLocalstackInheritedLiveness()
	if err != nil {
		t.Fatal(err)
	}
	ctx, closeLife := auditLocalstackChildLifetime(signalCtx, life)
	defer func() {
		if err := closeLife(); err != nil {
			t.Error("child liveness join", err)
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, 100*time.Second)
	defer cancel()
	mode := os.Getenv("ZASP_AUDIT_EXPORT_LOCALSTACK_MODE")
	address := os.Getenv("ZASP_AUDIT_EXPORT_LOCALSTACK_ADDRESS")
	if err := auditExportProcessInputs(dsn, mode, address); err != nil {
		t.Fatal(err)
	}
	ca, err := auditLocalstackChildPrivate(os.Getenv("ZASP_AUDIT_EXPORT_LOCALSTACK_CA"), 16384)
	if err != nil {
		t.Fatal(err)
	}
	tokenPath := os.Getenv("ZASP_AUDIT_EXPORT_LOCALSTACK_TOKEN")
	if _, err := auditLocalstackChildPrivate(tokenPath, 4096); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid owned TLS CA")
	}
	values := auditExportProductionEnvironment(mode)
	values["ZASP_POSTGRES_DSN"] = dsn
	values["ZASP_BATCH_SIZE"] = "1"
	values["ZASP_PROVIDER_TIMEOUT"] = "30s"
	policyPath := os.Getenv("ZASP_AUDIT_EXPORT_LOCALSTACK_POLICY")
	bucket := ""
	if mode == "audit-export" {
		body, err := auditLocalstackChildPrivate(policyPath, 128<<10)
		if err != nil {
			t.Fatal(err)
		}
		policies, err := auditexportconfig.ParsePolicies(body)
		if err != nil || len(policies) != 1 {
			t.Fatal("invalid sole owned policy", err)
		}
		bucket = policies[0].Bucket
		values["ZASP_AUDIT_EXPORT_POLICIES_JSON"] = string(body)
	} else if policyPath != "" || values["ZASP_AUDIT_EXPORT_POLICIES_JSON"] != "" {
		t.Fatal("publisher acquired storage policy")
	}
	config, err := loadWorkerRuntimeConfig(mapLookup(values))
	if err != nil {
		t.Fatal("strict child configuration", err)
	}
	clients, err := newAuditExportProductionClients(config)
	if err != nil {
		t.Fatal(err)
	}
	defer clients.transport.CloseIdleConnections()
	clients.credentials.(*auditExportCredentialCache).provider.(*outboxWebIdentityProvider).tokenFile = tokenPath
	clients.transport.TLSClientConfig.RootCAs = roots
	clients.transport.TLSClientConfig.ServerName = "example.com"
	clients.transport.DialContext = func(ctx context.Context, network, destination string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(destination)
		if err != nil || port != "443" || (host != "sts.us-east-1.amazonaws.com" && host != "sqs.us-east-1.amazonaws.com" && (mode != "audit-export" || host != bucket+".s3.us-east-1.amazonaws.com")) {
			return nil, errors.New("untrusted child destination")
		}
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, address)
	}
	runtime, err := composeAuditExportWorkerRuntime(ctx, config, combinedE2ERecoveryDatabase(t, ctx, dsn), clients)
	if err != nil {
		t.Fatal("registered child composition", err)
	}
	runErr := runtime.Processor.RunOnce(ctx)
	closeErr := runtime.Close()
	if runErr != nil || closeErr != nil {
		t.Fatal("owned child operation", runErr, closeErr)
	}
	t.Logf("registered LocalStack process completed: mode=%s pid=%d", mode, os.Getpid())
}

func auditLocalstackInheritedLiveness() (*os.File, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(3, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFIFO {
		return nil, errors.New("invalid inherited liveness pipe")
	}
	// NewFile must see O_NONBLOCK when it registers with Go's poller; setting
	// it after wrapping a blocking inherited FD cannot make Close join Read.
	if err := unix.SetNonblock(3, true); err != nil {
		return nil, err
	}
	return os.NewFile(3, "owned-parent-liveness"), nil
}

func auditLocalstackChildPrivate(path string, maximum int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("invalid private child path")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 1 || info.Size() > maximum {
		return nil, errors.New("invalid private child file")
	}
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(body)) != info.Size() {
		return nil, errors.New("private child read changed")
	}
	return body, nil
}
