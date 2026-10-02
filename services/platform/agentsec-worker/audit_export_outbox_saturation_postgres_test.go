//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"golang.org/x/sys/unix"
)

// This separate entry cannot widen the ordinary process fault/outcome contract.
// Only its fixed 100+3 phases call the actual composed publisher repeatedly.
func TestAuditExportOutboxSaturationProcessWorkerPostgres(t *testing.T) {
	dsn := os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_DSN")
	if dsn == "" {
		t.Skip("requires parent-owned saturation fixture")
	}
	mode, phase := os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_MODE"), os.Getenv("ZASP_AUDIT_EXPORT_SATURATION_PHASE")
	count, budget, err := auditExportSaturationPhase(mode, phase, os.Getenv("ZASP_AUDIT_EXPORT_SATURATION_RELEASE_FD"), os.Getenv("ZASP_AUDIT_EXPORT_SATURATION_RESULT_FD"), os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_FAULT"), os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_OUTCOME"))
	if err != nil {
		t.Fatal("saturation admission", err)
	}
	address := os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_ADDRESS")
	if err := auditExportProcessInputs(dsn, mode, address); err != nil {
		t.Fatal("saturation admission", err)
	}
	// Check actual inherited descriptor types/directions before TLS, STS or PG.
	for fd, direction := range map[int]int{3: unix.O_RDONLY, 4: unix.O_WRONLY} {
		if err := auditExportSaturationPipe(fd, direction); err != nil {
			t.Fatal("saturation admission", err)
		}
		if err := unix.SetNonblock(fd, true); err != nil {
			t.Fatal("saturation admission", err)
		}
	}
	release, result := os.NewFile(3, "saturation-release"), os.NewFile(4, "saturation-result")
	defer release.Close()
	defer result.Close()
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err := release.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := result.SetWriteDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	ca := auditExportProcessPrivateFile(t, os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_CA"), 16384)
	tokenPath := os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_TOKEN")
	_ = auditExportProcessPrivateFile(t, tokenPath, 4096)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid owned TLS CA")
	}
	values := auditExportProductionEnvironment(mode)
	values["ZASP_POSTGRES_DSN"], values["ZASP_BATCH_SIZE"] = dsn, "1"
	config, err := loadWorkerRuntimeConfig(mapLookup(values))
	if err != nil {
		t.Fatal("strict saturation configuration", err)
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
		if err != nil || port != "443" || (host != "sts.us-east-1.amazonaws.com" && host != "sqs.us-east-1.amazonaws.com") {
			return nil, errors.New("unexpected saturation provider destination")
		}
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, address)
	}
	sends := &auditExportSaturationSDKObserver{runtimeQueueAPI: clients.queue}
	clients.queue = sends
	runtime, err := composeAuditExportWorkerRuntime(ctx, config, combinedE2ERecoveryDatabase(t, ctx, dsn), clients)
	if err != nil {
		t.Fatal("registered saturation composition", err)
	}
	defer func() {
		if err := runtime.Close(); err != nil {
			t.Error("saturation runtime cleanup", err)
		}
	}()
	for call := 1; call <= count; call++ {
		if err := auditExportSaturationByte(release, 'N'); err != nil {
			t.Fatal("saturation release protocol", call, err)
		}
		before := sends.snapshot()
		runErr := runtime.Processor.RunOnce(ctx)
		after := sends.snapshot()
		outcome := byte('X')
		if runErr != nil && after.Calls == before.Calls+1 && after.Received500 == before.Received500+1 && after.Aborts == before.Aborts {
			outcome = 'E'
		} else if runErr != nil && after.Calls == before.Calls+1 && after.Received500 == before.Received500 && after.Aborts == before.Aborts+1 {
			outcome = 'U'
		} else if runErr == nil {
			outcome = 'S'
		}
		t.Logf("delegated SDK Send observed: call=%d status=%d code=%s request_context_live=%t received500=%d aborts=%d outcome=%c", call, after.Status, after.Code, after.ContextLive, after.Received500, after.Aborts, outcome)
		if n, err := result.Write([]byte{outcome}); err != nil || n != 1 {
			t.Fatal("saturation result protocol", call, err)
		}
		expected := byte('E')
		if phase == "abort1" {
			expected = 'U'
		}
		if outcome != expected || ctx.Err() != nil {
			t.Fatal("saturation actual SDK evidence refused", call, outcome, expected, runErr, ctx.Err())
		}
	}
	if err := auditExportSaturationEOF(release); err != nil {
		t.Fatal("saturation release count", err)
	}
	t.Logf("registered saturation process completed: phase=%s calls=%d pid=%d", phase, count, os.Getpid())
}

type auditExportSaturationSDKResult struct {
	Calls, Received500, Aborts, Status int
	Code                               string
	ContextLive                        bool
}

// Observe only after delegating to the actual SDK. Output/error, options,
// production timeout and NopRetryer pass through untouched.
type auditExportSaturationSDKObserver struct {
	runtimeQueueAPI
	mu     sync.Mutex
	result auditExportSaturationSDKResult
}

func (o *auditExportSaturationSDKObserver) SendMessageBatch(ctx context.Context, input *sqs.SendMessageBatchInput, options ...func(*sqs.Options)) (*sqs.SendMessageBatchOutput, error) {
	output, err := o.runtimeQueueAPI.SendMessageBatch(ctx, input, options...)
	var response *smithyhttp.ResponseError
	var api smithy.APIError
	var sendError *smithyhttp.RequestSendError
	var network net.Error
	hasResponse := errors.As(err, &response)
	status, code := 0, ""
	if hasResponse && response.Response != nil && response.Response.Response != nil {
		status = response.HTTPStatusCode()
	}
	if errors.As(err, &api) {
		code = api.ErrorCode()
	}
	live := ctx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !(errors.As(err, &network) && network.Timeout())
	o.mu.Lock()
	o.result.Calls++
	o.result.Status, o.result.Code, o.result.ContextLive = status, code, live
	if err != nil && live && status == 500 && code == "InternalError" {
		o.result.Received500++
	}
	// Smithy wraps transport errors with a status-0 placeholder response, even
	// when no HTTP response arrived. Require its actual Send/EOF error chain.
	if err != nil && live && status == 0 && code == "" && errors.As(err, &sendError) && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
		o.result.Aborts++
	}
	o.mu.Unlock()
	return output, err
}

func (o *auditExportSaturationSDKObserver) snapshot() auditExportSaturationSDKResult {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.result
}

func auditExportSaturationPhase(mode, phase, releaseFD, resultFD, fault, outcome string) (int, time.Duration, error) {
	if mode != "audit-export-outbox" || releaseFD != "3" || resultFD != "4" || fault != "" || outcome != "" {
		return 0, 0, errors.New("invalid saturation mode/FD/fault")
	}
	switch phase {
	case "first100":
		return 100, 5 * time.Minute, nil
	case "last3":
		return 3, 45 * time.Second, nil
	case "abort1":
		return 1, 45 * time.Second, nil
	default:
		return 0, 0, errors.New("invalid saturation phase")
	}
}

func auditExportSaturationPipe(fd, direction int) error {
	var stat unix.Stat_t
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFIFO || flags&unix.O_ACCMODE != direction {
		return errors.New("invalid saturation inherited pipe direction/type")
	}
	return nil
}

func auditExportSaturationByte(reader io.Reader, expected byte) error {
	var body [1]byte
	if _, err := io.ReadFull(reader, body[:]); err != nil {
		return fmt.Errorf("saturation incomplete byte: %w", err)
	}
	if body[0] != expected {
		return fmt.Errorf("saturation unexpected byte %q", body[0])
	}
	return nil
}

func auditExportSaturationEOF(reader io.Reader) error {
	var extra [1]byte
	if n, err := reader.Read(extra[:]); n != 0 || err != io.EOF {
		return errors.New("saturation trailing byte or missing EOF")
	}
	return nil
}

// A swapped mode/phase/descriptor must fail before any database/provider access.
func TestAuditExportOutboxSaturationProtocolRefusals(t *testing.T) {
	for _, test := range []struct {
		phase  string
		count  int
		budget time.Duration
	}{{"first100", 100, 5 * time.Minute}, {"last3", 3, 45 * time.Second}, {"abort1", 1, 45 * time.Second}} {
		count, budget, err := auditExportSaturationPhase("audit-export-outbox", test.phase, "3", "4", "", "")
		if err != nil || count != test.count || budget != test.budget {
			t.Fatal("fixed phase refused", test.phase, count, budget, err)
		}
	}
	for _, input := range [][6]string{
		{"audit-export", "first100", "3", "4", "", ""},
		{"audit-export-outbox", "100", "3", "4", "", ""},
		{"audit-export-outbox", "last103", "3", "4", "", ""},
		{"audit-export-outbox", "first100", "4", "3", "", ""},
		{"audit-export-outbox", "first100", "03", "4", "", ""},
		{"audit-export-outbox", "first100", "3", "4", "finish-outbox-response", ""},
		{"audit-export-outbox", "first100", "3", "4", "", "error"},
		{"audit-export", "abort1", "3", "4", "", ""},
		{"audit-export-outbox", "abort2", "3", "4", "", ""},
		{"audit-export-outbox", "abort1", "4", "3", "", ""},
		{"audit-export-outbox", "abort1", "3", "4", "", "error"},
	} {
		if _, _, err := auditExportSaturationPhase(input[0], input[1], input[2], input[3], input[4], input[5]); err == nil {
			t.Fatal("unsafe saturation admission", input)
		}
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	if auditExportSaturationPipe(int(reader.Fd()), unix.O_RDONLY) != nil || auditExportSaturationPipe(int(writer.Fd()), unix.O_WRONLY) != nil || auditExportSaturationPipe(int(reader.Fd()), unix.O_WRONLY) == nil || auditExportSaturationPipe(int(writer.Fd()), unix.O_RDONLY) == nil || auditExportSaturationPipe(-1, unix.O_RDONLY) == nil {
		t.Fatal("inherited pipe direction refusal failed")
	}
	regular, err := os.CreateTemp(t.TempDir(), "not-a-pipe")
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	if auditExportSaturationPipe(int(regular.Fd()), unix.O_RDWR) == nil {
		t.Fatal("regular file admitted as protocol pipe")
	}
	for _, input := range []string{"", "S", "X", "U"} {
		if auditExportSaturationByte(bytes.NewBufferString(input), 'E') == nil {
			t.Fatal("missing/false completion accepted", input)
		}
	}
	if auditExportSaturationByte(bytes.NewBufferString("E"), 'E') != nil || auditExportSaturationEOF(bytes.NewBuffer(nil)) != nil || auditExportSaturationEOF(bytes.NewBufferString("N")) == nil {
		t.Fatal("bounded byte count refusal failed")
	}
}
