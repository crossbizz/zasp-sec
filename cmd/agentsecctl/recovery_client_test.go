package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	recoveryBackupID  = "pid_7d000001-0000-4000-8000-000000000001"
	recoveryRestoreID = "pid_7d000002-0000-4000-8000-000000000002"
)

func TestRecoveryClientUsesPinnedTLSAndExactPublicContracts(t *testing.T) {
	requests := make([]*http.Request, 0, 4)
	bodies := make([][]byte, 0, 2)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests = append(requests, request.Clone(context.Background()))
		if request.Method == http.MethodPost {
			var body bytes.Buffer
			_, _ = body.ReadFrom(request.Body)
			bodies = append(bodies, body.Bytes())
		}
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("ETag", `"1"`)
		if request.Method == http.MethodPost {
			response.Header().Set("X-Audit-ID", "pid_7d000003-0000-4000-8000-000000000003")
			response.WriteHeader(http.StatusAccepted)
		}
		switch request.URL.Path {
		case "/api/v1/recovery/backups", "/api/v1/recovery/backups/" + recoveryBackupID:
			_, _ = response.Write([]byte(recoveryBackupFixture()))
		case "/api/v1/recovery/restores", "/api/v1/recovery/restores/" + recoveryRestoreID:
			_, _ = response.Write([]byte(recoveryRestoreFixture()))
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	configuration, dial := recoveryTLSFixture(t, server)
	client, err := newRecoveryClientWithDial(configuration, dial)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx := context.Background()
	backup, err := client.StartBackup(ctx, recoveryBackupStart{BackupID: recoveryBackupID, RetentionDays: 30, IdempotencyKey: "recovery-backup-idempotency-0001", ControlVersion: 0})
	if err != nil || backup.ID != recoveryBackupID || backup.State != "queued" {
		t.Fatalf("backup=%#v err=%v", backup, err)
	}
	if _, err := client.GetBackup(ctx, recoveryBackupID); err != nil {
		t.Fatal(err)
	}
	manifest := recoveryManifestFixture()
	restore, err := client.StartRestore(ctx, recoveryRestoreStart{RestoreID: recoveryRestoreID, TargetEnvironment: "recovery-test", Manifest: manifest, IdempotencyKey: "recovery-restore-idempotency-0001", ControlVersion: 0})
	if err != nil || restore.ID != recoveryRestoreID || restore.State != "queued" {
		t.Fatalf("restore=%#v err=%v", restore, err)
	}
	if _, err := client.GetRestore(ctx, recoveryRestoreID); err != nil {
		t.Fatal(err)
	}
	if len(requests) != 4 || len(bodies) != 2 {
		t.Fatalf("requests=%d bodies=%d", len(requests), len(bodies))
	}
	for index, request := range requests {
		if request.Header.Get("Authorization") != "Bearer "+strings.Repeat("t", 48) || request.Header.Get("Accept") != "application/json" || request.URL.RawQuery != "" || request.Header.Get("X-Organization-ID") != "" || request.Header.Get("X-Workspace-ID") != "" || request.Header.Get("X-Environment-ID") != "" {
			t.Fatalf("request[%d]=%#v", index, request)
		}
	}
	for _, index := range []int{0, 2} {
		if requests[index].Header.Get("Content-Type") != "application/json" || requests[index].Header.Get("Idempotency-Key") == "" || requests[index].Header.Get("If-Match") != `"0"` {
			t.Fatalf("mutation headers[%d]=%#v", index, requests[index].Header)
		}
	}
	if string(bodies[0]) != `{"backup_id":"`+recoveryBackupID+`","retention_days":30}` {
		t.Fatalf("backup body=%s", bodies[0])
	}
	var restoreBody struct {
		Manifest          recoveryManifestLocator `json:"manifest"`
		RestoreID         string                  `json:"restore_id"`
		TargetEnvironment string                  `json:"target_environment"`
	}
	if decodeRecoveryJSON(bodies[1], &restoreBody) != nil || restoreBody.RestoreID != recoveryRestoreID || restoreBody.TargetEnvironment != "recovery-test" || !reflect.DeepEqual(restoreBody.Manifest, manifest) {
		t.Fatalf("restore body=%s", bodies[1])
	}
}

func TestRecoveryClientRejectsBrowserOnlyReceiptOnBearerMutation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("ETag", `"1"`)
		response.Header().Set("X-Audit-ID", "pid_7d000003-0000-4000-8000-000000000003")
		response.Header().Set("X-Mutation-Receipt-ID", "pid_7d000004-0000-4000-8000-000000000004")
		response.WriteHeader(http.StatusAccepted)
		_, _ = response.Write([]byte(recoveryBackupFixture()))
	}))
	defer server.Close()
	configuration, dial := recoveryTLSFixture(t, server)
	client, err := newRecoveryClientWithDial(configuration, dial)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.StartBackup(context.Background(), recoveryBackupStart{BackupID: recoveryBackupID, RetentionDays: 30, IdempotencyKey: "recovery-backup-idempotency-0001", ControlVersion: 0}); !errors.Is(err, errRecoveryAPIUnavailable) {
		t.Fatalf("receipt leak error=%v", err)
	}
}

func TestRecoveryClientRejectsRedirectOversizeAndUnpinnedAuthorityWithoutLeaks(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1/recovery/backups/"+recoveryBackupID {
			response.Header().Set("Location", "/credential/"+strings.Repeat("s", 32))
			response.WriteHeader(http.StatusFound)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(bytes.Repeat([]byte("x"), maximumRecoveryResponseBytes+1))
	}))
	defer server.Close()
	configuration, dial := recoveryTLSFixture(t, server)
	client, err := newRecoveryClientWithDial(configuration, dial)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.GetBackup(context.Background(), recoveryBackupID); !errors.Is(err, errRecoveryAPIUnavailable) || strings.Contains(err.Error(), "credential") || strings.Contains(err.Error(), strings.Repeat("t", 16)) {
		t.Fatalf("redirect error=%v", err)
	}
	for _, mutate := range []func(*RecoveryClientConfig){
		func(value *RecoveryClientConfig) {
			value.Endpoint = strings.Replace(value.Endpoint, "example.com", "127.0.0.1", 1)
		},
		func(value *RecoveryClientConfig) { value.Endpoint += "/api" },
		func(value *RecoveryClientConfig) { value.Timeout = 31 * time.Second },
	} {
		value := configuration
		mutate(&value)
		if _, err := newRecoveryClientWithDial(value, dial); !errors.Is(err, errRecoveryClientConfiguration) {
			t.Fatalf("configuration=%#v err=%v", value, err)
		}
	}
	oversize := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("ETag", `"1"`)
		_, _ = response.Write(bytes.Repeat([]byte("x"), maximumRecoveryResponseBytes+1))
	}))
	defer oversize.Close()
	oversizeConfig, oversizeDial := recoveryTLSFixture(t, oversize)
	oversizeClient, err := newRecoveryClientWithDial(oversizeConfig, oversizeDial)
	if err != nil {
		t.Fatal(err)
	}
	defer oversizeClient.Close()
	if _, err := oversizeClient.GetBackup(context.Background(), recoveryBackupID); !errors.Is(err, errRecoveryAPIUnavailable) {
		t.Fatalf("oversize err=%v", err)
	}
	timed := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) { <-request.Context().Done() }))
	defer timed.Close()
	timedConfig, timedDial := recoveryTLSFixture(t, timed)
	timedConfig.Timeout = 100 * time.Millisecond
	timedClient, err := newRecoveryClientWithDial(timedConfig, timedDial)
	if err != nil {
		t.Fatal(err)
	}
	defer timedClient.Close()
	if _, err := timedClient.GetBackup(context.Background(), recoveryBackupID); !errors.Is(err, errRecoveryAPIUnavailable) {
		t.Fatalf("timeout err=%v", err)
	}
}

func TestRecoveryClientRejectsCredentialPermissionsAndSymlinkedCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	configuration, dial := recoveryTLSFixture(t, server)
	if err := os.Chmod(configuration.CredentialFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := newRecoveryClientWithDial(configuration, dial); !errors.Is(err, errRecoveryClientConfiguration) {
		t.Fatalf("credential permissions err=%v", err)
	}
	if err := os.Chmod(configuration.CredentialFile, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.Symlink(configuration.CABundleFile, symlink); err != nil {
		t.Fatal(err)
	}
	configuration.CABundleFile = symlink
	if _, err := newRecoveryClientWithDial(configuration, dial); !errors.Is(err, errRecoveryClientConfiguration) {
		t.Fatalf("symlinked CA err=%v", err)
	}
}

func TestRecoveryCommandsParseExactGrammarAndRejectLegacyBareBackupWithoutReadingStdin(t *testing.T) {
	manifestFile := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(manifestFile, []byte(mustRecoveryJSON(t, recoveryManifestFixture())), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &recoveryCommandClientFake{}
	factory := func(RecoveryClientConfig) (recoveryCommandClient, error) { return fake, nil }
	common := []string{"--endpoint", "https://recovery.example.com", "--credential-file", "/secure/token", "--ca-bundle-file", "/secure/ca.pem", "--timeout", "5s"}
	commands := [][]string{
		append([]string{"backup", "start"}, append(common, "--backup-id", recoveryBackupID, "--retention-days", "30", "--idempotency-key", "recovery-backup-idempotency-0001", "--if-match", `"0"`)...),
		append([]string{"backup", "get"}, append(common, "--backup-id", recoveryBackupID)...),
		append([]string{"restore", "start"}, append(common, "--restore-id", recoveryRestoreID, "--target-environment", "recovery-test", "--manifest-file", manifestFile, "--idempotency-key", "recovery-restore-idempotency-0001", "--if-match", `"0"`)...),
		append([]string{"restore", "get"}, append(common, "--restore-id", recoveryRestoreID)...),
	}
	for _, command := range commands {
		var output bytes.Buffer
		if err := runRecoveryCommandWithFactory(context.Background(), &output, command, factory); err != nil || !json.Valid(output.Bytes()) {
			t.Fatalf("command=%v output=%s err=%v", command, output.Bytes(), err)
		}
	}
	if !reflect.DeepEqual(fake.calls, []string{"backup:start", "backup:get", "restore:start", "restore:get"}) {
		t.Fatalf("calls=%v", fake.calls)
	}
	reader := &countingRecoveryReader{}
	if err := runReleaseCommand(&bytes.Buffer{}, reader, []string{"backup"}); !errors.Is(err, errInvalidArguments) || reader.calls != 0 {
		t.Fatalf("legacy backup err=%v reads=%d", err, reader.calls)
	}
}

func TestRecoveryResponseValidatorsRejectImpossibleStateTuples(t *testing.T) {
	backup := mustRecoveryBackupFixture()
	manifest := recoveryManifestFixture()
	backup.Manifest = &manifest
	if validRecoveryBackup(backup) {
		t.Fatal("queued backup accepted a manifest")
	}
	backup = mustRecoveryBackupFixture()
	backup.State, backup.StartedAt, backup.CompletedAt = "succeeded", "2026-08-25T16:00:01Z", "2026-08-25T16:00:02Z"
	if validRecoveryBackup(backup) {
		t.Fatal("succeeded backup accepted without manifest")
	}
	restore := mustRecoveryRestoreFixture()
	restore.State, restore.StartedAt, restore.CompletedAt = "succeeded", "2026-08-25T16:00:01Z", "2026-08-25T16:00:02Z"
	observed := recoveryCounts{Assets: 1}
	restore.ObservedCounts = &observed
	restore.ValidationEvidence = &recoveryValidationEvidence{State: "validated", ExpectedCounts: recoveryCounts{Assets: 2}, ObservedCounts: observed, Evidence: recoveryArtifactLocator{}}
	if validRecoveryRestore(restore) {
		t.Fatal("succeeded restore accepted mismatched validation")
	}
	invalidSignature := recoveryManifestFixture()
	invalidSignature.Signature = strings.Repeat("A", 44) + "!"
	if validRecoveryManifest(invalidSignature) {
		t.Fatal("invalid signature accepted")
	}
}

func TestRecoveryResponseValidatorsAcceptExactPrestartDispatchExhaustion(t *testing.T) {
	backup := mustRecoveryBackupFixture()
	backup.Version, backup.State, backup.ErrorCode, backup.CompletedAt = 2, "failed", "exhausted", "2026-08-25T16:00:02Z"
	if !validRecoveryBackup(backup) {
		t.Fatalf("backup=%#v", backup)
	}
	restore := mustRecoveryRestoreFixture()
	restore.Version, restore.State, restore.ErrorCode, restore.CompletedAt = 2, "failed", "exhausted", "2026-08-25T16:00:02Z"
	if !validRecoveryRestore(restore) {
		t.Fatalf("restore=%#v", restore)
	}
	backup.CompletedAt = "2026-08-25T15:59:59Z"
	if validRecoveryBackup(backup) {
		t.Fatal("prestart-exhausted backup accepted completion before creation")
	}
	restore.CompletedAt = "2026-08-25T15:59:59Z"
	if validRecoveryRestore(restore) {
		t.Fatal("prestart-exhausted restore accepted completion before creation")
	}
}

type recoveryCommandClientFake struct{ calls []string }

func (fake *recoveryCommandClientFake) StartBackup(context.Context, recoveryBackupStart) (recoveryBackup, error) {
	fake.calls = append(fake.calls, "backup:start")
	return mustRecoveryBackupFixture(), nil
}
func (fake *recoveryCommandClientFake) GetBackup(context.Context, string) (recoveryBackup, error) {
	fake.calls = append(fake.calls, "backup:get")
	return mustRecoveryBackupFixture(), nil
}
func (fake *recoveryCommandClientFake) StartRestore(context.Context, recoveryRestoreStart) (recoveryRestore, error) {
	fake.calls = append(fake.calls, "restore:start")
	return mustRecoveryRestoreFixture(), nil
}
func (fake *recoveryCommandClientFake) GetRestore(context.Context, string) (recoveryRestore, error) {
	fake.calls = append(fake.calls, "restore:get")
	return mustRecoveryRestoreFixture(), nil
}
func (*recoveryCommandClientFake) Close() error { return nil }

type countingRecoveryReader struct{ calls int }

func (reader *countingRecoveryReader) Read([]byte) (int, error) {
	reader.calls++
	return 0, errors.New("unexpected read")
}

func recoveryTLSFixture(t *testing.T, server *httptest.Server) (RecoveryClientConfig, func(context.Context, string, string) (net.Conn, error)) {
	t.Helper()
	directory := t.TempDir()
	credential := filepath.Join(directory, "token")
	ca := filepath.Join(directory, "ca.pem")
	if err := os.WriteFile(credential, []byte(strings.Repeat("t", 48)), 0o600); err != nil {
		t.Fatal(err)
	}
	certificate := server.Certificate()
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(server.URL)
	port := parsed.Port()
	configuration := RecoveryClientConfig{Endpoint: "https://example.com:" + port, CredentialFile: credential, CABundleFile: ca, Timeout: 5 * time.Second}
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, server.Listener.Addr().String())
	}
	return configuration, dial
}

func recoveryBackupFixture() string {
	return `{"id":"` + recoveryBackupID + `","version":1,"state":"queued","retention_days":30,"attempt":0,"created_at":"2026-08-25T16:00:00Z"}`
}

func recoveryRestoreFixture() string {
	return `{"id":"` + recoveryRestoreID + `","version":1,"state":"queued","target_environment":"recovery-test","attempt":0,"manifest":` + mustRecoveryJSON(nil, recoveryManifestFixture()) + `,"created_at":"2026-08-25T16:00:00Z"}`
}

func recoveryManifestFixture() recoveryManifestLocator {
	return recoveryManifestLocator{Reference: "s3://zasp-evidence/organizations/pid_7d000010-0000-4000-8000-000000000010/workspaces/pid_7d000011-0000-4000-8000-000000000011/environments/pid_7d000012-0000-4000-8000-000000000012/artifacts/pid_7d000013-0000-4000-8000-000000000013", VersionID: "version-1", SHA256: strings.Repeat("a", 64), SizeBytes: 2048, MediaType: "application/vnd.zasp.recovery-manifest+json", Schema: "recovery_signed_manifest_v1", SigningKeyID: "123e4567-e89b-42d3-a456-426614174000", Signature: base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))}
}

func mustRecoveryBackupFixture() recoveryBackup {
	var value recoveryBackup
	_ = decodeRecoveryJSON([]byte(recoveryBackupFixture()), &value)
	return value
}

func mustRecoveryRestoreFixture() recoveryRestore {
	var value recoveryRestore
	_ = decodeRecoveryJSON([]byte(recoveryRestoreFixture()), &value)
	return value
}

func mustRecoveryJSON(t *testing.T, value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		return ""
	}
	return string(encoded)
}
