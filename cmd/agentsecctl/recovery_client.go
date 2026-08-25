package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const maximumRecoveryResponseBytes = 64 << 10

var (
	errRecoveryClientConfiguration = errors.New("recovery client configuration rejected")
	errRecoveryAPIUnavailable      = errors.New("recovery API unavailable")
	recoveryProductIDPattern       = regexp.MustCompile(`^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	recoveryReferencePattern       = regexp.MustCompile(`^s3://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]/organizations/(pid_[0-9a-f-]{36})/workspaces/(pid_[0-9a-f-]{36})/environments/(pid_[0-9a-f-]{36})/artifacts/(pid_[0-9a-f-]{36})$`)
	recoveryVersionPattern         = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]+$`)
	recoveryMediaTypePattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,127}$`)
)

type RecoveryClientConfig struct {
	Endpoint       string
	CredentialFile string
	CABundleFile   string
	Timeout        time.Duration
}

type recoveryManifestLocator struct {
	Reference    string `json:"reference"`
	VersionID    string `json:"version_id"`
	SHA256       string `json:"sha256"`
	SizeBytes    int64  `json:"size_bytes"`
	MediaType    string `json:"media_type"`
	Schema       string `json:"schema"`
	SigningKeyID string `json:"signing_key_id"`
	Signature    string `json:"signature"`
}

type recoveryArtifactLocator struct {
	Reference string `json:"reference"`
	VersionID string `json:"version_id"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	MediaType string `json:"media_type"`
	Schema    string `json:"schema"`
}

type recoveryCounts struct {
	Assets   uint64 `json:"assets"`
	Findings uint64 `json:"findings"`
	Policies uint64 `json:"policies"`
}

type recoveryValidationEvidence struct {
	State          string                  `json:"state"`
	ExpectedCounts recoveryCounts          `json:"expected_counts"`
	ObservedCounts recoveryCounts          `json:"observed_counts"`
	Evidence       recoveryArtifactLocator `json:"evidence"`
}

type recoveryCleanupEvidence struct {
	State    string                  `json:"state"`
	Evidence recoveryArtifactLocator `json:"evidence"`
}

type recoveryBackup struct {
	ID            string                   `json:"id"`
	Version       int64                    `json:"version"`
	State         string                   `json:"state"`
	RetentionDays int                      `json:"retention_days"`
	Attempt       int                      `json:"attempt"`
	Manifest      *recoveryManifestLocator `json:"manifest,omitempty"`
	ErrorCode     string                   `json:"error_code,omitempty"`
	CreatedAt     string                   `json:"created_at"`
	StartedAt     string                   `json:"started_at,omitempty"`
	CompletedAt   string                   `json:"completed_at,omitempty"`
}

type recoveryRestore struct {
	ID                 string                      `json:"id"`
	Version            int64                       `json:"version"`
	State              string                      `json:"state"`
	TargetEnvironment  string                      `json:"target_environment"`
	Attempt            int                         `json:"attempt"`
	Manifest           recoveryManifestLocator     `json:"manifest"`
	ObservedCounts     *recoveryCounts             `json:"observed_counts,omitempty"`
	ValidationEvidence *recoveryValidationEvidence `json:"validation_evidence,omitempty"`
	CleanupEvidence    *recoveryCleanupEvidence    `json:"cleanup_evidence,omitempty"`
	ErrorCode          string                      `json:"error_code,omitempty"`
	CreatedAt          string                      `json:"created_at"`
	StartedAt          string                      `json:"started_at,omitempty"`
	CompletedAt        string                      `json:"completed_at,omitempty"`
}

type recoveryBackupStart struct {
	BackupID       string
	RetentionDays  int
	IdempotencyKey string
	ControlVersion int64
}

type recoveryRestoreStart struct {
	RestoreID         string
	TargetEnvironment string
	Manifest          recoveryManifestLocator
	IdempotencyKey    string
	ControlVersion    int64
}

type recoveryCommandClient interface {
	StartBackup(context.Context, recoveryBackupStart) (recoveryBackup, error)
	GetBackup(context.Context, string) (recoveryBackup, error)
	StartRestore(context.Context, recoveryRestoreStart) (recoveryRestore, error)
	GetRestore(context.Context, string) (recoveryRestore, error)
	Close() error
}

type recoveryClient struct {
	config    RecoveryClientConfig
	client    *http.Client
	transport *http.Transport
}

func NewRecoveryClient(config RecoveryClientConfig) (*recoveryClient, error) {
	return newRecoveryClientWithDial(config, nil)
}

func newRecoveryClientWithDial(config RecoveryClientConfig, dial func(context.Context, string, string) (net.Conn, error)) (*recoveryClient, error) {
	parsed, err := url.Parse(config.Endpoint)
	if err != nil || parsed.String() != config.Endpoint || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || net.ParseIP(parsed.Hostname()) != nil || parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" || config.Timeout < 100*time.Millisecond || config.Timeout > 30*time.Second {
		return nil, errRecoveryClientConfiguration
	}
	caBundle, err := readOwnedRecoveryFile(config.CABundleFile, 1<<20, false)
	if err != nil || !validRecoveryCABundle(caBundle) {
		clear(caBundle)
		return nil, errRecoveryClientConfiguration
	}
	defer clear(caBundle)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caBundle) {
		return nil, errRecoveryClientConfiguration
	}
	credential, credentialErr := readRecoveryCredential(config.CredentialFile)
	clear(credential)
	if credentialErr != nil {
		return nil, errRecoveryClientConfiguration
	}
	if dial == nil {
		dial = (&net.Dialer{Timeout: config.Timeout, KeepAlive: 30 * time.Second}).DialContext
	}
	transport := &http.Transport{Proxy: nil, DialContext: dial, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: parsed.Hostname()}, TLSHandshakeTimeout: config.Timeout, ResponseHeaderTimeout: config.Timeout, MaxResponseHeaderBytes: 64 << 10}
	client := &http.Client{Transport: transport, Timeout: config.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errRecoveryAPIUnavailable }}
	return &recoveryClient{config: config, client: client, transport: transport}, nil
}

func (client *recoveryClient) Close() error {
	if client != nil && client.transport != nil {
		client.transport.CloseIdleConnections()
	}
	return nil
}

func (client *recoveryClient) StartBackup(ctx context.Context, input recoveryBackupStart) (recoveryBackup, error) {
	if !validRecoveryProductID(input.BackupID) || input.RetentionDays < 7 || input.RetentionDays > 90 || !validRecoveryMutationAuthority(input.IdempotencyKey, input.ControlVersion) {
		return recoveryBackup{}, errInvalidArguments
	}
	body, _ := json.Marshal(struct {
		BackupID      string `json:"backup_id"`
		RetentionDays int    `json:"retention_days"`
	}{input.BackupID, input.RetentionDays})
	var result recoveryBackup
	if err := client.call(ctx, http.MethodPost, "/api/v1/recovery/backups", body, input.IdempotencyKey, input.ControlVersion, http.StatusAccepted, &result); err != nil || !validRecoveryBackup(result) {
		return recoveryBackup{}, errRecoveryAPIUnavailable
	}
	return result, nil
}

func (client *recoveryClient) GetBackup(ctx context.Context, id string) (recoveryBackup, error) {
	if !validRecoveryProductID(id) {
		return recoveryBackup{}, errInvalidArguments
	}
	var result recoveryBackup
	if err := client.call(ctx, http.MethodGet, "/api/v1/recovery/backups/"+url.PathEscape(id), nil, "", 0, http.StatusOK, &result); err != nil || !validRecoveryBackup(result) || result.ID != id {
		return recoveryBackup{}, errRecoveryAPIUnavailable
	}
	return result, nil
}

func (client *recoveryClient) StartRestore(ctx context.Context, input recoveryRestoreStart) (recoveryRestore, error) {
	if !validRecoveryProductID(input.RestoreID) || !validRecoveryTarget(input.TargetEnvironment) || !validRecoveryManifest(input.Manifest) || !validRecoveryMutationAuthority(input.IdempotencyKey, input.ControlVersion) {
		return recoveryRestore{}, errInvalidArguments
	}
	body, _ := json.Marshal(struct {
		Manifest          recoveryManifestLocator `json:"manifest"`
		RestoreID         string                  `json:"restore_id"`
		TargetEnvironment string                  `json:"target_environment"`
	}{input.Manifest, input.RestoreID, input.TargetEnvironment})
	var result recoveryRestore
	if err := client.call(ctx, http.MethodPost, "/api/v1/recovery/restores", body, input.IdempotencyKey, input.ControlVersion, http.StatusAccepted, &result); err != nil || !validRecoveryRestore(result) {
		return recoveryRestore{}, errRecoveryAPIUnavailable
	}
	return result, nil
}

func (client *recoveryClient) GetRestore(ctx context.Context, id string) (recoveryRestore, error) {
	if !validRecoveryProductID(id) {
		return recoveryRestore{}, errInvalidArguments
	}
	var result recoveryRestore
	if err := client.call(ctx, http.MethodGet, "/api/v1/recovery/restores/"+url.PathEscape(id), nil, "", 0, http.StatusOK, &result); err != nil || !validRecoveryRestore(result) || result.ID != id {
		return recoveryRestore{}, errRecoveryAPIUnavailable
	}
	return result, nil
}

func (client *recoveryClient) call(ctx context.Context, method, path string, body []byte, idempotency string, controlVersion int64, status int, output any) error {
	if client == nil || client.client == nil || ctx == nil || ctx.Err() != nil || !strings.HasPrefix(path, "/api/v1/recovery/") || strings.Contains(path, "//") || len(body) > maximumRecoveryManifestBytes {
		return errRecoveryAPIUnavailable
	}
	credential, err := readRecoveryCredential(client.config.CredentialFile)
	if err != nil {
		return errRecoveryAPIUnavailable
	}
	defer clear(credential)
	request, err := http.NewRequestWithContext(ctx, method, client.config.Endpoint+path, bytes.NewReader(body))
	if err != nil {
		return errRecoveryAPIUnavailable
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+string(credential))
	request.Header.Set("User-Agent", "agentsecctl/recovery-v1")
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", idempotency)
		request.Header.Set("If-Match", fmt.Sprintf(`"%d"`, controlVersion))
	}
	response, err := client.client.Do(request)
	if err != nil {
		return errRecoveryAPIUnavailable
	}
	defer response.Body.Close()
	encoded, readErr := io.ReadAll(io.LimitReader(response.Body, maximumRecoveryResponseBytes+1))
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if readErr != nil || len(encoded) < 2 || len(encoded) > maximumRecoveryResponseBytes || response.StatusCode != status || response.Header.Get("Cache-Control") != "no-store" || mediaErr != nil || mediaType != "application/json" {
		return errRecoveryAPIUnavailable
	}
	if method == http.MethodPost && (!validRecoveryProductID(response.Header.Get("X-Audit-ID")) || !validRecoveryProductID(response.Header.Get("X-Mutation-Receipt-ID"))) {
		return errRecoveryAPIUnavailable
	}
	if err := decodeRecoveryJSON(encoded, output); err != nil {
		return errRecoveryAPIUnavailable
	}
	version := recoveryResultVersion(output)
	if version < 1 || response.Header.Get("ETag") != fmt.Sprintf(`"%d"`, version) {
		return errRecoveryAPIUnavailable
	}
	return nil
}

func recoveryResultVersion(value any) int64 {
	switch result := value.(type) {
	case *recoveryBackup:
		return result.Version
	case *recoveryRestore:
		return result.Version
	default:
		return 0
	}
}

func decodeRecoveryJSON(encoded []byte, target any) error {
	if len(encoded) < 2 || len(encoded) > maximumRecoveryResponseBytes || !uniqueReleaseJSON(encoded) {
		return errRecoveryAPIUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errRecoveryAPIUnavailable
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errRecoveryAPIUnavailable
	}
	return nil
}

func readRecoveryCredential(path string) ([]byte, error) {
	value, err := readOwnedRecoveryFile(path, 16<<10, true)
	if err != nil || len(value) < 16 || bytes.ContainsAny(value, " \t\r\n\x00") {
		clear(value)
		return nil, errRecoveryClientConfiguration
	}
	return value, nil
}

func readOwnedRecoveryFile(path string, maximum int64, secret bool) ([]byte, error) {
	if path == "" || maximum < 1 {
		return nil, errRecoveryClientConfiguration
	}
	before, err := os.Lstat(path)
	if err != nil || !validOwnedRecoveryFile(before, maximum, secret) {
		return nil, errRecoveryClientConfiguration
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errRecoveryClientConfiguration
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !validOwnedRecoveryFile(opened, maximum, secret) || !os.SameFile(before, opened) {
		return nil, errRecoveryClientConfiguration
	}
	value, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(value) < 1 || int64(len(value)) > maximum {
		clear(value)
		return nil, errRecoveryClientConfiguration
	}
	afterOpen, openErr := file.Stat()
	afterPath, pathErr := os.Lstat(path)
	if openErr != nil || pathErr != nil || !validOwnedRecoveryFile(afterOpen, maximum, secret) || !validOwnedRecoveryFile(afterPath, maximum, secret) || !os.SameFile(before, afterOpen) || !os.SameFile(before, afterPath) || opened.Size() != afterOpen.Size() || opened.Mode() != afterOpen.Mode() {
		clear(value)
		return nil, errRecoveryClientConfiguration
	}
	return value, nil
}

func validOwnedRecoveryFile(info os.FileInfo, maximum int64, secret bool) bool {
	if info == nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximum || info.Mode().Perm()&0o022 != 0 || secret && info.Mode().Perm()&0o077 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}

func validRecoveryCABundle(value []byte) bool {
	certificates := 0
	for len(value) > 0 {
		block, rest := pem.Decode(value)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return false
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return false
		}
		certificates++
		value = rest
	}
	return certificates >= 1 && certificates <= 32
}

func validRecoveryBackup(value recoveryBackup) bool {
	if !validRecoveryProductID(value.ID) || value.Version < 1 || value.Version > 1_000_000 || value.RetentionDays < 7 || value.RetentionDays > 90 || value.Attempt < 0 || value.Attempt > 100 || !validRecoveryTime(value.CreatedAt) || !validRecoveryError(value.ErrorCode) {
		return false
	}
	created, _ := parseRecoveryTime(value.CreatedAt)
	started, startedErr := parseRecoveryOptionalTime(value.StartedAt)
	completed, completedErr := parseRecoveryOptionalTime(value.CompletedAt)
	if startedErr != nil || completedErr != nil || value.StartedAt != "" && started.Before(created) || value.CompletedAt != "" && (value.StartedAt == "" || completed.Before(started)) {
		return false
	}
	switch value.State {
	case "queued":
		return value.StartedAt == "" && value.CompletedAt == "" && value.Manifest == nil && value.ErrorCode == ""
	case "draining", "capturing", "publishing":
		return validRecoveryTime(value.StartedAt) && value.CompletedAt == "" && value.Manifest == nil && value.ErrorCode == ""
	case "succeeded":
		return validRecoveryTime(value.StartedAt) && validRecoveryTime(value.CompletedAt) && value.Manifest != nil && validRecoveryManifest(*value.Manifest) && value.ErrorCode == ""
	case "retryable":
		return validRecoveryTime(value.StartedAt) && value.CompletedAt == "" && value.Manifest == nil && value.ErrorCode != ""
	case "failed":
		return validRecoveryTime(value.StartedAt) && validRecoveryTime(value.CompletedAt) && value.Manifest == nil && value.ErrorCode != ""
	default:
		return false
	}
}

func validRecoveryRestore(value recoveryRestore) bool {
	if !validRecoveryProductID(value.ID) || value.Version < 1 || value.Version > 1_000_000 || value.Attempt < 0 || value.Attempt > 100 || !validRecoveryTarget(value.TargetEnvironment) || !validRecoveryManifest(value.Manifest) || !validRecoveryTime(value.CreatedAt) || !validRecoveryError(value.ErrorCode) {
		return false
	}
	created, _ := parseRecoveryTime(value.CreatedAt)
	started, startedErr := parseRecoveryOptionalTime(value.StartedAt)
	completed, completedErr := parseRecoveryOptionalTime(value.CompletedAt)
	if startedErr != nil || completedErr != nil || value.StartedAt != "" && started.Before(created) || value.CompletedAt != "" && (value.StartedAt == "" || completed.Before(started)) || value.ObservedCounts != nil && !validRecoveryCounts(*value.ObservedCounts) || value.ValidationEvidence != nil && !validRecoveryValidation(*value.ValidationEvidence) || value.CleanupEvidence != nil && !validRecoveryCleanup(*value.CleanupEvidence) {
		return false
	}
	switch value.State {
	case "queued":
		return value.StartedAt == "" && value.CompletedAt == "" && value.ObservedCounts == nil && value.ValidationEvidence == nil && value.CleanupEvidence == nil && value.ErrorCode == ""
	case "verifying", "provisioning", "validating":
		return validRecoveryTime(value.StartedAt) && value.CompletedAt == "" && value.ObservedCounts == nil && value.ValidationEvidence == nil && value.CleanupEvidence == nil && value.ErrorCode == ""
	case "rebuilding", "cleanup_required", "cleaning":
		return validRecoveryTime(value.StartedAt) && value.CompletedAt == "" && value.ObservedCounts == nil && value.ValidationEvidence != nil && validRecoveryValidation(*value.ValidationEvidence) && value.CleanupEvidence == nil && value.ErrorCode == ""
	case "succeeded":
		return validRecoveryTime(value.StartedAt) && validRecoveryTime(value.CompletedAt) && value.ObservedCounts != nil && value.ValidationEvidence != nil && value.CleanupEvidence != nil && validRecoveryValidation(*value.ValidationEvidence) && validRecoveryCleanup(*value.CleanupEvidence) && value.CleanupEvidence.State == "deleted" && *value.ObservedCounts == value.ValidationEvidence.ObservedCounts && value.ErrorCode == ""
	case "retryable":
		return validRecoveryTime(value.StartedAt) && value.CompletedAt == "" && value.ObservedCounts == nil && value.ErrorCode != ""
	case "failed", "failed_cleanup":
		return validRecoveryTime(value.StartedAt) && validRecoveryTime(value.CompletedAt) && value.ObservedCounts == nil && value.ErrorCode != "" && (value.State != "failed_cleanup" || value.CleanupEvidence != nil && value.CleanupEvidence.State == "failed")
	default:
		return false
	}
}

func validRecoveryValidation(value recoveryValidationEvidence) bool {
	return value.State == "validated" && value.ExpectedCounts == value.ObservedCounts && validRecoveryArtifact(value.Evidence, "recovery_validation_v1")
}

func validRecoveryCleanup(value recoveryCleanupEvidence) bool {
	return (value.State == "deleted" || value.State == "failed") && validRecoveryArtifact(value.Evidence, "recovery_cleanup_v1")
}

func validRecoveryManifest(value recoveryManifestLocator) bool {
	signature, signatureErr := base64.RawStdEncoding.Strict().DecodeString(value.Signature)
	return validRecoveryArtifact(recoveryArtifactLocator{Reference: value.Reference, VersionID: value.VersionID, SHA256: value.SHA256, SizeBytes: value.SizeBytes, MediaType: value.MediaType, Schema: value.Schema}, "recovery_signed_manifest_v1") && value.MediaType == "application/vnd.zasp.recovery-manifest+json" && regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(value.SigningKeyID) && signatureErr == nil && len(signature) >= sha256.Size && len(signature) <= 512
}

func validRecoveryCounts(value recoveryCounts) bool {
	return value.Assets <= 1_000_000_000 && value.Findings <= 1_000_000_000 && value.Policies <= 1_000_000_000
}

func validRecoveryArtifact(value recoveryArtifactLocator, schema string) bool {
	parts := recoveryReferencePattern.FindStringSubmatch(value.Reference)
	digest, err := hex.DecodeString(value.SHA256)
	return len(parts) == 5 && validRecoveryProductID(parts[1]) && validRecoveryProductID(parts[2]) && validRecoveryProductID(parts[3]) && validRecoveryProductID(parts[4]) && len(value.VersionID) >= 1 && len(value.VersionID) <= 1024 && recoveryVersionPattern.MatchString(value.VersionID) && err == nil && len(digest) == sha256.Size && !bytes.Equal(digest, make([]byte, sha256.Size)) && value.SizeBytes >= 1 && value.SizeBytes <= 64<<20 && value.Schema == schema && (schema == "recovery_signed_manifest_v1" || recoveryMediaTypePattern.MatchString(value.MediaType))
}

func validRecoveryError(value string) bool {
	return value == "" || contains([]string{"dependency_unavailable", "outcome_unknown", "signature_invalid", "manifest_invalid", "manifest_expired", "validation_failed", "projection_mismatch", "cleanup_failed", "exhausted", "lease_lost", "cancelled"}, value)
}

func validRecoveryProductID(value string) bool { return recoveryProductIDPattern.MatchString(value) }

func validRecoveryTarget(value string) bool {
	return value != "production" && len(value) >= 1 && len(value) <= 63 && regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`).MatchString(value)
}

func validRecoveryTime(value string) bool {
	_, err := parseRecoveryTime(value)
	return err == nil
}

func parseRecoveryTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	_, offset := parsed.Zone()
	if err != nil || offset != 0 || value != strings.TrimSpace(value) {
		return time.Time{}, errRecoveryAPIUnavailable
	}
	return parsed, nil
}

func parseRecoveryOptionalTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	return parseRecoveryTime(value)
}

func validRecoveryMutationAuthority(key string, version int64) bool {
	return len(key) >= 16 && len(key) <= 128 && key == strings.TrimSpace(key) && !strings.ContainsAny(key, " \t\r\n\x00") && version >= 0 && version <= 1_000_000
}

type recoveryCommandClientFactory func(RecoveryClientConfig) (recoveryCommandClient, error)

func runRecoveryCommand(output io.Writer, arguments []string) error {
	return runRecoveryCommandWithFactory(context.Background(), output, arguments, func(config RecoveryClientConfig) (recoveryCommandClient, error) { return NewRecoveryClient(config) })
}

func runRecoveryCommandWithFactory(ctx context.Context, output io.Writer, arguments []string, factory recoveryCommandClientFactory) error {
	if ctx == nil || ctx.Err() != nil || output == nil || factory == nil || len(arguments) < 2 || !contains([]string{"backup", "restore"}, arguments[0]) || !contains([]string{"start", "get"}, arguments[1]) {
		return errInvalidArguments
	}
	seenFlags := make(map[string]struct{})
	for index := 2; index < len(arguments); index += 2 {
		if index+1 >= len(arguments) || !strings.HasPrefix(arguments[index], "--") {
			return errInvalidArguments
		}
		if _, duplicate := seenFlags[arguments[index]]; duplicate {
			return errInvalidArguments
		}
		seenFlags[arguments[index]] = struct{}{}
	}
	flags := flag.NewFlagSet("recovery", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	endpoint := flags.String("endpoint", "", "")
	credential := flags.String("credential-file", "", "")
	caBundle := flags.String("ca-bundle-file", "", "")
	timeoutValue := flags.String("timeout", "", "")
	backupID := flags.String("backup-id", "", "")
	restoreID := flags.String("restore-id", "", "")
	retention := flags.String("retention-days", "", "")
	target := flags.String("target-environment", "", "")
	manifestFile := flags.String("manifest-file", "", "")
	idempotency := flags.String("idempotency-key", "", "")
	match := flags.String("if-match", "", "")
	if flags.Parse(arguments[2:]) != nil || flags.NArg() != 0 {
		return errInvalidArguments
	}
	timeout, err := time.ParseDuration(*timeoutValue)
	if err != nil {
		return errInvalidArguments
	}
	config := RecoveryClientConfig{Endpoint: *endpoint, CredentialFile: *credential, CABundleFile: *caBundle, Timeout: timeout}
	client, err := factory(config)
	if err != nil || client == nil {
		return errRecoveryClientConfiguration
	}
	defer client.Close()
	var result any
	switch arguments[0] + ":" + arguments[1] {
	case "backup:start":
		retentionDays, parseErr := strconv.Atoi(*retention)
		controlVersion, matchErr := parseRecoveryControlVersion(*match)
		if parseErr != nil || matchErr != nil || *restoreID != "" || *target != "" || *manifestFile != "" {
			return errInvalidArguments
		}
		result, err = client.StartBackup(ctx, recoveryBackupStart{BackupID: *backupID, RetentionDays: retentionDays, IdempotencyKey: *idempotency, ControlVersion: controlVersion})
	case "backup:get":
		if *restoreID != "" || *retention != "" || *target != "" || *manifestFile != "" || *idempotency != "" || *match != "" {
			return errInvalidArguments
		}
		result, err = client.GetBackup(ctx, *backupID)
	case "restore:start":
		controlVersion, matchErr := parseRecoveryControlVersion(*match)
		manifestBytes, manifestErr := readOwnedRecoveryFile(*manifestFile, maximumRecoveryManifestBytes, false)
		var manifest recoveryManifestLocator
		decodeErr := decodeRecoveryJSON(manifestBytes, &manifest)
		clear(manifestBytes)
		if matchErr != nil || manifestErr != nil || decodeErr != nil || *backupID != "" || *retention != "" {
			return errInvalidArguments
		}
		result, err = client.StartRestore(ctx, recoveryRestoreStart{RestoreID: *restoreID, TargetEnvironment: *target, Manifest: manifest, IdempotencyKey: *idempotency, ControlVersion: controlVersion})
	case "restore:get":
		if *backupID != "" || *retention != "" || *target != "" || *manifestFile != "" || *idempotency != "" || *match != "" {
			return errInvalidArguments
		}
		result, err = client.GetRestore(ctx, *restoreID)
	}
	if err != nil {
		return err
	}
	return encodeJSON(output, result)
}

func parseRecoveryControlVersion(value string) (int64, error) {
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
		return 0, errInvalidArguments
	}
	number := value[1 : len(value)-1]
	parsed, err := strconv.ParseInt(number, 10, 64)
	if err != nil || parsed < 0 || parsed > 1_000_000 || strconv.FormatInt(parsed, 10) != number {
		return 0, errInvalidArguments
	}
	return parsed, nil
}

var _ recoveryCommandClient = (*recoveryClient)(nil)
