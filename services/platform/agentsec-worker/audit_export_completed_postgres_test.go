package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/audit"
)

type auditExportOwnedSDKObject struct {
	Body    []byte      `json:"body"`
	Version string      `json:"version"`
	Headers http.Header `json:"headers"`
}

// Keep the renewal wire check separate so invalid requests can exercise the
// same refusal path without starting another PostgreSQL/runtime composition.
func auditExportCompletedRenewal(r *http.Request, queueURL, exportID, receipt string, active bool) (string, error) {
	var request struct {
		QueueURL string `json:"QueueUrl"`
		Entries  []struct {
			ID         string `json:"Id"`
			Receipt    string `json:"ReceiptHandle"`
			Visibility int    `json:"VisibilityTimeout"`
		} `json:"Entries"`
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4097))
	if r.Method != http.MethodPost || r.Host != "sqs.us-east-1.amazonaws.com" || r.Header.Get("X-Amz-Target") != "AmazonSQS.ChangeMessageVisibilityBatch" ||
		err != nil || len(raw) > 4096 || json.Unmarshal(raw, &request) != nil || request.QueueURL != queueURL ||
		!strings.Contains(r.Header.Get("Authorization"), "Credential=ASIAOWNEDFIXTURE000/") || r.Header.Get("X-Amz-Security-Token") != "owned-fixture-session-not-real" ||
		!active || receipt == "" || len(request.Entries) != 1 || request.Entries[0].ID != exportID || request.Entries[0].Receipt != receipt || request.Entries[0].Visibility != 180 {
		return "", errors.New("queue renewal authority")
	}
	return request.Entries[0].ID, nil
}

func TestAuditExportCompletedProviderRenewalContract(t *testing.T) {
	// A permissive renewal branch would accept the duration, ownership and
	// request-authority mutations below. Expectations use literal wire inputs.
	const queueURL = "https://sqs.us-east-1.amazonaws.com/123456789012/agentsec-audit-exports"
	const exportID = "pid_52000004-0000-4000-8000-000000000004"
	for _, mode := range []string{"current delivery", "wrong queue", "unsigned", "wrong credential", "wrong token", "wrong method", "wrong host", "wrong operation", "wrong ID", "foreign receipt", "previous receipt", "before Receive", "after ACK", "wrong duration", "missing duration", "duplicate", "empty", "malformed", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			queue, id, receipt, active := queueURL, exportID, "owned-completed-receipt-2", true
			entry := map[string]any{"Id": id, "ReceiptHandle": receipt, "VisibilityTimeout": 180}
			switch mode {
			case "wrong queue":
				queue += "-foreign"
			case "wrong ID":
				entry["Id"] = "foreign"
			case "foreign receipt":
				entry["ReceiptHandle"] = "foreign"
			case "previous receipt":
				entry["ReceiptHandle"] = "owned-completed-receipt-1"
			case "before Receive", "after ACK":
				active = false
			case "wrong duration":
				entry["VisibilityTimeout"] = 300
			case "missing duration":
				delete(entry, "VisibilityTimeout")
			}
			entries := []any{entry}
			if mode == "duplicate" {
				entries = append(entries, entry)
			} else if mode == "empty" {
				entries = nil
			}
			body, err := json.Marshal(map[string]any{"QueueUrl": queue, "Entries": entries})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "malformed" {
				body = []byte("{")
			}
			if mode == "oversized" {
				body = append(body, bytes.Repeat([]byte(" "), 4097)...)
			}
			r := httptest.NewRequest(http.MethodPost, "https://sqs.us-east-1.amazonaws.com/", bytes.NewReader(body))
			r.Header.Set("X-Amz-Target", "AmazonSQS.ChangeMessageVisibilityBatch")
			r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=ASIAOWNEDFIXTURE000/fixture")
			r.Header.Set("X-Amz-Security-Token", "owned-fixture-session-not-real")
			switch mode {
			case "unsigned":
				r.Header.Del("Authorization")
			case "wrong credential":
				r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=FOREIGN/fixture")
			case "wrong token":
				r.Header.Set("X-Amz-Security-Token", "foreign")
			case "wrong method":
				r.Method = http.MethodGet
			case "wrong host":
				r.Host = "foreign.invalid"
			case "wrong operation":
				r.Header.Set("X-Amz-Target", "AmazonSQS.SendMessageBatch")
			}
			got, err := auditExportCompletedRenewal(r, queueURL, exportID, receipt, active)
			if mode == "current delivery" {
				if err != nil || got != exportID {
					t.Fatal("current receipt renewal rejected or returned wrong batch ID", got, err)
				}
			} else if err == nil || got != "" {
				t.Fatal("invalid renewal granted receipt authority", mode, got, err)
			}
		})
	}
}

// This observer never supplies SQL responses. It records returned, committed
// intent authority so the owned provider can reject writes before preparation.
type auditExportCompletedDatabase struct {
	base                        recoveryJSONDatabase
	mu                          sync.Mutex
	intents                     map[string]auditExportIntent
	finish                      json.RawMessage
	records, prepares, finishes int
	queries, inFlight           int
}

func (d *auditExportCompletedDatabase) SecurityAgentRunContextAvailable(ctx context.Context) (bool, error) {
	if d == nil || ctx == nil || ctx.Err() != nil {
		return false, errWorkerExecution
	}
	capability, ok := d.base.(interface {
		SecurityAgentRunContextAvailable(context.Context) (bool, error)
	})
	if !ok {
		return false, errWorkerExecution
	}
	return capability.SecurityAgentRunContextAvailable(ctx)
}

func (d *auditExportCompletedDatabase) QueryJSON(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	d.mu.Lock()
	d.inFlight++
	d.mu.Unlock()
	body, err := d.base.QueryJSON(ctx, query, args...)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.inFlight--
	d.queries++
	if err != nil {
		return body, err
	}
	switch query {
	case auditExportWorkerPrepareChunkSQL, auditExportWorkerPrepareManifestSQL:
		var wire struct {
			Binding    audit.ExportBinding `json:"binding"`
			Kind       string              `json:"kind"`
			ArtifactID string              `json:"artifact_id"`
			Reference  string              `json:"object_reference"`
			SHA256     string              `json:"sha256"`
			Size       int64               `json:"size_bytes"`
		}
		if json.Unmarshal(body, &wire) != nil {
			return nil, errors.New("invalid observed intent")
		}
		d.intents[wire.Reference] = auditExportIntent{Binding: wire.Binding, Kind: wire.Kind, ArtifactID: wire.ArtifactID, ObjectReference: wire.Reference, SHA256: wire.SHA256, SizeBytes: wire.Size}
		d.prepares++
	case auditExportWorkerRecordChunkSQL:
		d.records++
	case auditExportWorkerFinishSQL:
		d.finishes++
		d.finish = bytes.Clone(body)
	}
	return body, nil
}

func TestAuditExportCompletedWorkerPostgres(t *testing.T) {
	dsn, scope, exportID := auditExportAuthorityPostgresInputs(t)
	expected := auditExportAuthorityExpectedEvents(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	database := &auditExportCompletedDatabase{base: combinedE2ERecoveryDatabase(t, ctx, dsn), intents: map[string]auditExportIntent{}}
	authority, err := newPostgresAuditExportAuthorityContext(ctx, database, auditExportWorkerPolicyFixture())
	if err != nil {
		t.Fatal(err)
	}
	values := auditExportProductionEnvironment("audit-export")
	values["ZASP_BATCH_SIZE"] = "1"
	config, err := loadWorkerRuntimeConfig(mapLookup(values))
	if err != nil {
		t.Fatal(err)
	}
	// The declared queue wakeup is not a durable outbox publication. Its complete
	// canonical envelope traverses the actual SDK, SQS driver and queue decoder.
	wakeup, err := auditExportWakeupJob(auditExportWakeup{Schema: auditExportWakeupSchema, OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), ExportID: exportID, PolicyID: auditExportWorkerPolicyFixture().PolicyID})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(struct {
		Version         int             `json:"version"`
		JobID           string          `json:"job_id"`
		OrganizationID  string          `json:"organization_id"`
		WorkspaceID     string          `json:"workspace_id"`
		EnvironmentID   string          `json:"environment_id"`
		Kind            string          `json:"kind"`
		Payload         json.RawMessage `json:"payload"`
		AuthorityDigest string          `json:"authority_digest"`
	}{1, exportID, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), "audit-export", wakeup.Payload, hex.EncodeToString(wakeup.AuthorityDigest[:])})
	if err != nil {
		t.Fatal(err)
	}
	const token = "header.payload.signature-with-private-SDK-test-token-1234567890123456789"
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	objects := map[string]auditExportOwnedSDKObject{}
	var assumes, identities, receives, renewals, deletes, puts, heads, gets, losses int
	var receipt string
	var active, renewalIdle bool
	var deliveryRenewals, receiveQueries, renewalQueries int
	discovered := false
	var fixtureFailure string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		refuse := func(reason string) {
			fixtureFailure = reason
			http.Error(w, "owned provider rejected request", http.StatusBadRequest)
		}
		signed := strings.Contains(r.Header.Get("Authorization"), "Credential=ASIAOWNEDFIXTURE000/") && r.Header.Get("X-Amz-Security-Token") == "owned-fixture-session-not-real"
		if r.Host == "sts.us-east-1.amazonaws.com" {
			if r.Method != http.MethodPost || r.ParseForm() != nil {
				refuse("STS form")
				return
			}
			w.Header().Set("Content-Type", "text/xml")
			switch r.Form.Get("Action") {
			case "AssumeRoleWithWebIdentity":
				if r.Form.Get("RoleArn") != values["ZASP_AUDIT_EXPORT_WRITER_ROLE_ARN"] || r.Form.Get("RoleSessionName") != "zasp-audit-export-worker" || r.Form.Get("WebIdentityToken") != token || r.Form.Get("DurationSeconds") != "900" || r.Header.Get("Authorization") != "" {
					refuse("STS role/token")
					return
				}
				assumes++
				fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>ASIAOWNEDFIXTURE000</AccessKeyId><SecretAccessKey>owned-fixture-secret-not-real</SecretAccessKey><SessionToken>owned-fixture-session-not-real</SessionToken><Expiration>%s</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`, time.Now().Add(10*time.Minute).UTC().Format(time.RFC3339))
			case "GetCallerIdentity":
				if !signed {
					refuse("unsigned STS identity")
					return
				}
				identities++
				io.WriteString(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:sts::123456789012:assumed-role/zasp-production-audit-export-worker/zasp-audit-export-worker</Arn><UserId>owned-user</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`)
			default:
				refuse("unexpected STS operation")
			}
			return
		}
		if !signed {
			refuse("unsigned SDK request")
			return
		}
		if r.Host == "sqs.us-east-1.amazonaws.com" {
			if r.Header.Get("X-Amz-Target") == "AmazonSQS.ChangeMessageVisibilityBatch" {
				id, err := auditExportCompletedRenewal(r, values["ZASP_AUDIT_EXPORT_QUEUE_URL"], exportID, receipt, active)
				if err != nil {
					refuse(err.Error())
					return
				}
				database.mu.Lock()
				queries, idle := database.queries, database.inFlight == 0
				database.mu.Unlock()
				if deliveryRenewals == 0 && (queries != receiveQueries || !idle) {
					refuse("initial queue renewal after SQL execution began")
					return
				}
				renewalQueries, renewalIdle = queries, idle
				deliveryRenewals++
				renewals++
				w.Header().Set("Content-Type", "application/x-amz-json-1.0")
				json.NewEncoder(w).Encode(map[string]any{"Successful": []any{map[string]string{"Id": id}}})
				return
			}
			var request struct {
				QueueURL   string   `json:"QueueUrl"`
				Attributes []string `json:"AttributeNames"`
				Maximum    int      `json:"MaxNumberOfMessages"`
				Visibility int      `json:"VisibilityTimeout"`
				Entries    []struct {
					ID      string `json:"Id"`
					Receipt string `json:"ReceiptHandle"`
				} `json:"Entries"`
			}
			raw, err := io.ReadAll(io.LimitReader(r.Body, 4097))
			if err != nil || len(raw) > 4096 || json.Unmarshal(raw, &request) != nil || request.QueueURL != values["ZASP_AUDIT_EXPORT_QUEUE_URL"] {
				refuse("queue request authority")
				return
			}
			w.Header().Set("Content-Type", "application/x-amz-json-1.0")
			switch r.Header.Get("X-Amz-Target") {
			case "AmazonSQS.GetQueueAttributes":
				if !reflect.DeepEqual(request.Attributes, []string{"QueueArn", "RedrivePolicy"}) {
					refuse("queue attributes")
					return
				}
				io.WriteString(w, `{"Attributes":{"QueueArn":"arn:aws:sqs:us-east-1:123456789012:agentsec-audit-exports","RedrivePolicy":"{\"deadLetterTargetArn\":\"arn:aws:sqs:us-east-1:123456789012:agentsec-audit-exports-dlq\",\"maxReceiveCount\":20}"}}`)
			case "AmazonSQS.ReceiveMessage":
				if request.Maximum != 1 || request.Visibility != 180 || active {
					refuse("queue lease/batch")
					return
				}
				database.mu.Lock()
				receiveQueries = database.queries
				idle := database.inFlight == 0
				database.mu.Unlock()
				if !idle {
					refuse("queue receive during SQL execution")
					return
				}
				receives++
				receipt = fmt.Sprintf("owned-completed-receipt-%d", receives)
				active, renewalIdle = true, false
				deliveryRenewals, renewalQueries = 0, 0
				digest := md5.Sum(envelope)
				json.NewEncoder(w).Encode(map[string]any{"Messages": []any{map[string]any{"Body": string(envelope), "MessageId": "owned-completed-message", "ReceiptHandle": receipt, "MD5OfBody": hex.EncodeToString(digest[:]), "Attributes": map[string]string{"ApproximateReceiveCount": strconv.Itoa(receives)}}}})
			case "AmazonSQS.DeleteMessageBatch":
				if !active || len(request.Entries) != 1 || request.Entries[0].ID != exportID || request.Entries[0].Receipt != receipt {
					refuse("queue ACK receipt")
					return
				}
				database.mu.Lock()
				queries, idle := database.queries, database.inFlight == 0
				database.mu.Unlock()
				// Require initial and post-execution renewal on each receipt, with
				// any number of periodic renewals between them. This query check
				// precedes the provider's own real Terminal-ready-before-ACK query.
				if deliveryRenewals < 2 || !renewalIdle || !idle || renewalQueries != queries || queries <= receiveQueries {
					refuse("queue ACK without post-execution renewal")
					return
				}
				state, err := authority.Terminal(r.Context(), scope, exportID)
				if err != nil || state != "ready" {
					refuse("queue ACK before real SQL ready")
					return
				}
				deletes++
				active = false
				json.NewEncoder(w).Encode(map[string]any{"Successful": []any{map[string]string{"Id": request.Entries[0].ID}}})
			default:
				refuse("unexpected SQS operation")
			}
			return
		}
		policy := auditExportWorkerPolicyFixture()
		if r.Host != policy.Bucket+".s3.us-east-1.amazonaws.com" || r.Header.Get("X-Amz-Expected-Bucket-Owner") != policy.ExpectedBucketOwner {
			refuse("S3 bucket/owner")
			return
		}
		reference := "s3://" + policy.Bucket + r.URL.Path
		database.mu.Lock()
		intent, prepared := database.intents[reference]
		database.mu.Unlock()
		if !prepared {
			refuse("S3 write/read before persisted intent")
			return
		}
		object, exists := objects[reference]
		if r.Method == http.MethodPut {
			puts++
			if exists || r.Header.Get("If-None-Match") != "*" || r.Header.Get("X-Amz-Server-Side-Encryption") != "aws:kms" || r.Header.Get("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id") != policy.KMSKeyARN || r.Header.Get("Content-Type") != "application/json" {
				refuse("S3 immutable/KMS request")
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, audit.ExportMaximumChunkBytes+1))
			digest := sha256.Sum256(body)
			if err != nil || len(body) > audit.ExportMaximumChunkBytes || int64(len(body)) != intent.SizeBytes || hex.EncodeToString(digest[:]) != intent.SHA256 || r.Header.Get("X-Amz-Checksum-Sha256") != base64.StdEncoding.EncodeToString(digest[:]) {
				refuse("S3 exact intended body/checksum")
				return
			}
			for key, value := range map[string]string{"organization_id": intent.Binding.OrganizationID, "workspace_id": intent.Binding.WorkspaceID, "environment_id": intent.Binding.EnvironmentID, "artifact_id": intent.ArtifactID, "media_type": "application/json", "sha256": intent.SHA256} {
				if r.Header.Get("X-Amz-Meta-"+key) != value {
					refuse("S3 scoped metadata")
					return
				}
			}
			if intent.Kind == "chunk" {
				chunk, err := audit.DecodeExportChunk(body)
				if err != nil || chunk.Binding != intent.Binding {
					refuse("S3 canonical chunk")
					return
				}
				for i, event := range chunk.Events {
					raw, err := audit.EncodeExportEvent(event)
					if err != nil || !bytes.Equal(raw, expected[chunk.FirstEvent-1+int64(i)]) {
						refuse("S3 changed original source")
						return
					}
				}
			} else {
				manifest, err := audit.DecodeExportManifest(body)
				if err != nil || manifest.Binding != intent.Binding || manifest.EventCount != 1006 || manifest.ChunkCount != 2 {
					refuse("S3 canonical full manifest")
					return
				}
			}
			version := fmt.Sprintf("owned-TLS-version-%d", len(objects)+1)
			// Keep only artifact response authority, never request credentials or
			// signed authorization values, in the private captured object report.
			headers := make(http.Header)
			for key, values := range r.Header {
				if strings.HasPrefix(strings.ToLower(key), "x-amz-meta-") || strings.HasPrefix(strings.ToLower(key), "x-amz-server-side-encryption") || key == "X-Amz-Checksum-Sha256" || key == "Content-Type" {
					headers[key] = append([]string(nil), values...)
				}
			}
			headers.Set("X-Amz-Version-Id", version)
			headers.Set("Content-Length", strconv.Itoa(len(body)))
			object = auditExportOwnedSDKObject{Body: bytes.Clone(body), Version: version, Headers: headers}
			objects[reference] = object
			// Store once, then lose the actual HTTP response. The production driver
			// must discover and pin this version before recording any SQL receipt.
			if losses == 0 {
				losses++
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					refuse("owned lost-response fixture")
					return
				}
				conn.Close()
				return
			}
		} else {
			if !exists || r.Header.Get("X-Amz-Checksum-Mode") != "ENABLED" {
				refuse("S3 exact read")
				return
			}
			version := r.URL.Query().Get("versionId")
			if version != object.Version {
				if r.Method != http.MethodHead || version != "" || losses != 1 || discovered || object.Version != "owned-TLS-version-1" {
					refuse("S3 unpinned version")
					return
				}
				discovered = true
			}
			switch r.Method {
			case http.MethodHead:
				heads++
			case http.MethodGet:
				gets++
			default:
				refuse("unexpected S3 method")
				return
			}
		}
		for key, values := range object.Headers {
			if strings.HasPrefix(strings.ToLower(key), "x-amz-meta-") || strings.HasPrefix(strings.ToLower(key), "x-amz-server-side-encryption") || key == "X-Amz-Version-Id" || key == "X-Amz-Checksum-Sha256" || key == "Content-Length" || key == "Content-Type" {
				w.Header()[key] = append([]string(nil), values...)
			}
		}
		if r.Method == http.MethodPut {
			w.Header().Set("Content-Length", "0")
		}
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			w.Write(object.Body)
		}
	}))
	defer server.Close()
	providerFailure := func() string {
		mu.Lock()
		defer mu.Unlock()
		return fixtureFailure
	}
	for iteration := 0; iteration < 2; iteration++ {
		clients, err := newAuditExportProductionClients(config)
		if err != nil {
			t.Fatal(err)
		}
		clients.credentials.(*auditExportCredentialCache).provider.(*outboxWebIdentityProvider).tokenFile = tokenFile
		roots := x509.NewCertPool()
		roots.AddCert(server.Certificate())
		clients.transport.TLSClientConfig.RootCAs = roots
		clients.transport.TLSClientConfig.ServerName = server.Certificate().DNSNames[0]
		clients.transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		}
		runtime, err := composeAuditExportWorkerRuntime(ctx, config, database, clients)
		if err != nil {
			clients.transport.CloseIdleConnections()
			t.Fatal("actual production SDK/PG startup", err, providerFailure())
		}
		err = runtime.Processor.RunOnce(ctx)
		closeErr := runtime.Close()
		if err != nil || closeErr != nil {
			t.Fatal("actual production SDK/PG completion", err, closeErr, providerFailure())
		}
		mu.Lock()
		count, acks, writes, fault := len(objects), deletes, puts, fixtureFailure
		deliveryCount, renewalCount, deliveryRenewalCount, pending := receives, renewals, deliveryRenewals, active
		mu.Unlock()
		database.mu.Lock()
		prepares, records, finishes := database.prepares, database.records, database.finishes
		database.mu.Unlock()
		if count != 3 || acks != iteration+1 || writes != 3 || fault != "" || prepares != 3 || records != 2 || finishes != 1 {
			t.Fatal("completion/replay changed durable or provider effects", count, acks, writes, prepares, records, finishes, fault)
		}
		if deliveryCount != iteration+1 || deliveryRenewalCount < 2 || renewalCount < 2*(iteration+1) || pending {
			t.Fatal("completion/replay lost per-delivery renewal ownership", deliveryCount, deliveryRenewalCount, renewalCount, pending)
		}
		t.Logf("completed SDK receipt delivery=%d renewals=%d cumulative_renewals=%d ACKs=%d: initial renewal before SQL, post-execution renewal before real Terminal-ready ACK", deliveryCount, deliveryRenewalCount, renewalCount, acks)
	}
	mu.Lock()
	defer mu.Unlock()
	if assumes != 2 || identities != 4 || receives != 2 || deletes != 2 || losses != 1 || !discovered || heads != 7 || gets != 6 {
		t.Fatal("SDK boundaries or lost-Put reconciliation not exercised", assumes, identities, receives, deletes, losses, heads, gets)
	}
	encoded, err := json.Marshal(objects)
	if err != nil || len(encoded) > 2<<20 {
		t.Fatal("owned provider output bound", err)
	}
	output := os.Getenv("ZASP_AUDIT_EXPORT_WORKER_TEST_EXPECTED") + ".objects.json"
	if err := os.WriteFile(output, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("registered PostgreSQL completed export through actual production worker and owned TLS STS/SQS/S3 SDK: two chunks plus manifest, saved-Put/lost-response recovered, ready before ACK and fresh composition replay without new writes; seeded wakeup only, durable outbox/live AWS pending")
}
