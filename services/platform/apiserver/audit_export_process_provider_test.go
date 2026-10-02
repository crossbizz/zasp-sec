//go:build darwin || linux

package apiserver

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/audit"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const auditExportProcessQueue = "https://sqs.us-east-1.amazonaws.com/123456789012/agentsec-audit-exports"
const auditExportProcessToken = "header.payload.owned-process-test-token-not-a-real-credential-1234567890123456789"

// A second delivery that has not ACKed must not borrow the first delivery's
// ACK or renewal timestamps. These are receipt diagnostics, not expiry proof.
func TestAuditExportProcessProviderRedeliverySnapshot(t *testing.T) {
	for _, prepare := range []string{"redeliver", "receive"} {
		t.Run(prepare, func(t *testing.T) {
			at := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
			message := &auditExportProcessMessage{Body: []byte("saved-exact-body"), ID: "saved-message", Receipt: "old-receipt", Deliveries: 1, Deleted: true, ReceivedAt: at, RenewedAt: []time.Time{at.Add(time.Second)}, AcknowledgedAt: at.Add(2 * time.Second)}
			p := &auditExportProcessProvider{messages: []*auditExportProcessMessage{message}, sends: 1, receives: 1, renewalAttempts: 1, renewals: 1, deleteAttempts: 1, deletes: 1}
			if prepare == "redeliver" {
				p.redeliver(t)
				if !message.AcknowledgedAt.IsZero() || !message.ReceivedAt.IsZero() || len(message.RenewedAt) != 0 {
					t.Error("redelivery still attributes prior delivery timing")
				}
			} else {
				// Exercise Receive's own reset independently of redeliver's reset.
				message.Deleted = false
			}
			r := httptest.NewRequest(http.MethodPost, "https://sqs.us-east-1.amazonaws.com/", strings.NewReader(fmt.Sprintf(`{"QueueUrl":%q,"MaxNumberOfMessages":1,"VisibilityTimeout":180}`, auditExportProcessQueue)))
			r.Header.Set("X-Amz-Target", "AmazonSQS.ReceiveMessage")
			w := httptest.NewRecorder()
			p.queue(w, r, "worker")
			if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte("saved-exact-body")) || message.Deliveries != 2 || message.ReceivedAt.IsZero() {
				t.Fatal("exact second delivery absent", w.Code)
			}
			want := `refusal="" sends=1 receives=2 renewal_attempts=1 renewals=1 delete_attempts=1 deletes=1 receive_to_renewal=[] receive_to_ACK=[]`
			if got := p.queueReceiptSnapshot(); got != want {
				t.Fatalf("unACKed second delivery snapshot: got %s want %s", got, want)
			}
		})
	}
}

// Strict request-contract tests only. Injected stale state is not evidence of
// an elapsed visibility window; real replay timing stays on the message record.
func TestAuditExportProcessProviderVisibilityContract(t *testing.T) {
	for _, mode := range []string{"live worker", "publisher", "wrong queue", "wrong ID", "wrong duration", "missing duration", "foreign handle", "old handle", "deleted", "expired", "duplicate", "empty"} {
		t.Run(mode, func(t *testing.T) {
			args := make([]any, 8)
			args[7] = "pid_52000004-0000-4000-8000-000000000004"
			before := time.Now()
			message := &auditExportProcessMessage{ID: "owned-message", Receipt: "current-private-receipt", Visible: before.Add(5 * time.Second)}
			p := &auditExportProcessProvider{args: args, messages: []*auditExportProcessMessage{message}}
			role, url, id, receipt, duration := "worker", auditExportProcessQueue, args[7].(string), message.Receipt, 180
			switch mode {
			case "publisher":
				role = "outbox"
			case "wrong queue":
				url += "-foreign"
			case "wrong ID":
				id = "foreign"
			case "wrong duration":
				duration = 300
			case "missing duration":
				duration = 0
			case "foreign handle":
				receipt = "foreign"
			case "old handle":
				receipt = "old-private-receipt"
			case "deleted":
				message.Deleted = true
			case "expired":
				message.Visible = before.Add(-time.Second)
			}
			original := message.Visible
			entry := map[string]any{"Id": id, "ReceiptHandle": receipt, "VisibilityTimeout": duration}
			entries := []any{entry}
			if mode == "duplicate" {
				entries = append(entries, entry)
			}
			if mode == "empty" {
				entries = nil
			}
			body, err := json.Marshal(map[string]any{"QueueUrl": url, "Entries": entries})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, "https://sqs.us-east-1.amazonaws.com/", bytes.NewReader(body))
			r.Header.Set("X-Amz-Target", "AmazonSQS.ChangeMessageVisibilityBatch")
			w := httptest.NewRecorder()
			p.queue(w, r, role)
			if mode == "live worker" {
				var response struct {
					Successful []struct {
						ID string `json:"Id"`
					}
				}
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || len(response.Successful) != 1 || response.Successful[0].ID != args[7] || message.Visible.Before(before.Add(180*time.Second)) {
					t.Fatalf("live renewal rejected or incomplete: status=%d refusal=%s", w.Code, p.failure)
				}
			} else if w.Code != 400 || p.failure == "" || !message.Visible.Equal(original) {
				t.Fatal("invalid renewal changed receipt authority", mode, w.Code)
			}
		})
	}
}

type auditExportProcessObject struct {
	Body    []byte
	Version string
	Headers http.Header
}
type auditExportProcessMessage struct {
	Body           []byte
	ID, Receipt    string
	Visible        time.Time
	Deliveries     int
	Deleted        bool
	ReceivedAt     time.Time
	RenewedAt      []time.Time
	AcknowledgedAt time.Time
}
type auditExportProcessProvider struct {
	mu                                                          sync.Mutex
	server                                                      *httptest.Server
	observer, worker                                            *pgx.Conn
	args                                                        []any
	events                                                      []json.RawMessage
	objects                                                     map[string]auditExportProcessObject
	messages                                                    []*auditExportProcessMessage
	sends, receives, deletes, deleteAttempts, puts, heads, gets int
	identities, assumes                                         map[string]int
	failure                                                     string
	renewalAttempts, renewals                                   int
	loseNextSend                                                bool
	lostSends                                                   int
	sendAttempts, bufferedSendErrors, failSendsRemaining        int
	abortNextFailedSend                                         bool
	abortedSends                                                int
	beforeFailedSend                                            func(context.Context) error
	policy                                                      migrations.AuditExportConfiguration
	forwardS3                                                   http.Handler
	executorPutFault, executorSaveFault                         bool
	executorFaultReference                                      string
	expectedFailedTerminal                                      bool
	beforeFailedACK                                             func(context.Context) error
	recoveryDiscoveryEnabled                                    bool
	recoveryDiscoveries                                         int
}

// Locked, redacted evidence only. Never include body, credential or handle.
func (p *auditExportProcessProvider) queueReceiptSnapshot() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	renewed, acknowledged := []time.Duration{}, []time.Duration{}
	for _, message := range p.messages {
		if message.ReceivedAt.IsZero() {
			continue
		}
		for _, at := range message.RenewedAt {
			renewed = append(renewed, at.Sub(message.ReceivedAt))
		}
		if !message.AcknowledgedAt.IsZero() {
			acknowledged = append(acknowledged, message.AcknowledgedAt.Sub(message.ReceivedAt))
		}
	}
	return fmt.Sprintf("refusal=%q sends=%d receives=%d renewal_attempts=%d renewals=%d delete_attempts=%d deletes=%d receive_to_renewal=%v receive_to_ACK=%v", p.failure, p.sends, p.receives, p.renewalAttempts, p.renewals, p.deleteAttempts, p.deletes, renewed, acknowledged)
}

func newAuditExportProcessProvider(t *testing.T, ctx context.Context, f auditExportPG, worker *pgx.Conn, args []any, events []json.RawMessage) *auditExportProcessProvider {
	return newAuditExportProcessProviderWithPolicy(t, ctx, f, worker, args, events, auditExportTestPolicy(), nil)
}

// The policy and S3 handler are trusted owner inputs, fixed before the listener
// starts. Queue data never supplies storage policy or forwarding authority.
func newAuditExportProcessProviderWithPolicy(t *testing.T, ctx context.Context, f auditExportPG, worker *pgx.Conn, args []any, events []json.RawMessage, policy migrations.AuditExportConfiguration, forwardS3 http.Handler) *auditExportProcessProvider {
	t.Helper()
	if _, err := migrations.AuditExportPolicyDigest(policy); err != nil {
		t.Fatal("invalid trusted process policy")
	}
	observer, err := pgx.ConnectConfig(ctx, f.admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	owner := auditHTTPFixtureOwnerFrom(ctx)
	if owner != nil {
		auditHTTPFixtureOwnConnection(ctx, "process provider observer", observer)
	}
	p := &auditExportProcessProvider{observer: observer, worker: worker, args: args, events: events, objects: map[string]auditExportProcessObject{}, identities: map[string]int{}, assumes: map[string]int{}, policy: policy, forwardS3: forwardS3}
	p.server = httptest.NewTLSServer(http.HandlerFunc(p.serve))
	if owner != nil {
		owner.handlers = append(owner.handlers, auditHTTPFixtureClose{"unused process listener", func(ctx context.Context) error {
			if err := p.server.Config.Shutdown(ctx); err != nil {
				return err
			}
			p.server.Close()
			return nil
		}})
	} else {
		t.Cleanup(func() {
			p.server.Close()
			closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := p.observer.Close(closeCtx); err != nil {
				t.Error("provider observer cleanup", err)
			}
		})
	}
	return p
}

func (p *auditExportProcessProvider) refuse(w http.ResponseWriter, reason string) {
	if p.failure == "" {
		p.failure = reason
	}
	http.Error(w, "owned process provider rejected request", http.StatusBadRequest)
}
func (p *auditExportProcessProvider) serve(w http.ResponseWriter, r *http.Request) {
	if p.forwardS3 != nil && r.Host != "sts.us-east-1.amazonaws.com" && r.Host != "sqs.us-east-1.amazonaws.com" {
		// The forwarding adapter authenticates the worker's original S3 request.
		// It must never inherit the STS/SQS state lock across network calls/waits.
		p.forwardS3.ServeHTTP(w, r)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	role := ""
	for _, candidate := range []string{"worker", "outbox"} {
		if strings.Contains(r.Header.Get("Authorization"), "Credential=ASIAPROCESS"+strings.ToUpper(candidate)+"/") && r.Header.Get("X-Amz-Security-Token") == "owned-process-session-"+candidate {
			role = candidate
		}
	}
	if r.Host == "sts.us-east-1.amazonaws.com" {
		if r.Method != http.MethodPost || r.URL.Path != "/" || r.URL.RawQuery != "" || r.ParseForm() != nil {
			p.refuse(w, "STS request")
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		switch r.Form.Get("Action") {
		case "AssumeRoleWithWebIdentity":
			for _, candidate := range []string{"worker", "outbox"} {
				if r.Form.Get("RoleArn") == "arn:aws:iam::123456789012:role/zasp-production-audit-export-"+candidate && r.Form.Get("RoleSessionName") == "zasp-audit-export-"+candidate {
					role = candidate
				}
			}
			if role == "" || r.Form.Get("WebIdentityToken") != auditExportProcessToken || r.Form.Get("DurationSeconds") != "900" || r.Header.Get("Authorization") != "" {
				p.refuse(w, "STS role/token")
				return
			}
			p.assumes[role]++
			fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>ASIAPROCESS%s</AccessKeyId><SecretAccessKey>owned-process-secret-not-real</SecretAccessKey><SessionToken>owned-process-session-%s</SessionToken><Expiration>%s</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`, strings.ToUpper(role), role, time.Now().Add(10*time.Minute).UTC().Format(time.RFC3339))
		case "GetCallerIdentity":
			if role == "" {
				p.refuse(w, "unsigned STS identity")
				return
			}
			p.identities[role]++
			fmt.Fprintf(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:sts::123456789012:assumed-role/zasp-production-audit-export-%s/zasp-audit-export-%s</Arn><UserId>owned-process-user</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`, role, role)
		default:
			p.refuse(w, "unexpected STS action")
		}
		return
	}
	if role == "" {
		p.refuse(w, "unsigned SDK request")
		return
	}
	if r.Host == "sqs.us-east-1.amazonaws.com" {
		p.queue(w, r, role)
		return
	}
	if role != "worker" {
		p.refuse(w, "publisher attempted storage")
		return
	}
	p.storage(w, r)
}

func (p *auditExportProcessProvider) queue(w http.ResponseWriter, r *http.Request, role string) {
	if r.Method != http.MethodPost || r.URL.Path != "/" || r.URL.RawQuery != "" {
		p.refuse(w, "queue route")
		return
	}
	var input struct {
		QueueURL   string   `json:"QueueUrl"`
		Attributes []string `json:"AttributeNames"`
		Maximum    int      `json:"MaxNumberOfMessages"`
		Visibility int      `json:"VisibilityTimeout"`
		Entries    []struct {
			ID         string `json:"Id"`
			Body       string `json:"MessageBody"`
			Group      string `json:"MessageGroupId"`
			Receipt    string `json:"ReceiptHandle"`
			Visibility int    `json:"VisibilityTimeout"`
		} `json:"Entries"`
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 8193))
	if err != nil || len(raw) > 8192 || json.Unmarshal(raw, &input) != nil || input.QueueURL != auditExportProcessQueue {
		p.refuse(w, "queue authority")
		return
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	switch r.Header.Get("X-Amz-Target") {
	case "AmazonSQS.GetQueueAttributes":
		if !reflect.DeepEqual(input.Attributes, []string{"QueueArn", "RedrivePolicy"}) {
			p.refuse(w, "queue attributes")
			return
		}
		io.WriteString(w, `{"Attributes":{"QueueArn":"arn:aws:sqs:us-east-1:123456789012:agentsec-audit-exports","RedrivePolicy":"{\"deadLetterTargetArn\":\"arn:aws:sqs:us-east-1:123456789012:agentsec-audit-exports-dlq\",\"maxReceiveCount\":20}"}}`)
	case "AmazonSQS.SendMessageBatch":
		if role != "outbox" || len(input.Entries) != 1 {
			p.refuse(w, "queue publisher isolation")
			return
		}
		entry := input.Entries[0]
		// This independently fixes the closed wire field order and policy identity.
		payload := fmt.Sprintf(`{"schema":"audit-export-wakeup-v1","organization_id":%q,"workspace_id":%q,"environment_id":%q,"export_id":%q,"policy_id":%q}`, p.args[0], p.args[1], p.args[2], p.args[7], p.policy.PolicyID)
		digest := sha256.Sum256([]byte(payload))
		expected := fmt.Sprintf(`{"version":1,"job_id":%q,"organization_id":%q,"workspace_id":%q,"environment_id":%q,"kind":"audit-export","payload":%s,"authority_digest":%q}`, p.args[7], p.args[0], p.args[1], p.args[2], payload, hex.EncodeToString(digest[:]))
		if entry.ID != p.args[7] || entry.Group != p.args[0] || entry.Body != expected {
			p.refuse(w, "changed canonical wakeup")
			return
		}
		p.sendAttempts++
		if p.failSendsRemaining > 0 {
			barrier := p.beforeFailedSend
			if barrier == nil {
				p.refuse(w, "saturation Send lacks owner observation")
				return
			}
			// Parent observes the real leased row here. It owns all PG access;
			// neither the provider lock nor a PG connection crosses the wait.
			p.mu.Unlock()
			err := barrier(r.Context())
			p.mu.Lock()
			if err != nil {
				p.refuse(w, "saturation Send observation interrupted")
				return
			}
			abort := p.abortNextFailedSend
			p.abortNextFailedSend = false
			p.mu.Unlock()
			if abort {
				hijacker, ok := w.(http.Hijacker)
				if !ok {
					p.mu.Lock()
					p.refuse(w, "saturation abort requires HTTP1 connection")
					return
				}
				connection, _, hijackErr := hijacker.Hijack()
				if hijackErr == nil {
					hijackErr = connection.Close()
				}
				p.mu.Lock()
				if hijackErr != nil {
					p.failure = "saturation connection abort failed"
					return
				}
				p.failSendsRemaining--
				p.abortedSends++
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			_, err = io.WriteString(w, `{"__type":"InternalError","message":"owned saturation Send failure"}`)
			p.mu.Lock()
			if err != nil {
				p.refuse(w, "saturation Send error response not written")
				return
			}
			p.failSendsRemaining--
			// This is a buffered write count, not proof of SDK receipt. The
			// saturation child separately observes the delegated SDK error.
			p.bufferedSendErrors++
			return
		}
		p.sends++
		message := &auditExportProcessMessage{Body: []byte(entry.Body), ID: fmt.Sprintf("owned-process-message-%d", p.sends)}
		p.messages = append(p.messages, message)
		if p.loseNextSend {
			p.loseNextSend = false
			p.lostSends++
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				p.refuse(w, "owned Send loss requires HTTP1 connection")
				return
			}
			connection, _, err := hijacker.Hijack()
			if err != nil {
				p.refuse(w, "owned Send connection loss")
				return
			}
			_ = connection.Close()
			return
		}
		sum := md5.Sum(message.Body)
		json.NewEncoder(w).Encode(map[string]any{"Successful": []any{map[string]string{"Id": entry.ID, "MessageId": message.ID, "MD5OfMessageBody": hex.EncodeToString(sum[:])}}})
	case "AmazonSQS.ReceiveMessage":
		if role != "worker" || input.Maximum != 1 || input.Visibility != 180 {
			p.refuse(w, "queue consumer isolation/lease")
			return
		}
		p.receives++
		messages := []any{}
		for _, message := range p.messages {
			if message.Deleted || message.Visible.After(time.Now()) {
				continue
			}
			message.Deliveries++
			message.Receipt = fmt.Sprintf("owned-process-receipt-%s-%d", message.ID, message.Deliveries)
			message.ReceivedAt = time.Now()
			message.RenewedAt = nil
			message.AcknowledgedAt = time.Time{}
			message.Visible = message.ReceivedAt.Add(180 * time.Second)
			sum := md5.Sum(message.Body)
			messages = append(messages, map[string]any{"Body": string(message.Body), "MessageId": message.ID, "ReceiptHandle": message.Receipt, "MD5OfBody": hex.EncodeToString(sum[:]), "Attributes": map[string]string{"ApproximateReceiveCount": strconv.Itoa(message.Deliveries)}})
			break
		}
		json.NewEncoder(w).Encode(map[string]any{"Messages": messages})
	case "AmazonSQS.ChangeMessageVisibilityBatch":
		p.renewalAttempts++
		if role != "worker" || len(input.Entries) != 1 || input.Entries[0].ID != p.args[7] || input.Entries[0].Visibility != 180 || input.Entries[0].Body != "" || input.Entries[0].Group != "" {
			p.refuse(w, "queue renewal authority/duration")
			return
		}
		var selected *auditExportProcessMessage
		now := time.Now()
		for _, message := range p.messages {
			if !message.Deleted && message.Receipt != "" && message.Receipt == input.Entries[0].Receipt && message.Visible.After(now) {
				selected = message
			}
		}
		if selected == nil {
			p.refuse(w, "stale queue renewal receipt")
			return
		}
		selected.Visible = now.Add(180 * time.Second)
		selected.RenewedAt = append(selected.RenewedAt, now)
		p.renewals++
		json.NewEncoder(w).Encode(map[string]any{"Successful": []any{map[string]string{"Id": input.Entries[0].ID}}})
	case "AmazonSQS.DeleteMessageBatch":
		p.deleteAttempts++
		if role != "worker" || len(input.Entries) != 1 || input.Entries[0].ID != p.args[7] {
			p.refuse(w, "queue delete authority")
			return
		}
		var selected *auditExportProcessMessage
		for _, message := range p.messages {
			if !message.Deleted && message.Receipt == input.Entries[0].Receipt && message.Visible.After(time.Now()) {
				selected = message
			}
		}
		if selected == nil {
			p.refuse(w, "stale queue receipt")
			return
		}
		policy := p.policy
		digest, err := migrations.AuditExportPolicyDigest(policy)
		if err != nil {
			p.refuse(w, "trusted policy")
			return
		}
		digestBytes, _ := hex.DecodeString(digest)
		var terminal json.RawMessage
		// Don't carry the provider mutex through a database wait. The registered
		// Terminal proof and optional parent failure proof finish before deletion.
		p.mu.Unlock()
		terminalErr := p.worker.QueryRow(r.Context(), `SELECT zasp_audit_export_terminal($1,$2,$3,$4,$5,$6,$7,$8)`, p.args[0], p.args[1], p.args[2], p.args[7], policy.PolicyID, digestBytes, p.args[11], p.args[12]).Scan(&terminal)
		p.mu.Lock()
		if terminalErr != nil {
			p.refuse(w, "registered Terminal before ACK")
			return
		}
		var proof struct {
			State string `json:"state"`
		}
		expected := "ready"
		if p.expectedFailedTerminal {
			expected = "failed"
		}
		if json.Unmarshal(terminal, &proof) != nil || proof.State != expected {
			p.refuse(w, "ACK before durable ready")
			return
		}
		if p.expectedFailedTerminal {
			check := p.beforeFailedACK
			if check == nil {
				p.refuse(w, "failed ACK lacks independent parent proof")
				return
			}
			p.mu.Unlock()
			err := check(r.Context())
			p.mu.Lock()
			if err != nil {
				p.refuse(w, "failed ACK independent completion/accounting proof")
				return
			}
		}
		if selected.Deleted || selected.Receipt != input.Entries[0].Receipt || !selected.Visible.After(time.Now()) {
			p.refuse(w, "stale queue receipt after Terminal")
			return
		}
		selected.Deleted = true
		selected.AcknowledgedAt = time.Now()
		p.deletes++
		json.NewEncoder(w).Encode(map[string]any{"Successful": []any{map[string]string{"Id": input.Entries[0].ID}}})
	default:
		p.refuse(w, "unexpected SQS operation")
	}
}

func (p *auditExportProcessProvider) storage(w http.ResponseWriter, r *http.Request) {
	policy := auditExportTestPolicy()
	if r.Host != policy.Bucket+".s3.us-east-1.amazonaws.com" || r.Header.Get("X-Amz-Expected-Bucket-Owner") != policy.ExpectedBucketOwner {
		p.refuse(w, "S3 bucket/owner")
		return
	}
	reference := "s3://" + policy.Bucket + r.URL.Path
	var kind, id, capture string
	var ordinal, size int64
	var digest []byte
	err := p.observer.QueryRow(r.Context(), `SELECT kind,ordinal,artifact_id,capture_id,sha256,size_bytes FROM zasp_audit_export_intents WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND export_id=$4 AND object_reference=$5`, p.args[0], p.args[1], p.args[2], p.args[7], reference).Scan(&kind, &ordinal, &id, &capture, &digest, &size)
	if err != nil {
		p.refuse(w, "S3 before committed intent")
		return
	}
	binding := audit.ExportBinding{OrganizationID: p.args[0].(string), WorkspaceID: p.args[1].(string), EnvironmentID: p.args[2].(string), ExportID: p.args[7].(string), CaptureID: capture}
	expected, err := auditExportProcessExpected(binding, p.events)
	if err != nil {
		p.refuse(w, "independent expected bytes")
		return
	}
	wanted, ok := expected[fmt.Sprintf("%s:%d", kind, ordinal)]
	hash := sha256.Sum256(wanted)
	expectedRef := fmt.Sprintf("s3://%s/organizations/%s/workspaces/%s/environments/%s/exports/%s", policy.Bucket, binding.OrganizationID, binding.WorkspaceID, binding.EnvironmentID, id)
	if !ok || reference != expectedRef || size != int64(len(wanted)) || !bytes.Equal(digest, hash[:]) {
		p.refuse(w, "persisted intent differs from source")
		return
	}
	object, exists := p.objects[reference]
	if r.Method == http.MethodPut {
		p.puts++
		if !auditExportProcessS3Query(r.Method, r.URL.RawQuery, "") || r.Header.Get("If-None-Match") != "*" || r.Header.Get("X-Amz-Server-Side-Encryption") != "aws:kms" || r.Header.Get("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id") != policy.KMSKeyARN || r.Header.Get("Content-Type") != "application/json" {
			p.refuse(w, "S3 conditional/KMS request")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, audit.ExportMaximumChunkBytes+1))
		if err != nil || !bytes.Equal(body, wanted) || r.Header.Get("X-Amz-Checksum-Sha256") != base64.StdEncoding.EncodeToString(hash[:]) {
			p.refuse(w, "S3 canonical body/checksum")
			return
		}
		for key, value := range map[string]string{"organization_id": binding.OrganizationID, "workspace_id": binding.WorkspaceID, "environment_id": binding.EnvironmentID, "artifact_id": id, "media_type": "application/json", "sha256": hex.EncodeToString(hash[:])} {
			if r.Header.Get("X-Amz-Meta-"+key) != value {
				p.refuse(w, "S3 scoped metadata")
				return
			}
		}
		// Opt-in outage after actual intent, role, request and body validation.
		// A saved version is retained even though neither SDK request confirms it.
		if p.executorPutFault {
			if p.executorFaultReference != "" && p.executorFaultReference != reference {
				p.refuse(w, "executor fault changed issued reference")
				return
			}
			p.executorFaultReference = reference
			if p.executorSaveFault && !exists {
				headers := r.Header.Clone()
				p.objects[reference] = auditExportProcessObject{Body: bytes.Clone(body), Version: "owned-executor-ambiguous-version-1", Headers: headers}
			}
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, `<Error><Code>InternalError</Code><Message>owned issued object outage</Message></Error>`)
			return
		}
		if exists {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusPreconditionFailed)
			io.WriteString(w, `<Error><Code>PreconditionFailed</Code></Error>`)
			return
		}
		headers := make(http.Header)
		for key, values := range r.Header {
			if strings.HasPrefix(strings.ToLower(key), "x-amz-meta-") || strings.HasPrefix(strings.ToLower(key), "x-amz-server-side-encryption") || key == "X-Amz-Checksum-Sha256" || key == "Content-Type" {
				headers[key] = append([]string(nil), values...)
			}
		}
		object = auditExportProcessObject{Body: bytes.Clone(body), Version: fmt.Sprintf("owned-process-version-%d", len(p.objects)+1), Headers: headers}
		object.Headers.Set("X-Amz-Version-Id", object.Version)
		object.Headers.Set("Content-Length", strconv.Itoa(len(body)))
		p.objects[reference] = object
	} else {
		// Put errors cause real SDK discovery. Only this exact failed reference
		// admits an unversioned HEAD, and it can return only failure, never bytes,
		// a version, or successful object headers. Normal reads stay pinned.
		if p.executorPutFault && reference == p.executorFaultReference && r.Method == http.MethodHead && r.URL.RawQuery == "" && r.Header.Get("X-Amz-Checksum-Mode") == "ENABLED" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		discovery := auditExportRecoveryDiscovery(p.recoveryDiscoveryEnabled, exists, r)
		if !exists || r.Header.Get("X-Amz-Checksum-Mode") != "ENABLED" || (!discovery && !auditExportProcessS3Query(r.Method, r.URL.RawQuery, object.Version)) {
			p.refuse(w, "S3 immutable version read")
			return
		}
		if r.Method == http.MethodHead {
			p.heads++
			if discovery {
				p.recoveryDiscoveries++
			}
		} else if r.Method == http.MethodGet {
			p.gets++
		} else {
			p.refuse(w, "unexpected S3 method")
			return
		}
	}
	for key, values := range object.Headers {
		w.Header()[key] = append([]string(nil), values...)
	}
	if r.Method == http.MethodPut {
		w.Header().Set("Content-Length", "0")
	}
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		w.Write(object.Body)
	}
}

// The storage caller has already checked the exact committed scoped intent.
// Opt-in recovery can discover only an existing object's immutable version.
func auditExportRecoveryDiscovery(enabled, exists bool, r *http.Request) bool {
	return enabled && exists && r.Method == http.MethodHead && r.URL.RawQuery == "" && r.Header.Get("X-Amz-Checksum-Mode") == "ENABLED"
}

func auditExportProcessExpected(binding audit.ExportBinding, events []json.RawMessage) (map[string][]byte, error) {
	result := map[string][]byte{}
	previous := audit.ExportZeroDigest
	var total int64
	count := (len(events) + 999) / 1000
	for ordinal := 1; ordinal <= count; ordinal++ {
		first, last := (ordinal-1)*1000, min(ordinal*1000, len(events))
		chunk := audit.ExportChunk{Schema: audit.ExportChunkSchema, Binding: binding, Ordinal: int64(ordinal), FirstEvent: int64(first + 1), EventCount: int64(last - first), PreviousDigest: previous}
		for _, raw := range events[first:last] {
			event, err := audit.DecodeExportEvent(raw)
			if err != nil {
				return nil, err
			}
			chunk.Events = append(chunk.Events, event)
		}
		body, err := audit.EncodeExportChunk(chunk)
		if err != nil {
			return nil, err
		}
		result[fmt.Sprintf("chunk:%d", ordinal)] = body
		total += int64(len(body))
		sum := sha256.Sum256(body)
		previous = hex.EncodeToString(sum[:])
	}
	body, err := audit.EncodeExportManifest(audit.ExportManifest{Schema: audit.ExportManifestSchema, Binding: binding, EventCount: int64(len(events)), ChunkCount: int64(count), ChunkBytes: total, ChainRoot: previous})
	if err != nil {
		return nil, err
	}
	result["manifest:0"] = body
	return result, nil
}

// Model standard-queue duplicate delivery from the exact bytes previously sent
// through the SDK. No caller supplies a replacement payload or new wakeup.
func (p *auditExportProcessProvider) redeliver(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.messages) != 1 || !p.messages[0].Deleted || p.deletes != 1 {
		t.Fatal("duplicate requires first confirmed delivery")
	}
	message := p.messages[0]
	message.Deleted = false
	message.Visible = time.Time{}
	message.Receipt = ""
	message.ReceivedAt = time.Time{}
	message.RenewedAt = nil
	message.AcknowledgedAt = time.Time{}
}

func (p *auditExportProcessProvider) problem() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.failure
}

func auditExportProcessS3Query(method, raw, version string) bool {
	query, err := url.ParseQuery(raw)
	if err != nil {
		return false
	}
	if method == http.MethodPut {
		return len(query) == 1 && len(query["x-id"]) == 1 && query.Get("x-id") == "PutObject"
	}
	if version == "" || len(query["versionId"]) != 1 || query.Get("versionId") != version {
		return false
	}
	if method == http.MethodHead {
		return len(query) == 1
	}
	return method == http.MethodGet && len(query) == 2 && len(query["x-id"]) == 1 && query.Get("x-id") == "GetObject"
}

func TestAuditExportProcessS3QueryIsClosed(t *testing.T) {
	for _, test := range []struct {
		method, raw, version string
		want                 bool
	}{
		{"PUT", "x-id=PutObject", "", true}, {"HEAD", "versionId=v1", "v1", true}, {"GET", "x-id=GetObject&versionId=v1", "v1", true},
		{"PUT", "", "", false}, {"PUT", "x-id=PutObject&x-id=PutObject", "", false}, {"PUT", "x-id=DeleteObject", "", false},
		{"GET", "x-id=GetObject&versionId=v2", "v1", false}, {"GET", "x-id=GetObject", "v1", false},
		{"GET", "x-id=GetObject&versionId=v1&versionId=v1", "v1", false}, {"GET", "x-id=GetObject&versionId=v1&unknown=x", "v1", false},
		{"HEAD", "versionId=v1&x-id=GetObject", "v1", false}, {"DELETE", "versionId=v1", "v1", false},
		{"GET", "x-id=GetObject&versionId=v1&bad=%GG", "v1", false},
	} {
		if auditExportProcessS3Query(test.method, test.raw, test.version) != test.want {
			t.Fatal("closed SDK query mismatch", test.method, test.raw)
		}
	}
}
