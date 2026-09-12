package sandboxcutover

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

const artifactFixtureKMS = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"

// This is an immutable object fixture served through the real AWS SDK. No S3
// write or provenance fallback is involved in constructing the reader.
func cutoverArtifactFixture(t *testing.T, fault string) (*fixture, *S3ArtifactReader, *[]string, *sync.Mutex) {
	t.Helper()
	f := fixtureWithReceipt(t)
	r := &f.initialRecords[0]
	receipt, err := runtimeprojection.DecodeReceipt(f.receiptBody)
	if err != nil {
		t.Fatal(err)
	}
	scope := r.Binding.Scope
	archiveKey := fmt.Sprintf("runtime/v15/%s/%s/%s/%s/%020d/%s.json", scope.OrganizationID(), scope.WorkspaceID(), scope.EnvironmentID(), scope.EnvironmentID(), r.Binding.Generation, r.Binding.BatchID)
	receipt.ArchiveReference = "s3://zasp-evidence/" + archiveKey
	batch := runtimeprojection.Batch{Scope: scope, BatchID: r.Binding.BatchID, Generation: r.Binding.Generation, ArchiveReference: receipt.ArchiveReference, ArchiveVersionID: receipt.ArchiveVersionID, ArchiveDigest: receipt.ArchiveDigest, Body: f.archiveBody, Correlations: []runtimecorrelation.Result{{EventID: receipt.Items[0].EventID, Confidence: receipt.Items[0].Confidence}}}
	project := runtimeprojection.Project
	if fault == "sandbox" {
		project = runtimeprojection.ProjectSandbox
		r.ProjectVersion, r.CompleteVersion, receipt.ImplementationVersion = "runtime-projection-v2", "runtime-complete-v2", "runtime-projection-v2"
		batch.Correlations[0] = runtimecorrelation.Result{EventID: receipt.Items[0].EventID, Confidence: domain.EvidenceConfidenceStrong, AgentID: scope.OrganizationID(), SessionID: scope.WorkspaceID(), SandboxID: "owned-sandbox", SandboxSourceSensorID: scope.EnvironmentID()}
	}
	projected, err := project(batch)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Items, receipt.EffectDigest = projected.Items, projected.ContentDigest
	body, digest, reference, err := runtimeprojection.EncodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	f.receiptBody, r.Binding.ReceiptDigest = body, digest
	receiptKey := fmt.Sprintf("organizations/%s/workspaces/%s/environments/%s/artifacts/%s", scope.OrganizationID(), scope.WorkspaceID(), scope.EnvironmentID(), reference)
	r.ReceiptReference = "s3://zasp-evidence/" + receiptKey
	var mu sync.Mutex
	calls := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		mu.Lock()
		calls = append(calls, request.Method+" "+request.URL.RequestURI())
		mu.Unlock()
		if request.Method != "HEAD" && request.Method != "GET" {
			t.Error("artifact mutation", request.Method)
			w.WriteHeader(405)
			return
		}
		if request.Header.Get("X-Amz-Expected-Bucket-Owner") != "123456789012" || request.Header.Get("X-Amz-Checksum-Mode") != "ENABLED" || !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Error("missing exact request pins")
		}
		key := strings.TrimPrefix(request.URL.Path, "/zasp-evidence/")
		data, version := f.receiptBody, r.ReceiptVersion
		metadata := map[string]string{"organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "media_type": "application/json", "artifact_id": reference.String()}
		if key == archiveKey {
			data, version = f.archiveBody, receipt.ArchiveVersionID
			delete(metadata, "artifact_id")
		} else if key != receiptKey {
			t.Error("unowned object", key)
			w.WriteHeader(404)
			return
		}
		query := request.URL.Query()
		if request.Method == "GET" && query.Get("x-id") == "GetObject" {
			query.Del("x-id")
		}
		if query.Get("versionId") != version || len(query) != 1 || len(query["versionId"]) != 1 {
			t.Error("read not exact version", request.URL)
		}
		if fault == "slow" {
			<-request.Context().Done()
			return
		}
		digest := sha256.Sum256(data)
		metadata["sha256"] = hex.EncodeToString(digest[:])
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", fmt.Sprint(len(data)))
		w.Header().Set("X-Amz-Version-Id", version)
		w.Header().Set("X-Amz-Server-Side-Encryption", "aws:kms")
		w.Header().Set("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id", artifactFixtureKMS)
		w.Header().Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(digest[:]))
		for key, value := range metadata {
			w.Header().Set("X-Amz-Meta-"+key, value)
		}
		if strings.HasPrefix(fault, "archive-") && key == archiveKey || strings.HasPrefix(fault, "receipt-") && key == receiptKey {
			switch strings.TrimPrefix(strings.TrimPrefix(fault, "archive-"), "receipt-") {
			case "kms":
				w.Header().Set("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id", "foreign")
			case "version":
				w.Header().Set("X-Amz-Version-Id", "other")
			case "scope":
				w.Header().Set("X-Amz-Meta-Organization_id", "foreign")
			case "extra-metadata":
				w.Header().Set("X-Amz-Meta-Extra", "foreign")
			case "bytes":
				data = bytes.Clone(data)
				data[0] ^= 1
			case "size":
				w.Header().Set("Content-Length", fmt.Sprint(65<<20))
			}
		}
		if request.Method == "GET" {
			_, _ = w.Write(data)
		}
	}))
	t.Cleanup(server.Close)
	client := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), UsePathStyle: true, Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "fixture-key", SecretAccessKey: "fixture-secret"}, nil
	}), HTTPClient: server.Client()})
	reader, err := NewS3ArtifactReader(client, ArtifactConfig{Binding: f.release, Bucket: "zasp-evidence", ExpectedBucketOwner: "123456789012", KMSKeyARN: artifactFixtureKMS})
	if err != nil {
		t.Fatal("read-only constructor", err)
	}
	return f, reader, &calls, &mu
}

func TestCutoverArtifactsReadExactVersionedObjects(t *testing.T) {
	f, reader, calls, mu := cutoverArtifactFixture(t, "none")
	body, archive, err := reader.Read(context.Background(), f.release, f.initialRecords[0])
	if err != nil || !bytes.Equal(body, f.receiptBody) || !bytes.Equal(archive, f.archiveBody) {
		t.Fatal("exact immutable read failed", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*calls) != 4 || !strings.HasPrefix((*calls)[0], "HEAD ") || !strings.HasPrefix((*calls)[1], "GET ") || !strings.HasPrefix((*calls)[2], "HEAD ") || !strings.HasPrefix((*calls)[3], "GET ") {
		t.Fatal("expected only receipt/archive HEAD+GET", *calls)
	}
}

func TestCutoverArtifactsRejectChangedProviderObjects(t *testing.T) {
	for _, fault := range []string{"receipt-kms", "receipt-version", "receipt-scope", "receipt-extra-metadata", "receipt-bytes", "receipt-size", "archive-kms", "archive-version", "archive-scope", "archive-extra-metadata", "archive-bytes", "archive-size", "slow"} {
		t.Run(fault, func(t *testing.T) {
			f, reader, calls, mu := cutoverArtifactFixture(t, fault)
			timeout := 5 * time.Second
			if fault == "slow" {
				timeout = 100 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			body, archive, err := reader.Read(ctx, f.release, f.initialRecords[0])
			if err == nil || body != nil || archive != nil {
				t.Fatal("untrusted object returned", err)
			}
			if fault != "slow" && ctx.Err() != nil {
				t.Fatal("deadline masked object validation", ctx.Err())
			}
			mu.Lock()
			defer mu.Unlock()
			if strings.HasPrefix(fault, "archive-") && !strings.Contains(strings.Join(*calls, "\n"), "HEAD /zasp-evidence/runtime/v15/") {
				t.Fatal("archive fault never reached target", *calls)
			}
		})
	}
}

func TestCutoverArtifactsReadSandboxProjectionWithStrongSource(t *testing.T) {
	f, reader, calls, mu := cutoverArtifactFixture(t, "sandbox")
	body, archive, err := reader.Read(context.Background(), f.release, f.initialRecords[0])
	if err != nil {
		t.Fatal("schema50 sandbox artifact rejected", err)
	}
	documents, err := sessionsearch.BuildDocuments(f.initialRecords[0].Binding, body, archive)
	if err != nil || len(documents) != 1 || documents[0].Confidence != "strong" || documents[0].SandboxID != "owned-sandbox" || documents[0].SandboxSourceSensorID != f.initialRecords[0].Binding.Scope.EnvironmentID().String() {
		t.Fatal("sandbox/source changed", documents, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*calls) != 4 {
		t.Fatal("sandbox did not use exact receipt/archive reads", *calls)
	}
}

func TestCutoverArtifactsRejectUnboundAuthorityBeforeIO(t *testing.T) {
	for _, fault := range []string{"binding", "bucket", "scope", "version", "projection", "complete", "mixed-complete", "zero-digest", "events", "documents", "cancelled", "nil-context"} {
		t.Run(fault, func(t *testing.T) {
			f, reader, calls, mu := cutoverArtifactFixture(t, "none")
			b, r, ctx := f.release, f.initialRecords[0], context.Background()
			switch fault {
			case "binding":
				b.ProviderIdentity = "foreign"
			case "bucket":
				r.ReceiptReference = strings.Replace(r.ReceiptReference, "zasp-evidence", "foreign", 1)
			case "scope":
				r.ReceiptReference = strings.Replace(r.ReceiptReference, r.Binding.Scope.OrganizationID().String(), r.Binding.BatchID.String(), 1)
			case "version":
				r.ReceiptVersion = ""
			case "projection":
				r.ProjectVersion = "runtime-projection-v3"
			case "complete":
				r.CompleteVersion = "runtime-complete-v3"
			case "mixed-complete":
				r.CompleteVersion = "runtime-complete-v2"
			case "zero-digest":
				r.Binding.ReceiptDigest = [32]byte{}
			case "events":
				r.EventIDs = nil
			case "documents":
				r.DocumentIDs = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil-context":
				ctx = nil
			}
			if _, _, err := reader.Read(ctx, b, r); err == nil {
				t.Fatal("unbound read accepted")
			}
			mu.Lock()
			defer mu.Unlock()
			if len(*calls) != 0 {
				t.Fatal("invalid authority reached provider", *calls)
			}
		})
	}
}

func TestCutoverArtifactsCapturedDigestAndEventSetStayAuthority(t *testing.T) {
	for _, fault := range []string{"receipt-digest", "event-id", "document-id", "document-duplicate"} {
		t.Run(fault, func(t *testing.T) {
			f, reader, _, _ := cutoverArtifactFixture(t, "none")
			r := f.initialRecords[0]
			switch fault {
			case "receipt-digest":
				r.Binding.ReceiptDigest = sha256.Sum256([]byte("other committed receipt"))
			case "event-id":
				r.EventIDs = []string{r.Binding.BatchID.String()}
			case "document-id":
				r.DocumentIDs = []string{strings.Repeat("f", 64)}
			case "document-duplicate":
				r.EventIDs = append(r.EventIDs, r.EventIDs[0])
				r.DocumentIDs = append(r.DocumentIDs, r.DocumentIDs[0])
			}
			if body, archive, err := reader.Read(context.Background(), f.release, r); err == nil || body != nil || archive != nil {
				t.Fatal("provider content replaced captured expected authority", err)
			}
		})
	}
}

func TestCutoverArtifactsConstructorRejectsMissingPins(t *testing.T) {
	f, reader, _, _ := cutoverArtifactFixture(t, "none")
	for _, fault := range []string{"nil-api", "bucket", "owner", "kms", "release"} {
		t.Run(fault, func(t *testing.T) {
			config, api := reader.config, reader.api
			switch fault {
			case "nil-api":
				api = nil
			case "bucket":
				config.Bucket = "../foreign"
			case "owner":
				config.ExpectedBucketOwner = ""
			case "kms":
				config.KMSKeyARN = "alias/unpinned"
			case "release":
				config.Binding = ReleaseBinding{}
			}
			if _, err := NewS3ArtifactReader(api, config); err == nil {
				t.Fatal("missing immutable pin accepted")
			}
		})
	}
	// A caller's later config change does not rewrite the copied binding.
	config := reader.config
	config.Binding.ProviderIdentity = "changed"
	if _, _, err := reader.Read(context.Background(), f.release, f.initialRecords[0]); err != nil {
		t.Fatal(err)
	}
}
