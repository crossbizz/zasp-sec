package opensearchdriver

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

// The caller must own a disposable single-node OpenSearch instance. This is
// actual provider-contract evidence, not PostgreSQL authority or cloud IAM proof.
func TestSandboxSessionIndexLocalOpenSearch(t *testing.T) {
	endpoint := os.Getenv("ZASP_SANDBOX_SEARCH_E2E_ENDPOINT")
	if endpoint == "" {
		t.Skip("requires owned disposable OpenSearch harness")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" || parsed.Port() == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		t.Fatal("owned loopback endpoint required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	for {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/_cluster/health?wait_for_status=yellow&timeout=1s", nil)
		response, err := client.Do(request)
		if err == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				break
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("local OpenSearch not ready")
		case <-time.After(250 * time.Millisecond):
		}
	}
	for _, name := range []string{"zasp-runtime-sessions-v1", "zasp-runtime-sessions-v2"} {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/"+name, nil)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 404 {
			t.Fatal("refusing nonempty provider fixture", name)
		}
	}
	config := Config{Endpoint: endpoint, Region: "us-east-1", RequestTimeout: 5 * time.Second, MaximumRequestBytes: 8 << 20, MaximumResponseBytes: 8 << 20, AllowTestLoopback: true}
	credentials := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
	})
	clock := func() time.Time { return time.Now().UTC() }
	old, err := NewSessionIndex(config, credentials, v4.NewSigner(), clock)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	index, err := NewSandboxSessionIndex(config, credentials, v4.NewSigner(), clock)
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()
	for _, selected := range []*SessionIndex{old, index} {
		if err := selected.InitializeSchema(ctx); err != nil {
			t.Fatal("initialize", err)
		}
		request, _ := http.NewRequestWithContext(ctx, http.MethodPut, endpoint+"/"+selected.indexName()+"/_settings", strings.NewReader(`{"index":{"number_of_replicas":0}}`))
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatal("single-node settings rejected")
		}
	}
	binding, body, archive := sandboxSessionWriteFixture(t)
	documents, err := sessionsearch.BuildDocuments(binding, body, archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := index.VerifyVisibleDocuments(ctx, documents); err == nil {
		t.Fatal("unwritten occurrence reported searchable")
	}
	for i := 0; i < 2; i++ {
		result, err := index.Apply(ctx, binding, body, archive)
		if err != nil || len(result.DocumentIDs) != 1 || result.ReceiptDigest != binding.ReceiptDigest {
			t.Fatal("sandbox real write/replay", err)
		}
	}
	if err := index.VerifyVisibleDocuments(ctx, documents); err != nil {
		t.Fatal("exact sandbox search visibility", err)
	}
	legacyBinding, legacyBody, legacyArchive := sessionWriteFixture(t)
	// A second committed occurrence has a distinct generation. The production
	// projection encoder binds this generation into its effect and receipt.
	receipt, err := runtimeprojection.DecodeReceipt(legacyBody)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Generation = 2
	item := receipt.Items[0]
	projected, err := runtimeprojection.Project(runtimeprojection.Batch{Scope: receipt.Scope, BatchID: receipt.BatchID, Generation: 2, ArchiveReference: receipt.ArchiveReference, ArchiveVersionID: receipt.ArchiveVersionID, ArchiveDigest: receipt.ArchiveDigest, Body: legacyArchive, Correlations: []runtimecorrelation.Result{{EventID: item.EventID, Confidence: item.Confidence}}})
	if err != nil {
		t.Fatal(err)
	}
	receipt.Items, receipt.EffectDigest = projected.Items, projected.ContentDigest
	legacyBody, legacyBinding.ReceiptDigest, _, err = runtimeprojection.EncodeReceipt(receipt)
	legacyBinding.Generation = 2
	if err != nil {
		t.Fatal(err)
	}
	for _, selected := range []*SessionIndex{old, index} {
		if _, err := selected.Apply(ctx, legacyBinding, legacyBody, legacyArchive); err != nil {
			t.Fatal("historical backfill", err)
		}
	}
	legacyDocuments, err := sessionsearch.BuildDocuments(legacyBinding, legacyBody, legacyArchive)
	if err != nil {
		t.Fatal(err)
	}
	if err := old.VerifyVisibleDocuments(ctx, legacyDocuments); err != nil {
		t.Fatal("legacy exact visibility", err)
	}
	if err := index.VerifyVisibleDocuments(ctx, append(documents, legacyDocuments...)); err != nil {
		t.Fatal("mixed historical/sandbox exact visibility", err)
	}
	forged := append([]sessionsearch.Document(nil), documents...)
	forged[0].SandboxID = "not-the-committed-sandbox"
	if err := index.VerifyVisibleDocuments(ctx, forged); err == nil {
		t.Fatal("altered full source passed exact visibility")
	}
	page, err := index.Search(ctx, binding.Scope, sessionsearch.Filters{}, "", 25)
	if err != nil || len(page.InvestigationIDs) != 2 || page.InvestigationIDs[0] != testProductID(t, 6).String() || page.InvestigationIDs[1] != "unattributed" {
		t.Fatal("v2 real query lost old/new investigations", page, err)
	}
	foreign, _ := domain.NewScope(testProductID(t, 99), binding.Scope.WorkspaceID(), binding.Scope.EnvironmentID())
	page, err = index.Search(ctx, foreign, sessionsearch.Filters{}, "", 25)
	if err != nil || len(page.InvestigationIDs) != 0 {
		t.Fatal("cross-tenant search leak", err)
	}
	page, err = old.Search(ctx, binding.Scope, sessionsearch.Filters{}, "", 25)
	if err != nil || len(page.InvestigationIDs) != 1 || page.InvestigationIDs[0] != "unattributed" {
		t.Fatal("legacy index altered", err)
	}
	t.Log("actual local OpenSearch: separate schemas, sandbox write/replay, historical backfill, scoped old/new query and foreign-tenant zero; no SQL authority, rollout or cloud IAM proof")
}
