package awsdiscovery

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

type resumingAWSInventoryCaller struct {
	recordingAWSInventoryCaller
	held      map[InventoryBinding]CollectionInventory
	resumed   []InventoryBinding
	retained  []InventoryBinding
	forget    bool
	resumeErr error
	tamper    func(*CollectionInventory)
}

func (caller *resumingAWSInventoryCaller) ResumeCollectionInventory(_ context.Context, credential []byte, binding InventoryBinding) (CollectionInventory, bool, error) {
	caller.resumed = append(caller.resumed, binding)
	if caller.resumeErr != nil {
		return CollectionInventory{}, false, caller.resumeErr
	}
	inventory, found := caller.held[binding]
	if !found || caller.forget || len(credential) == 0 {
		return CollectionInventory{}, false, nil
	}
	if caller.tamper != nil {
		caller.tamper(&inventory)
	}
	return inventory, true, nil
}

func (caller *resumingAWSInventoryCaller) RetainCollectionInventory(binding InventoryBinding, inventory CollectionInventory) {
	caller.retained = append(caller.retained, binding)
	if caller.held == nil {
		caller.held = make(map[InventoryBinding]CollectionInventory)
	}
	caller.held[binding] = inventory
}

func runInventoryPages(t *testing.T, api *InventoryCollectionAPI, credential []byte) []CollectionPage {
	t.Helper()
	request := CollectionPageRequest{Provider: collection.ProviderAWS, Subject: collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}, Page: 1, RemainingItems: 100, RemainingRelationships: 200, RemainingFindings: 7, RemainingBytes: 1 << 20}
	pages := make([]CollectionPage, 0, 4)
	for page := 1; page <= 4; page++ {
		request.Page = page
		result, err := api.FetchCollectionPage(context.Background(), credential, request)
		if err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
		pages = append(pages, result)
		request.Cursor = result.Cursor
	}
	return pages
}

// A caller that keeps the first page's inventory is asked for it on each
// later page and the account is read once. The pages are exactly the pages a
// caller that reads the account four times produces.
func TestInventoryCollectionAPIResumesTheFirstPagesInventoryOnLaterPages(t *testing.T) {
	t.Parallel()
	authority := awsInventoryAuthority(t, "pid_51000001-0000-4000-8000-000000000001")
	credential := []byte(`{"access_key_id":"ASIAABCDEFGHIJKLMNOP","expires_at":"2026-08-20T12:15:00Z","secret_access_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","session_token":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`)

	plain := &recordingAWSInventoryCaller{snapshot: awsInventoryFixture()}
	plainAPI, err := NewInventoryCollectionAPI(plain, &recordingSecurityAnalyzer{}, authority, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	want := runInventoryPages(t, plainAPI, credential)

	caller := &resumingAWSInventoryCaller{recordingAWSInventoryCaller: recordingAWSInventoryCaller{snapshot: awsInventoryFixture()}}
	analyzer := &recordingSecurityAnalyzer{}
	api, err := NewInventoryCollectionAPI(caller, analyzer, authority, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	got := runInventoryPages(t, api, credential)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resumed pages differ from pages read from the account")
	}
	if plain.calls != 4 || caller.calls != 1 || len(caller.retained) != 1 || len(caller.resumed) != 3 || len(analyzer.calls) != 2 {
		t.Fatalf("account reads plain=%d resumed=%d retained=%d resume calls=%d analyzer=%d", plain.calls, caller.calls, len(caller.retained), len(caller.resumed), len(analyzer.calls))
	}
	binding := caller.retained[0]
	if binding.Scope != authority.Scope || binding.IntegrationID != authority.IntegrationID || binding.ConnectionID != authority.ConnectionID || binding.JobID != authority.JobID || binding.Subject.ID != "123456789012" || binding.Digest != collectionInventoryDigest(caller.snapshot) {
		t.Fatalf("binding = %#v", binding)
	}
	for _, resumed := range caller.resumed {
		if resumed != binding {
			t.Fatalf("resume binding = %#v, want %#v", resumed, binding)
		}
	}
}

func TestInventoryCollectionAPIChecksAResumedInventoryLikeAFreshOne(t *testing.T) {
	t.Parallel()
	authority := awsInventoryAuthority(t, "pid_51000001-0000-4000-8000-000000000001")
	credential := []byte(`{"access_key_id":"ASIAABCDEFGHIJKLMNOP","expires_at":"2026-08-20T12:15:00Z","secret_access_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","session_token":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`)
	first := CollectionPageRequest{Provider: collection.ProviderAWS, Subject: collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}, Page: 1, RemainingItems: 100, RemainingRelationships: 200, RemainingFindings: 7, RemainingBytes: 1 << 20}
	build := func() (*resumingAWSInventoryCaller, *InventoryCollectionAPI, CollectionPageRequest) {
		caller := &resumingAWSInventoryCaller{recordingAWSInventoryCaller: recordingAWSInventoryCaller{snapshot: awsInventoryFixture()}}
		api, err := NewInventoryCollectionAPI(caller, &recordingSecurityAnalyzer{}, authority, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		account, err := api.FetchCollectionPage(context.Background(), credential, first)
		if err != nil {
			t.Fatal(err)
		}
		second := first
		second.Page, second.Cursor = 2, account.Cursor
		return caller, api, second
	}

	// Nothing held (another worker, a restart): the account is read again.
	caller, api, second := build()
	caller.forget = true
	if _, err := api.FetchCollectionPage(context.Background(), credential, second); err != nil || caller.calls != 2 || len(caller.retained) != 2 {
		t.Fatalf("not held: err=%v account reads=%d retained=%d", err, caller.calls, len(caller.retained))
	}

	// The credential check of the resume fails: the page fails and the
	// account is not read with that credential either.
	caller, api, second = build()
	caller.resumeErr = ErrDenied
	if _, err := api.FetchCollectionPage(context.Background(), credential, second); err == nil || caller.calls != 1 {
		t.Fatalf("refused resume: err=%v account reads=%d", err, caller.calls)
	}

	// A held inventory that is not the one the cursor names is refused.
	caller, api, second = build()
	caller.tamper = func(inventory *CollectionInventory) {
		other := awsInventoryFixture()
		other.ProwlerSource = []byte(`{"account_id":"123456789012","instances":[],"roles":[]}`)
		other.ProwlerDigest = [32]byte{}
		*inventory = other
	}
	if _, err := api.FetchCollectionPage(context.Background(), credential, second); err == nil || caller.calls != 1 {
		t.Fatalf("drifted resume: err=%v account reads=%d", err, caller.calls)
	}

	// A held inventory of another account, or with an expired credential,
	// fails the same validation a fresh read fails.
	for name, tamper := range map[string]func(*CollectionInventory){
		"account": func(inventory *CollectionInventory) { inventory.Identity.AccountID = "210987654321" },
		"expiry":  func(inventory *CollectionInventory) { inventory.CredentialExpiresAt = authority.ObservedAt },
	} {
		caller, api, second = build()
		caller.tamper = tamper
		if _, err := api.FetchCollectionPage(context.Background(), credential, second); err == nil || errors.Is(err, context.Canceled) || caller.calls != 1 {
			t.Fatalf("%s: err=%v account reads=%d", name, err, caller.calls)
		}
	}
}
