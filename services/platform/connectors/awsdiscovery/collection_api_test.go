package awsdiscovery

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

type recordingCollectionIdentityCaller struct {
	calls      int
	readiness  int
	credential []byte
	identity   Identity
	err        error
	panicCall  bool
}

func (caller *recordingCollectionIdentityCaller) GetCollectionIdentity(_ context.Context, credential []byte) (Identity, error) {
	caller.calls++
	caller.credential = bytes.Clone(credential)
	if caller.panicCall {
		panic("aws-collection-secret")
	}
	clear(credential)
	return caller.identity, caller.err
}

func (caller *recordingCollectionIdentityCaller) CheckCollectionReadiness(context.Context) error {
	caller.readiness++
	if caller.panicCall {
		panic("aws-readiness-secret")
	}
	return caller.err
}

func TestIdentityCollectionAPIReturnsCanonicalAccountPageWithoutCredential(t *testing.T) {
	t.Parallel()
	caller := &recordingCollectionIdentityCaller{identity: Identity{AccountID: "123456789012", PrincipalARN: "arn:aws:sts::123456789012:assumed-role/discovery/session"}}
	api, err := NewIdentityCollectionAPI(caller, time.Second)
	if err != nil {
		t.Fatalf("NewIdentityCollectionAPI() error = %v", err)
	}
	credential := []byte("temporary-aws-credential-value")
	page, err := api.FetchCollectionPage(context.Background(), credential, CollectionPageRequest{
		Provider: collection.ProviderAWS,
		Subject:  collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"},
		Cursor:   collection.Cursor{},
		Page:     1, RemainingItems: 1, RemainingBytes: 4096,
	})
	if err != nil {
		t.Fatalf("FetchCollectionPage() error = %v", err)
	}
	if caller.calls != 1 || string(caller.credential) != string(credential) || page.Subject.ID != "123456789012" || !page.Complete || page.Cursor == (collection.Cursor{}) || len(page.Entities) != 1 || len(page.Relationships) != 0 {
		t.Fatalf("page/call = %#v / %#v", page, caller)
	}
	if bytes.Contains(page.Raw, credential) || strings.Contains(string(page.Raw), caller.identity.PrincipalARN) || !bytes.Equal(page.Raw, mustAWSCollectionPage(t, page).Raw) {
		t.Fatalf("page raw leaked or is noncanonical: %s", page.Raw)
	}
}

func TestIdentityCollectionAPIRejectsHostileInputAndProviderOutputWithoutLeakage(t *testing.T) {
	t.Parallel()
	const secret = "aws-provider-secret-must-not-escape"
	valid := CollectionPageRequest{Provider: collection.ProviderAWS, Subject: collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}, Cursor: collection.Cursor{Provider: collection.ProviderAWS, Version: "cursor_v1", Value: "initial"}, Page: 1, RemainingItems: 1, RemainingBytes: 4096}
	for name, mutate := range map[string]func(*CollectionPageRequest){
		"provider": func(value *CollectionPageRequest) { value.Provider = collection.ProviderGitHub },
		"subject":  func(value *CollectionPageRequest) { value.Subject.ID = "999" },
		"cursor":   func(value *CollectionPageRequest) { value.Cursor.Value = " aws " },
		"page":     func(value *CollectionPageRequest) { value.Page = 2 },
		"items":    func(value *CollectionPageRequest) { value.RemainingItems = 0 },
		"bytes":    func(value *CollectionPageRequest) { value.RemainingBytes = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			caller := &recordingCollectionIdentityCaller{identity: Identity{AccountID: "123456789012", PrincipalARN: "arn:aws:sts::123456789012:assumed-role/discovery/session"}}
			api, _ := NewIdentityCollectionAPI(caller, time.Second)
			request := valid
			mutate(&request)
			if _, err := api.FetchCollectionPage(context.Background(), []byte("temporary-aws-credential-value"), request); !errors.Is(err, ErrInvalid) || caller.calls != 0 {
				t.Fatalf("FetchCollectionPage() = %v, calls %d", err, caller.calls)
			}
		})
	}
	for name, caller := range map[string]*recordingCollectionIdentityCaller{
		"wrong account":       {identity: Identity{AccountID: "999999999999", PrincipalARN: "arn:aws:sts::999999999999:assumed-role/discovery/session"}},
		"foreign arn account": {identity: Identity{AccountID: "123456789012", PrincipalARN: "arn:aws:sts::999999999999:assumed-role/discovery/session"}},
		"bad arn":             {identity: Identity{AccountID: "123456789012", PrincipalARN: "arn:aws:iam::123456789012:role/discovery"}},
		"error":               {err: errors.New(secret)},
		"panic":               {panicCall: true},
	} {
		t.Run(name, func(t *testing.T) {
			api, _ := NewIdentityCollectionAPI(caller, time.Second)
			_, err := api.FetchCollectionPage(context.Background(), []byte("temporary-aws-credential-value"), valid)
			want := collection.FailureMalformed
			if name == "wrong account" {
				want = collection.FailureDenied
			}
			if name == "error" || name == "panic" {
				want = collection.FailureRetryable
			}
			if !awsFailureHasCode(err, want) || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "aws-collection-secret") || caller.calls != 1 {
				t.Fatalf("FetchCollectionPage() error/calls = %q / %d", err, caller.calls)
			}
		})
	}
	foreign := valid
	foreign.Cursor = nextIdentityCursor(collection.Cursor{}, "999999999999")
	caller := &recordingCollectionIdentityCaller{}
	api, _ := NewIdentityCollectionAPI(caller, time.Second)
	if _, err := api.FetchCollectionPage(context.Background(), []byte("temporary-aws-credential-value"), foreign); !errors.Is(err, ErrInvalid) || caller.calls != 0 {
		t.Fatalf("foreign complete cursor error/calls = %v / %d", err, caller.calls)
	}
}

func TestIdentityCollectionAPIReadinessIsBoundedAndRedacted(t *testing.T) {
	t.Parallel()
	caller := &recordingCollectionIdentityCaller{}
	api, err := NewIdentityCollectionAPI(caller, time.Second)
	if err != nil || api.CheckCollectionReadiness(context.Background()) != nil || caller.readiness != 1 {
		t.Fatalf("readiness = %v / %d", err, caller.readiness)
	}
	caller.err = errors.New("aws-readiness-secret")
	if err := api.CheckCollectionReadiness(context.Background()); !errors.Is(err, ErrDenied) || strings.Contains(err.Error(), "secret") || caller.readiness != 2 {
		t.Fatalf("readiness error/calls = %q / %d", err, caller.readiness)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := api.CheckCollectionReadiness(cancelled); !errors.Is(err, ErrDenied) || caller.readiness != 2 {
		t.Fatalf("cancelled readiness = %v / %d", err, caller.readiness)
	}
}

func TestIdentityCollectionAPIPreservesTypedCallerRateLimit(t *testing.T) {
	t.Parallel()
	failure, _ := collection.NewFailure(collection.FailureRateLimited, time.Now().UTC().Add(time.Minute))
	caller := &recordingCollectionIdentityCaller{err: failure}
	api, _ := NewIdentityCollectionAPI(caller, time.Second)
	request := CollectionPageRequest{Provider: collection.ProviderAWS, Subject: collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}, Cursor: collection.Cursor{}, Page: 1, RemainingItems: 1, RemainingBytes: 4096}
	_, err := api.FetchCollectionPage(context.Background(), []byte("temporary-aws-credential-value"), request)
	var got *collection.Failure
	if !errors.As(err, &got) || got != failure || caller.calls != 1 {
		t.Fatalf("rate limit identity/calls = %p/%p / %d", got, failure, caller.calls)
	}
}

func mustAWSCollectionPage(t *testing.T, page CollectionPage) CollectionPage {
	t.Helper()
	canonical, err := NewCollectionPage(page.Subject, page.Cursor, page.Complete, page.Entities, page.Relationships)
	if err != nil {
		t.Fatalf("NewCollectionPage() error = %v", err)
	}
	return canonical
}

func awsFailureHasCode(err error, code collection.FailureCode) bool {
	var failure *collection.Failure
	return errors.As(err, &failure) && failure.Code() == code
}
