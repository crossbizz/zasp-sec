package awsdiscovery

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
)

const minimumIdentityPageBytes int64 = 4096

var (
	identityCursorPattern  = regexp.MustCompile(`^aws:complete:([0-9a-f]{16}):[0-9a-f]{16}$`)
	assumedRolePathPattern = regexp.MustCompile(`^[A-Za-z0-9+=,.@_/-]{1,900}$`)
)

type CollectionIdentityCaller interface {
	GetCollectionIdentity(context.Context, []byte) (Identity, error)
	CheckCollectionReadiness(context.Context) error
}

type IdentityCollectionAPI struct {
	caller  CollectionIdentityCaller
	timeout time.Duration
}

var _ CollectionAPI = (*IdentityCollectionAPI)(nil)

func NewIdentityCollectionAPI(caller CollectionIdentityCaller, timeout time.Duration) (*IdentityCollectionAPI, error) {
	if nilCollectionIdentityCaller(caller) || timeout < 100*time.Millisecond || timeout > 30*time.Second {
		return nil, ErrInvalid
	}
	return &IdentityCollectionAPI{caller: caller, timeout: timeout}, nil
}

func (api *IdentityCollectionAPI) FetchCollectionPage(ctx context.Context, credential []byte, request CollectionPageRequest) (CollectionPage, error) {
	if ctx != nil && ctx.Err() != nil {
		return CollectionPage{}, providercollection.ClassifyProviderError(ctx, ctx.Err())
	}
	if api == nil || nilCollectionIdentityCaller(api.caller) || ctx == nil || len(credential) < 16 || len(credential) > 65_536 || !validIdentityPageRequest(request) {
		return CollectionPage{}, ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, api.timeout)
	defer cancel()
	borrowed := append([]byte(nil), credential...)
	identity, err := callCollectionIdentity(api.caller, bounded, borrowed)
	clear(borrowed)
	if err != nil || bounded.Err() != nil {
		return CollectionPage{}, providercollection.ClassifyProviderError(bounded, err)
	}
	if identity.AccountID != request.Subject.ID {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureDenied)
	}
	if !validCollectionIdentity(identity) {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	stable, _ := json.Marshal(struct {
		AccountID string `json:"account_id"`
	}{AccountID: identity.AccountID})
	entity, err := json.Marshal(struct {
		ID             string          `json:"id"`
		Kind           string          `json:"kind"`
		SourceNativeID string          `json:"source_native_id"`
		DisplayName    string          `json:"display_name"`
		StableFields   json.RawMessage `json:"stable_fields"`
		Attributes     json.RawMessage `json:"attributes"`
	}{
		ID: deterministicIdentityEntityID(request.Subject, "aws_account", identity.AccountID), Kind: "aws_account",
		SourceNativeID: identity.AccountID, DisplayName: "AWS account " + identity.AccountID, StableFields: stable, Attributes: json.RawMessage(`{}`),
	})
	if err != nil {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	page, err := NewCollectionPage(request.Subject, nextIdentityCursor(request.Cursor, identity.AccountID), true, []json.RawMessage{entity}, nil)
	if err != nil || int64(len(page.Raw)) > request.RemainingBytes {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	return page, nil
}

func (api *IdentityCollectionAPI) CheckCollectionReadiness(ctx context.Context) error {
	if api == nil || nilCollectionIdentityCaller(api.caller) || ctx == nil || ctx.Err() != nil {
		return ErrDenied
	}
	bounded, cancel := context.WithTimeout(ctx, api.timeout)
	defer cancel()
	if err := callCollectionIdentityReadiness(api.caller, bounded); err != nil || bounded.Err() != nil {
		return ErrDenied
	}
	return nil
}

func validIdentityPageRequest(request CollectionPageRequest) bool {
	cursorValid := request.Cursor == (collection.Cursor{}) || request.Cursor.Provider == collection.ProviderAWS && request.Cursor.Version == "cursor_v1" && request.Cursor.Value == "initial"
	if match := identityCursorPattern.FindStringSubmatch(request.Cursor.Value); len(match) == 2 {
		cursorValid = request.Cursor.Provider == collection.ProviderAWS && request.Cursor.Version == "cursor_v1" && match[1] == providercollection.CompleteCursorBinding(collection.ProviderAWS, request.Subject)
	}
	return request.Provider == collection.ProviderAWS && request.Subject.Kind == "aws_account" && awsAccountIDPattern.MatchString(request.Subject.ID) &&
		cursorValid &&
		request.Page == 1 && request.RemainingItems >= 1 && request.RemainingBytes >= minimumIdentityPageBytes
}

var awsAccountIDPattern = regexp.MustCompile(`^[0-9]{12}$`)

func validCollectionIdentity(identity Identity) bool {
	prefix := "arn:aws:sts::" + identity.AccountID + ":assumed-role/"
	return awsAccountIDPattern.MatchString(identity.AccountID) && strings.HasPrefix(identity.PrincipalARN, prefix) && assumedRolePathPattern.MatchString(strings.TrimPrefix(identity.PrincipalARN, prefix))
}

func deterministicIdentityEntityID(subject collection.SubjectBinding, kind, nativeID string) string {
	digest := sha256.Sum256([]byte("aws\x1f" + subject.Kind + "\x1f" + subject.ID + "\x1f" + kind + "\x1f" + nativeID))
	digest[6] = digest[6]&0x0f | 0x40
	digest[8] = digest[8]&0x3f | 0x80
	return fmt.Sprintf("pid_%x-%x-%x-%x-%x", digest[0:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16])
}

func nextIdentityCursor(prior collection.Cursor, accountID string) collection.Cursor {
	digest := sha256.Sum256([]byte(prior.Value + "\x1f" + accountID))
	subject := collection.SubjectBinding{Kind: "aws_account", ID: accountID}
	return collection.Cursor{Provider: collection.ProviderAWS, Version: "cursor_v1", Value: fmt.Sprintf("aws:complete:%s:%x", providercollection.CompleteCursorBinding(collection.ProviderAWS, subject), digest[:8])}
}

func callCollectionIdentity(caller CollectionIdentityCaller, ctx context.Context, credential []byte) (identity Identity, resultErr error) {
	defer func() {
		if recover() != nil {
			identity = Identity{}
			resultErr = ErrDenied
		}
	}()
	return caller.GetCollectionIdentity(ctx, credential)
}

func callCollectionIdentityReadiness(caller CollectionIdentityCaller, ctx context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = ErrDenied
		}
	}()
	return caller.CheckCollectionReadiness(ctx)
}

func nilCollectionIdentityCaller(value CollectionIdentityCaller) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Pointer && reflected.IsNil()
}
