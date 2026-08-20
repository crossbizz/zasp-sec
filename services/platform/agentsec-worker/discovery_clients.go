package main

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/githubdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/idpdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/kubernetesdiscovery"
)

type discoveryCallerIdentityAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type discoveryCallerIdentityFactory func(string, aws.Credentials) (discoveryCallerIdentityAPI, error)

type discoveryAWSCollectionIdentityCaller struct {
	newCaller discoveryCallerIdentityFactory
}

func newDiscoveryAWSCollectionIdentityCaller(factory discoveryCallerIdentityFactory) (*discoveryAWSCollectionIdentityCaller, error) {
	if factory == nil {
		return nil, errDiscoveryCredentialUnavailable
	}
	return &discoveryAWSCollectionIdentityCaller{newCaller: factory}, nil
}

func (caller *discoveryAWSCollectionIdentityCaller) GetCollectionIdentity(ctx context.Context, credential []byte) (awsdiscovery.Identity, error) {
	if caller == nil || caller.newCaller == nil || ctx == nil || ctx.Err() != nil {
		return awsdiscovery.Identity{}, awsdiscovery.ErrDenied
	}
	envelope, err := decodeDiscoveryCredentialEnvelope(credential)
	if err != nil || envelope.Provider != collection.ProviderAWS {
		envelope.Destroy()
		return awsdiscovery.Identity{}, awsdiscovery.ErrDenied
	}
	if !envelope.ExpiresAt.After(time.Now().UTC()) {
		envelope.Destroy()
		return awsdiscovery.Identity{}, discoveryCredentialFailure(ctx, collection.FailureRetryable)
	}
	defer envelope.Destroy()
	credentials := aws.Credentials{AccessKeyID: string(envelope.AccessKeyID), SecretAccessKey: string(envelope.SecretAccessKey), SessionToken: string(envelope.SessionToken), CanExpire: true, Expires: envelope.ExpiresAt, Source: "zasp-discovery-assume-role"}
	client, err := caller.newCaller(envelope.Region, credentials)
	if err != nil || nilDiscoveryClientDependency(client) {
		clearAWSCredentials(&credentials)
		return awsdiscovery.Identity{}, awsdiscovery.ErrDenied
	}
	output, callErr := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}, func(options *sts.Options) { options.Retryer = aws.NopRetryer{} })
	clearAWSCredentials(&credentials)
	if callErr != nil || ctx.Err() != nil || output == nil || output.Account == nil || output.Arn == nil || *output.Account != envelope.SubjectID || !strings.HasPrefix(*output.Arn, "arn:aws:sts::"+envelope.SubjectID+":assumed-role/") {
		return awsdiscovery.Identity{}, awsdiscovery.ErrDenied
	}
	return awsdiscovery.Identity{AccountID: *output.Account, PrincipalARN: *output.Arn}, nil
}

func (caller *discoveryAWSCollectionIdentityCaller) CheckCollectionReadiness(ctx context.Context) error {
	if caller == nil || caller.newCaller == nil || ctx == nil || ctx.Err() != nil {
		return awsdiscovery.ErrDenied
	}
	return nil
}

type discoveryBearerCollectionAPI struct {
	provider     collection.Provider
	github       githubdiscovery.CollectionAPI
	kubernetes   func(kubernetesdiscovery.PinnedCollectionAPIConfig) (kubernetesdiscovery.CollectionAPI, error)
	okta         func(string, time.Duration) (idpdiscovery.CollectionAPI, error)
	allowedCIDRs []string
	timeout      time.Duration
}

func newDiscoveryGitHubCollectionAPI(api githubdiscovery.CollectionAPI) githubdiscovery.CollectionAPI {
	return &discoveryBearerCollectionAPI{provider: collection.ProviderGitHub, github: api}
}

func newDiscoveryKubernetesCollectionAPI(allowedCIDRs []string, factory func(kubernetesdiscovery.PinnedCollectionAPIConfig) (kubernetesdiscovery.CollectionAPI, error)) kubernetesdiscovery.CollectionAPI {
	return &discoveryBearerCollectionAPI{provider: collection.ProviderKubernetes, kubernetes: factory, allowedCIDRs: append([]string(nil), allowedCIDRs...), timeout: time.Second}
}

func newDiscoveryOktaCollectionAPI(factory func(string, time.Duration) (idpdiscovery.CollectionAPI, error), timeout time.Duration) idpdiscovery.CollectionAPI {
	return &discoveryBearerCollectionAPI{provider: collection.ProviderOkta, okta: factory, timeout: timeout}
}

func (api *discoveryBearerCollectionAPI) FetchCollectionPage(ctx context.Context, credential []byte, request githubdiscovery.CollectionPageRequest) (githubdiscovery.CollectionPage, error) {
	if api == nil || ctx == nil || ctx.Err() != nil || request.Provider != api.provider {
		return githubdiscovery.CollectionPage{}, discoveryCredentialFailure(ctx, collection.FailureMalformed)
	}
	envelope, err := decodeDiscoveryCredentialEnvelope(credential)
	if err != nil || envelope.Provider != request.Provider || envelope.SubjectKind != request.Subject.Kind || envelope.SubjectID != request.Subject.ID {
		envelope.Destroy()
		return githubdiscovery.CollectionPage{}, discoveryCredentialFailure(ctx, collection.FailureMalformed)
	}
	if !envelope.ExpiresAt.After(time.Now().UTC()) {
		envelope.Destroy()
		return githubdiscovery.CollectionPage{}, discoveryCredentialFailure(ctx, collection.FailureRetryable)
	}
	defer envelope.Destroy()
	token := bytes.Clone(envelope.BearerToken)
	defer clear(token)
	var delegate githubdiscovery.CollectionAPI
	switch api.provider {
	case collection.ProviderGitHub:
		delegate = api.github
	case collection.ProviderKubernetes:
		if api.kubernetes != nil && api.timeout >= 100*time.Millisecond && api.timeout <= 30*time.Second {
			delegate, err = api.kubernetes(kubernetesdiscovery.PinnedCollectionAPIConfig{Endpoint: envelope.Endpoint, CABundlePEM: bytes.Clone(envelope.CABundlePEM), AllowedCIDRs: append([]string(nil), api.allowedCIDRs...), Timeout: api.timeout})
		}
	case collection.ProviderOkta:
		if api.okta != nil && api.timeout >= 100*time.Millisecond && api.timeout <= 30*time.Second {
			delegate, err = api.okta(envelope.Issuer, api.timeout)
		}
	}
	if err != nil || nilDiscoveryClientDependency(delegate) {
		return githubdiscovery.CollectionPage{}, mapDiscoveryProviderClientError(ctx, err)
	}
	page, err := callDiscoveryCollectionPage(delegate, ctx, token, request)
	if err != nil {
		return githubdiscovery.CollectionPage{}, mapDiscoveryProviderClientError(ctx, err)
	}
	return page, nil
}

func (api *discoveryBearerCollectionAPI) CheckCollectionReadiness(ctx context.Context) error {
	if api == nil || ctx == nil || ctx.Err() != nil {
		return discoveryCredentialFailure(ctx, collection.FailureCancelled)
	}
	if api.provider == collection.ProviderGitHub {
		if nilDiscoveryClientDependency(api.github) {
			return discoveryCredentialFailure(ctx, collection.FailureMalformed)
		}
		if err := api.github.CheckCollectionReadiness(ctx); err != nil {
			return mapDiscoveryProviderClientError(ctx, err)
		}
		return nil
	}
	if api.provider == collection.ProviderKubernetes && api.kubernetes != nil && len(api.allowedCIDRs) > 0 && api.timeout >= 100*time.Millisecond && api.timeout <= 30*time.Second {
		return nil
	}
	if api.provider == collection.ProviderOkta && api.okta != nil && api.timeout >= 100*time.Millisecond && api.timeout <= 30*time.Second {
		return nil
	}
	return discoveryCredentialFailure(ctx, collection.FailureMalformed)
}

func callDiscoveryCollectionPage(api githubdiscovery.CollectionAPI, ctx context.Context, credential []byte, request githubdiscovery.CollectionPageRequest) (page githubdiscovery.CollectionPage, resultErr error) {
	defer func() {
		if recover() != nil {
			page = githubdiscovery.CollectionPage{}
			resultErr = discoveryCredentialFailure(ctx, collection.FailureOutcomeUnknown)
		}
	}()
	return api.FetchCollectionPage(ctx, credential, request)
}

func mapDiscoveryProviderClientError(ctx context.Context, err error) error {
	var failure *collection.Failure
	if errors.As(err, &failure) && failure != nil {
		return failure
	}
	return discoveryCredentialFailure(ctx, collection.FailureRetryable)
}

func clearAWSCredentials(credentials *aws.Credentials) {
	if credentials == nil {
		return
	}
	credentials.AccessKeyID, credentials.SecretAccessKey, credentials.SessionToken = "", "", ""
	*credentials = aws.Credentials{}
}

func nilDiscoveryClientDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Pointer && reflected.IsNil()
}

var _ awsdiscovery.CollectionIdentityCaller = (*discoveryAWSCollectionIdentityCaller)(nil)
var _ githubdiscovery.CollectionAPI = (*discoveryBearerCollectionAPI)(nil)
