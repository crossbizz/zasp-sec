package main

import (
	"context"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/recovery/neondriver"
)

type recoverySecretResolver interface {
	ResolveDiscoverySecret(context.Context, string) ([]byte, error)
}

type rotatingRecoveryNeonClient struct {
	secrets        recoverySecretResolver
	reference      string
	projectID      string
	parentBranchID string
	timeout        time.Duration
}

type recoveryNeonDelegate struct {
	neondriver.Client
	close func() error
}

func (delegate *recoveryNeonDelegate) Close() error {
	if delegate == nil || delegate.close == nil {
		return nil
	}
	return delegate.close()
}

func newRotatingRecoveryNeonClient(secrets recoverySecretResolver, reference, projectID, parentBranchID string, timeout time.Duration) (*rotatingRecoveryNeonClient, error) {
	if secrets == nil || reference != "ref:neon/project-api-key" || !recoveryNeonProjectPattern.MatchString(projectID) || !recoveryNeonBranchPattern.MatchString(parentBranchID) || timeout < time.Second || timeout > 30*time.Second {
		return nil, errRuntimeUnavailable
	}
	return &rotatingRecoveryNeonClient{secrets: secrets, reference: reference, projectID: projectID, parentBranchID: parentBranchID, timeout: timeout}, nil
}

func (client *rotatingRecoveryNeonClient) CreateBranch(ctx context.Context, request neondriver.CreateBranchRequest) (neondriver.Branch, error) {
	delegate, err := client.delegate(ctx)
	if err != nil {
		return neondriver.Branch{}, neondriver.ErrRetryable
	}
	defer delegate.Close()
	return delegate.CreateBranch(ctx, request)
}

func (client *rotatingRecoveryNeonClient) GetBranchByName(ctx context.Context, projectID, name string) (neondriver.Branch, error) {
	delegate, err := client.delegate(ctx)
	if err != nil {
		return neondriver.Branch{}, neondriver.ErrRetryable
	}
	defer delegate.Close()
	return delegate.GetBranchByName(ctx, projectID, name)
}

func (client *rotatingRecoveryNeonClient) DeleteBranch(ctx context.Context, projectID, branchID string) error {
	delegate, err := client.delegate(ctx)
	if err != nil {
		return neondriver.ErrRetryable
	}
	defer delegate.Close()
	return delegate.DeleteBranch(ctx, projectID, branchID)
}

func (client *rotatingRecoveryNeonClient) Ready(ctx context.Context) error {
	delegate, err := client.delegate(ctx)
	if err != nil {
		return neondriver.ErrRetryable
	}
	defer delegate.Close()
	return delegate.Ready(ctx)
}

func (client *rotatingRecoveryNeonClient) delegate(ctx context.Context) (*recoveryNeonDelegate, error) {
	if client == nil || ctx == nil || ctx.Err() != nil {
		return nil, errRuntimeUnavailable
	}
	secret, err := client.secrets.ResolveDiscoverySecret(ctx, client.reference)
	if err != nil {
		clear(secret)
		return nil, errRuntimeUnavailable
	}
	delegate, err := neondriver.NewProductionClient(secret, client.projectID, client.parentBranchID, client.timeout)
	clear(secret)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	closer, ok := delegate.(interface{ Close() error })
	if !ok {
		return nil, errRuntimeUnavailable
	}
	return &recoveryNeonDelegate{Client: delegate, close: closer.Close}, nil
}

var _ neondriver.Client = (*rotatingRecoveryNeonClient)(nil)
