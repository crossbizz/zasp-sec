package awsdiscovery

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
)

var ErrInvalid = errors.New("AWS connector input rejected")
var ErrDenied = errors.New("AWS connector identity denied")
var rolePattern = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,512}$`)
var regionPattern = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]$`)
var referencePattern = regexp.MustCompile(`^ref:aws/[a-z0-9][a-z0-9_./:-]{7,507}$`)

type Config struct{ RoleARN, ExternalIDReference, Region string }
type AssumeRoleRequest struct {
	RoleARN, Region string
	ExternalID      []byte
	Duration        time.Duration
}
type Identity struct{ AccountID, PrincipalARN string }

type ReferenceResolver interface {
	Resolve(context.Context, string) ([]byte, error)
}
type IdentityClient interface {
	GetCallerIdentity(context.Context, AssumeRoleRequest) (Identity, error)
}

type Adapter struct {
	client   IdentityClient
	resolver ReferenceResolver
	timeout  time.Duration
}

func NewAdapter(client IdentityClient, resolver ReferenceResolver, timeout time.Duration) (*Adapter, error) {
	if client == nil || resolver == nil || timeout < 100*time.Millisecond || timeout > 10*time.Second {
		return nil, ErrInvalid
	}
	return &Adapter{client: client, resolver: resolver, timeout: timeout}, nil
}

func (adapter *Adapter) TestConnection(ctx context.Context, config Config) (Identity, error) {
	match := rolePattern.FindStringSubmatch(config.RoleARN)
	if adapter == nil || adapter.client == nil || adapter.resolver == nil || ctx == nil || ctx.Err() != nil || len(match) != 2 || !referencePattern.MatchString(config.ExternalIDReference) || !regionPattern.MatchString(config.Region) {
		return Identity{}, ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, adapter.timeout)
	defer cancel()
	externalID, err := adapter.resolver.Resolve(bounded, config.ExternalIDReference)
	if err != nil || len(externalID) < 16 || len(externalID) > 256 {
		return Identity{}, ErrDenied
	}
	request := AssumeRoleRequest{RoleARN: config.RoleARN, Region: config.Region, ExternalID: append([]byte(nil), externalID...), Duration: 15 * time.Minute}
	identity, err := adapter.client.GetCallerIdentity(bounded, request)
	clear(request.ExternalID)
	clear(externalID)
	if err != nil || bounded.Err() != nil || identity.AccountID != match[1] || len(identity.PrincipalARN) > 1024 || !strings.HasPrefix(identity.PrincipalARN, "arn:aws:sts::"+match[1]+":assumed-role/") {
		return Identity{}, ErrDenied
	}
	return identity, nil
}
