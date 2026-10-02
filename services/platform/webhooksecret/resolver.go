package webhooksecret

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type SecretsManagerAPI interface {
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}
type Resolver struct {
	client  SecretsManagerAPI
	prefix  string
	timeout time.Duration
}

var ErrUnavailable = errors.New("response webhook secret unavailable")
var referencePattern = regexp.MustCompile(`^secret_ref_([A-Za-z0-9][A-Za-z0-9._/-]{0,115})$`)
var versionPattern = regexp.MustCompile(`^[A-Za-z0-9-]{32,64}$`)
var prefixPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9/_-]{2,127}$`)

func NewResolver(client SecretsManagerAPI, prefix string, timeout time.Duration) (*Resolver, error) {
	if client == nil || !prefixPattern.MatchString(prefix) || !strings.HasSuffix(prefix, "/webhook") || !canonicalSecretPath(prefix) || timeout < 100*time.Millisecond || timeout > 10*time.Second {
		return nil, ErrUnavailable
	}
	return &Resolver{client, prefix, timeout}, nil
}

// ResolveVersion never consults the unqualified v35 namespace or AWSCURRENT.
// The returned slice belongs to the caller, who must clear it after signing.
func (r *Resolver) ResolveVersion(ctx context.Context, organizationID, workspaceID, environmentID, reference, version string) ([]byte, error) {
	if r == nil || r.client == nil || ctx == nil || ctx.Err() != nil || !versionPattern.MatchString(version) {
		return nil, ErrUnavailable
	}
	for _, id := range []string{organizationID, workspaceID, environmentID} {
		if _, err := domain.ParseProductID(id); err != nil {
			return nil, ErrUnavailable
		}
	}
	match := referencePattern.FindStringSubmatch(reference)
	if len(match) != 2 || !canonicalSecretPath(match[1]) {
		return nil, ErrUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	name := r.prefix + "/" + organizationID + "/" + workspaceID + "/" + environmentID + "/" + match[1]
	output, err := r.client.GetSecretValue(bounded, &secretsmanager.GetSecretValueInput{SecretId: aws.String(name), VersionId: aws.String(version)}, func(options *secretsmanager.Options) { options.Retryer = aws.NopRetryer{} })
	if output == nil {
		return nil, ErrUnavailable
	}
	// Clear SDK-owned binary material even when the provider returns both output
	// and an error. Go strings cannot be securely erased; don't retain their pointer.
	defer func() { clear(output.SecretBinary); output.SecretString = nil }()
	if err != nil || bounded.Err() != nil || aws.ToString(output.VersionId) != version || output.SecretString != nil == (len(output.SecretBinary) > 0) {
		return nil, ErrUnavailable
	}
	var key []byte
	if output.SecretString != nil {
		key = []byte(*output.SecretString)
	} else {
		key = append([]byte(nil), output.SecretBinary...)
	}
	if len(key) < 32 || len(key) > 4096 {
		clear(key)
		return nil, ErrUnavailable
	}
	return key, nil
}

func canonicalSecretPath(s string) bool {
	if strings.Contains(s, "..") || strings.Contains(s, "//") {
		return false
	}
	for _, part := range strings.Split(s, "/") {
		if part == "" || part == "." {
			return false
		}
	}
	return true
}
