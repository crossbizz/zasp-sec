package opensearchdriver

import (
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
)

// NewConfiguredSessionIndex uses a fixed, explicitly selected session index.
func NewConfiguredSessionIndex(name string, config Config, credentials aws.CredentialsProvider, signer HTTPSigner, clock func() time.Time) (*SessionIndex, error) {
	switch name {
	case "", "zasp-runtime-sessions-v1":
		return NewSessionIndex(config, credentials, signer, clock)
	case "zasp-runtime-sessions-v2":
		return NewSandboxSessionIndex(config, credentials, signer, clock)
	default:
		return nil, runtimeindex.ErrConfiguration
	}
}

// ValidSessionIndexName rejects aliases, wildcards and unrecognized generations.
func ValidSessionIndexName(name string) bool {
	return name == "" || name == "zasp-runtime-sessions-v1" || name == "zasp-runtime-sessions-v2"
}

// NewRetainedSessionIndex explicitly binds a current request/lease visibility
// authority. Existing constructors preserve the original deployment profile;
// retention-enabled composition must use this constructor and a real adapter.
func NewRetainedSessionIndex(name string, config Config, credentials aws.CredentialsProvider, signer HTTPSigner, clock func() time.Time, visibility runtimeindex.EventVisibility) (*SessionIndex, error) {
	if nilInterface(visibility) {
		return nil, runtimeindex.ErrConfiguration
	}
	index, err := NewConfiguredSessionIndex(name, config, credentials, signer, clock)
	if err != nil {
		return nil, err
	}
	index.retention = visibility
	return index, nil
}

// NewRetainedSessionWriteIndex binds private worker-lease authority to writes.
// Read filtering remains a separate explicit constructor and request boundary.
func NewRetainedSessionWriteIndex(name string, config Config, credentials aws.CredentialsProvider, signer HTTPSigner, clock func() time.Time, authority runtimeindex.RetainedWriteAuthority) (*SessionIndex, error) {
	if nilInterface(authority) {
		return nil, runtimeindex.ErrConfiguration
	}
	index, err := NewConfiguredSessionIndex(name, config, credentials, signer, clock)
	if err != nil {
		return nil, err
	}
	index.retentionWrite = authority
	return index, nil
}
