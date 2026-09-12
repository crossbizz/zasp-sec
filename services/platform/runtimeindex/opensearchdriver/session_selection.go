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
