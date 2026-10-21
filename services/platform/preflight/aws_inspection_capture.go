package preflight

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"sync"
	"time"
)

// One process/run owns this private credential copy. It cannot be serialized or
// reconstructed from a report and never reloads an ambient credential source.
type awsInspectionCapture struct {
	mu          sync.Mutex
	credentials aws.Credentials
	closed      bool
}

func (c *awsInspectionCapture) Retrieve(ctx context.Context) (aws.Credentials, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || ctx == nil || ctx.Err() != nil || !c.credentials.HasKeys() || c.credentials.CanExpire && !c.credentials.Expires.After(time.Now().Add(time.Minute)) {
		return aws.Credentials{}, ErrRejected
	}
	return c.credentials, nil
}
func (c *awsInspectionCapture) release() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.credentials = aws.Credentials{}
}
