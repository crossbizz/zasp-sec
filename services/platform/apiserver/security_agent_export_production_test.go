package apiserver

import (
	"context"
	"errors"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"testing"
	"time"
)

type agentExportProductionDatabase struct {
	exportSettlementDatabase
	available bool
	probeErr  error
}

func (d *agentExportProductionDatabase) SecurityAgentExportsAvailable(context.Context) (bool, error) {
	return d.available, d.probeErr
}
func TestSecurityAgentExportProductionReleaseGate(t *testing.T) {
	for _, mode := range []string{"absent", "ready", "drift"} {
		t.Run(mode, func(t *testing.T) {
			db := &agentExportProductionDatabase{available: mode == "ready"}
			if mode == "drift" {
				db.probeErr = errors.New("drift")
			}
			c := ComplianceHandlerConfiguration{Bucket: "controlled-export-bucket", ExpectedBucketOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-4234-8234-123456789012", ProviderTimeout: time.Second, Client: s3.New(s3.Options{Region: "us-east-1"})}
			h, err := NewSecurityAgentExportProductionHandler(context.Background(), db, c)
			switch mode {
			case "absent":
				if h != nil || err != nil {
					t.Fatalf("older release rejected: %v", err)
				}
			case "drift":
				if h != nil || err == nil {
					t.Fatal("installed drift accepted")
				}
			case "ready":
				if h == nil || err != nil {
					t.Fatalf("ready export surface unavailable: %v", err)
				}
				if h.Ready(context.Background()) != nil {
					t.Fatal("ready check refused")
				}
				db.available = false
				if h.Ready(context.Background()) == nil {
					t.Fatal("downgrade kept readiness")
				}
			}
		})
	}
}
