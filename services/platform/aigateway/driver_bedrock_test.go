package aigateway

import (
	"net/netip"
	"testing"
)

func TestBedrockTriagePinsVPCERegionModelAndCredential(t *testing.T) {
	ip := netip.MustParseAddr("10.10.4.12")
	const host = "vpce-abcd-efgh.bedrock-runtime.us-east-1.vpce.amazonaws.com"
	const model = "anthropic.claude-haiku-4-5"
	const reference = "secret_ref_planner/o/w/e/key"
	const token = "temporary-test-token-material"
	_, b, err := NewBedrockTriage(host, ip, model, reference, token, 123)
	if err != nil || b.Region != "us" || b.CredentialDigest == "" || b.DeploymentDigest == "" {
		t.Fatal(b, err)
	}
	for _, h := range []string{"bedrock-runtime.us-east-1.amazonaws.com", "vpce-abcd.bedrock-runtime.ap-south-1.vpce.amazonaws.com", host + "/path", host + ":443@outside.test"} {
		if _, _, err := NewBedrockTriage(h, ip, model, reference, token, 123); err == nil {
			t.Fatal("accepted endpoint", h)
		}
	}
	if _, _, err := NewBedrockTriage(host, netip.MustParseAddr("192.0.2.3"), model, reference, token, 123); err == nil {
		t.Fatal("accepted public destination")
	}
}
