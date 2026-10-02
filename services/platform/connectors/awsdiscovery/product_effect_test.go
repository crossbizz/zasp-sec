package awsdiscovery

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"strings"
	"testing"
	"time"
)

// Keep the real security runner's input/output authority comparison. Only its
// external process is controlled; foreign effect output must never be accepted.
func TestProductEffectSecurityAuthorityRejectsForeignOutput(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		request := securityRequestFixture(t, SecurityModeCartographyAWS)
		request.Attempt, request.EffectID = 0, strings.Repeat("a", 64)
		process := &recordingSecurityProcess{}
		var observed string
		process.respond = func(_ securityProcessSpec, input []byte) []byte {
			document := decodeSecurityFrameForTest(t, input)
			authority, ok := document["authority"].(map[string]any)
			if !ok {
				t.Fatal("missing authority")
			}
			observed, _ = authority["effect_id"].(string)
			if foreign {
				authority["effect_id"] = strings.Repeat("b", 64)
				document["authority"] = authority
			}
			return securityResponseFrameForTest(t, document, json.RawMessage(`{"policies":[],"roles":[],"version":"0.139.1"}`))
		}
		runner := newSecurityRunnerForTest(process, time.Second, func() time.Time { return request.ObservedAt })
		_, err := runner.Collect(context.Background(), request, nil)
		if observed != request.EffectID || (err != nil) != foreign {
			t.Fatal("security product authority", foreign, observed, err)
		}
	}
}

type productEffectAnalyzer struct {
	recordingSecurityAnalyzer
	effect string
	got    string
}

func (a *productEffectAnalyzer) Collect(ctx context.Context, r CollectionSecurityRequest, credential []byte) (CollectionSecurityResult, error) {
	a.got = r.EffectID
	return a.recordingSecurityAnalyzer.Collect(ctx, r, credential)
}

func TestProductEffectInventoryPropagatesSecurityAuthority(t *testing.T) {
	authority := awsInventoryAuthority(t, "pid_51000001-0000-4000-8000-000000000001")
	authority.Attempt, authority.EffectID = 0, strings.Repeat("c", 64)
	analyzer := &productEffectAnalyzer{}
	api, err := NewInventoryCollectionAPI(&recordingAWSInventoryCaller{snapshot: awsInventoryFixture()}, analyzer, authority, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request := CollectionPageRequest{Provider: collection.ProviderAWS, Subject: collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}, Page: 1, RemainingItems: 100, RemainingRelationships: 200, RemainingFindings: 7, RemainingBytes: 1 << 20}
	first, err := api.FetchCollectionPage(context.Background(), []byte("controlled-credential"), request)
	if err != nil {
		t.Fatal(err)
	}
	request.Cursor, request.Page = first.Cursor, 2
	_, err = api.FetchCollectionPage(context.Background(), []byte("controlled-credential"), request)
	if err != nil || analyzer.got != authority.EffectID {
		t.Fatal("effect lost at actual inventory security boundary", analyzer.got, err)
	}
	authority.Attempt = 1
	if _, err := NewInventoryCollectionAPI(&recordingAWSInventoryCaller{snapshot: awsInventoryFixture()}, analyzer, authority, time.Second); err == nil {
		t.Fatal("mixed authority accepted")
	}
}
