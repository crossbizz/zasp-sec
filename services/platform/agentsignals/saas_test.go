package agentsignals

import (
	"reflect"
	"testing"
)

func TestSaaSSurfaceAndModelProviderRecordOnlyCatalogTokens(t *testing.T) {
	var evidence Evidence
	evidence.Surface("model_serving")
	evidence.Surface("anything else")
	if token := evidence.ModelProvider("amazon-bedrock"); token != "bedrock" {
		t.Fatalf("bedrock provider token = %q", token)
	}
	if token := evidence.ModelProvider("some-private-gateway"); token != "" {
		t.Fatalf("unknown provider token = %q", token)
	}
	if got := evidence.Signals(); !reflect.DeepEqual(got, []string{"model:bedrock", "surface:model_serving"}) || !evidence.IsAgent() {
		t.Fatalf("signals = %v", got)
	}
}
