package awsdiscovery

import "testing"

// An agent whose create event the audit log still holds carries who created
// it, when, and that the claim comes from CloudTrail; every other agent
// carries none of the three.
func TestAgentPageCarriesWhoCreatedAnAgent(t *testing.T) {
	t.Parallel()
	source := awsAgentSourceValue()
	source.Creators = []AgentInventoryCreator{
		{ARN: source.BedrockAgents[0].ARN, CreatedAt: "2026-10-01T09:30:15Z", CreatedBy: "dana.reyes@example.com"},
		{ARN: source.LambdaFunctions[0].ARN, CreatedAt: "2026-09-12T18:00:00Z", CreatedBy: "ci-deployer/release-481"},
	}
	page, _ := fetchAWSAgentPage(t, awsAgentInventory(t, source))
	entities, _ := decodeAWSAgentPage(t, page)
	want := map[string][3]string{
		source.BedrockAgents[0].ARN:   {"dana.reyes@example.com", "2026-10-01T09:30:15Z", "cloudtrail"},
		source.LambdaFunctions[0].ARN: {"ci-deployer/release-481", "2026-09-12T18:00:00Z", "cloudtrail"},
	}
	for arn, entity := range entities {
		expected, attributed := want[arn]
		for index, name := range []string{"created_by", "created_at", "created_by_source"} {
			value, present := entity.Attributes[name]
			if present != attributed || attributed && value != expected[index] {
				t.Fatalf("%s %s = %v (present %t), want %q (attributed %t)", arn, name, value, present, expected[index], attributed)
			}
		}
	}
	for name, creators := range map[string][]AgentInventoryCreator{
		"an ARN that is not an agent of the source": {{ARN: "arn:aws:lambda:us-east-1:123456789012:function:absent", CreatedAt: "2026-10-01T09:30:15Z", CreatedBy: "dana"}},
		"a gateway":                {{ARN: source.Gateways[0].ARN, CreatedAt: "2026-10-01T09:30:15Z", CreatedBy: "dana"}},
		"a time with an offset":    {{ARN: source.BedrockAgents[0].ARN, CreatedAt: "2026-10-01T09:30:15+02:00", CreatedBy: "dana"}},
		"a time that is not one":   {{ARN: source.BedrockAgents[0].ARN, CreatedAt: "yesterday", CreatedBy: "dana"}},
		"free text as the creator": {{ARN: source.BedrockAgents[0].ARN, CreatedAt: "2026-10-01T09:30:15Z", CreatedBy: "Dana Reyes (platform)"}},
		"an empty creator":         {{ARN: source.BedrockAgents[0].ARN, CreatedAt: "2026-10-01T09:30:15Z", CreatedBy: ""}},
		"a repeated agent":         {{ARN: source.BedrockAgents[0].ARN, CreatedAt: "2026-10-01T09:30:15Z", CreatedBy: "dana"}, {ARN: source.BedrockAgents[0].ARN, CreatedAt: "2026-10-02T09:30:15Z", CreatedBy: "eli"}},
		"creators out of order":    {{ARN: source.LambdaFunctions[0].ARN, CreatedAt: "2026-10-01T09:30:15Z", CreatedBy: "dana"}, {ARN: source.BedrockAgents[0].ARN, CreatedAt: "2026-10-02T09:30:15Z", CreatedBy: "eli"}},
	} {
		hostile := awsAgentSourceValue()
		hostile.Creators = creators
		if _, ok := EncodeAgentInventorySource(hostile); ok {
			t.Errorf("%s was accepted", name)
		}
	}
}
