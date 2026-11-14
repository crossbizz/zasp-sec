package awsdiscovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

const (
	awsAgentTestAccount = "123456789012"
	awsAgentTestRole    = "arn:aws:iam::123456789012:role/read"
)

// A mixed account: a Bedrock agent whose role the IAM phase emits, an
// AgentCore runtime whose role it does not, a gateway, and two Lambda
// functions inferred to be agents. AgentCore was refused in some region.
func awsAgentSourceValue() AgentInventorySource {
	return AgentInventorySource{
		AccountID:     awsAgentTestAccount,
		BedrockAgents: []AgentInventoryBedrockAgent{{AgentID: "AGENT12345", ARN: "arn:aws:bedrock:us-east-1:123456789012:agent/AGENT12345", Model: "anthropic.claude-sonnet", Name: "support", Region: "us-east-1", RoleARN: awsAgentTestRole, Status: "PREPARED"}},
		Gateways:      []AgentInventoryGateway{{ARN: "arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/gw-1", GatewayID: "gw-1", Name: "tools", Region: "us-west-2", Status: "READY"}},
		LambdaFunctions: []AgentInventoryLambdaFunction{
			{ARN: "arn:aws:lambda:us-east-1:123456789012:function:bot", Name: "bot", Region: "us-east-1", RoleARN: awsAgentTestRole, Signals: []string{"env:openai"}, State: "Active"},
			{ARN: "arn:aws:lambda:us-east-1:123456789012:function:invoker", Name: "invoker", Region: "us-east-1", RoleARN: awsAgentTestRole, Signals: []string{"iam:bedrock_invoke_model"}, State: ""},
		},
		Runtimes: []AgentInventoryRuntime{{ARN: "arn:aws:bedrock-agentcore:us-west-2:123456789012:runtime/rt-1", Name: "researcher", Region: "us-west-2", RoleARN: "arn:aws:iam::123456789012:role/not-in-inventory", RuntimeID: "rt-1", Status: "READY"}},
		Services: []AgentInventoryService{{Service: AgentServiceBedrockAgents, Status: AgentServiceCollected}, {Service: AgentServiceAgentCore, Status: AgentServiceAccessDenied}, {Service: AgentServiceLambda, Status: AgentServiceCollected}},
	}
}

func awsAgentSourceFixture() json.RawMessage {
	encoded, ok := EncodeAgentInventorySource(awsAgentSourceValue())
	if !ok {
		panic("agent source fixture is not canonical")
	}
	return encoded
}

func awsAgentInventory(t *testing.T, source AgentInventorySource) CollectionInventory {
	t.Helper()
	encoded, ok := EncodeAgentInventorySource(source)
	if !ok {
		t.Fatalf("source refused: %#v", source)
	}
	inventory := awsInventoryFixture()
	inventory.AgentSource, inventory.AgentDigest = encoded, sha256.Sum256(encoded)
	return inventory
}

// fetchAWSAgentPage runs the pages of one collection up to the agents page.
func fetchAWSAgentPage(t *testing.T, inventory CollectionInventory) (CollectionPage, CollectionInventoryAuthority) {
	t.Helper()
	authority := awsInventoryAuthority(t, "pid_51000001-0000-4000-8000-000000000001")
	api, err := NewInventoryCollectionAPI(&recordingAWSInventoryCaller{snapshot: inventory}, &recordingSecurityAnalyzer{}, authority, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request := CollectionPageRequest{Provider: collection.ProviderAWS, Subject: collection.SubjectBinding{Kind: "aws_account", ID: awsAgentTestAccount}, Page: 1, RemainingItems: 10_000, RemainingRelationships: 20_000, RemainingFindings: 7, RemainingBytes: 16 << 20}
	var page CollectionPage
	for number := 1; number <= 4; number++ {
		request.Page = number
		page, err = api.FetchCollectionPage(context.Background(), []byte("temporary-aws-credential-value"), request)
		if err != nil {
			t.Fatalf("page %d: %v", number, err)
		}
		request.Cursor = page.Cursor
	}
	return page, authority
}

type awsAgentTestEntity struct {
	ID             string         `json:"id"`
	Kind           string         `json:"kind"`
	SourceNativeID string         `json:"source_native_id"`
	DisplayName    string         `json:"display_name"`
	StableFields   map[string]any `json:"stable_fields"`
	Attributes     map[string]any `json:"attributes"`
}

type awsAgentTestRelationship struct {
	ID             string         `json:"id"`
	Kind           string         `json:"kind"`
	SourceNativeID string         `json:"source_native_id"`
	FromEntityID   string         `json:"from_entity_id"`
	ToEntityID     string         `json:"to_entity_id"`
	Attributes     map[string]any `json:"attributes"`
}

func decodeAWSAgentPage(t *testing.T, page CollectionPage) (map[string]awsAgentTestEntity, []awsAgentTestRelationship) {
	t.Helper()
	entities := make(map[string]awsAgentTestEntity, len(page.Entities))
	previous := ""
	for _, raw := range page.Entities {
		var entity awsAgentTestEntity
		if err := json.Unmarshal(raw, &entity); err != nil || entity.ID <= previous {
			t.Fatalf("entity %s: order or decode: %v", raw, err)
		}
		previous = entity.ID
		entities[entity.SourceNativeID] = entity
	}
	relationships := make([]awsAgentTestRelationship, 0, len(page.Relationships))
	previous = ""
	for _, raw := range page.Relationships {
		var relationship awsAgentTestRelationship
		if err := json.Unmarshal(raw, &relationship); err != nil || relationship.ID <= previous || len(relationship.Attributes) != 0 {
			t.Fatalf("relationship %s: order or decode: %v", raw, err)
		}
		previous = relationship.ID
		relationships = append(relationships, relationship)
	}
	return entities, relationships
}

func awsAgentJSONObject(t *testing.T, value any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestAgentPageEmitsExactEntitiesAndRelationshipsForAMixedAccount(t *testing.T) {
	t.Parallel()
	page, authority := fetchAWSAgentPage(t, awsInventoryFixture())
	if page.Complete || len(page.Findings) != 0 || !strings.HasPrefix(page.Cursor.Value, "aws:posture:") {
		t.Fatalf("agents page = %#v", page)
	}
	subject := collection.SubjectBinding{Kind: "aws_account", ID: awsAgentTestAccount}
	id := func(kind, native string) string {
		return deterministicAWSInventoryID(authority.Scope, subject, kind, native)
	}
	withRole := awsAgentJSONObject(t, agentsignals.Posture{CredentialActive: true})
	provider := func(platform string) map[string]any {
		return awsAgentJSONObject(t, agentsignals.NewDiscovery(agentsignals.MethodProviderAPI, platform, nil))
	}
	inferred := func(signals ...string) map[string]any {
		return awsAgentJSONObject(t, agentsignals.NewDiscovery(agentsignals.MethodInferred, "lambda_function", signals))
	}
	const (
		agentARN   = "arn:aws:bedrock:us-east-1:123456789012:agent/AGENT12345"
		runtimeARN = "arn:aws:bedrock-agentcore:us-west-2:123456789012:runtime/rt-1"
		gatewayARN = "arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/gw-1"
		botARN     = "arn:aws:lambda:us-east-1:123456789012:function:bot"
		invokerARN = "arn:aws:lambda:us-east-1:123456789012:function:invoker"
	)
	service := func(native, name, code, status string) awsAgentTestEntity {
		return awsAgentTestEntity{ID: id("aws_service", native), Kind: "aws_service", SourceNativeID: native, DisplayName: name, StableFields: map[string]any{"account_id": awsAgentTestAccount, "name": name, "service": code}, Attributes: map[string]any{"status": status}}
	}
	want := map[string]awsAgentTestEntity{
		"aws:bedrock-agent":     service("aws:bedrock-agent", "Bedrock Agents", "bedrock-agent", "collected"),
		"aws:bedrock-agentcore": service("aws:bedrock-agentcore", "Bedrock AgentCore", "bedrock-agentcore", "access_denied"),
		"aws:lambda":            service("aws:lambda", "Lambda", "lambda", "collected"),
		agentARN: {ID: id("aws_bedrock_agent", agentARN), Kind: "aws_bedrock_agent", SourceNativeID: agentARN, DisplayName: "support",
			StableFields: map[string]any{"account_id": awsAgentTestAccount, "agent_id": "AGENT12345", "arn": agentARN, "name": "support", "region": "us-east-1"},
			Attributes:   map[string]any{"status": "PREPARED", "model": "anthropic.claude-sonnet", "posture": withRole, "discovery": provider("bedrock_agent")}},
		runtimeARN: {ID: id("aws_agentcore_runtime", runtimeARN), Kind: "aws_agentcore_runtime", SourceNativeID: runtimeARN, DisplayName: "researcher",
			StableFields: map[string]any{"account_id": awsAgentTestAccount, "arn": runtimeARN, "name": "researcher", "region": "us-west-2", "runtime_id": "rt-1"},
			Attributes:   map[string]any{"status": "READY", "posture": withRole, "discovery": provider("agentcore_runtime")}},
		gatewayARN: {ID: id("aws_agentcore_gateway", gatewayARN), Kind: "aws_agentcore_gateway", SourceNativeID: gatewayARN, DisplayName: "tools",
			StableFields: map[string]any{"account_id": awsAgentTestAccount, "arn": gatewayARN, "gateway_id": "gw-1", "name": "tools", "region": "us-west-2"},
			Attributes:   map[string]any{"status": "READY"}},
		botARN: {ID: id("aws_inferred_agent", botARN), Kind: "aws_inferred_agent", SourceNativeID: botARN, DisplayName: "bot",
			StableFields: map[string]any{"account_id": awsAgentTestAccount, "arn": botARN, "name": "bot", "region": "us-east-1", "resource_type": "lambda_function"},
			Attributes:   map[string]any{"state": "Active", "posture": withRole, "discovery": inferred("env:openai")}},
		invokerARN: {ID: id("aws_inferred_agent", invokerARN), Kind: "aws_inferred_agent", SourceNativeID: invokerARN, DisplayName: "invoker",
			StableFields: map[string]any{"account_id": awsAgentTestAccount, "arn": invokerARN, "name": "invoker", "region": "us-east-1", "resource_type": "lambda_function"},
			Attributes:   map[string]any{"posture": withRole, "discovery": inferred("iam:bedrock_invoke_model")}},
	}
	entities, relationships := decodeAWSAgentPage(t, page)
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("entities =\n%#v\nwant\n%#v", entities, want)
	}
	account, role := id("aws_account", awsAgentTestAccount), id("aws_role", awsAgentTestRole)
	wantEdges := []string{}
	for native, entity := range want {
		wantEdges = append(wantEdges, "contains|"+awsAgentTestAccount+"|contains|"+native+"|"+account+"|"+entity.ID)
	}
	// The runtime's role is not a role of this inventory: no edge to it.
	for _, native := range []string{agentARN, botARN, invokerARN} {
		wantEdges = append(wantEdges, "uses_identity|"+native+"|uses_identity|"+awsAgentTestRole+"|"+want[native].ID+"|"+role)
	}
	gotEdges := make([]string, 0, len(relationships))
	for _, relationship := range relationships {
		gotEdges = append(gotEdges, relationship.Kind+"|"+relationship.SourceNativeID+"|"+relationship.FromEntityID+"|"+relationship.ToEntityID)
	}
	sort.Strings(wantEdges)
	sort.Strings(gotEdges)
	if !reflect.DeepEqual(gotEdges, wantEdges) {
		t.Fatalf("relationships =\n%s\nwant\n%s", strings.Join(gotEdges, "\n"), strings.Join(wantEdges, "\n"))
	}
}

// An agent without an execution role has no active credential, and a state
// the provider did not give is not an attribute.
func TestAgentPagePostureFollowsTheExecutionRole(t *testing.T) {
	t.Parallel()
	source := awsAgentSourceValue()
	source.BedrockAgents[0].RoleARN, source.BedrockAgents[0].Model, source.BedrockAgents[0].Status = "", "", ""
	page, _ := fetchAWSAgentPage(t, awsAgentInventory(t, source))
	entities, relationships := decodeAWSAgentPage(t, page)
	agent := entities[source.BedrockAgents[0].ARN]
	if !reflect.DeepEqual(agent.Attributes, map[string]any{"posture": awsAgentJSONObject(t, agentsignals.Posture{}), "discovery": awsAgentJSONObject(t, agentsignals.NewDiscovery(agentsignals.MethodProviderAPI, "bedrock_agent", nil))}) {
		t.Fatalf("attributes = %#v", agent.Attributes)
	}
	for _, relationship := range relationships {
		if relationship.Kind == "uses_identity" && relationship.FromEntityID == agent.ID {
			t.Fatalf("agent without a role has an identity edge: %#v", relationship)
		}
	}
}

// Whatever the AI services answered, the collection still completes and the
// answer is the status of the service entity.
func TestAgentPageReportsServiceStatusAndStillCompletes(t *testing.T) {
	t.Parallel()
	for _, statuses := range [][3]string{
		{AgentServiceCollected, AgentServiceCollected, AgentServiceCollected},
		{AgentServiceAccessDenied, AgentServiceAccessDenied, AgentServiceAccessDenied},
		{AgentServiceUnavailable, AgentServiceUnavailable, AgentServiceUnavailable},
		{AgentServiceAccessDenied, AgentServiceUnavailable, AgentServiceCollected},
	} {
		source := AgentInventorySource{AccountID: awsAgentTestAccount, BedrockAgents: []AgentInventoryBedrockAgent{}, Gateways: []AgentInventoryGateway{}, LambdaFunctions: []AgentInventoryLambdaFunction{}, Runtimes: []AgentInventoryRuntime{},
			Services: []AgentInventoryService{{Service: AgentServiceBedrockAgents, Status: statuses[0]}, {Service: AgentServiceAgentCore, Status: statuses[1]}, {Service: AgentServiceLambda, Status: statuses[2]}}}
		authority := awsInventoryAuthority(t, "pid_51000001-0000-4000-8000-000000000001")
		api, err := NewInventoryCollectionAPI(&recordingAWSInventoryCaller{snapshot: awsAgentInventory(t, source)}, &recordingSecurityAnalyzer{}, authority, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		pages := runInventoryPages(t, api, []byte("temporary-aws-credential-value"))
		if len(pages) != 5 || !pages[4].Complete || len(pages[3].Entities) != 3 || len(pages[3].Relationships) != 3 {
			t.Fatalf("%v: pages = %#v", statuses, pages)
		}
		entities, _ := decodeAWSAgentPage(t, pages[3])
		for index, native := range []string{"aws:bedrock-agent", "aws:bedrock-agentcore", "aws:lambda"} {
			if entity := entities[native]; entity.Kind != "aws_service" || !reflect.DeepEqual(entity.Attributes, map[string]any{"status": statuses[index]}) {
				t.Fatalf("%v: %s = %#v", statuses, native, entity)
			}
		}
	}
}

func TestInventoryCursorNamesEachOfTheFivePhasesInOrder(t *testing.T) {
	t.Parallel()
	authority := awsInventoryAuthority(t, "pid_51000001-0000-4000-8000-000000000001")
	api, err := NewInventoryCollectionAPI(&recordingAWSInventoryCaller{snapshot: awsInventoryFixture()}, &recordingSecurityAnalyzer{}, authority, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	credential := []byte("temporary-aws-credential-value")
	pages := runInventoryPages(t, api, credential)
	for index, phase := range []string{"iam", "resources", "agents", "posture", "complete"} {
		if !strings.HasPrefix(pages[index].Cursor.Value, "aws:"+phase+":") || pages[index].Complete != (phase == "complete") {
			t.Fatalf("page %d cursor = %q complete=%v", index+1, pages[index].Cursor.Value, pages[index].Complete)
		}
	}
	request := CollectionPageRequest{Provider: collection.ProviderAWS, Subject: collection.SubjectBinding{Kind: "aws_account", ID: awsAgentTestAccount}, RemainingItems: 100, RemainingRelationships: 200, RemainingFindings: 7, RemainingBytes: 1 << 20}
	// A cursor is accepted only on the page of its phase, and there is no
	// sixth page.
	for name, bad := range map[string]struct {
		page   int
		cursor collection.Cursor
	}{
		"agents cursor on the resources page": {3, pages[2].Cursor},
		"posture cursor on the agents page":   {4, pages[3].Cursor},
		"resources cursor on the last page":   {5, pages[1].Cursor},
		"agents cursor skipped":               {5, pages[2].Cursor},
		"sixth page":                          {6, pages[3].Cursor},
	} {
		request.Page, request.Cursor = bad.page, bad.cursor
		if _, err := api.FetchCollectionPage(context.Background(), credential, request); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: error = %v", name, err)
		}
	}
}

// The agent source is part of the inventory a run is bound to: a later page
// that sees another agent source is refused, whether the account was read
// again or a kept inventory was handed back.
func TestInventoryDigestBindsTheAgentSource(t *testing.T) {
	t.Parallel()
	other := awsAgentSourceValue()
	other.LambdaFunctions = other.LambdaFunctions[:1]
	changed := awsAgentInventory(t, other)
	if collectionInventoryDigest(changed) == collectionInventoryDigest(awsInventoryFixture()) {
		t.Fatal("the inventory digest ignores the agent source")
	}
	authority := awsInventoryAuthority(t, "pid_51000001-0000-4000-8000-000000000001")
	credential := []byte("temporary-aws-credential-value")
	first := CollectionPageRequest{Provider: collection.ProviderAWS, Subject: collection.SubjectBinding{Kind: "aws_account", ID: awsAgentTestAccount}, Page: 1, RemainingItems: 100, RemainingRelationships: 200, RemainingFindings: 7, RemainingBytes: 1 << 20}

	caller := &recordingAWSInventoryCaller{snapshot: awsInventoryFixture()}
	api, err := NewInventoryCollectionAPI(caller, &recordingSecurityAnalyzer{}, authority, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	account, err := api.FetchCollectionPage(context.Background(), credential, first)
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.Page, second.Cursor = 2, account.Cursor
	caller.snapshot = changed
	if _, err := api.FetchCollectionPage(context.Background(), credential, second); !errors.Is(err, ErrInvalid) {
		t.Fatalf("drifted agent source on a fresh read: %v", err)
	}

	resuming := &resumingAWSInventoryCaller{recordingAWSInventoryCaller: recordingAWSInventoryCaller{snapshot: awsInventoryFixture()}}
	api, err = NewInventoryCollectionAPI(resuming, &recordingSecurityAnalyzer{}, authority, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if account, err = api.FetchCollectionPage(context.Background(), credential, first); err != nil {
		t.Fatal(err)
	}
	second.Cursor = account.Cursor
	resuming.tamper = func(inventory *CollectionInventory) {
		inventory.AgentSource, inventory.AgentDigest = changed.AgentSource, changed.AgentDigest
	}
	if _, err := api.FetchCollectionPage(context.Background(), credential, second); !errors.Is(err, ErrInvalid) || resuming.calls != 1 {
		t.Fatalf("drifted agent source on resume: %v, account reads %d", err, resuming.calls)
	}
	// A resumed page sees the agent source the first page read.
	resuming.tamper = nil
	var seen []byte
	resuming.tamper = func(inventory *CollectionInventory) { seen = bytes.Clone(inventory.AgentSource) }
	if _, err := api.FetchCollectionPage(context.Background(), credential, second); err != nil || !bytes.Equal(seen, awsInventoryFixture().AgentSource) {
		t.Fatalf("resume: %v, agent source %s", err, seen)
	}
}

func TestInventoryRefusesAHostileAgentSource(t *testing.T) {
	t.Parallel()
	encode := func(t *testing.T, value any) json.RawMessage {
		t.Helper()
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	many := func(count int) []AgentInventoryLambdaFunction {
		functions := make([]AgentInventoryLambdaFunction, count)
		for index := range functions {
			name := fmt.Sprintf("fn-%05d", index)
			functions[index] = AgentInventoryLambdaFunction{ARN: "arn:aws:lambda:us-east-1:123456789012:function:" + name, Name: name, Region: "us-east-1", Signals: []string{"env:openai"}}
		}
		return functions
	}
	cases := map[string]func(*testing.T, *CollectionInventory){
		"missing source": func(_ *testing.T, inventory *CollectionInventory) {
			inventory.AgentSource, inventory.AgentDigest = nil, sha256.Sum256(nil)
		},
		"digest mismatch": func(_ *testing.T, inventory *CollectionInventory) { inventory.AgentDigest[0] ^= 0xff },
		"digest of another source": func(t *testing.T, inventory *CollectionInventory) {
			other := awsAgentSourceValue()
			other.Gateways = []AgentInventoryGateway{}
			inventory.AgentSource = encode(t, other)
		},
		"wrong account id": func(t *testing.T, inventory *CollectionInventory) {
			source := awsAgentSourceValue()
			source.AccountID = "210987654321"
			inventory.AgentSource = encode(t, source)
		},
		"agent of another account": func(t *testing.T, inventory *CollectionInventory) {
			source := awsAgentSourceValue()
			source.BedrockAgents[0].ARN = "arn:aws:bedrock:us-east-1:210987654321:agent/AGENT12345"
			inventory.AgentSource = encode(t, source)
		},
		"region not the ARN's": func(t *testing.T, inventory *CollectionInventory) {
			source := awsAgentSourceValue()
			source.Runtimes[0].Region = "eu-west-1"
			inventory.AgentSource = encode(t, source)
		},
		"unknown member": func(_ *testing.T, inventory *CollectionInventory) {
			inventory.AgentSource = bytes.Replace(inventory.AgentSource, []byte(`{"account_id"`), []byte(`{"Environment":{"OPENAI_API_KEY":"x"},"account_id"`), 1)
		},
		"unknown item field": func(_ *testing.T, inventory *CollectionInventory) {
			inventory.AgentSource = bytes.Replace(inventory.AgentSource, []byte(`"signals":["env:openai"]`), []byte(`"signals":["env:openai"],"environment":{"OPENAI_API_KEY":"x"}`), 1)
		},
		"not canonical": func(_ *testing.T, inventory *CollectionInventory) {
			inventory.AgentSource = append([]byte(" "), inventory.AgentSource...)
		},
		"unsorted functions": func(t *testing.T, inventory *CollectionInventory) {
			source := awsAgentSourceValue()
			source.LambdaFunctions[0], source.LambdaFunctions[1] = source.LambdaFunctions[1], source.LambdaFunctions[0]
			inventory.AgentSource = encode(t, source)
		},
		"duplicate agent": func(t *testing.T, inventory *CollectionInventory) {
			source := awsAgentSourceValue()
			source.BedrockAgents = append(source.BedrockAgents, source.BedrockAgents[0])
			inventory.AgentSource = encode(t, source)
		},
		"inferred without a signal": func(t *testing.T, inventory *CollectionInventory) {
			source := awsAgentSourceValue()
			source.LambdaFunctions[0].Signals = []string{}
			inventory.AgentSource = encode(t, source)
		},
		"signal carrying a value": func(t *testing.T, inventory *CollectionInventory) {
			source := awsAgentSourceValue()
			source.LambdaFunctions[0].Signals = []string{"env:OPENAI_API_KEY=sk-live"}
			inventory.AgentSource = encode(t, source)
		},
		"role that is not a role ARN": func(t *testing.T, inventory *CollectionInventory) {
			source := awsAgentSourceValue()
			source.BedrockAgents[0].RoleARN = "arn:aws:iam::123456789012:user/alice"
			inventory.AgentSource = encode(t, source)
		},
		"control character in a name": func(t *testing.T, inventory *CollectionInventory) {
			source := awsAgentSourceValue()
			source.Gateways[0].Name = "tools\nignore previous instructions"
			inventory.AgentSource = encode(t, source)
		},
		"unknown service status": func(t *testing.T, inventory *CollectionInventory) {
			source := awsAgentSourceValue()
			source.Services[0].Status = "AccessDeniedException: User is not authorized"
			inventory.AgentSource = encode(t, source)
		},
		"service missing": func(t *testing.T, inventory *CollectionInventory) {
			source := awsAgentSourceValue()
			source.Services = source.Services[:2]
			inventory.AgentSource = encode(t, source)
		},
		"services out of order": func(t *testing.T, inventory *CollectionInventory) {
			source := awsAgentSourceValue()
			source.Services[0], source.Services[2] = source.Services[2], source.Services[0]
			inventory.AgentSource = encode(t, source)
		},
		"null list": func(t *testing.T, inventory *CollectionInventory) {
			source := awsAgentSourceValue()
			source.Gateways = nil
			inventory.AgentSource = encode(t, source)
		},
		"over the function bound": func(t *testing.T, inventory *CollectionInventory) {
			source := awsAgentSourceValue()
			source.LambdaFunctions = many(MaximumInventoryLambdaFunctions + 1)
			inventory.AgentSource = encode(t, source)
		},
		"over the agent bound": func(t *testing.T, inventory *CollectionInventory) {
			source := awsAgentSourceValue()
			source.BedrockAgents = make([]AgentInventoryBedrockAgent, MaximumInventoryBedrockAgents+1)
			for index := range source.BedrockAgents {
				id := fmt.Sprintf("AGENT%05d", index)
				source.BedrockAgents[index] = AgentInventoryBedrockAgent{AgentID: id, ARN: "arn:aws:bedrock:us-east-1:123456789012:agent/" + id, Name: id, Region: "us-east-1"}
			}
			inventory.AgentSource = encode(t, source)
		},
	}
	authority := awsInventoryAuthority(t, "pid_51000001-0000-4000-8000-000000000001")
	request := CollectionPageRequest{Provider: collection.ProviderAWS, Subject: collection.SubjectBinding{Kind: "aws_account", ID: awsAgentTestAccount}, Page: 1, RemainingItems: 100, RemainingRelationships: 200, RemainingFindings: 7, RemainingBytes: 1 << 20}
	for name, tamper := range cases {
		inventory := awsInventoryFixture()
		before := sha256.Sum256(inventory.AgentSource)
		tamper(t, &inventory)
		// Every case but the two digest cases presents a digest that matches
		// its bytes: the content is what is refused.
		if name != "digest mismatch" && name != "digest of another source" && name != "missing source" && sha256.Sum256(inventory.AgentSource) != before {
			inventory.AgentDigest = sha256.Sum256(inventory.AgentSource)
		}
		api, err := NewInventoryCollectionAPI(&recordingAWSInventoryCaller{snapshot: inventory}, &recordingSecurityAnalyzer{}, authority, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		// The first page already refuses it: nothing of the account is emitted.
		if page, err := api.FetchCollectionPage(context.Background(), []byte("temporary-aws-credential-value"), request); err == nil || len(page.Entities) != 0 {
			t.Fatalf("%s: accepted (%v)", name, err)
		}
	}
	// The bound itself is accepted.
	source := awsAgentSourceValue()
	source.LambdaFunctions = many(MaximumInventoryLambdaFunctions)
	page, _ := fetchAWSAgentPage(t, awsAgentInventory(t, source))
	if len(page.Entities) != MaximumInventoryLambdaFunctions+6 {
		t.Fatalf("entities at the bound = %d", len(page.Entities))
	}
}
