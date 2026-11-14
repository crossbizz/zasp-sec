package agentsignals

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestIAMPatternMatchesWildcards(t *testing.T) {
	for _, tc := range []struct {
		pattern, value string
		want           bool
	}{
		{"bedrock:invokemodel", "bedrock:invokemodel", true},
		{"bedrock:invoke*", "bedrock:invokemodel", true},
		{"bedrock:invoke*", "bedrock:invokemodelwithresponsestream", true},
		{"bedrock:*model", "bedrock:invokemodel", true},
		{"bedrock:*model", "bedrock:invokemodelwithresponsestream", false},
		{"bedrock:invoke?odel", "bedrock:invokemodel", true},
		{"bedrock:invoke?odel", "bedrock:invokemmodel", false},
		{"*", "anything:at/all", true},
		{"**", "", true},
		{"", "", true},
		{"", "a", false},
		{"a", "", false},
		{"s3:get*object", "s3:getobject", true},
		{"s3:get*object", "s3:getbucketobjectlock", false},
		// A star matches ":" and "/" as IAM does.
		{"bedrock*model", "bedrock:invokemodel", true},
		{"arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/a/b/c", true},
		// Backtracking on the last star.
		{"a*b*c", "aXbYbZc", true},
		{"a*b*c", "aXbYbZ", false},
		// Matching is case-sensitive: callers lower-case both sides.
		{"bedrock:InvokeModel", "bedrock:invokemodel", false},
	} {
		if got := IAMPatternMatches(tc.pattern, tc.value); got != tc.want {
			t.Errorf("IAMPatternMatches(%q, %q) = %v, want %v", tc.pattern, tc.value, got, tc.want)
		}
	}
}

func TestGrantedAIActionsExpandsOnlyNamedServices(t *testing.T) {
	for _, tc := range []struct {
		name     string
		patterns []string
		want     []string
	}{
		{"exact action", []string{"bedrock:InvokeModel"}, []string{"bedrock:InvokeModel"}},
		{"case and space insensitive", []string{"  BEDROCK:invokemodel "}, []string{"bedrock:InvokeModel"}},
		{"service wildcard", []string{"bedrock:*"}, []string{"bedrock:InvokeAgent", "bedrock:InvokeFlow", "bedrock:InvokeInlineAgent", "bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream", "bedrock:RetrieveAndGenerate"}},
		{"prefix wildcard", []string{"sagemaker:InvokeEndpoint*"}, []string{"sagemaker:InvokeEndpoint", "sagemaker:InvokeEndpointWithResponseStream"}},
		{"agentcore", []string{"bedrock-agentcore:Invoke*"}, []string{"bedrock-agentcore:InvokeAgentRuntime", "bedrock-agentcore:InvokeGateway"}},
		{"merged and deduplicated", []string{"bedrock:InvokeModel", "bedrock:Invoke*Agent", "bedrock:InvokeModel"}, []string{"bedrock:InvokeModel", "bedrock:InvokeAgent", "bedrock:InvokeInlineAgent"}},
		// Administrative grants are reported by their own check, not expanded.
		{"full admin", []string{"*"}, []string{}},
		{"service wildcard in service", []string{"*:Invoke*"}, []string{}},
		{"partial service wildcard", []string{"bed*:InvokeModel"}, []string{}},
		{"no service", []string{"InvokeModel"}, []string{}},
		{"empty service", []string{":InvokeModel"}, []string{}},
		{"unrelated service", []string{"s3:*", "iam:PassRole"}, []string{}},
		{"none", nil, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := GrantedAIActions(tc.patterns...)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)
			if got == nil {
				t.Fatal("GrantedAIActions returned nil, want an empty slice")
			}
			if len(got) != len(want) || (len(want) > 0 && !reflect.DeepEqual(got, want)) {
				t.Fatalf("GrantedAIActions(%q) = %q, want %q", tc.patterns, got, want)
			}
			if !sort.StringsAreSorted(got) {
				t.Fatalf("GrantedAIActions(%q) = %q, not sorted", tc.patterns, got)
			}
		})
	}
}

func TestAIActionCatalogIsSortedAndUnique(t *testing.T) {
	if !sort.StringsAreSorted(aiActionNames) {
		t.Fatalf("aiActionNames is not sorted: %q", aiActionNames)
	}
	seen := map[string]bool{}
	for _, action := range aiActionNames {
		if seen[strings.ToLower(action)] {
			t.Fatalf("aiActionNames repeats %q", action)
		}
		seen[strings.ToLower(action)] = true
	}
}

func TestInvocationActionMapsAuditEventsToAuthorizingAction(t *testing.T) {
	for event, want := range map[string]string{
		"InvokeModel": "bedrock:InvokeModel", "invokemodel": "bedrock:InvokeModel", "Converse": "bedrock:InvokeModel",
		"InvokeModelWithResponseStream": "bedrock:InvokeModelWithResponseStream", "ConverseStream": "bedrock:InvokeModelWithResponseStream",
	} {
		if got, ok := InvocationAction(event); !ok || got != want {
			t.Errorf("InvocationAction(%q) = %q, %v; want %q", event, got, ok, want)
		}
	}
	for _, event := range []string{"", "InvokeAgent", "ListFoundationModels", "InvokeEndpoint"} {
		if got, ok := InvocationAction(event); ok {
			t.Errorf("InvocationAction(%q) = %q, want no action", event, got)
		}
	}
	// Every authorizing action is a catalog action, so a granted action can be
	// matched with its observed use.
	for event, action := range invocationActions {
		found := false
		for _, catalog := range aiActionNames {
			found = found || catalog == action
		}
		if !found {
			t.Errorf("invocationActions[%q] = %q is not in aiActionNames", event, action)
		}
	}
}

func TestObservableAIActionOnlyForActionsTheAuditLogShows(t *testing.T) {
	for _, action := range []string{"bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"} {
		if !ObservableAIAction(action) {
			t.Errorf("ObservableAIAction(%q) = false, want true", action)
		}
	}
	// An action whose use cannot be seen must never be called unused.
	for _, action := range []string{"bedrock:InvokeAgent", "sagemaker:InvokeEndpoint", "bedrock-agentcore:InvokeAgentRuntime", "bedrock:invokemodel", ""} {
		if ObservableAIAction(action) {
			t.Errorf("ObservableAIAction(%q) = true, want false", action)
		}
	}
}

func TestDataActionClassifiesReadAndWrite(t *testing.T) {
	for _, tc := range []struct {
		action, service, access string
		ok                      bool
	}{
		{"s3:GetObject", "s3", "read", true},
		{"S3:ListBucket", "s3", "read", true},
		{" s3:HeadObject ", "s3", "read", true},
		{"s3:PutObject", "s3", "write", true},
		{"s3:DeleteObject", "s3", "write", true},
		{"s3:*", "s3", "write", true},
		{"s3:Get*", "s3", "read", true},
		{"dynamodb:Query", "dynamodb", "read", true},
		{"dynamodb:Scan", "dynamodb", "read", true},
		{"dynamodb:BatchGetItem", "dynamodb", "read", true},
		{"dynamodb:*Item", "dynamodb", "write", true},
		{"dynamodb:BatchWriteItem", "dynamodb", "write", true},
		{"secretsmanager:GetSecretValue", "secretsmanager", "read", true},
		{"secretsmanager:DescribeSecret", "secretsmanager", "read", true},
		{"secretsmanager:PutSecretValue", "secretsmanager", "write", true},
		{"rds-data:ExecuteStatement", "rds-data", "write", true},
		{"ssm:GetParameter", "ssm", "read", true},
		{"ssm:GetParametersByPath", "ssm", "read", true},
		{"ssm:PutParameter", "ssm", "write", true},
		{"ssm:*", "ssm", "write", true},
		// Systems Manager is a data store only through its parameters.
		{"ssm:SendCommand", "", "", false},
		{"ssm:GetDocument", "", "", false},
		{"ec2:DescribeInstances", "", "", false},
		{"bedrock:InvokeModel", "", "", false},
		{"*", "", "", false},
		{"s3", "", "", false},
		{"s3:", "", "", false},
		{"", "", "", false},
	} {
		service, access, ok := DataAction(tc.action)
		if service != tc.service || access != tc.access || ok != tc.ok {
			t.Errorf("DataAction(%q) = %q, %q, %v; want %q, %q, %v", tc.action, service, access, ok, tc.service, tc.access, tc.ok)
		}
	}
}

func TestInvocationEventNamesAreAllUnderstoodByInvoked(t *testing.T) {
	names := InvocationEventNames()
	if len(names) != len(invocationEvents) {
		t.Fatalf("InvocationEventNames() has %d names, invocationEvents has %d", len(names), len(invocationEvents))
	}
	if !sort.StringsAreSorted(names) {
		t.Fatalf("InvocationEventNames() = %q, not sorted", names)
	}
	for _, name := range names {
		if _, ok := invocationEvents[strings.ToLower(name)]; !ok {
			t.Errorf("InvocationEventNames() lists %q, which Invoked ignores", name)
		}
		var evidence Evidence
		evidence.Invoked(name)
		if !evidence.IsAgent() || len(evidence.Signals()) != 1 || !strings.HasPrefix(evidence.Signals()[0], "invoke:") {
			t.Errorf("Invoked(%q) recorded %q, want one strong invoke signal", name, evidence.Signals())
		}
	}
	// The returned slice is a fresh copy: a caller cannot change the list.
	names[0] = "Mutated"
	if InvocationEventNames()[0] == "Mutated" {
		t.Fatal("InvocationEventNames returned shared storage")
	}
}

func TestIsMCPConfigPath(t *testing.T) {
	for _, value := range []string{".mcp.json", "mcp.json", "/.mcp.json", "tools/mcp.json", ".cursor/mcp.json", "app/.cursor/mcp.json", ".vscode/mcp.json", "claude_desktop_config.json", "a/b/Claude_Desktop_Config.json", ".MCP.JSON", "./x/../.mcp.json"} {
		if !IsMCPConfigPath(value) {
			t.Errorf("IsMCPConfigPath(%q) = false, want true", value)
		}
	}
	for _, value := range []string{"", "/", "mcp.json.bak", "notmcp.json", "my.mcp.json.txt", "mcp.yaml", ".cursor/mcp.jsonc", "package.json", "mcp.json/readme.md"} {
		if IsMCPConfigPath(value) {
			t.Errorf("IsMCPConfigPath(%q) = true, want false", value)
		}
	}
	// Every path the parser is documented to read is recognised at the root.
	for _, candidate := range MCPConfigPaths {
		if !IsMCPConfigPath(candidate) {
			t.Errorf("IsMCPConfigPath(%q) = false for a listed MCPConfigPaths entry", candidate)
		}
	}
}

func TestIsClaudeSettingsPath(t *testing.T) {
	for _, value := range []string{".claude/settings.json", "/.claude/settings.json", "service/.claude/settings.json", ".Claude/Settings.JSON", "./.claude/../.claude/settings.json"} {
		if !IsClaudeSettingsPath(value) {
			t.Errorf("IsClaudeSettingsPath(%q) = false, want true", value)
		}
	}
	// The personal settings.local.json is not shared and is not read.
	for _, value := range []string{"", "settings.json", ".claude/settings.local.json", "claude/settings.json", "x.claude/settings.json", ".claude/settings.json.bak", ".claude"} {
		if IsClaudeSettingsPath(value) {
			t.Errorf("IsClaudeSettingsPath(%q) = true, want false", value)
		}
	}
}
