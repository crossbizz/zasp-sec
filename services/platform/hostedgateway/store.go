package hostedgateway

import (
	"context"
	"errors"
	"regexp"
)

// Errors of a Store.
var (
	// ErrNotFound: the Environment has no such gateway server.
	ErrNotFound = errors.New("gateway server not found")
	// ErrForbidden: the token may not use the gateway.
	ErrForbidden = errors.New("gateway use not permitted")
	// ErrUnavailable: the policy could not be read or the record not written.
	ErrUnavailable = errors.New("gateway store unavailable")
)

// Policy is the gateway policy of an Environment.
type Policy struct {
	Version int64
	// UnapprovedServers says what happens to a server the MCP registry has
	// no decision for: "allow" or "refuse". A blocked server is always
	// refused.
	UnapprovedServers string
	// DeniedToolRisks are the risk classes (execute, write, network, read,
	// unclassified) whose tools are hidden from tools/list and refused in
	// tools/call.
	DeniedToolRisks []string
	// RequestsPerMinute is the rate one API token may send; 0 is no limit.
	RequestsPerMinute int
}

// Server is one upstream MCP server registered behind the gateway.
type Server struct {
	ID          string
	Name        string
	UpstreamURL string
	Enabled     bool
	// AllowedTools, when not empty, are the only tools that may be called.
	// DeniedTools may never be called.
	AllowedTools []string
	DeniedTools  []string
	// Approval is the MCP registry's decision for the server's host:
	// approved, unapproved or blocked.
	Approval string
}

// Session is what one gateway request is decided under.
type Session struct {
	Policy           Policy
	Guardrail        Modes
	GuardrailVersion int64
	// Server is set for an MCP request.
	Server *Server
}

// Surfaces and directions of a record.
const (
	SurfaceMCP        = "mcp"
	SurfaceLLM        = "llm"
	DirectionRequest  = "request"
	DirectionResponse = "response"
)

// Record is one decision. It has no member that could hold a prompt, an
// argument, a result or an answer.
type Record struct {
	Surface   string
	Operation string
	Direction string
	Decision  string
	Reason    string
	Rules     []MatchedRule
	Bytes     int64
	Digest    string
	ToolName  string
	Provider  string
	Model     string
	AgentID   string
}

// ToolSeen is a tool a server listed through the gateway: its name and the
// risk class of the name. A description or a schema is never kept.
type ToolSeen struct {
	Name string
	Risk string
}

// Store answers what a request is decided under and takes its records. One
// Store value serves one request of one token.
type Store interface {
	// Open returns the session of the request. serverID is the gateway
	// server of an MCP request and empty for a model request.
	Open(ctx context.Context, serverID string) (Session, error)
	// Record writes the decisions of the request, and the tools the server
	// listed.
	Record(ctx context.Context, serverID string, records []Record, tools []ToolSeen) error
}

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)

// ValidIdentifier reports whether value may be recorded as a tool name, a
// model name or an agent identifier.
func ValidIdentifier(value string) bool { return identifierPattern.MatchString(value) }

func recordable(value string) string {
	if ValidIdentifier(value) {
		return value
	}
	return ""
}
