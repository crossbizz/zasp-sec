// Package mcpserver exposes a fixed catalog of product reads over the stateless
// MCP transport. The caller supplies an authenticated reader for this request.
package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type Read func(context.Context, string, string, url.Values) (int, []byte)

type tool struct {
	name        string
	operation   string
	description string
}

var catalog = []tool{
	{"list_agents", "listAgents", "List agents in the current environment. Continue with the returned cursor."},
	{"get_attack_path", "getAttackPath", "Read an authorized attack path for defensive review."},
	{"inspect_session", "getSessionIntent", "Read observed session evidence and its current outcome."},
	{"get_addon_drift", "getAddonDeploymentApproval", "Read the deployment review state for an add-on version."},
	{"get_posture_summary", "getAgentPostureSummary", "Read an agent’s approved purpose, granted access and observed use."},
}

type itemInput struct {
	ID string `json:"id" jsonschema:"Product identifier from this environment"`
}
type addonInput struct {
	ID    string `json:"id" jsonschema:"Add-on version identifier"`
	Agent string `json:"agent_id" jsonschema:"Agent receiving this deployment"`
}
type listInput struct {
	Cursor string `json:"cursor,omitempty" jsonschema:"Opaque cursor returned by the previous page"`
}

func description(t tool) *mcp.Tool {
	return &mcp.Tool{Name: t.name, Description: t.description, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: new(bool)}}
}

func result(status int, raw []byte) (*mcp.CallToolResult, any, error) {
	switch {
	case status == http.StatusForbidden || status == http.StatusNotFound || status == http.StatusUnauthorized:
		return nil, nil, errors.New("This record is unavailable for the current credential and scope.")
	case status != http.StatusOK || len(raw) > 128<<10 || !json.Valid(raw):
		return nil, nil, errors.New("The product read could not return a bounded result.")
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(raw)}}}, nil, nil
}

func addTool(s *mcp.Server, t tool, read Read) {
	if t.operation == "getAddonDeploymentApproval" {
		mcp.AddTool(s, description(t), func(ctx context.Context, _ *mcp.CallToolRequest, in addonInput) (*mcp.CallToolResult, any, error) {
			if _, err := domain.ParseProductID(in.ID); err != nil {
				return nil, nil, errors.New("A valid add-on version identifier is required.")
			}
			if _, err := domain.ParseProductID(in.Agent); err != nil {
				return nil, nil, errors.New("A valid deployment agent identifier is required.")
			}
			return result(read(ctx, t.operation, in.ID, url.Values{"agent_id": {in.Agent}}))
		})
		return
	}
	if t.operation == "listAgents" {
		mcp.AddTool(s, description(t), func(ctx context.Context, _ *mcp.CallToolRequest, in listInput) (*mcp.CallToolResult, any, error) {
			if len(in.Cursor) > 2048 || strings.ContainsAny(in.Cursor, "\r\n") {
				return nil, nil, errors.New("Invalid page cursor.")
			}
			q := url.Values{"limit": {"20"}}
			if in.Cursor != "" {
				q.Set("cursor", in.Cursor)
			}
			return result(read(ctx, t.operation, "", q))
		})
		return
	}
	mcp.AddTool(s, description(t), func(ctx context.Context, _ *mcp.CallToolRequest, in itemInput) (*mcp.CallToolResult, any, error) {
		if _, err := domain.ParseProductID(in.ID); err != nil {
			return nil, nil, errors.New("A valid product identifier is required.")
		}
		return result(read(ctx, t.operation, in.ID, nil))
	})
}

// Each request gets its own catalog and reader. There is no shared MCP session
// or cached product authorization between requests, tenants or replicas.
func Serve(w http.ResponseWriter, r *http.Request, visible func(string) bool, read Read) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Body == nil {
		http.Error(w, "A JSON-RPC message is required", http.StatusBadRequest)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, (16<<10)+1))
	if err != nil || len(raw) > 16<<10 {
		http.Error(w, "MCP message exceeds the request limit", http.StatusRequestEntityTooLarge)
		return
	}
	message := bytes.TrimSpace(raw)
	if len(message) == 0 || message[0] != '{' || !json.Valid(message) {
		http.Error(w, "Send one JSON-RPC object per POST", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(message))
	server := mcp.NewServer(&mcp.Implementation{Name: "zasp", Version: "1"}, nil)
	for _, t := range catalog {
		if visible(t.operation) {
			addTool(server, t, read)
		}
	}
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	handler.ServeHTTP(w, r)
}
