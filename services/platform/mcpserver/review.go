package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type Proposal struct {
	Reference string
	Name      string
	Action    string
	Effect    string
}
type ReviewTools struct {
	Visible func(string) bool
	Review  func(context.Context, string, Proposal) (int, []byte)
}

type draftInput struct {
	RequestID string `json:"request_id" jsonschema:"Stable product identifier for this proposal and all retries"`
	Name      string `json:"name" jsonschema:"Short policy title shown to its reviewer"`
	Action    string `json:"tool_action" jsonschema:"Exact action identifier to match"`
	Effect    string `json:"effect" jsonschema:"Proposed effect: monitor or block"`
}

var actionName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$`)
var title = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9 ._()/-]{0,95}$`)

func addReviewTools(s *mcp.Server, h *ReviewTools) {
	if h == nil {
		return
	}
	if h.Visible("propose_policy") {
		mcp.AddTool(s, &mcp.Tool{Name: "propose_policy", Description: "Save a draft Environment policy for human review. Activation requires a separate rollout.", Annotations: &mcp.ToolAnnotations{IdempotentHint: true, DestructiveHint: new(bool), OpenWorldHint: new(bool)}}, func(ctx context.Context, _ *mcp.CallToolRequest, in draftInput) (*mcp.CallToolResult, any, error) {
			if _, err := domain.ParseProductID(in.RequestID); err != nil || !title.MatchString(in.Name) || !actionName.MatchString(in.Action) || in.Effect != "block" && in.Effect != "monitor" {
				return nil, nil, errors.New("Supply a proposal identifier, a short title, an exact tool action and a monitor or block effect.")
			}
			return result(h.Review(ctx, "propose_policy", Proposal{Reference: in.RequestID, Name: in.Name, Action: in.Action, Effect: in.Effect}))
		})
	}
	for _, t := range []tool{
		{"request_containment", "", "Open the pending containment approval identified by id. A human reviews the exact plan before any containment."},
		{"trigger_verification", "", "Open the case identified by id for owner review of existing signed verification receipts."},
	} {
		if !h.Visible(t.name) {
			continue
		}
		mcp.AddTool(s, description(t), func(ctx context.Context, _ *mcp.CallToolRequest, in itemInput) (*mcp.CallToolResult, any, error) {
			if _, err := domain.ParseProductID(in.ID); err != nil {
				return nil, nil, errors.New("A valid approval or case identifier is required.")
			}
			return result(h.Review(ctx, t.name, Proposal{Reference: in.ID}))
		})
	}
}

func PendingReview(id, link string) (int, []byte) {
	raw, err := json.Marshal(map[string]string{"record_id": id, "state": "human_review_required", "review_url": link})
	if err != nil {
		return http.StatusInternalServerError, nil
	}
	return http.StatusOK, raw
}
