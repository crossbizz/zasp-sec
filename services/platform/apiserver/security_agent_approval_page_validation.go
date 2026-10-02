package apiserver

import "time"

func validSecurityAgentApprovalPage(page SecurityAgentApprovalPage, input SecurityAgentApprovalPageRequest) bool {
	if len(page.Items) > input.Limit || (page.NextCreatedAt == nil) != (page.NextID == "") {
		return false
	}
	if page.NextCreatedAt != nil && (page.NextCreatedAt.IsZero() || page.NextCreatedAt.Location() != time.UTC || !validProductID(page.NextID) || len(page.Items) == 0) {
		return false
	}
	seen := make(map[string]bool, len(page.Items))
	for _, item := range page.Items {
		if !validSecurityAgentApproval(item) || seen[item.ID] || input.State != "" && item.State != input.State || input.RunID != "" && item.RunID != input.RunID {
			return false
		}
		seen[item.ID] = true
	}
	return true
}
