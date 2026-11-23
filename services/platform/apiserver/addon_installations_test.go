package apiserver

import (
	"encoding/json"
	"net/url"
	"testing"
)

// The fleet test calls this reader between signed inventory deliveries. Its
// own findings-only PAT creates the review; its browser sees scoped evidence.
func installedDigestImpact(t *testing.T, b *installedBaseline, admin, submitter installedPrincipal, digest string) func(string) ([]map[string]any, string) {
	t.Helper()
	h := &discoveryWorkflowSurface{addons: &addonReviewHandler{database: b.product, newProductID: newWorkflowProductID}}
	v := b.serve(h, submitter, "submitAddonScan", "POST", "/api/v1/addon-scans", nil, addonTestReport(b.e, `"`+digest+`"`), map[string]string{"Idempotency-Key": "fleet-observation-" + b.id()})
	var receipt struct {
		Version string `json:"version_id"`
	}
	if v.Code != 200 || json.Unmarshal(v.Body.Bytes(), &receipt) != nil || !validProductID(receipt.Version) {
		t.Fatal("create digest review", v.Code, v.Body.String())
	}
	return func(cursor string) ([]map[string]any, string) {
		t.Helper()
		path := "/api/v1/addon-versions/" + receipt.Version + "/installations?limit=1"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		res := b.serve(h, admin, "listAddonVersionInstallations", "GET", path, map[string]string{"id": receipt.Version}, "", nil)
		var page struct {
			Items []map[string]any `json:"items"`
			Next  *string          `json:"next_cursor"`
		}
		if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &page) != nil || page.Items == nil {
			t.Fatalf("installation page %d %s", res.Code, res.Body.String())
		}
		if page.Next != nil {
			return page.Items, *page.Next
		}
		return page.Items, ""
	}
}
