package apiserver

import (
	"strings"
	"testing"
)

func TestAuditExportPublicPageFilters(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	first, err := parseAuditListQuery("to=2026-09-13T00%3A00%3A00Z&action=identity_provider.createSSOConnection&from=2026-09-12T00%3A00%3A00.1Z", identity)
	if err != nil || first.limit != 50 || first.filters.from != "2026-09-12T00:00:00.100000Z" {
		t.Fatalf("valid filters: %#v %v", first, err)
	}
	second, err := parseAuditListQuery("limit=50&from=2026-09-12T00:00:00.100000Z&action=identity_provider.createSSOConnection&to=2026-09-13T00:00:00.000000Z", identity)
	if err != nil || first.digest != second.digest {
		t.Fatal("equivalent normalized filters changed cursor binding", err)
	}
	for _, query := range []string{"action=Policy.update", "action=é", "action=", "Action=policy.update", "action=policy.update&%61ction=policy.update", "limit=0", "limit=101", "cursor=", "after_id=x", "from=2026-02-30T00:00:00Z", "from=2026-09-12T00:00:00.0000001Z", "from=2026-09-12T00:00:00+00:00", "from=2026-09-13T00:00:00Z&to=2026-09-12T00:00:00Z", "actor_id=bogus", "outcome=rejected", "action=a%00b", "action=%ff", "action=%ZZ", "&", strings.Repeat("x", 2049)} {
		if _, err := parseAuditListQuery(query, identity); err == nil {
			t.Errorf("accepted malformed query %q", query)
		}
	}
	for _, query := range []string{"action=identity_provider.createssoconnection", "outcome=failed", "limit=1", "limit=100"} {
		if _, err := parseAuditListQuery(query, identity); err != nil {
			t.Errorf("valid query %q: %v", query, err)
		}
	}
}
