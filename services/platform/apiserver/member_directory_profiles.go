package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	platformidentity "github.com/zasp-ai/zasp-sec/services/platform/identity"
)

const memberDirectoryBatchSize = 20

func (p *RepositoryIdentityProvider) MemberProfiles(ctx context.Context, organization string, refs []string) ([]DirectoryMember, error) {
	driver := p.memberDirectoryDriver()
	if driver == nil || !validExactStytchReference(organization, "organization-") || len(refs) == 0 || len(refs) > memberDirectoryBatchSize {
		return nil, ErrRepositoryOperation
	}
	requested := make(map[string]bool, len(refs))
	for _, ref := range refs {
		if !validExactStytchReference(ref, "member-") || requested[ref] {
			return nil, ErrRepositoryOperation
		}
		requested[ref] = true
	}
	input := map[string]any{"organization_ids": []string{organization}, "limit": len(refs), "query": stytchSearchQuery{
		Operator: "AND", Operands: []stytchSearchOperand{{Name: "member_ids", Value: refs}},
	}}
	var response struct {
		StatusCode int               `json:"status_code"`
		Members    []DirectoryMember `json:"members"`
	}
	if err := driver.doJSON(ctx, http.MethodPost, "/v1/b2b/organizations/members/search", input, &response); err != nil || response.StatusCode != http.StatusOK {
		return nil, ErrRepositoryUnavailable
	}
	for _, member := range response.Members {
		if member.OrganizationReference != organization || !requested[member.Reference] {
			return nil, ErrRepositoryUnavailable
		}
		delete(requested, member.Reference)
	}
	return response.Members, nil
}

// Existing memberships hold only provider references. Fill missing profile
// fields from the directory, leaving locally edited names and invited addresses
// intact. A provider outage must not hide the authoritative membership page.
func (r *PostgresRepository) enrichMemberPage(ctx context.Context, organizationID string, payload json.RawMessage) json.RawMessage {
	var page map[string]json.RawMessage
	if json.Unmarshal(payload, &page) != nil {
		return payload
	}
	var rows []map[string]any
	decoder := json.NewDecoder(bytes.NewReader(page["items"]))
	decoder.UseNumber()
	if decoder.Decode(&rows) != nil || len(rows) == 0 || len(rows) > 101 {
		return payload
	}
	org := ""
	byRef := make(map[string]map[string]any)
	var refs []string
	for _, row := range rows {
		scope, _ := row["organization_id"].(string)
		providerOrg, _ := row["organization_reference"].(string)
		ref, _ := row["member_reference"].(string)
		if scope != organizationID || !validExactStytchReference(providerOrg, "organization-") || (org != "" && org != providerOrg) {
			return payload
		}
		org = providerOrg
		if row["email"] != nil && row["display_name"] != nil {
			continue
		}
		if !validExactStytchReference(ref, "member-") || byRef[ref] != nil {
			return payload
		}
		refs = append(refs, ref)
		byRef[ref] = row
	}
	readCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	changed := false
	for start := 0; start < len(refs); start += memberDirectoryBatchSize {
		batch := refs[start:min(start+memberDirectoryBatchSize, len(refs))]
		members, err := r.memberDirectory.MemberProfiles(readCtx, org, batch)
		if err != nil {
			break
		}
		for _, member := range members {
			row := byRef[member.Reference]
			if row == nil || member.OrganizationReference != org {
				continue
			}
			if email, ok := platformidentity.CanonicalMemberEmail(member.Email); ok && row["email"] == nil {
				row["email"] = email
				changed = true
			}
			if validAdministrationName(member.Name) && row["display_name"] == nil {
				row["display_name"] = member.Name
				changed = true
			}
		}
	}
	if !changed {
		return payload
	}
	items, err := json.Marshal(rows)
	if err != nil {
		return payload
	}
	page["items"] = items
	enriched, err := json.Marshal(page)
	if err != nil {
		return payload
	}
	return enriched
}
