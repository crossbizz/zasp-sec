package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"slices"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type postLoginScope struct {
	Organization string `json:"organization_id"`
	Workspace    string `json:"workspace_id"`
	Environment  string `json:"environment_id"`
	Label        string `json:"label"`
}
type postLoginSnapshot struct {
	Principal postLoginPrincipal     `json:"principal"`
	Scopes    []postLoginScope       `json:"scopes"`
	Revision  authorization.Revision `json:"revision"`
}

type postLoginPrincipal struct {
	ID                    string `json:"id"`
	OrganizationID        string `json:"organization_id"`
	OrganizationReference string `json:"organization_reference"`
	MemberReference       string `json:"member_reference"`
	Role                  string `json:"role"`
	Active                bool   `json:"active"`
}

func (p postLoginPrincipal) valid(i RequestIdentity) bool {
	return p.ID == i.PrincipalID.String() && p.OrganizationID == i.Scope.OrganizationID().String() && validStytchReference(p.OrganizationReference, "organization-") && validStytchReference(p.MemberReference, "member-") && validMembershipRole(p.Role) && p.Active
}

// Pointers distinguish required zero/empty pending-state values from omission
// or null. The SQL table permits an unconfigured generation and applied=0.
type postLoginRevision struct {
	OrganizationID string  `json:"organization_id"`
	Desired        *int64  `json:"desired"`
	Applied        *int64  `json:"applied"`
	Generation     *int64  `json:"generation"`
	StoreID        *string `json:"store_id"`
	ModelID        *string `json:"model_id"`
}

var postLoginProjectionID = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

func (r postLoginRevision) value(i RequestIdentity) (authorization.Revision, bool) {
	if r.OrganizationID != i.Scope.OrganizationID().String() || r.Desired == nil || r.Applied == nil || r.Generation == nil || r.StoreID == nil || r.ModelID == nil || *r.Desired < 1 || *r.Applied < 0 || *r.Applied > *r.Desired || *r.Generation < 0 {
		return authorization.Revision{}, false
	}
	if *r.Generation == 0 {
		if *r.StoreID != "" || *r.ModelID != "" {
			return authorization.Revision{}, false
		}
	} else if !postLoginProjectionID.MatchString(*r.StoreID) || !postLoginProjectionID.MatchString(*r.ModelID) {
		return authorization.Revision{}, false
	}
	return authorization.Revision{OrganizationID: r.OrganizationID, Desired: *r.Desired, Applied: *r.Applied, Generation: *r.Generation, StoreID: *r.StoreID, ModelID: *r.ModelID}, true
}

type postLoginContextKey struct{}
type postLoginAuthorization struct {
	identity                  RequestIdentity
	binding                   json.RawMessage
	revision                  authorization.Revision
	purpose                   string
	permissions, capabilities []string
	environmentAudit          bool
}

func postLoginBinding(i RequestIdentity) (json.RawMessage, error) {
	c := i.credentialBinding
	if !validRequestIdentity(i, false) || c.Kind != i.CredentialKind || c.ID == "" || c.Digest == ([32]byte{}) || !validPermissions(c.PATCeiling) {
		return nil, authorization.ErrInvalid
	}
	csrf := ""
	if c.Kind == CredentialBrowserSession {
		d := sha256.Sum256([]byte(i.CSRFToken))
		csrf = hex.EncodeToString(d[:])
	}
	return json.Marshal(map[string]any{"credential_kind": c.Kind, "credential_id": c.ID, "credential_digest": hex.EncodeToString(c.Digest[:]), "principal_id": i.PrincipalID.String(), "organization_id": i.Scope.OrganizationID().String(), "workspace_id": i.Scope.WorkspaceID().String(), "environment_id": i.Scope.EnvironmentID().String(), "csrf_digest": csrf, "pat_ceiling": append([]string{}, c.PATCeiling...)})
}

func validatePostLoginScopes(scopes []postLoginScope, i RequestIdentity) error {
	if len(scopes) == 0 || len(scopes) > 10000 {
		return authorization.ErrUnavailable
	}
	active := false
	seen := map[string]bool{}
	for _, s := range scopes {
		o, oe := domain.ParseProductID(s.Organization)
		w, we := domain.ParseProductID(s.Workspace)
		e, ee := domain.ParseProductID(s.Environment)
		scope, se := domain.NewScope(o, w, e)
		key := s.Workspace + "/" + s.Environment
		if oe != nil || we != nil || ee != nil || se != nil || o != i.Scope.OrganizationID() || s.Label == "" || seen[key] {
			return authorization.ErrUnavailable
		}
		seen[key] = true
		active = active || scope == i.Scope
	}
	if !active {
		return authorization.ErrConflict
	}
	return nil
}

func readPostLoginSnapshot(ctx context.Context, d *PostgresJSONDatabase, i RequestIdentity, b json.RawMessage) (postLoginSnapshot, error) {
	var s postLoginSnapshot
	_, err := d.identityTransaction(ctx, identityPostLoginSnapshot, []any{string(b)}, func(raw json.RawMessage) error {
		var wire struct {
			Principal postLoginPrincipal `json:"principal"`
			Scopes    []postLoginScope   `json:"scopes"`
			Revision  postLoginRevision  `json:"revision"`
		}
		if decodeStrictIdentityAdministration(raw, &wire) != nil || !wire.Principal.valid(i) {
			return authorization.ErrUnavailable
		}
		revision, valid := wire.Revision.value(i)
		if !valid || validatePostLoginScopes(wire.Scopes, i) != nil {
			return authorization.ErrUnavailable
		}
		s = postLoginSnapshot{Principal: wire.Principal, Scopes: wire.Scopes, Revision: revision}
		return nil
	})
	if err != nil {
		return postLoginSnapshot{}, postLoginError(err)
	}
	return s, nil
}
func postLoginError(err error) error {
	if errors.Is(err, ErrRepositoryConflict) {
		return authorization.ErrConflict
	}
	return err
}

func (r *PostgresRepository) postLoginRead(ctx context.Context, i RequestIdentity, scopes bool) (json.RawMessage, error) {
	g, ok := ctx.Value(postLoginContextKey{}).(postLoginAuthorization)
	b, err := postLoginBinding(i)
	if !ok || err != nil || !slices.Equal(b, g.binding) || g.identity.Scope != i.Scope || g.identity.PrincipalID != i.PrincipalID || scopes != (g.purpose == "listSessionScopes") || !postLoginOperation(g.purpose) {
		return nil, authorization.ErrUnavailable
	}
	d, err := r.nativeIdentityDatabase()
	if err != nil {
		return nil, err
	}
	correlation, err := newWorkflowProductID()
	if err != nil {
		return nil, ErrRepositoryUnavailable
	}
	revision, _ := json.Marshal(g.revision)
	payload, err := d.identityTransaction(ctx, identityPostLoginRead, []any{string(b), string(revision), correlation, g.purpose}, func(raw json.RawMessage) error {
		if scopes {
			var page struct {
				Items []postLoginScope `json:"items"`
			}
			if decodeStrictIdentityAdministration(raw, &page) != nil {
				return authorization.ErrUnavailable
			}
			return validatePostLoginScopes(page.Items, i)
		}
		var result struct {
			Principal     postLoginPrincipal `json:"principal"`
			CorrelationID string             `json:"correlation_id"`
		}
		if decodeStrictIdentityAdministration(raw, &result) != nil || !result.Principal.valid(i) || !validProductID(result.CorrelationID) || result.CorrelationID != correlation {
			return authorization.ErrUnavailable
		}
		return nil
	})
	return payload, postLoginError(err)
}

func postLoginOperation(p string) bool {
	return p == "bootstrapSession" || p == "getCurrentPrincipal" || p == "listSessionScopes"
}

func postLoginBootstrap(ctx context.Context, payload json.RawMessage, i RequestIdentity, exports bool) (json.RawMessage, error) {
	g, ok := ctx.Value(postLoginContextKey{}).(postLoginAuthorization)
	if !ok {
		return authorizedBootstrapForInstallation(payload, i, exports)
	}
	if g.purpose != "bootstrapSession" || g.identity.PrincipalID != i.PrincipalID || g.identity.Scope != i.Scope {
		return nil, authorization.ErrUnavailable
	}
	i.Permissions = append([]string{}, g.permissions...)
	body, err := authorizedBootstrapForInstallation(payload, i, false)
	if err != nil {
		return nil, err
	}
	var value map[string]json.RawMessage
	if json.Unmarshal(body, &value) != nil {
		return nil, authorization.ErrUnavailable
	}
	caps := append([]string{}, g.capabilities...)
	if exports && g.environmentAudit {
		caps = append(caps, "audit.exports")
	}
	slices.Sort(caps)
	value["capabilities"], _ = json.Marshal(caps)
	return json.Marshal(value)
}
